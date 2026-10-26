package ldapauthz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

const adminsDN = "CN=App-Admins,OU=Groups,DC=corp,DC=example,DC=com"

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ldap_authz {
		url ldap://dc:389
		bind_dn "CN=svc,DC=corp"
		bind_password {env.LDAP_BIND_PASSWORD}
		base_dn "DC=corp"
		user {http.auth.user.id}
		user_filter "(sAMAccountName={user})"
		strip_domain corp.example.com
		strip_domain example.com
		require {http.auth.user.realm} corp
		require {http.auth.user.realm} partner
		ca_file /etc/ca.pem
		nested
		starttls
		allow "CN=A,DC=corp" "CN=B,DC=corp"
		allow "CN=C,DC=corp"
		cache_ttl 10m
		negative_ttl 1m
		timeout 2s
		stale_ttl 15m
	}`)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	want := Handler{
		URL:          "ldap://dc:389",
		BindDN:       "CN=svc,DC=corp",
		BindPassword: "{env.LDAP_BIND_PASSWORD}",
		BaseDN:       "DC=corp",
		User:         "{http.auth.user.id}",
		UserFilter:   "(sAMAccountName={user})",
		StripDomain:  []string{"corp.example.com", "example.com"},
		Require:      map[string][]string{"{http.auth.user.realm}": {"corp", "partner"}},
		CAFile:       "/etc/ca.pem",
		Nested:       true,
		StartTLS:     true,
		Allow:        []string{"CN=A,DC=corp", "CN=B,DC=corp", "CN=C,DC=corp"},
		CacheTTL:     caddy.Duration(10 * time.Minute),
		NegativeTTL:  caddy.Duration(time.Minute),
		Timeout:      caddy.Duration(2 * time.Second),
		StaleTTL:     caddy.Duration(15 * time.Minute),
	}
	got, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(exp) {
		t.Errorf("got  %s\nwant %s", got, exp)
	}
}

// TestUnmarshalCaddyfileEmptyValues covers options fed by unset environment
// variables, which expand to nothing (bare option) or "" (quoted).
func TestUnmarshalCaddyfileEmptyValues(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ldap_authz {
		url ldaps://dc.corp.example.com:636
		bind_dn "CN=svc,DC=corp,DC=example,DC=com"
		bind_password secret
		base_dn "DC=corp,DC=example,DC=com"
		user
		user_filter ""
		ca_file
		strip_domain
		strip_domain ""
		require
		require ""
		nested off
		starttls false
		allow_any_user ""
		allow
		allow ""
		allow "` + adminsDN + `"
		cache_ttl
		negative_ttl ""
		timeout ""
		stale_ttl
	}`)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if h.User != "" || h.UserFilter != "" || h.CAFile != "" || len(h.StripDomain) != 0 || len(h.Require) != 0 ||
		h.Nested || h.StartTLS || h.AllowAnyUser || !slices.Equal(h.Allow, []string{adminsDN}) ||
		h.CacheTTL != 0 || h.NegativeTTL != 0 || h.Timeout != 0 || h.StaleTTL != 0 {
		t.Fatalf("empty values not left unset: %+v", h)
	}
	if err := provisionAndValidate(&h); err != nil {
		t.Fatal(err)
	}
	checkDefaults(t, &h)
}

// TestEmptyAllowFailsClosed is the regression test for an unset allow list
// silently permitting every user in the directory.
func TestEmptyAllowFailsClosed(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ldap_authz {
		url ldaps://dc.corp.example.com:636
		bind_dn "CN=svc,DC=corp,DC=example,DC=com"
		bind_password secret
		base_dn "DC=corp,DC=example,DC=com"
		allow
		allow_any_user ""
	}`)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if err := provisionAndValidate(&h); err == nil {
		t.Fatal("config with no allow groups was accepted")
	}
}

func TestAllowAnyUser(t *testing.T) {
	h := validHandler()
	h.Allow, h.AllowAnyUser = nil, true
	if err := provisionAndValidate(h); err != nil {
		t.Fatal(err)
	}
	if h.memberFilter != "" {
		t.Errorf("memberFilter = %q, want none", h.memberFilter)
	}
}

func TestUnmarshalCaddyfileFlags(t *testing.T) {
	tests := map[string]bool{
		"nested":       true,
		"nested on":    true,
		"nested ON":    true,
		"nested true":  true,
		"nested 1":     true,
		"nested off":   false,
		"nested false": false,
		"nested 0":     false,
		`nested ""`:    false,
	}
	for line, want := range tests {
		t.Run(line, func(t *testing.T) {
			var h Handler
			d := caddyfile.NewTestDispenser("ldap_authz {\n" + line + "\n}")
			if err := h.UnmarshalCaddyfile(d); err != nil {
				t.Fatal(err)
			}
			if h.Nested != want {
				t.Errorf("Nested = %v, want %v", h.Nested, want)
			}
		})
	}
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	tests := map[string]string{
		"unknown option":          `bogus`,
		"extra arg":               `url a b`,
		"bad duration":            `cache_ttl soon`,
		"off not stale":           `cache_ttl off`,
		"zero cache_ttl":          `cache_ttl 0`,
		"negative timeout":        `timeout -1s`,
		"zero stale_ttl":          `stale_ttl 0`,
		"extra duration":          `timeout 1s 2s`,
		"bad flag":                `nested maybe`,
		"extra flag args":         `nested on off`,
		"require without value":   `require {http.auth.user.realm}`,
		"require empty value":     `require {http.auth.user.realm} ""`,
		"require not placeholder": `require realm corp`,
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			var h Handler
			d := caddyfile.NewTestDispenser("ldap_authz {\n" + line + "\n}")
			if err := h.UnmarshalCaddyfile(d); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func validHandler() *Handler {
	return &Handler{
		URL:          "ldaps://dc.corp.example.com:636",
		BindDN:       "CN=svc,DC=corp,DC=example,DC=com",
		BindPassword: "secret",
		BaseDN:       "DC=corp,DC=example,DC=com",
		Allow:        []string{adminsDN},
	}
}

func provisionAndValidate(h *Handler) error {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := h.Provision(ctx); err != nil {
		return err
	}
	return h.Validate()
}

func checkDefaults(t *testing.T, h *Handler) {
	t.Helper()
	if h.User != defaultUser || h.UserFilter != defaultFilter ||
		h.CacheTTL != caddy.Duration(defaultCacheTTL) || h.NegativeTTL != caddy.Duration(defaultNegativeTTL) ||
		h.Timeout != caddy.Duration(defaultTimeout) || h.StaleTTL != 0 {
		t.Errorf("defaults not applied: user=%q filter=%q cache_ttl=%v negative_ttl=%v timeout=%v stale_ttl=%v",
			h.User, h.UserFilter, time.Duration(h.CacheTTL), time.Duration(h.NegativeTTL),
			time.Duration(h.Timeout), time.Duration(h.StaleTTL))
	}
}

func TestProvisionDefaults(t *testing.T) {
	t.Setenv("LDAPAUTHZ_TEST_PASSWORD", "s3cret")
	h := validHandler()
	h.BindPassword = "{env.LDAPAUTHZ_TEST_PASSWORD}"
	if err := provisionAndValidate(h); err != nil {
		t.Fatal(err)
	}
	checkDefaults(t, h)
	if h.addr != "dc.corp.example.com:636" || h.tlsConf.ServerName != "dc.corp.example.com" {
		t.Errorf("addr = %q, server name = %q", h.addr, h.tlsConf.ServerName)
	}
	if want := "(|(memberOf=" + adminsDN + "))"; h.memberFilter != want {
		t.Errorf("memberFilter = %q, want %q", h.memberFilter, want)
	}
	if n := cap(h.slots); n != maxLookups {
		t.Errorf("lookup slots = %d, want %d", n, maxLookups)
	}
	// The password is resolved into an unexported field and the config
	// keeps the placeholder, so marshaling the handler cannot leak it.
	if h.bindPassword != "s3cret" || h.BindPassword != "{env.LDAPAUTHZ_TEST_PASSWORD}" {
		t.Error("resolved password was not kept out of the config")
	}
	if out, err := json.Marshal(h); err != nil || strings.Contains(string(out), "s3cret") {
		t.Errorf("marshaled handler contains the password, or failed: %v", err)
	}
}

func TestProvisionURL(t *testing.T) {
	tests := []struct {
		url      string
		starttls bool
		addr     string
		host     string
	}{
		{"ldaps://dc.corp.example.com", false, "dc.corp.example.com:636", "dc.corp.example.com"},
		{"ldaps://dc.corp.example.com:3269/", false, "dc.corp.example.com:3269", "dc.corp.example.com"},
		{"LDAPS://dc.corp.example.com", false, "dc.corp.example.com:636", "dc.corp.example.com"},
		{"ldap://dc.corp.example.com", true, "dc.corp.example.com:389", "dc.corp.example.com"},
		{"ldaps://[2001:db8::1]:636", false, "[2001:db8::1]:636", "2001:db8::1"},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			h := validHandler()
			h.URL, h.StartTLS = tt.url, tt.starttls
			if err := provisionAndValidate(h); err != nil {
				t.Fatalf("%s: %v", tt.url, err)
			}
			if h.addr != tt.addr || h.tlsConf.ServerName != tt.host {
				t.Errorf("%s: addr = %q, server name = %q; want %q, %q", tt.url, h.addr, h.tlsConf.ServerName, tt.addr, tt.host)
			}
		})
	}
}

func TestProvisionAndValidateErrors(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Handler){
		"bare CN in allow":         func(h *Handler) { h.Allow = []string{"App-Admins"} },
		"single RDN in allow":      func(h *Handler) { h.Allow = []string{"CN=App-Admins"} },
		"empty allow entry":        func(h *Handler) { h.Allow = []string{""} },
		"no allow groups":          func(h *Handler) { h.Allow = nil },
		"allow and allow_any_user": func(h *Handler) { h.AllowAnyUser = true },
		"missing url":              func(h *Handler) { h.URL = "" },
		"missing base_dn":          func(h *Handler) { h.BaseDN = "" },
		"missing bind_dn":          func(h *Handler) { h.BindDN = "" },
		"missing password":         func(h *Handler) { h.BindPassword = "" },
		"unset env password":       func(h *Handler) { h.BindPassword = "{env.LDAPAUTHZ_TEST_UNSET}" },
		"ldaps with starttls":      func(h *Handler) { h.StartTLS = true },
		"ldap without starttls":    func(h *Handler) { h.URL = "ldap://dc.corp.example.com:389" },
		"other scheme":             func(h *Handler) { h.URL = "ldapi:///var/run/slapd/ldapi" },
		"url with path":            func(h *Handler) { h.URL = "ldaps://dc.corp.example.com/DC=corp" },
		"url with query":           func(h *Handler) { h.URL = "ldaps://dc.corp.example.com?cn" },
		"url with userinfo":        func(h *Handler) { h.URL = "ldaps://svc:pw@dc.corp.example.com" },
		"url without host":         func(h *Handler) { h.URL = "ldaps://:636" },
		"url with bad port":        func(h *Handler) { h.URL = "ldaps://dc.corp.example.com:ldaps" },
		"filter without user":      func(h *Handler) { h.UserFilter = "(objectClass=user)" },
		"filter syntax":            func(h *Handler) { h.UserFilter = "(sAMAccountName={user}" },
		"missing ca_file":          func(h *Handler) { h.CAFile = "/nonexistent/ca.pem" },
		"ca_file without certs":    func(h *Handler) { h.CAFile = notPEM },
		"strip_domain flag value":  func(h *Handler) { h.StripDomain = []string{"on"} },
		"strip_domain with at":     func(h *Handler) { h.StripDomain = []string{"@corp.example.com"} },
		"require not placeholder":  func(h *Handler) { h.Require = map[string][]string{"realm": {"corp"}} },
		"require without values":   func(h *Handler) { h.Require = map[string][]string{"{http.auth.user.realm}": nil} },
		"require empty value":      func(h *Handler) { h.Require = map[string][]string{"{http.auth.user.realm}": {""}} },
		"negative cache_ttl":       func(h *Handler) { h.CacheTTL = -1 },
		"negative negative_ttl":    func(h *Handler) { h.NegativeTTL = -1 },
		"negative timeout":         func(h *Handler) { h.Timeout = -1 },
		"negative stale_ttl":       func(h *Handler) { h.StaleTTL = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			h := validHandler()
			mutate(h)
			if err := provisionAndValidate(h); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestMemberFilter(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		nested bool
		want   string
	}{
		{"direct", []string{adminsDN}, false, `(|(memberOf=` + adminsDN + `))`},
		{"nested", []string{adminsDN, "CN=Users,OU=Groups,DC=corp"}, true,
			`(|(memberOf:1.2.840.113556.1.4.1941:=` + adminsDN + `)(memberOf:1.2.840.113556.1.4.1941:=CN=Users,OU=Groups,DC=corp))`},
		{"escaped", []string{"CN=R(D)\\, Team*,OU=\u00c9quipe,DC=corp"}, false,
			`(|(memberOf=CN=R\28D\29\5c, Team\2a,OU=\c3\89quipe,DC=corp))`},
		{"trimmed", []string{"  " + adminsDN + " "}, false, `(|(memberOf=` + adminsDN + `))`},
		{"none", nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := memberFilter(tt.groups, tt.nested)
			if got != tt.want {
				t.Errorf("memberFilter = %q, want %q", got, tt.want)
			}
			if got != "" {
				if _, err := ldap.CompileFilter(got); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestUserFilter(t *testing.T) {
	h := &Handler{UserFilter: defaultFilter}
	now := time.Unix(1_700_000_000, 0)
	got := h.userFilter("*)(cn={now_filetime}", now)
	if want := `(userPrincipalName=\2a\29\28cn={now_filetime})`; !strings.Contains(got, want) {
		t.Errorf("filter %q lacks %q: the identity must be escaped and never substituted again", got, want)
	}
	if want := "(accountExpires>=" + strconv.FormatInt(filetime(now), 10) + ")"; !strings.Contains(got, want) {
		t.Errorf("filter %q lacks %q", got, want)
	}
	if _, err := ldap.CompileFilter(got); err != nil {
		t.Error(err)
	}
}

func TestFiletime(t *testing.T) {
	// The Unix epoch as a FILETIME is a well-known constant.
	if got := filetime(time.Unix(0, 0)); got != 116444736000000000 {
		t.Errorf("filetime(epoch) = %d", got)
	}
}

func TestIdentity(t *testing.T) {
	plain := &Handler{}
	strip := &Handler{StripDomain: []string{"corp.example.com", "KINGS.Example"}}
	tests := []struct {
		name string
		h    *Handler
		id   string
		want string // empty: denied
	}{
		{"plain", plain, "alice@corp.example.com", "alice@corp.example.com"},
		{"plain non-ASCII", plain, "jos\u00e9@corp.example.com", "jos\u00e9@corp.example.com"},
		{"control character", plain, "alice\n@corp.example.com", ""},
		{"NUL", plain, "alice\x00", ""},
		{"bidi override", plain, "alice\u202e@corp.example.com", ""},
		{"invalid UTF-8", plain, "alice\xff@corp.example.com", ""},
		{"too long", plain, strings.Repeat("a", maxIdentityLen+1), ""},
		{"longest", plain, strings.Repeat("a", maxIdentityLen), strings.Repeat("a", maxIdentityLen)},
		{"strip", strip, "alice@corp.example.com", "alice"},
		{"strip any case", strip, "alice@CORP.Example.COM", "alice"},
		{"strip second domain", strip, "bob@kings.example", "bob"},
		{"other domain", strip, "alice@attacker.example", ""},
		{"lookalike suffix", strip, "alice@corp.example.com.attacker.example", ""},
		{"Kelvin sign in domain", strip, "bob@\u212aings.example", ""},
		{"no domain", strip, "alice", ""},
		{"empty name", strip, "@corp.example.com", ""},
		{"empty domain", strip, "alice@", ""},
		{"two at signs", strip, "alice@attacker.example@corp.example.com", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.identity(tt.id)
			if tt.want == "" {
				if err == nil {
					t.Errorf("identity(%q) = %q, want denied", tt.id, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("identity(%q) = %q, %v; want %q", tt.id, got, err, tt.want)
			}
		})
	}
}

// testHandler returns a handler ready for authorize and ServeHTTP whose
// directory lookups are answered by lookup.
func testHandler(lookup func(context.Context, string) error) *Handler {
	return &Handler{
		User:        defaultUser,
		CacheTTL:    caddy.Duration(time.Minute),
		NegativeTTL: caddy.Duration(10 * time.Second),
		Timeout:     caddy.Duration(time.Second),
		log:         zap.NewNop(),
		cache:       &cache{entries: make(map[string]entry)},
		slots:       make(chan struct{}, maxLookups),
		lookupFn:    lookup,
	}
}

// request returns a request carrying the placeholders an authentication
// handler would have set.
func request(vars map[string]string) *http.Request {
	repl := caddy.NewReplacer()
	for k, v := range vars {
		repl.Set(k, v)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
}

// serve runs h on r and reports whether the request was passed on.
func serve(h *Handler, r *http.Request) (passed bool, err error) {
	err = h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		passed = true
		return nil
	}))
	return passed, err
}

// status returns the HTTP status of a handler error, or 0 for nil.
func status(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		t.Fatalf("err = %v, not a handler error", err)
	}
	return he.StatusCode
}

func TestServeHTTP(t *testing.T) {
	errDown := errors.New("dial tcp 10.0.0.5:636: i/o timeout")
	alice := map[string]string{"http.auth.user.email": "alice@corp.example.com", "http.auth.user.realm": "corp"}
	with := func(k, v string) map[string]string {
		m := maps.Clone(alice)
		m[k] = v
		return m
	}
	tests := []struct {
		name    string
		vars    map[string]string
		answer  error
		status  int // 0: passed to the next handler
		lookups int
	}{
		{"no identity", nil, nil, http.StatusUnauthorized, 0},
		{"allowed", alice, nil, 0, 1},
		{"other realm", with("http.auth.user.realm", "social"), nil, http.StatusForbidden, 0},
		{"no realm", with("http.auth.user.realm", ""), nil, http.StatusForbidden, 0},
		{"malformed identity", with("http.auth.user.email", "alice\u202e@corp.example.com"), nil, http.StatusForbidden, 0},
		{"oversized identity", with("http.auth.user.email", strings.Repeat("a", 4096)), nil, http.StatusForbidden, 0},
		{"not found", alice, errNotFound, http.StatusForbidden, 1},
		{"ambiguous", alice, errAmbiguous, http.StatusForbidden, 1},
		{"not a member", alice, errNotMember, http.StatusForbidden, 1},
		{"directory down", alice, errDown, http.StatusServiceUnavailable, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lookups int
			h := testHandler(func(context.Context, string) error {
				lookups++
				return tt.answer
			})
			h.Require = map[string][]string{"{http.auth.user.realm}": {"corp"}}

			passed, err := serve(h, request(tt.vars))
			if got := status(t, err); got != tt.status || passed != (tt.status == 0) {
				t.Errorf("status = %d, passed = %v; want %d", got, passed, tt.status)
			}
			if err != nil {
				for _, secret := range []string{"10.0.0.5", "not found", "member", "matched"} {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("error %q reveals the reason", err)
					}
				}
			}
			if lookups != tt.lookups {
				t.Errorf("lookups = %d, want %d", lookups, tt.lookups)
			}
		})
	}
}

// stubDirectory answers lookups from a table keyed by the exact identity,
// and records every identity it is asked about.
type stubDirectory struct {
	mu      sync.Mutex
	answers map[string]error // nil value: allowed; missing: errNotFound
	down    error            // when set, every lookup fails with it
	asked   []string
}

func (s *stubDirectory) lookup(_ context.Context, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, user)
	if s.down != nil {
		return s.down
	}
	if answer, ok := s.answers[user]; ok {
		return answer
	}
	return errNotFound
}

func stubHandler(answers map[string]error) (*Handler, *stubDirectory) {
	s := &stubDirectory{answers: answers}
	if s.answers == nil {
		s.answers = make(map[string]error)
	}
	return testHandler(s.lookup), s
}

// age moves the expiry of user's cache entry to d ago.
func age(h *Handler, user string, d time.Duration) {
	h.cache.mu.Lock()
	defer h.cache.mu.Unlock()
	e := h.cache.entries[user]
	e.exp = time.Now().Add(-d)
	h.cache.entries[user] = e
}

func TestCache(t *testing.T) {
	errDown := errors.New("dial: connection refused")
	const alice = "alice@corp.example.com"

	t.Run("hit", func(t *testing.T) {
		h, s := stubHandler(map[string]error{alice: nil})
		for range 3 {
			if err := h.authorize(alice); err != nil {
				t.Fatal(err)
			}
		}
		if n := len(s.asked); n != 1 {
			t.Errorf("lookups = %d, want 1", n)
		}
	})

	t.Run("key is the exact identity", func(t *testing.T) {
		h, s := stubHandler(map[string]error{"Alice@corp.example.com": nil})
		if err := h.authorize("Alice@corp.example.com"); err != nil {
			t.Fatal(err)
		}
		if err := h.authorize("alice@corp.example.com"); !errors.Is(err, errNotFound) {
			t.Errorf("err = %v; the directory, not the cache, decides whether case matters", err)
		}
		if want := []string{"Alice@corp.example.com", "alice@corp.example.com"}; !slices.Equal(s.asked, want) {
			t.Errorf("asked %q, want %q", s.asked, want)
		}
	})

	// Unicode lowercasing turns these into admin and kate, which let one
	// user be served another's cached grant.
	t.Run("lookalikes do not share entries", func(t *testing.T) {
		victims := map[string]string{
			"adm\u0130n@corp.example.com": "admin@corp.example.com", // U+0130
			"\u212aate@corp.example.com":  "kate@corp.example.com",  // Kelvin sign
		}
		for attacker, victim := range victims {
			if strings.ToLower(attacker) != victim {
				t.Fatalf("test input %q does not lowercase to %q", attacker, victim)
			}
			h, s := stubHandler(map[string]error{victim: nil})
			if err := h.authorize(victim); err != nil {
				t.Fatal(err)
			}
			if err := h.authorize(attacker); !errors.Is(err, errNotFound) {
				t.Errorf("%q: err = %v, want errNotFound", attacker, err)
			}
			if want := []string{victim, attacker}; !slices.Equal(s.asked, want) {
				t.Errorf("asked %q, want %q", s.asked, want)
			}
		}
	})

	t.Run("expired refreshes", func(t *testing.T) {
		h, s := stubHandler(map[string]error{alice: nil})
		h.authorize(alice)
		age(h, alice, time.Second)
		h.authorize(alice)
		if n := len(s.asked); n != 2 {
			t.Errorf("lookups = %d, want 2", n)
		}
	})

	for _, denial := range []error{errNotFound, errAmbiguous} {
		t.Run(denial.Error()+" is cached for negative_ttl", func(t *testing.T) {
			h, s := stubHandler(map[string]error{"bob": denial})
			for range 2 {
				if err := h.authorize("bob"); !errors.Is(err, denial) {
					t.Fatalf("err = %v, want %v", err, denial)
				}
			}
			if n := len(s.asked); n != 1 {
				t.Errorf("lookups = %d, want 1", n)
			}
			if ttl := time.Until(h.cache.entries["bob"].exp); ttl > time.Duration(h.NegativeTTL) {
				t.Errorf("cached for %v, want at most negative_ttl", ttl)
			}
			age(h, "bob", time.Second)
			h.authorize("bob")
			if n := len(s.asked); n != 2 {
				t.Errorf("lookups = %d after expiry, want 2", n)
			}
		})
	}

	t.Run("not a member is cached for cache_ttl", func(t *testing.T) {
		h, _ := stubHandler(map[string]error{"bob": errNotMember})
		if err := h.authorize("bob"); !errors.Is(err, errNotMember) {
			t.Fatalf("err = %v, want errNotMember", err)
		}
		if ttl := time.Until(h.cache.entries["bob"].exp); ttl <= time.Duration(h.NegativeTTL) {
			t.Errorf("cached for %v, want cache_ttl", ttl)
		}
	})

	t.Run("stale is off by default", func(t *testing.T) {
		h, s := stubHandler(map[string]error{alice: nil})
		h.authorize(alice)
		age(h, alice, time.Second)
		s.down = errDown
		if err := h.authorize(alice); !errors.Is(err, errDown) {
			t.Errorf("err = %v, want errDown", err)
		}
	})

	t.Run("stale within grace", func(t *testing.T) {
		h, s := stubHandler(map[string]error{alice: nil})
		h.StaleTTL = caddy.Duration(time.Hour)
		h.authorize(alice)
		age(h, alice, 30*time.Minute)
		s.down = errDown
		if err := h.authorize(alice); err != nil {
			t.Errorf("err = %v, want the stale grant", err)
		}
	})

	t.Run("stale past grace", func(t *testing.T) {
		h, s := stubHandler(map[string]error{alice: nil})
		h.StaleTTL = caddy.Duration(time.Hour)
		h.authorize(alice)
		age(h, alice, 2*time.Hour)
		s.down = errDown
		if err := h.authorize(alice); !errors.Is(err, errDown) {
			t.Errorf("err = %v, want errDown", err)
		}
	})

	t.Run("stale denial stays a denial", func(t *testing.T) {
		h, s := stubHandler(map[string]error{"bob": errNotMember})
		h.StaleTTL = caddy.Duration(time.Hour)
		h.authorize("bob")
		age(h, "bob", time.Second)
		s.down = errDown
		if err := h.authorize("bob"); !errors.Is(err, errNotMember) {
			t.Errorf("err = %v, want errNotMember", err)
		}
	})

	t.Run("not found replaces a stale grant", func(t *testing.T) {
		h, s := stubHandler(map[string]error{alice: nil})
		h.StaleTTL = caddy.Duration(time.Hour)
		h.authorize(alice)
		age(h, alice, time.Second)
		delete(s.answers, alice) // removed from the directory
		if err := h.authorize(alice); !errors.Is(err, errNotFound) {
			t.Fatalf("err = %v, want errNotFound", err)
		}
		age(h, alice, time.Second)
		s.down = errDown
		if err := h.authorize(alice); !errors.Is(err, errNotFound) {
			t.Errorf("err = %v; an outage must not bring the old grant back", err)
		}
	})

	t.Run("sweep keeps entries within grace", func(t *testing.T) {
		h, _ := stubHandler(map[string]error{"old": nil, "stale": nil, "new": nil})
		h.StaleTTL = caddy.Duration(time.Hour)
		h.authorize("old")
		h.authorize("stale")
		age(h, "old", 2*time.Hour)
		age(h, "stale", 30*time.Minute)
		h.cache.lastSweep = time.Time{}
		h.authorize("new")
		if _, ok := h.cache.entries["old"]; ok {
			t.Error("entry past grace not swept")
		}
		if _, ok := h.cache.entries["stale"]; !ok {
			t.Error("entry within grace swept")
		}
	})
}

// waitFor polls cond until it holds, failing the test after a few seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
	}
}

func TestLookupSlots(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	var running, peak atomic.Int32
	h := testHandler(func(context.Context, string) error {
		n := running.Add(1)
		defer running.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		return nil
	})
	h.Timeout = caddy.Duration(10 * time.Second)

	var wg sync.WaitGroup
	for i := range 3 * maxLookups {
		wg.Go(func() { h.authorize(fmt.Sprintf("user%d@corp.example.com", i)) })
	}
	waitFor(t, func() bool { return running.Load() == maxLookups })
	time.Sleep(20 * time.Millisecond) // time for any lookup past the cap to start
	if n := running.Load(); n != maxLookups {
		t.Errorf("running = %d, want %d", n, maxLookups)
	}
	unblock()
	wg.Wait()
	if p := peak.Load(); p != maxLookups {
		t.Errorf("peak = %d, want %d", p, maxLookups)
	}
}

func TestLookupBusy(t *testing.T) {
	release := make(chan struct{})
	h := testHandler(func(context.Context, string) error {
		<-release
		return nil
	})
	h.Timeout = caddy.Duration(50 * time.Millisecond)
	var wg sync.WaitGroup
	for i := range maxLookups {
		wg.Go(func() { h.authorize(fmt.Sprintf("hold%d@corp.example.com", i)) })
	}
	t.Cleanup(func() {
		close(release)
		wg.Wait()
	})
	waitFor(t, func() bool { return len(h.slots) == maxLookups })
	if err := h.authorize("late@corp.example.com"); !errors.Is(err, errBusy) {
		t.Errorf("err = %v, want errBusy", err)
	}
}
