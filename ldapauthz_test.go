package ldapauthz

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

const adminsDN = "CN=App-Admins,OU=Groups,DC=corp,DC=example,DC=com"

func mustDN(t *testing.T, s string) *ldap.DN {
	t.Helper()
	dn, err := ldap.ParseDN(s)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", s, err)
	}
	return dn
}

func TestToGroups(t *testing.T) {
	got := toGroups([]string{"garbage", adminsDN, ""})
	if len(got) != 1 || !got[0].EqualFold(mustDN(t, adminsDN)) {
		t.Fatalf("toGroups = %v, want only %s", got, adminsDN)
	}
}

func TestPermitted(t *testing.T) {
	h := &Handler{allow: []*ldap.DN{mustDN(t, adminsDN)}}
	tests := []struct {
		name   string
		groups []string
		want   bool
	}{
		{"exact", []string{adminsDN}, true},
		{"case and spacing", []string{"cn=app-admins, ou=groups, dc=CORP, dc=example, dc=com"}, true},
		{"one of many", []string{"CN=Other,OU=Groups,DC=corp,DC=example,DC=com", adminsDN}, true},
		{"same CN other OU", []string{"CN=App-Admins,OU=Evil,DC=corp,DC=example,DC=com"}, false},
		{"unrelated", []string{"CN=Other,OU=Groups,DC=corp,DC=example,DC=com"}, false},
		{"garbage", []string{"App-Admins"}, false},
		{"none", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.permitted(toGroups(tt.groups)); got != tt.want {
				t.Errorf("permitted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ldap_authz {
		url ldap://dc:389
		bind_dn "CN=svc,DC=corp"
		bind_password secret
		base_dn "DC=corp"
		user {http.auth.user.id}
		user_filter "(sAMAccountName={user})"
		ca_file /etc/ca.pem
		strip_domain
		nested
		starttls
		allow "CN=A,DC=corp" "CN=B,DC=corp"
		allow "CN=C,DC=corp"
		cache_ttl 10m
		timeout 2s
		stale_ttl off
	}`)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	want := Handler{
		URL:          "ldap://dc:389",
		BindDN:       "CN=svc,DC=corp",
		BindPassword: "secret",
		BaseDN:       "DC=corp",
		User:         "{http.auth.user.id}",
		UserFilter:   "(sAMAccountName={user})",
		CAFile:       "/etc/ca.pem",
		StripDomain:  true,
		Nested:       true,
		StartTLS:     true,
		Allow:        []string{"CN=A,DC=corp", "CN=B,DC=corp", "CN=C,DC=corp"},
		CacheTTL:     caddy.Duration(10 * time.Minute),
		Timeout:      caddy.Duration(2 * time.Second),
		StaleTTL:     -1,
	}
	if h.URL != want.URL || h.BindDN != want.BindDN || h.BindPassword != want.BindPassword ||
		h.BaseDN != want.BaseDN || h.User != want.User || h.UserFilter != want.UserFilter ||
		h.CAFile != want.CAFile || h.StripDomain != want.StripDomain || h.Nested != want.Nested ||
		h.StartTLS != want.StartTLS || !slices.Equal(h.Allow, want.Allow) ||
		h.CacheTTL != want.CacheTTL || h.Timeout != want.Timeout || h.StaleTTL != want.StaleTTL {
		t.Errorf("got  %+v\nwant %+v", h, want)
	}
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	tests := map[string]string{
		"unknown option": `bogus`,
		"missing arg":    `url`,
		"extra arg":      `url a b`,
		"empty allow":    `allow`,
		"bad duration":   `cache_ttl soon`,
		"off not stale":  `cache_ttl off`,
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

func TestProvisionDefaults(t *testing.T) {
	h := validHandler()
	if err := provisionAndValidate(h); err != nil {
		t.Fatal(err)
	}
	if h.User != defaultUser || h.UserFilter != defaultFilter ||
		h.CacheTTL != caddy.Duration(5*time.Minute) || h.Timeout != caddy.Duration(5*time.Second) ||
		h.StaleTTL != caddy.Duration(time.Hour) || len(h.allow) != 1 {
		t.Errorf("defaults not applied: %+v", h)
	}
}

func TestProvisionAndValidateErrors(t *testing.T) {
	tests := map[string]func(*Handler){
		"bare CN in allow":    func(h *Handler) { h.Allow = []string{"App-Admins"} },
		"single RDN in allow": func(h *Handler) { h.Allow = []string{"CN=App-Admins"} },
		"empty allow entry":   func(h *Handler) { h.Allow = []string{""} },
		"missing url":         func(h *Handler) { h.URL = "" },
		"missing base_dn":     func(h *Handler) { h.BaseDN = "" },
		"missing bind_dn":     func(h *Handler) { h.BindDN = "" },
		"missing password":    func(h *Handler) { h.BindPassword = "" },
		"unset env password":  func(h *Handler) { h.BindPassword = "{env.LDAPAUTHZ_TEST_UNSET}" },
		"ldaps with starttls": func(h *Handler) { h.StartTLS = true },
		"ldap without starttls": func(h *Handler) {
			h.URL = "ldap://dc.corp.example.com:389"
		},
		"filter without user": func(h *Handler) { h.UserFilter = "(objectClass=user)" },
		"missing ca_file":     func(h *Handler) { h.CAFile = "/nonexistent/ca.pem" },
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

// fakeLookup returns a cache-ready Handler whose lookups return result/err
// and increment calls.
func fakeLookup(stale caddy.Duration) (h *Handler, calls *int, result *[]*ldap.DN, err *error) {
	calls, result, err = new(int), new([]*ldap.DN), new(error)
	h = &Handler{
		CacheTTL: caddy.Duration(time.Minute),
		StaleTTL: stale,
		log:      zap.NewNop(),
		cache:    &cache{entries: make(map[string]cached)},
	}
	h.lookupFn = func(string) ([]*ldap.DN, error) {
		*calls++
		return *result, *err
	}
	return h, calls, result, err
}

// age moves a cached entry's expiry to d ago.
func age(h *Handler, key string, d time.Duration) {
	e := h.cache.entries[key]
	e.exp = time.Now().Add(-d)
	h.cache.entries[key] = e
}

func TestGroupsCache(t *testing.T) {
	errDown := errors.New("dial: connection refused")
	admins := []*ldap.DN{mustDN(t, adminsDN)}

	t.Run("hit", func(t *testing.T) {
		h, calls, result, _ := fakeLookup(caddy.Duration(time.Hour))
		*result = admins
		for range 3 {
			if g, err := h.groups("Alice@corp"); err != nil || len(g) != 1 {
				t.Fatalf("groups = %v, %v", g, err)
			}
		}
		if _, err := h.groups("alice@CORP"); err != nil {
			t.Fatal(err)
		}
		if *calls != 1 {
			t.Errorf("calls = %d, want 1", *calls)
		}
	})

	t.Run("expired refreshes", func(t *testing.T) {
		h, calls, result, _ := fakeLookup(caddy.Duration(time.Hour))
		*result = admins
		h.groups("alice")
		age(h, "alice", time.Second)
		h.groups("alice")
		if *calls != 2 {
			t.Errorf("calls = %d, want 2", *calls)
		}
	})

	t.Run("not found is not cached", func(t *testing.T) {
		h, calls, _, err := fakeLookup(caddy.Duration(time.Hour))
		*err = errNotFound
		for range 2 {
			if _, e := h.groups("bob"); !errors.Is(e, errNotFound) {
				t.Fatalf("err = %v, want errNotFound", e)
			}
		}
		if *calls != 2 {
			t.Errorf("calls = %d, want 2", *calls)
		}
	})

	t.Run("not found evicts stale entry", func(t *testing.T) {
		h, _, result, err := fakeLookup(caddy.Duration(time.Hour))
		*result = admins
		h.groups("alice")
		age(h, "alice", time.Second)
		*result, *err = nil, errNotFound
		h.groups("alice")
		*err = errDown
		if _, e := h.groups("alice"); !errors.Is(e, errDown) {
			t.Errorf("err = %v, want errDown (no stale entry)", e)
		}
	})

	t.Run("stale within grace", func(t *testing.T) {
		h, _, result, err := fakeLookup(caddy.Duration(time.Hour))
		*result = admins
		h.groups("alice")
		age(h, "alice", 30*time.Minute)
		*result, *err = nil, errDown
		if g, e := h.groups("alice"); e != nil || len(g) != 1 {
			t.Errorf("groups = %v, %v; want stale admins", g, e)
		}
	})

	t.Run("stale past grace", func(t *testing.T) {
		h, _, result, err := fakeLookup(caddy.Duration(time.Hour))
		*result = admins
		h.groups("alice")
		age(h, "alice", 2*time.Hour)
		*result, *err = nil, errDown
		if _, e := h.groups("alice"); !errors.Is(e, errDown) {
			t.Errorf("err = %v, want errDown", e)
		}
	})

	t.Run("stale disabled", func(t *testing.T) {
		h, _, result, err := fakeLookup(-1)
		*result = admins
		h.groups("alice")
		age(h, "alice", time.Second)
		*result, *err = nil, errDown
		if _, e := h.groups("alice"); !errors.Is(e, errDown) {
			t.Errorf("err = %v, want errDown", e)
		}
	})

	t.Run("sweep keeps entries within grace", func(t *testing.T) {
		h, _, result, _ := fakeLookup(caddy.Duration(time.Hour))
		*result = admins
		h.groups("old")
		h.groups("stale")
		age(h, "old", 2*time.Hour)
		age(h, "stale", 30*time.Minute)
		h.cache.lastSweep = time.Time{}
		h.groups("new")
		if _, ok := h.cache.entries["old"]; ok {
			t.Error("entry past grace not swept")
		}
		if _, ok := h.cache.entries["stale"]; !ok {
			t.Error("entry within grace swept")
		}
	})
}
