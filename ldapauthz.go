// Package ldapauthz provides a Caddy HTTP handler that authorizes an
// already-authenticated user by Active Directory group membership.
package ldapauthz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	defaultUser = "{http.auth.user.email}"

	// defaultFilter matches the userPrincipalName of an enabled account
	// that has not expired.
	defaultFilter = "(&(objectCategory=person)(objectClass=user)(userPrincipalName={user})" +
		"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
		"(|(accountExpires=0)(accountExpires>={now_filetime})))"

	defaultCacheTTL    = 5 * time.Minute
	defaultNegativeTTL = 30 * time.Second
	defaultTimeout     = 5 * time.Second

	// inChain is LDAP_MATCHING_RULE_IN_CHAIN, which makes AD follow
	// nested group membership.
	inChain = "1.2.840.113556.1.4.1941"

	// maxIdentityLen is the longest identity looked up: the size limit of
	// userPrincipalName in AD.
	maxIdentityLen = 1024

	// maxLookups caps the directory lookups running at once.
	maxLookups = 16

	// minGroupRDNs is the fewest RDNs an allow entry may have, which
	// rejects a bare name such as CN=Admins.
	minGroupRDNs = 2

	// filetimeOffset is the number of seconds from 1601-01-01, where
	// Windows FILETIME starts, to the Unix epoch.
	filetimeOffset = 11644473600
)

// Denials: the directory answered, and the user may not pass.
var (
	errNotFound  = errors.New("user not found in directory")
	errAmbiguous = errors.New("user filter matched more than one entry")
	errNotMember = errors.New("not a member of an allowed group")
)

// errBusy means no lookup slot came free before the timeout.
var errBusy = errors.New("too many concurrent directory lookups")

// Errors returned to clients. The reasons are logged, never sent.
var (
	errUnauthenticated = errors.New("authentication required")
	errDenied          = errors.New("access denied")
	errUnavailable     = errors.New("directory unavailable")
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("ldap_authz", parseCaddyfile)
}

// Handler authorizes an authenticated user by Active Directory group
// membership. It must run after an authentication handler that sets the
// user's identity in a placeholder. The user is looked up in the directory,
// and the request is passed on only if the directory confirms they are a
// member of one of the allowed groups.
//
// Responses: 401 if there is no identity, 403 if the user is not allowed,
// 503 if the directory cannot be queried. The response never says why; the
// reason is logged.
type Handler struct {
	// The directory URL: ldaps://host[:636], or ldap://host[:389] with
	// StartTLS enabled. Only a scheme, host and port are allowed. Required.
	URL string `json:"url"`

	// DN of the service account used to search the directory. Required.
	BindDN string `json:"bind_dn"`

	// Password for BindDN. Use a runtime placeholder such as
	// {env.LDAP_BIND_PASSWORD} or {file./run/secrets/ldap} so the secret
	// stays out of the stored config. Required.
	BindPassword string `json:"bind_password"`

	// Search base for users. Required.
	BaseDN string `json:"base_dn"`

	// Placeholder holding the authenticated identity.
	// Default: {http.auth.user.email}
	User string `json:"user,omitempty"`

	// LDAP filter used to find the user. Must contain {user}, which is
	// replaced with the escaped identity. {now_filetime} is replaced with
	// the current time as a Windows FILETIME, for accountExpires checks.
	// Default: match userPrincipalName against enabled, unexpired accounts.
	UserFilter string `json:"user_filter,omitempty"`

	// Domains the identity may belong to. When set, the identity must end
	// in @ and one of these domains, compared case-insensitively, and that
	// suffix is removed before lookup, e.g. to match sAMAccountName. Any
	// other identity is denied.
	StripDomain []string `json:"strip_domain,omitempty"`

	// Placeholders that must each hold one of the listed values, e.g.
	// {"{http.auth.user.realm}": ["corp"]}. Use it to accept identities
	// only from the identity provider whose users are the directory's.
	Require map[string][]string `json:"require,omitempty"`

	// Resolve nested group membership using LDAP_MATCHING_RULE_IN_CHAIN.
	Nested bool `json:"nested,omitempty"`

	// Upgrade an ldap:// connection with StartTLS.
	StartTLS bool `json:"starttls,omitempty"`

	// PEM file of CA certificates used to verify the directory's
	// certificate. Default: the system pool.
	CAFile string `json:"ca_file,omitempty"`

	// Full DNs of the groups allowed access. The directory resolves and
	// compares them. Required unless AllowAnyUser is set.
	Allow []string `json:"allow,omitempty"`

	// Permit every user that UserFilter finds. Must be set explicitly to
	// run without Allow, so that a missing allow list fails closed.
	AllowAnyUser bool `json:"allow_any_user,omitempty"`

	// How long the answer for a user found in the directory is cached,
	// whether they are allowed or not. Default: 5m.
	CacheTTL caddy.Duration `json:"cache_ttl,omitempty"`

	// How long a user who is not found, or who matches more than one
	// entry, is cached as denied. Default: 30s.
	NegativeTTL caddy.Duration `json:"negative_ttl,omitempty"`

	// The most time a request waits for the directory: queueing for a
	// lookup slot, connecting, TLS, binding and searching. Default: 5s.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// How long past its expiry a cached answer is still used while the
	// directory cannot be reached. A revoked user keeps access this much
	// longer during an outage. Default: 0, which disables it.
	StaleTTL caddy.Duration `json:"stale_ttl,omitempty"`

	addr         string
	tlsConf      *tls.Config
	bindPassword string
	memberFilter string
	log          *zap.Logger
	cache        *cache
	slots        chan struct{}
	lookupFn     func(context.Context, string) error
}

type cache struct {
	sf        singleflight.Group
	mu        sync.RWMutex
	entries   map[string]entry
	lastSweep time.Time
}

// entry is a cached answer from the directory. denial is nil if the user
// is allowed, and otherwise says why they are not.
type entry struct {
	denial error
	exp    time.Time
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ldap_authz",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	h.log = ctx.Logger()
	h.cache = &cache{entries: make(map[string]entry)}
	h.slots = make(chan struct{}, maxLookups)
	h.lookupFn = h.lookup
	h.bindPassword = caddy.NewReplacer().ReplaceAll(h.BindPassword, "")

	if h.User == "" {
		h.User = defaultUser
	}
	if h.UserFilter == "" {
		h.UserFilter = defaultFilter
	}
	if h.CacheTTL == 0 {
		h.CacheTTL = caddy.Duration(defaultCacheTTL)
	}
	if h.NegativeTTL == 0 {
		h.NegativeTTL = caddy.Duration(defaultNegativeTTL)
	}
	if h.Timeout == 0 {
		h.Timeout = caddy.Duration(defaultTimeout)
	}
	if strings.Contains(h.User, "{http.request.") {
		h.log.Warn("user is read from request data, which the client controls unless a trusted proxy sets it",
			zap.String("user", h.User))
	}
	if h.AllowAnyUser {
		h.log.Warn("allow_any_user is on: every user found by user_filter is permitted")
	}

	for _, g := range h.Allow {
		dn, err := ldap.ParseDN(g)
		if err != nil || len(dn.RDNs) < minGroupRDNs {
			return fmt.Errorf("allow: %q is not a full group DN", g)
		}
	}
	h.memberFilter = memberFilter(h.Allow, h.Nested)
	if h.memberFilter != "" {
		if _, err := ldap.CompileFilter(h.memberFilter); err != nil {
			return fmt.Errorf("allow: %w", err)
		}
	}

	addr, host, err := parseURL(h.URL, h.StartTLS)
	if err != nil {
		return err
	}
	h.addr = addr
	h.tlsConf = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if h.CAFile != "" {
		pem, err := os.ReadFile(h.CAFile)
		if err != nil {
			return fmt.Errorf("reading ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("ca_file contains no certificates")
		}
		h.tlsConf.RootCAs = pool
	}
	return nil
}

func (h *Handler) Validate() error {
	if h.BaseDN == "" || h.BindDN == "" || h.bindPassword == "" {
		return errors.New("base_dn, bind_dn and bind_password are required")
	}
	if !strings.Contains(h.UserFilter, "{user}") {
		return errors.New("user_filter must contain {user}")
	}
	if _, err := ldap.CompileFilter(h.userFilter("x", time.Now())); err != nil {
		return fmt.Errorf("user_filter: %w", err)
	}
	switch {
	case len(h.Allow) == 0 && !h.AllowAnyUser:
		return errors.New("allow needs at least one group DN; to permit every directory user, set allow_any_user instead")
	case len(h.Allow) > 0 && h.AllowAnyUser:
		return errors.New("allow and allow_any_user cannot both be set")
	}
	for _, d := range h.StripDomain {
		if _, err := strconv.ParseBool(d); err == nil || d == "on" || d == "off" {
			return fmt.Errorf("strip_domain takes the domains to accept, e.g. strip_domain corp.example.com, not %q", d)
		}
		if d == "" || strings.ContainsAny(d, "@ ") {
			return fmt.Errorf("strip_domain: %q is not a domain", d)
		}
	}
	for p, vals := range h.Require {
		if !isPlaceholder(p) {
			return fmt.Errorf("require: %q is not a placeholder", p)
		}
		if len(vals) == 0 || slices.Contains(vals, "") {
			return fmt.Errorf("require: %s needs one or more non-empty values", p)
		}
	}
	if h.CacheTTL < 0 || h.NegativeTTL < 0 || h.Timeout < 0 || h.StaleTTL < 0 {
		return errors.New("cache_ttl, negative_ttl, timeout and stale_ttl must not be negative")
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	id := repl.ReplaceAll(h.User, "")
	if id == "" {
		h.log.Debug("no authenticated user", zap.String("placeholder", h.User))
		return caddyhttp.Error(http.StatusUnauthorized, errUnauthenticated)
	}
	for p, vals := range h.Require {
		if v := repl.ReplaceAll(p, ""); !slices.Contains(vals, v) {
			h.log.Info("access denied", zap.String("user", clip(id)),
				zap.String("reason", "require not met"), zap.String("placeholder", p), zap.String("value", clip(v)))
			return caddyhttp.Error(http.StatusForbidden, errDenied)
		}
	}
	user, err := h.identity(id)
	if err != nil {
		h.log.Info("access denied", zap.String("user", clip(id)), zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, errDenied)
	}

	err = h.authorize(user)
	switch {
	case err == nil:
		h.log.Debug("access granted", zap.String("user", user))
		return next.ServeHTTP(w, r)
	case isDenial(err):
		h.log.Info("access denied", zap.String("user", user), zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, errDenied)
	default:
		h.log.Error("directory lookup failed", zap.String("user", user), zap.Error(err))
		return caddyhttp.Error(http.StatusServiceUnavailable, errUnavailable)
	}
}

// identity checks the authenticated identity and returns the name to look
// up in the directory.
func (h *Handler) identity(id string) (string, error) {
	if len(id) > maxIdentityLen || !utf8.ValidString(id) || strings.ContainsFunc(id, invisible) {
		return "", errors.New("identity is malformed")
	}
	if len(h.StripDomain) == 0 {
		return id, nil
	}
	i := strings.LastIndexByte(id, '@')
	if i <= 0 || strings.IndexByte(id[:i], '@') >= 0 {
		return "", errors.New("identity is not of the form name@domain")
	}
	domain := id[i+1:]
	for _, d := range h.StripDomain {
		if asciiEqualFold(domain, d) {
			return id[:i], nil
		}
	}
	return "", fmt.Errorf("domain %q is not accepted", domain)
}

// invisible reports whether r is a control or formatting character, which
// has no place in an identity and can disguise it in logs.
func invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// asciiEqualFold reports whether a and b are equal with ASCII letters
// compared case-insensitively. Unlike strings.EqualFold, it never treats
// distinct runes such as the Kelvin sign and K as equal.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// authorize returns nil if user may pass, a denial (errNotFound,
// errAmbiguous or errNotMember) if not, and any other error if the
// directory could not be asked. Answers are cached under the exact
// identity: case-insensitive matching is left to the directory, so two
// identities share an answer only if the directory matches them to the
// same entry.
func (h *Handler) authorize(user string) error {
	h.cache.mu.RLock()
	e, ok := h.cache.entries[user]
	h.cache.mu.RUnlock()
	if ok && time.Now().Before(e.exp) {
		return e.denial
	}
	_, err, _ := h.cache.sf.Do(user, func() (any, error) {
		return nil, h.refresh(user)
	})
	return err
}

// refresh asks the directory about user and caches the answer. If the
// directory cannot answer, it falls back to the cached answer while that
// is within stale_ttl of its expiry.
func (h *Handler) refresh(user string) error {
	err := h.query(user)
	now := time.Now()
	if err == nil || isDenial(err) {
		h.store(user, err, now)
		return err
	}
	if e, ok := h.stale(user, now); ok {
		h.log.Warn("directory unavailable, using stale answer", zap.String("user", user), zap.Error(err))
		return e.denial
	}
	return err
}

// query runs one directory lookup within the timeout, after waiting for a
// free lookup slot. The deadline does not come from the HTTP request,
// because the answer is shared with every request waiting on it.
func (h *Handler) query(user string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(h.Timeout))
	defer cancel()
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-ctx.Done():
		return errBusy
	}
	return h.lookupFn(ctx, user)
}

func (h *Handler) store(user string, denial error, now time.Time) {
	ttl := time.Duration(h.CacheTTL)
	if errors.Is(denial, errNotFound) || errors.Is(denial, errAmbiguous) {
		ttl = time.Duration(h.NegativeTTL)
	}
	h.cache.mu.Lock()
	defer h.cache.mu.Unlock()
	h.sweep(now)
	h.cache.entries[user] = entry{denial: denial, exp: now.Add(ttl)}
}

// stale returns the cached entry for user if it may still stand in for
// the directory.
func (h *Handler) stale(user string, now time.Time) (entry, bool) {
	if h.StaleTTL <= 0 {
		return entry{}, false
	}
	h.cache.mu.RLock()
	e, ok := h.cache.entries[user]
	h.cache.mu.RUnlock()
	return e, ok && !now.After(e.exp.Add(time.Duration(h.StaleTTL)))
}

// sweep drops entries that can no longer be used, at most once per
// cache_ttl. The caller must hold h.cache.mu for writing.
func (h *Handler) sweep(now time.Time) {
	if now.Sub(h.cache.lastSweep) < time.Duration(h.CacheTTL) {
		return
	}
	for k, e := range h.cache.entries {
		if now.After(e.exp.Add(time.Duration(h.StaleTTL))) {
			delete(h.cache.entries, k)
		}
	}
	h.cache.lastSweep = now
}

// isDenial reports whether err is the directory's answer that the user may
// not pass, as opposed to a failure to get an answer.
func isDenial(err error) bool {
	return errors.Is(err, errNotFound) || errors.Is(err, errAmbiguous) || errors.Is(err, errNotMember)
}

// lookup asks the directory whether user may pass, returning the same
// results as authorize. Every network operation ends by ctx's deadline.
func (h *Handler) lookup(ctx context.Context, user string) error {
	conn, err := h.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(h.BindDN, h.bindPassword); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	limit := timeLimit(ctx)
	debug := h.log.Core().Enabled(zap.DebugLevel)
	attrs := []string{"1.1"} // no attributes
	if debug {
		attrs = []string{"memberOf"}
	}
	filter := h.userFilter(user, time.Now())
	// A size limit of 2 is enough to tell one match from several.
	res, err := conn.Search(ldap.NewSearchRequest(h.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 2, limit, false, filter, attrs, nil))
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return errAmbiguous
	case err != nil:
		return fmt.Errorf("user search: %w", err)
	case len(res.Entries) == 0:
		h.log.Debug("user not found", zap.String("user", user), zap.String("base_dn", h.BaseDN), zap.String("filter", filter))
		return errNotFound
	case len(res.Entries) > 1:
		return errAmbiguous
	}
	dn := res.Entries[0].DN
	if debug {
		h.log.Debug("user found", zap.String("user", user), zap.String("dn", dn),
			zap.Strings("member_of", res.Entries[0].GetAttributeValues("memberOf")))
	}
	if h.AllowAnyUser {
		return nil
	}

	// The directory checks membership on the user's own entry, so it
	// resolves the group DNs by its own rules rather than this module
	// comparing strings.
	res, err = conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, limit, false, h.memberFilter, []string{"1.1"}, nil))
	if err != nil {
		return fmt.Errorf("membership search: %w", err)
	}
	if len(res.Entries) != 1 {
		return errNotMember
	}
	return nil
}

// dial connects to the directory over TLS. The connection's deadline is
// ctx's, so no step can outlast the timeout, the StartTLS handshake
// included.
func (h *Handler) dial(ctx context.Context) (*ldap.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(dl); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("dial: %w", err)
		}
	}
	timeout := time.Duration(h.Timeout)

	if h.StartTLS {
		conn := ldap.NewConn(raw, false)
		conn.Start()
		conn.SetTimeout(timeout)
		if err := conn.StartTLS(h.tlsConf); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
		return conn, nil
	}
	tc := tls.Client(raw, h.tlsConf)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	conn := ldap.NewConn(tc, true)
	conn.Start()
	conn.SetTimeout(timeout)
	return conn, nil
}

// userFilter returns the user search filter for user at time now. Both
// placeholders are replaced in a single pass, so text from the identity is
// never substituted again.
func (h *Handler) userFilter(user string, now time.Time) string {
	return strings.NewReplacer(
		"{user}", ldap.EscapeFilter(user),
		"{now_filetime}", strconv.FormatInt(filetime(now), 10),
	).Replace(h.UserFilter)
}

// filetime converts t to a Windows FILETIME: 100ns intervals since 1601.
func filetime(t time.Time) int64 {
	return (t.Unix() + filetimeOffset) * 10_000_000
}

// memberFilter returns a filter that matches an entry that is a member of
// any of groups: directly, or also through nested groups if nested is set.
func memberFilter(groups []string, nested bool) string {
	if len(groups) == 0 {
		return ""
	}
	assertion := "(memberOf="
	if nested {
		assertion = "(memberOf:" + inChain + ":="
	}
	var b strings.Builder
	b.WriteString("(|")
	for _, g := range groups {
		b.WriteString(assertion)
		b.WriteString(ldap.EscapeFilter(strings.TrimSpace(g)))
		b.WriteString(")")
	}
	b.WriteString(")")
	return b.String()
}

// timeLimit returns the whole seconds left before ctx's deadline, at least
// one, for the server-side search time limit.
func timeLimit(ctx context.Context) int {
	dl, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return max(1, int(time.Until(dl).Seconds()))
}

// parseURL checks the directory URL and returns the address to dial and
// the host name to verify the certificate against.
func parseURL(raw string, startTLS bool) (addr, host string, err error) {
	if raw == "" {
		return "", "", errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("url: %w", err)
	}
	var port string
	switch {
	case u.Scheme == "ldaps" && !startTLS:
		port = "636"
	case u.Scheme == "ldap" && startTLS:
		port = "389"
	default:
		return "", "", errors.New("url: use ldaps://, or ldap:// with starttls")
	}
	if u.Opaque != "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "", errors.New("url: only a scheme, host and port are allowed")
	}
	host = u.Hostname()
	if host == "" {
		return "", "", errors.New("url: missing host")
	}
	if p := u.Port(); p != "" {
		port = p
	}
	return net.JoinHostPort(host, port), host, nil
}

func isPlaceholder(s string) bool {
	return len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}'
}

// clip shortens s for logging. It is for identities that have not been
// checked yet, which may be arbitrarily long.
func clip(s string) string {
	const n = 128
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	ldap_authz {
//	    url            <ldaps://host[:636] | ldap://host[:389]>
//	    bind_dn        <dn>
//	    bind_password  <password>
//	    base_dn        <dn>
//	    user           <placeholder>
//	    user_filter    <filter>
//	    strip_domain   [<domain...>]
//	    require        [<placeholder> <value...>]
//	    nested         [on | off]
//	    starttls       [on | off]
//	    ca_file        <path>
//	    allow          [<group_dn...>]
//	    allow_any_user [on | off]
//	    cache_ttl      <duration>
//	    negative_ttl   <duration>
//	    timeout        <duration>
//	    stale_ttl      <duration | off>
//	}
//
// allow, strip_domain and require may be repeated. Every option accepts an
// empty or missing value so it can be set from an environment variable such
// as {$LDAP_BASE_DN}: an empty value leaves the default in place. Two cases
// fail closed instead: require with a placeholder but no value is an error,
// and so is an empty allow list unless allow_any_user is on. A flag with no
// value is on, so write a flag as e.g. nested "{$LDAP_NESTED:off}" to keep
// it off when the variable is unset or empty.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	strs := map[string]*string{
		"url":           &h.URL,
		"bind_dn":       &h.BindDN,
		"bind_password": &h.BindPassword,
		"base_dn":       &h.BaseDN,
		"user":          &h.User,
		"user_filter":   &h.UserFilter,
		"ca_file":       &h.CAFile,
	}
	flags := map[string]*bool{
		"nested":         &h.Nested,
		"starttls":       &h.StartTLS,
		"allow_any_user": &h.AllowAnyUser,
	}
	durations := map[string]*caddy.Duration{
		"cache_ttl":    &h.CacheTTL,
		"negative_ttl": &h.NegativeTTL,
		"timeout":      &h.Timeout,
		"stale_ttl":    &h.StaleTTL,
	}
	for d.NextBlock(0) {
		opt := d.Val()
		args := d.RemainingArgs()
		switch opt {
		case "allow":
			h.Allow = append(h.Allow, nonEmpty(args)...)
			continue
		case "strip_domain":
			h.StripDomain = append(h.StripDomain, nonEmpty(args)...)
			continue
		case "require":
			if len(nonEmpty(args)) == 0 {
				continue
			}
			p, vals := args[0], nonEmpty(args[1:])
			if !isPlaceholder(p) {
				return d.Errf("require: %q is not a placeholder", p)
			}
			if len(vals) == 0 {
				return d.Errf("require: no value given for %s", p)
			}
			if h.Require == nil {
				h.Require = make(map[string][]string)
			}
			h.Require[p] = append(h.Require[p], vals...)
			continue
		}
		if len(args) > 1 {
			return d.ArgErr()
		}
		var v string
		if len(args) == 1 {
			v = args[0]
		}
		if p, ok := strs[opt]; ok {
			*p = v
			continue
		}
		if p, ok := flags[opt]; ok {
			on, err := parseFlag(args)
			if err != nil {
				return d.Errf("%s: %v", opt, err)
			}
			*p = on
			continue
		}
		if p, ok := durations[opt]; ok {
			dur, err := parseDuration(opt, v)
			if err != nil {
				return d.Errf("%s: %v", opt, err)
			}
			*p = dur
			continue
		}
		return d.Errf("unknown option %q", opt)
	}
	return nil
}

// parseFlag reports whether a flag is on. No value means on; an empty value
// (an unset environment variable in quotes) means off.
func parseFlag(args []string) (bool, error) {
	if len(args) == 0 {
		return true, nil
	}
	switch v := strings.ToLower(args[0]); v {
	case "on":
		return true, nil
	case "off", "":
		return false, nil
	default:
		return strconv.ParseBool(v)
	}
}

// parseDuration parses a duration option. An empty value leaves the
// default, and stale_ttl also accepts off. Any other value must be a
// positive duration, so that e.g. cache_ttl 0 is not mistaken for turning
// the cache off.
func parseDuration(opt, v string) (caddy.Duration, error) {
	if v == "" || (opt == "stale_ttl" && v == "off") {
		return 0, nil
	}
	dur, err := caddy.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	if dur <= 0 {
		return 0, errors.New("must be a positive duration")
	}
	return caddy.Duration(dur), nil
}

// nonEmpty returns args without empty strings, which unset environment
// variables leave behind.
func nonEmpty(args []string) []string {
	var out []string
	for _, a := range args {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Handler)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
