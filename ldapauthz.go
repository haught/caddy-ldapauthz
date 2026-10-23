// Package ldapauthz provides a Caddy HTTP handler that authorizes an
// already-authenticated user by Active Directory group membership.
package ldapauthz

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	defaultUser   = "{http.auth.user.email}"
	defaultFilter = "(&(objectCategory=person)(objectClass=user)(userPrincipalName={user})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	nestedFilter  = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))"
)

var errNotFound = errors.New("user not found in directory")

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("ldap_authz", parseCaddyfile)
}

// Handler authorizes an authenticated user by Active Directory group
// membership. It must run after an authentication handler that sets the
// user's identity in a placeholder. The user is looked up in the directory
// and the request is passed on only if they are a member of one of the
// allowed groups.
//
// Responses: 401 if there is no identity, 403 if the user is not found or
// not in an allowed group, 503 if the directory cannot be queried.
type Handler struct {
	// The directory URL: ldaps://host:636, or ldap://host:389 with
	// StartTLS enabled. Required.
	URL string `json:"url"`

	// DN of the service account used to search the directory. Required.
	BindDN string `json:"bind_dn"`

	// Password for BindDN. Supports placeholders such as {env.VAR}.
	// Required.
	BindPassword string `json:"bind_password"`

	// Search base for users and groups. Required.
	BaseDN string `json:"base_dn"`

	// Placeholder holding the authenticated identity.
	// Default: {http.auth.user.email}
	User string `json:"user,omitempty"`

	// LDAP filter used to find the user. Must contain {user}, which is
	// replaced with the escaped identity. Default: match userPrincipalName
	// against enabled user accounts.
	UserFilter string `json:"user_filter,omitempty"`

	// Drop the @domain suffix from the identity before lookup, e.g. to
	// match sAMAccountName.
	StripDomain bool `json:"strip_domain,omitempty"`

	// Resolve nested group membership using LDAP_MATCHING_RULE_IN_CHAIN.
	Nested bool `json:"nested,omitempty"`

	// Upgrade an ldap:// connection with StartTLS.
	StartTLS bool `json:"starttls,omitempty"`

	// PEM file of CA certificates used to verify the directory's
	// certificate. Default: the system pool.
	CAFile string `json:"ca_file,omitempty"`

	// Full DNs of the groups allowed access, compared case-insensitively.
	// If empty, any user found in the directory is allowed.
	Allow []string `json:"allow,omitempty"`

	// How long a successful lookup is cached. Users that are not found
	// are never cached. Default: 5m.
	CacheTTL caddy.Duration `json:"cache_ttl,omitempty"`

	// Timeout for connecting to the directory and for each query.
	// Default: 5s.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// How long past CacheTTL a cached result is still used when the
	// directory is unreachable. A negative value disables this.
	// Default: 1h.
	StaleTTL caddy.Duration `json:"stale_ttl,omitempty"`

	tlsConf  *tls.Config
	allow    []*ldap.DN
	log      *zap.Logger
	cache    *cache
	lookupFn func(string) ([]*ldap.DN, error)
}

type cache struct {
	sf        singleflight.Group
	mu        sync.RWMutex
	entries   map[string]cached
	lastSweep time.Time
}

type cached struct {
	groups []*ldap.DN
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
	h.cache = &cache{entries: make(map[string]cached)}
	h.lookupFn = h.lookup
	h.BindPassword = caddy.NewReplacer().ReplaceAll(h.BindPassword, "")

	if h.User == "" {
		h.User = defaultUser
	}
	if h.UserFilter == "" {
		h.UserFilter = defaultFilter
	}
	if h.CacheTTL == 0 {
		h.CacheTTL = caddy.Duration(5 * time.Minute)
	}
	if h.Timeout == 0 {
		h.Timeout = caddy.Duration(5 * time.Second)
	}
	if h.StaleTTL == 0 {
		h.StaleTTL = caddy.Duration(time.Hour)
	}

	h.allow = make([]*ldap.DN, 0, len(h.Allow))
	for _, g := range h.Allow {
		dn, err := ldap.ParseDN(g)
		if err != nil || len(dn.RDNs) < 2 {
			return fmt.Errorf("allow: %q is not a full group DN", g)
		}
		h.allow = append(h.allow, dn)
	}

	u, err := url.Parse(h.URL)
	if err != nil {
		return fmt.Errorf("parsing url: %w", err)
	}
	h.tlsConf = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
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
	if h.URL == "" || h.BaseDN == "" || h.BindDN == "" || h.BindPassword == "" {
		return errors.New("url, base_dn, bind_dn and bind_password are required")
	}
	u, _ := url.Parse(h.URL)
	switch {
	case u.Scheme == "ldaps" && !h.StartTLS:
	case u.Scheme == "ldap" && h.StartTLS:
	default:
		return errors.New("use ldaps:// or ldap:// with starttls")
	}
	if !strings.Contains(h.UserFilter, "{user}") {
		return errors.New("user_filter must contain {user}")
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	user := repl.ReplaceAll(h.User, "")
	if h.StripDomain {
		user, _, _ = strings.Cut(user, "@")
	}
	if user == "" {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("no authenticated user"))
	}

	groups, err := h.groups(user)
	if errors.Is(err, errNotFound) {
		return caddyhttp.Error(http.StatusForbidden, err)
	}
	if err != nil {
		h.log.Error("ldap lookup failed", zap.String("user", user), zap.Error(err))
		return caddyhttp.Error(http.StatusServiceUnavailable, err)
	}

	if len(h.allow) > 0 && !h.permitted(groups) {
		h.log.Info("access denied", zap.String("user", user))
		return caddyhttp.Error(http.StatusForbidden, errors.New("not in an allowed group"))
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) permitted(groups []*ldap.DN) bool {
	for _, g := range groups {
		for _, a := range h.allow {
			if a.EqualFold(g) {
				return true
			}
		}
	}
	return false
}

func (h *Handler) groups(user string) ([]*ldap.DN, error) {
	key := strings.ToLower(user)

	h.cache.mu.RLock()
	c, ok := h.cache.entries[key]
	h.cache.mu.RUnlock()
	if ok && time.Now().Before(c.exp) {
		return c.groups, nil
	}

	v, err, _ := h.cache.sf.Do(key, func() (any, error) {
		g, err := h.lookupFn(user)
		now := time.Now()
		ttl := time.Duration(h.CacheTTL)
		grace := max(0, time.Duration(h.StaleTTL))

		h.cache.mu.Lock()
		defer h.cache.mu.Unlock()
		switch {
		case err == nil:
			if now.Sub(h.cache.lastSweep) > ttl {
				for k, e := range h.cache.entries {
					if now.After(e.exp.Add(grace)) {
						delete(h.cache.entries, k)
					}
				}
				h.cache.lastSweep = now
			}
			h.cache.entries[key] = cached{g, now.Add(ttl)}
		case errors.Is(err, errNotFound):
			delete(h.cache.entries, key)
		default:
			if c, ok := h.cache.entries[key]; ok && now.Before(c.exp.Add(grace)) {
				h.log.Warn("ldap unavailable, serving stale", zap.String("user", user), zap.Error(err))
				return c.groups, nil
			}
		}
		return g, err
	})
	g, _ := v.([]*ldap.DN)
	return g, err
}

func (h *Handler) lookup(user string) ([]*ldap.DN, error) {
	conn, err := h.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(h.BindDN, h.BindPassword); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	limit := max(1, int(time.Duration(h.Timeout).Seconds()))
	filter := strings.ReplaceAll(h.UserFilter, "{user}", ldap.EscapeFilter(user))
	res, err := conn.Search(ldap.NewSearchRequest(h.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, limit, false, filter, []string{"memberOf"}, nil))
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}
	if n := len(res.Entries); n != 1 {
		if n > 1 {
			h.log.Warn("user_filter matched multiple entries", zap.String("user", user), zap.Int("count", n))
		}
		return nil, errNotFound
	}
	entry := res.Entries[0]

	if len(h.allow) == 0 {
		return nil, nil
	}
	if !h.Nested {
		return toGroups(entry.GetAttributeValues("memberOf")), nil
	}

	gres, err := conn.SearchWithPaging(ldap.NewSearchRequest(h.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, limit, false,
		fmt.Sprintf(nestedFilter, ldap.EscapeFilter(entry.DN)), []string{"cn"}, nil), 500)
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	dns := make([]string, len(gres.Entries))
	for i, e := range gres.Entries {
		dns[i] = e.DN
	}
	return toGroups(dns), nil
}

func (h *Handler) dial() (*ldap.Conn, error) {
	d := &net.Dialer{Timeout: time.Duration(h.Timeout)}
	conn, err := ldap.DialURL(h.URL, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(h.tlsConf))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if h.StartTLS {
		if err := conn.StartTLS(h.tlsConf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	conn.SetTimeout(time.Duration(h.Timeout))
	return conn, nil
}

func toGroups(dns []string) []*ldap.DN {
	out := make([]*ldap.DN, 0, len(dns))
	for _, dn := range dns {
		if p, err := ldap.ParseDN(dn); err == nil && len(p.RDNs) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	ldap_authz {
//	    url           <ldaps://host:636 | ldap://host:389>
//	    bind_dn       <dn>
//	    bind_password <password>
//	    base_dn       <dn>
//	    user          <placeholder>
//	    user_filter   <filter>
//	    strip_domain
//	    nested
//	    starttls
//	    ca_file       <path>
//	    allow         <group_dn...>
//	    cache_ttl     <duration>
//	    timeout       <duration>
//	    stale_ttl     <duration | off>
//	}
//
// allow may be repeated.
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
	for d.NextBlock(0) {
		opt := d.Val()
		if p, ok := strs[opt]; ok {
			if !d.AllArgs(p) {
				return d.ArgErr()
			}
			continue
		}
		switch opt {
		case "strip_domain":
			h.StripDomain = true
		case "nested":
			h.Nested = true
		case "starttls":
			h.StartTLS = true
		case "allow":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.Allow = append(h.Allow, args...)
		case "cache_ttl", "timeout", "stale_ttl":
			var v string
			if !d.AllArgs(&v) {
				return d.ArgErr()
			}
			var dur time.Duration
			if opt == "stale_ttl" && v == "off" {
				dur = -1
			} else {
				var err error
				if dur, err = caddy.ParseDuration(v); err != nil {
					return d.Errf("%s: %v", opt, err)
				}
			}
			switch opt {
			case "cache_ttl":
				h.CacheTTL = caddy.Duration(dur)
			case "timeout":
				h.Timeout = caddy.Duration(dur)
			case "stale_ttl":
				h.StaleTTL = caddy.Duration(dur)
			}
		default:
			return d.Errf("unknown option %q", opt)
		}
	}
	return nil
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
