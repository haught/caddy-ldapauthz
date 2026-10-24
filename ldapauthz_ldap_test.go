package ldapauthz

// Tests that drive the real lookup against a minimal fake LDAP server.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

const (
	aliceDN = "CN=Alice,OU=Users,DC=corp,DC=example,DC=com"
	bobDN   = "CN=Bob,OU=Users,DC=corp,DC=example,DC=com"
)

// testPKI is a CA, written to caFile, and a certificate for 127.0.0.1
// signed by it.
type testPKI struct {
	caFile string
	server tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey := newKey(t)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ldapauthz test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if ca, err = x509.ParseCertificate(caDER); err != nil {
		t.Fatal(err)
	}

	key := newKey(t)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return testPKI{caFile: caFile, server: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// stall says where a fake directory stops responding.
type stall int

const (
	_               stall = iota // respond normally
	stallOnConnect               // accept the connection, then say nothing
	stallInStartTLS              // accept StartTLS, then never finish the handshake
)

// fakeConfig sets up a fake directory. It is fixed before the server
// starts, so connection goroutines read it without locking.
type fakeConfig struct {
	ldaps    bool // TLS from the first byte; otherwise StartTLS
	password string
	stall    stall
	// search returns the entries for a search; nil means none.
	search func(seenSearch) []fakeEntry
	// code returns the result code for a search; nil or success means
	// the entries from search are sent.
	code func(seenSearch) uint16
}

// seenSearch is a search request as the fake directory received it.
type seenSearch struct {
	base      string
	scope     int64
	sizeLimit int64
	filter    string // as decompiled by go-ldap, which re-escapes values
	attrs     []string
}

type fakeEntry struct {
	dn    string
	attrs map[string][]string
}

// fakeLDAP is a minimal LDAP server on 127.0.0.1. It answers simple binds,
// searches and StartTLS, which is all the handler sends.
type fakeLDAP struct {
	fakeConfig
	ln    net.Listener
	tls   *tls.Config
	conns atomic.Int32
	binds atomic.Int32

	mu       sync.Mutex
	closed   bool
	open     []net.Conn
	searches []seenSearch
}

func newFakeLDAP(t *testing.T, pki testPKI, cfg fakeConfig) *fakeLDAP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeLDAP{
		fakeConfig: cfg,
		ln:         ln,
		tls:        &tls.Config{Certificates: []tls.Certificate{pki.server}, MinVersion: tls.VersionTLS12},
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			f.mu.Lock()
			if f.closed {
				c.Close()
			}
			f.open = append(f.open, c)
			f.mu.Unlock()
			wg.Go(func() { f.serve(c) })
		}
	})
	t.Cleanup(func() {
		ln.Close()
		f.mu.Lock()
		f.closed = true
		for _, c := range f.open {
			c.Close()
		}
		f.mu.Unlock()
		wg.Wait()
	})
	return f
}

func (f *fakeLDAP) serve(c net.Conn) {
	defer c.Close()
	if f.stall == stallOnConnect {
		io.Copy(io.Discard, c)
		return
	}
	if f.ldaps {
		tc := tls.Server(c, f.tls)
		if tc.Handshake() != nil {
			return
		}
		c = tc
	}
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			f.binds.Add(1)
			code := uint16(ldap.LDAPResultInvalidCredentials)
			if len(op.Children) == 3 && op.Children[2].Data.String() == f.password {
				code = ldap.LDAPResultSuccess
			}
			send(c, id, ldapResult(ldap.ApplicationBindResponse, code))
		case ldap.ApplicationSearchRequest:
			s := f.record(op)
			code := uint16(ldap.LDAPResultSuccess)
			if f.code != nil {
				code = f.code(s)
			}
			var entries []fakeEntry
			if f.search != nil && code == ldap.LDAPResultSuccess {
				entries = f.search(s)
			}
			if s.sizeLimit > 0 && int64(len(entries)) > s.sizeLimit {
				entries, code = entries[:s.sizeLimit], ldap.LDAPResultSizeLimitExceeded
			}
			for _, e := range entries {
				send(c, id, e.packet())
			}
			send(c, id, ldapResult(ldap.ApplicationSearchResultDone, code))
		case ldap.ApplicationExtendedRequest: // the handler only sends StartTLS
			send(c, id, ldapResult(ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess))
			if f.stall == stallInStartTLS {
				io.Copy(io.Discard, c)
				return
			}
			tc := tls.Server(c, f.tls)
			if tc.Handshake() != nil {
				return
			}
			c = tc
		default: // unbind, or anything unexpected
			return
		}
	}
}

func (f *fakeLDAP) record(op *ber.Packet) seenSearch {
	var s seenSearch
	if len(op.Children) == 8 {
		s.base, _ = op.Children[0].Value.(string)
		s.scope, _ = op.Children[1].Value.(int64)
		s.sizeLimit, _ = op.Children[3].Value.(int64)
		s.filter, _ = ldap.DecompileFilter(op.Children[6])
		for _, a := range op.Children[7].Children {
			v, _ := a.Value.(string)
			s.attrs = append(s.attrs, v)
		}
	}
	f.mu.Lock()
	f.searches = append(f.searches, s)
	f.mu.Unlock()
	return s
}

func (f *fakeLDAP) seen() []seenSearch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.searches)
}

// ldapResult returns a response shaped as an LDAPResult, such as a
// BindResponse or SearchResultDone.
func ldapResult(tag ber.Tag, code uint16) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(code), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return op
}

func (e fakeEntry) packet() *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "objectName"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, vals := range e.attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	op.AppendChild(attrs)
	return op
}

func send(c net.Conn, id int64, op *ber.Packet) {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "message")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "messageID"))
	msg.AppendChild(op)
	c.Write(msg.Bytes())
}

// corpDirectory answers like an AD holding alice, a member of App-Admins;
// bob, a member of nothing; two entries that match pair; and three that
// match triple.
func corpDirectory(s seenSearch) []fakeEntry {
	switch s.scope {
	case ldap.ScopeWholeSubtree:
		switch {
		case strings.Contains(s.filter, "(userPrincipalName=alice@corp.example.com)"):
			return []fakeEntry{{dn: aliceDN, attrs: map[string][]string{"memberOf": {adminsDN}}}}
		case strings.Contains(s.filter, "(userPrincipalName=bob@corp.example.com)"):
			return []fakeEntry{{dn: bobDN}}
		case strings.Contains(s.filter, "(userPrincipalName=pair@corp.example.com)"):
			return []fakeEntry{{dn: "CN=Pair1,DC=corp"}, {dn: "CN=Pair2,DC=corp"}}
		case strings.Contains(s.filter, "(userPrincipalName=triple@corp.example.com)"):
			return []fakeEntry{{dn: "CN=Triple1,DC=corp"}, {dn: "CN=Triple2,DC=corp"}, {dn: "CN=Triple3,DC=corp"}}
		}
	case ldap.ScopeBaseObject:
		if s.base == aliceDN && strings.Contains(s.filter, adminsDN) {
			return []fakeEntry{{dn: aliceDN}}
		}
	}
	return nil
}

// directoryHandler returns a provisioned handler that uses f.
func directoryHandler(t *testing.T, f *fakeLDAP, caFile string, mutate func(*Handler)) *Handler {
	t.Helper()
	h := &Handler{
		URL:          "ldaps://" + f.ln.Addr().String(),
		BindDN:       "CN=svc,OU=Service Accounts,DC=corp,DC=example,DC=com",
		BindPassword: "secret",
		BaseDN:       "DC=corp,DC=example,DC=com",
		CAFile:       caFile,
		Allow:        []string{adminsDN},
		Timeout:      caddy.Duration(2 * time.Second),
	}
	if !f.ldaps {
		h.URL, h.StartTLS = "ldap://"+f.ln.Addr().String(), true
	}
	if mutate != nil {
		mutate(h)
	}
	if err := provisionAndValidate(h); err != nil {
		t.Fatal(err)
	}
	h.log = zap.NewNop()
	return h
}

func lookupCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// normalize returns filter in the form the fake directory reports
// received filters: compiled, then decompiled, by go-ldap.
func normalize(t *testing.T, filter string) string {
	t.Helper()
	p, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ldap.DecompileFilter(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDirectoryLookup(t *testing.T) {
	pki := newTestPKI(t)
	for _, ldaps := range []bool{true, false} {
		name := "starttls"
		if ldaps {
			name = "ldaps"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeLDAP(t, pki, fakeConfig{ldaps: ldaps, password: "secret", search: corpDirectory})
			h := directoryHandler(t, f, pki.caFile, nil)
			tests := []struct {
				user string
				want error
			}{
				{"alice@corp.example.com", nil},
				{"bob@corp.example.com", errNotMember},
				{"nobody@corp.example.com", errNotFound},
				{"pair@corp.example.com", errAmbiguous},   // two entries
				{"triple@corp.example.com", errAmbiguous}, // over the size limit
			}
			for _, tt := range tests {
				if err := h.lookup(lookupCtx(t), tt.user); !errors.Is(err, tt.want) {
					t.Errorf("%s: err = %v, want %v", tt.user, err, tt.want)
				}
			}
		})
	}
}

func TestDirectorySearches(t *testing.T) {
	pki := newTestPKI(t)
	f := newFakeLDAP(t, pki, fakeConfig{ldaps: true, password: "secret", search: corpDirectory})
	h := directoryHandler(t, f, pki.caFile, func(h *Handler) {
		h.Nested = true
		h.Allow = append(h.Allow, `CN=R\, D,OU=Groups,DC=corp,DC=example,DC=com`)
	})
	if err := h.lookup(lookupCtx(t), "alice@corp.example.com"); err != nil {
		t.Fatal(err)
	}
	got := f.seen()
	if len(got) != 2 {
		t.Fatalf("searches = %+v, want a user search and a membership search", got)
	}

	user := got[0]
	if user.base != h.BaseDN || user.scope != ldap.ScopeWholeSubtree || user.sizeLimit != 2 ||
		!slices.Equal(user.attrs, []string{"1.1"}) {
		t.Errorf("user search = %+v", user)
	}
	for _, part := range []string{
		"(userPrincipalName=alice@corp.example.com)",
		"(!(userAccountControl:1.2.840.113556.1.4.803:=2))",
		"(accountExpires>=",
	} {
		if !strings.Contains(user.filter, part) {
			t.Errorf("user filter %q lacks %q", user.filter, part)
		}
	}

	// The membership check runs on alice's own entry and names the groups
	// exactly as configured, for AD to resolve.
	member := got[1]
	want := normalize(t, `(|(memberOf:1.2.840.113556.1.4.1941:=`+adminsDN+`)`+
		`(memberOf:1.2.840.113556.1.4.1941:=CN=R\5c, D,OU=Groups,DC=corp,DC=example,DC=com))`)
	if member.base != aliceDN || member.scope != ldap.ScopeBaseObject || member.sizeLimit != 1 ||
		!slices.Equal(member.attrs, []string{"1.1"}) || member.filter != want {
		t.Errorf("membership search = %+v, want filter %q", member, want)
	}
}

func TestDirectoryEscaping(t *testing.T) {
	pki := newTestPKI(t)
	f := newFakeLDAP(t, pki, fakeConfig{ldaps: true, password: "secret", search: corpDirectory})
	h := directoryHandler(t, f, pki.caFile, nil)
	if err := h.lookup(lookupCtx(t), "*)(objectClass=*"); !errors.Is(err, errNotFound) {
		t.Fatalf("err = %v, want errNotFound", err)
	}
	got := f.seen()
	if want := `(userPrincipalName=\2a\29\28objectClass=\2a)`; len(got) != 1 || !strings.Contains(got[0].filter, want) {
		t.Errorf("searches = %+v; want the identity sent as the single value %s", got, want)
	}
}

func TestDirectoryAllowAnyUser(t *testing.T) {
	pki := newTestPKI(t)
	f := newFakeLDAP(t, pki, fakeConfig{ldaps: true, password: "secret", search: corpDirectory})
	h := directoryHandler(t, f, pki.caFile, func(h *Handler) { h.Allow, h.AllowAnyUser = nil, true })
	if err := h.lookup(lookupCtx(t), "bob@corp.example.com"); err != nil {
		t.Fatalf("err = %v, want bob allowed", err)
	}
	if n := len(f.seen()); n != 1 {
		t.Errorf("searches = %d, want only the user search", n)
	}
}

func TestDirectoryBindFailure(t *testing.T) {
	pki := newTestPKI(t)
	f := newFakeLDAP(t, pki, fakeConfig{ldaps: true, password: "rotated", search: corpDirectory})
	h := directoryHandler(t, f, pki.caFile, nil)
	err := h.lookup(lookupCtx(t), "alice@corp.example.com")
	if isDenial(err) || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("err = %v, want an invalid-credentials failure", err)
	}
	if n := len(f.seen()); n != 0 {
		t.Errorf("searched %d times after a failed bind", n)
	}
}

func TestDirectoryUntrustedCertificate(t *testing.T) {
	pki, other := newTestPKI(t), newTestPKI(t)
	for _, ldaps := range []bool{true, false} {
		f := newFakeLDAP(t, pki, fakeConfig{ldaps: ldaps, password: "secret", search: corpDirectory})
		h := directoryHandler(t, f, other.caFile, nil) // trusts a different CA
		err := h.lookup(lookupCtx(t), "alice@corp.example.com")
		if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
			t.Errorf("ldaps=%v: err = %v, want an unknown-authority error", ldaps, err)
		}
		if n := f.binds.Load(); n != 0 {
			t.Errorf("ldaps=%v: %d binds over an unverified connection", ldaps, n)
		}
	}
}

// TestDirectorySearchErrors checks that a directory error is a failure,
// answered with 503 or a stale answer, never a cached denial or a grant.
func TestDirectorySearchErrors(t *testing.T) {
	pki := newTestPKI(t)
	tests := map[string]struct {
		scope int64
		code  uint16
	}{
		"user search":       {ldap.ScopeWholeSubtree, ldap.LDAPResultBusy},
		"membership search": {ldap.ScopeBaseObject, ldap.LDAPResultUnwillingToPerform},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFakeLDAP(t, pki, fakeConfig{
				ldaps: true, password: "secret", search: corpDirectory,
				code: func(s seenSearch) uint16 {
					if s.scope == tt.scope {
						return tt.code
					}
					return ldap.LDAPResultSuccess
				},
			})
			h := directoryHandler(t, f, pki.caFile, nil)
			err := h.authorize("alice@corp.example.com")
			if isDenial(err) || !ldap.IsErrorWithCode(err, tt.code) {
				t.Errorf("err = %v, want a failure with result code %d", err, tt.code)
			}
			if _, cached := h.cache.entries["alice@corp.example.com"]; cached {
				t.Error("a failed lookup was cached")
			}
		})
	}
}

func TestDirectoryUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens on addr now
	h := validHandler()
	h.URL = "ldaps://" + addr
	if err := provisionAndValidate(h); err != nil {
		t.Fatal(err)
	}
	h.log = zap.NewNop()
	if err := h.authorize("alice@corp.example.com"); err == nil || isDenial(err) {
		t.Errorf("err = %v, want a directory failure", err)
	}
}

func TestDirectoryNegativeCache(t *testing.T) {
	pki := newTestPKI(t)
	f := newFakeLDAP(t, pki, fakeConfig{ldaps: true, password: "secret", search: corpDirectory})
	h := directoryHandler(t, f, pki.caFile, nil)
	for range 5 {
		if err := h.authorize("nobody@corp.example.com"); !errors.Is(err, errNotFound) {
			t.Fatalf("err = %v, want errNotFound", err)
		}
	}
	if n := f.conns.Load(); n != 1 {
		t.Errorf("%d directory connections for 5 requests, want 1", n)
	}
}

// TestDirectoryTimeouts is the regression test for StartTLS hanging past
// the timeout: every stall must end the lookup at about the timeout.
func TestDirectoryTimeouts(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name  string
		ldaps bool
		stall stall
	}{
		{"ldaps silent server", true, stallOnConnect},
		{"starttls silent server", false, stallOnConnect},
		{"starttls stalled handshake", false, stallInStartTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeLDAP(t, pki, fakeConfig{ldaps: tt.ldaps, password: "secret", stall: tt.stall})
			h := directoryHandler(t, f, pki.caFile, func(h *Handler) {
				h.Timeout = caddy.Duration(200 * time.Millisecond)
			})
			start := time.Now()
			err := h.authorize("alice@corp.example.com")
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("lookup took %v with a %v timeout", took, time.Duration(h.Timeout))
			}
			if err == nil || isDenial(err) {
				t.Errorf("err = %v, want a directory failure", err)
			}
		})
	}
}

func TestDirectoryServeHTTP(t *testing.T) {
	pki := newTestPKI(t)
	f := newFakeLDAP(t, pki, fakeConfig{ldaps: true, password: "secret", search: corpDirectory})
	h := directoryHandler(t, f, pki.caFile, nil)
	h.log = zaptest.NewLogger(t) // debug level, which also logs memberOf
	for user, want := range map[string]int{
		"alice@corp.example.com":  0,
		"bob@corp.example.com":    http.StatusForbidden,
		"nobody@corp.example.com": http.StatusForbidden,
	} {
		passed, err := serve(h, request(map[string]string{"http.auth.user.email": user}))
		if got := status(t, err); got != want || passed != (want == 0) {
			t.Errorf("%s: status = %d, passed = %v; want %d", user, got, passed, want)
		}
	}
}
