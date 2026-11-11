package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The console can serve https itself, so that it, and the relay hub on the
// same listener, work without a TLS reverse proxy in front. It is optional,
// chosen by tls in [console] or in the console's Relay hub tab:
//
//	tls = "self_signed"   pf-simple is its own certificate authority
//	tls = "directory"     the certificate is yours
//
// Either way the files are in tls_dir, "certs" next to the config file
// unless it says otherwise:
//
//	ca.pem      the CA's certificate          give this to clients to trust
//	ca.key      the CA's private key          self_signed only
//	server.pem  the server's certificate (and chain)
//	server.key  the server's private key
//
// self_signed makes all four. Both certificates renew themselves, at start
// and while running, well before they expire. Only the certificates are
// replaced, never the keys: a renewed CA certificate has the same key and
// name, so a client that trusts ca.pem keeps trusting the server through
// every renewal. The server certificate is also issued again when the
// names and addresses it should carry change.
//
// directory only reads server.pem and server.key, and reads them again
// when they change, so replacing them by hand, or by whatever renews them,
// takes effect without a restart.

const (
	tlsOff        = "off"
	tlsSelfSigned = "self_signed"
	tlsDirectory  = "directory"

	caLife   = 10 * 365 * 24 * time.Hour
	caRenew  = 2 * 365 * 24 * time.Hour // renewed with this much left
	leafLife = 365 * 24 * time.Hour
	// A third of its life left: the usual point to renew a certificate.
	leafRenew = leafLife / 3
	// How often a running server looks at its certificates again.
	selfRecheck = time.Hour
	certRecheck = 30 * time.Second

	defaultTLSDir = "certs"
)

// tlsNow is the clock the own CA goes by; tests move it.
var tlsNow = time.Now

// checkTLSMode validates tls from a config file or the console. Empty
// means off.
func checkTLSMode(mode string) (string, error) {
	switch mode {
	case "", tlsOff:
		return tlsOff, nil
	case tlsSelfSigned, tlsDirectory:
		return mode, nil
	}
	return "", fmt.Errorf("tls must be %q, %q or %q, not %q", tlsOff, tlsSelfSigned, tlsDirectory, mode)
}

// tlsManager is the console listener's TLS: which mode it is in, the
// certificate it serves, and the switch between plain and TLS, which
// happens without closing the listener.
type tlsManager struct {
	listenAddr string
	baseDir    string // what a relative tls_dir is relative to
	// persist writes the settings to the config file; nil when pf-simple
	// was started from the command line, and they are fixed then.
	persist func(mode, dir string, names []string) error

	mu    sync.Mutex
	mode  string
	dir   string   // as configured; "" means defaultTLSDir
	names []string // extra names for a self-signed certificate
	// current returns the certificate being served; nil when TLS is off.
	current func() *tls.Certificate
	config  atomic.Pointer[tls.Config] // nil when TLS is off
}

func newTLSManager(listenAddr, configPath string) *tlsManager {
	m := &tlsManager{listenAddr: listenAddr, mode: tlsOff}
	if configPath != "" {
		m.baseDir = filepath.Dir(configPath)
	}
	return m
}

// resolve is where the files of dir are: a relative tls_dir is relative to
// the config file, or to the working directory without one.
func (m *tlsManager) resolve(dir string) string {
	if dir == "" {
		dir = defaultTLSDir
	}
	if filepath.IsAbs(dir) || m.baseDir == "" {
		return dir
	}
	return filepath.Join(m.baseDir, dir)
}

// build prepares a mode without switching to it, so that a certificate
// that cannot be made or read leaves everything as it was.
func (m *tlsManager) build(mode, dir string, names []string) (*tls.Config, func() *tls.Certificate, error) {
	if mode == tlsOff {
		return nil, nil, nil
	}
	// HTTP/1.1 only: the console's WebSockets take over the connection.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	at := m.resolve(dir)
	if mode == tlsDirectory {
		files := &certFiles{certPath: filepath.Join(at, leafCertFile), keyPath: filepath.Join(at, leafKeyFile)}
		if _, err := files.load(); err != nil {
			return nil, nil, fmt.Errorf("tls = %q needs %s and %s in %s: %w", tlsDirectory, leafCertFile, leafKeyFile, at, err)
		}
		cfg.GetCertificate = files.get
		return cfg, files.peek, nil
	}
	own := &ownCA{dir: at, listenAddr: m.listenAddr, names: names}
	if _, err := own.ensure(); err != nil {
		return nil, nil, err
	}
	cfg.GetCertificate = own.get
	return cfg, own.peek, nil
}

// start applies the settings pf-simple was started with.
func (m *tlsManager) start(mode, dir string, names []string) error {
	cfg, current, err := m.build(mode, dir, names)
	if err != nil {
		return fmt.Errorf("console TLS: %w", err)
	}
	m.mu.Lock()
	m.mode, m.dir, m.names, m.current = mode, dir, names, current
	m.mu.Unlock()
	m.config.Store(cfg)
	return nil
}

var errTLSFixed = errors.New("the console's TLS can only be changed when pf-simple runs from a config file (-c)")

// set changes the settings from the console: it prepares the certificate,
// saves the settings, and only then switches the listener. Connections that
// are open stay as they are; new ones get the new mode.
func (m *tlsManager) set(mode, dir string, names []string) error {
	if m.persist == nil {
		return errTLSFixed
	}
	cfg, current, err := m.build(mode, dir, names)
	if err != nil {
		return &tlsSetupError{err}
	}
	if err := m.persist(mode, dir, names); err != nil {
		return err
	}
	m.mu.Lock()
	m.mode, m.dir, m.names, m.current = mode, dir, names, current
	m.mu.Unlock()
	m.config.Store(cfg)
	log.Printf("console TLS: changed from the console: %s", m.describe())
	changes.notify()
	return nil
}

// tlsSetupError is a certificate that could not be made or read: the
// user's to fix, not a failure of the server.
type tlsSetupError struct{ err error }

func (e *tlsSetupError) Error() string { return e.err.Error() }

// listen makes ln serve whatever mode is current when a connection comes.
func (m *tlsManager) listen(ln net.Listener) net.Listener { return &tlsListener{Listener: ln, m: m} }

type tlsListener struct {
	net.Listener
	m *tlsManager
}

func (l *tlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if cfg := l.m.config.Load(); cfg != nil {
		return tls.Server(conn, cfg), nil
	}
	return conn, nil
}

// tlsState is the console's view of its TLS.
type tlsState struct {
	// Manage says whether the settings can be changed here: only when
	// they are kept in a config file.
	Manage bool     `json:"manage"`
	Mode   string   `json:"mode"`  // "off", "self_signed" or "directory"
	Dir    string   `json:"dir"`   // tls_dir as configured; "" is the default
	Path   string   `json:"path"`  // where that is
	Names  []string `json:"names"` // tls_names
	// The certificate being served; absent when TLS is off.
	CertNames   []string `json:"certNames,omitempty"`
	NotAfter    int64    `json:"notAfter,omitempty"` // unix milliseconds
	Fingerprint string   `json:"fingerprint,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
}

func (m *tlsManager) snapshot() tlsState {
	m.mu.Lock()
	st := tlsState{Manage: m.persist != nil, Mode: m.mode, Dir: m.dir, Path: m.resolve(m.dir), Names: append([]string{}, m.names...)}
	current := m.current
	m.mu.Unlock()
	if current != nil {
		if cert := current(); cert != nil && cert.Leaf != nil {
			st.CertNames, st.NotAfter = certNames(cert.Leaf), cert.Leaf.NotAfter.UnixMilli()
			st.Fingerprint, st.Issuer = tunnel.Fingerprint(cert.Leaf), cert.Leaf.Issuer.CommonName
		}
	}
	return st
}

// describe is the settings and certificate in one line, for the log.
func (m *tlsManager) describe() string {
	st := m.snapshot()
	switch st.Mode {
	case tlsOff:
		return "off; the console speaks plain http"
	case tlsSelfSigned:
		return fmt.Sprintf("self-signed, own CA in %s; clients trust %s (pf-client --ca); server certificate for %s, valid until %s, SHA-256 %s",
			st.Path, filepath.Join(st.Path, caCertFile), strings.Join(st.CertNames, ", "), time.UnixMilli(st.NotAfter).Format("2006-01-02"), st.Fingerprint)
	}
	return fmt.Sprintf("certificate from %s, for %s, valid until %s, SHA-256 %s",
		filepath.Join(st.Path, leafCertFile), strings.Join(st.CertNames, ", "), time.UnixMilli(st.NotAfter).Format("2006-01-02"), st.Fingerprint)
}

func parseKeyPair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &cert, nil
}

// ---------- pf-simple as its own CA ----------

const (
	caKeyFile    = "ca.key"
	caCertFile   = "ca.pem"
	leafKeyFile  = "server.key"
	leafCertFile = "server.pem"
)

// ownCA keeps the CA and the server certificate in dir up to date.
type ownCA struct {
	dir        string
	listenAddr string
	names      []string // extra names and addresses for the server certificate

	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
}

func (o *ownCA) peek() *tls.Certificate {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cert
}

// get serves the certificate, looking at it again every selfRecheck. If it
// cannot be renewed the one in use stays, and the next look tries again.
func (o *ownCA) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	o.mu.Lock()
	cert, due := o.cert, time.Since(o.checked) >= selfRecheck
	o.mu.Unlock()
	if !due {
		return cert, nil
	}
	fresh, err := o.ensure()
	if err != nil {
		log.Printf("console TLS: keeping the certificate in use; it could not be renewed: %v", err)
		o.mu.Lock()
		o.checked = time.Now()
		o.mu.Unlock()
		return cert, nil
	}
	return fresh, nil
}

// ensure makes whatever is missing or due in dir and returns the server
// certificate with its chain. Keys are only ever created, never replaced.
func (o *ownCA) ensure() (*tls.Certificate, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// The folder is readable, for ca.crt; the keys in it are not.
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return nil, err
	}
	now := tlsNow()

	caKey, err := loadOrMakeKey(filepath.Join(o.dir, caKeyFile))
	if err != nil {
		return nil, err
	}
	caPath := filepath.Join(o.dir, caCertFile)
	ca := readCert(caPath)
	if ca == nil || !samePublicKey(ca.PublicKey, caKey.Public()) || !ca.IsCA || now.Before(ca.NotBefore) || ca.NotAfter.Sub(now) < caRenew {
		tpl := &x509.Certificate{
			Subject:               pkix.Name{CommonName: "pf-simple CA", Organization: []string{"pf-simple"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(caLife),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        true,
		}
		if ca != nil && samePublicKey(ca.PublicKey, caKey.Public()) {
			// A renewal keeps the name, so certificates issued before it
			// still chain to the new one, and the other way round.
			tpl.Subject = ca.Subject
		} else if host, err := os.Hostname(); err == nil && host != "" {
			tpl.Subject.CommonName += " (" + host + ")"
		}
		if ca, err = issue(tpl, tpl, caKey.Public(), caKey, caPath); err != nil {
			return nil, err
		}
		log.Printf("console TLS: issued the CA certificate %s, valid until %s", caPath, ca.NotAfter.Format("2006-01-02"))
	}

	leafKey, err := loadOrMakeKey(filepath.Join(o.dir, leafKeyFile))
	if err != nil {
		return nil, err
	}
	leafPath := filepath.Join(o.dir, leafCertFile)
	dns, ips := o.wanted()
	leaf := readCert(leafPath)
	why := ""
	switch {
	case leaf == nil:
		why = "there was none"
	case !samePublicKey(leaf.PublicKey, leafKey.Public()):
		why = "the old one was for another key"
	case leaf.CheckSignatureFrom(ca) != nil:
		why = "the old one was not issued by this CA"
	case now.Before(leaf.NotBefore) || leaf.NotAfter.Sub(now) < leafRenew:
		why = "the old one was due for renewal"
	case !coversNames(leaf, dns, ips):
		why = "its names and addresses changed"
	}
	if why != "" {
		notAfter := now.Add(leafLife)
		if notAfter.After(ca.NotAfter) {
			notAfter = ca.NotAfter
		}
		tpl := &x509.Certificate{
			Subject:               pkix.Name{CommonName: dns[len(dns)-1], Organization: []string{"pf-simple"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              dns,
			IPAddresses:           ips,
		}
		if leaf, err = issue(tpl, ca, leafKey.Public(), caKey, leafPath); err != nil {
			return nil, err
		}
		log.Printf("console TLS: issued the server certificate %s (%s), valid until %s, SHA-256 %s", leafPath, why, leaf.NotAfter.Format("2006-01-02"), tunnel.Fingerprint(leaf))
	}
	o.cert = &tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Raw}, PrivateKey: leafKey, Leaf: leaf}
	o.checked = now
	return o.cert, nil
}

// wanted is what the server certificate should name: localhost, this
// machine's host name, the console's listen address, the IPv4 addresses of
// its interfaces, and whatever tls_names adds. A client reaching the server by
// a name that is not here needs that name in tls_names.
func (o *ownCA) wanted() (dns []string, ips []net.IP) {
	dns = []string{"localhost"}
	addName := func(name string) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		for _, have := range dns {
			if have == name {
				return
			}
		}
		if name != "" {
			dns = append(dns, name)
		}
	}
	ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addIP := func(ip net.IP) {
		if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return
		}
		for _, have := range ips {
			if have.Equal(ip) {
				return
			}
		}
		ips = append(ips, ip)
	}
	if host, _, err := net.SplitHostPort(o.listenAddr); err == nil {
		addIP(net.ParseIP(host))
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			// IPv4 only: IPv6 hosts change their temporary addresses
			// daily, and each change would mean a new certificate. A
			// fixed IPv6 address can be named in tls_names.
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				addIP(ipnet.IP)
			}
		}
	}
	if host, err := os.Hostname(); err == nil {
		addName(host)
	}
	for _, name := range o.names {
		if ip := net.ParseIP(strings.TrimSpace(name)); ip != nil {
			addIP(ip)
		} else {
			addName(name)
		}
	}
	return dns, ips
}

// coversNames reports whether cert still fits: it has exactly the wanted
// names and at least the wanted addresses. An address it has and the
// machine has lost, such as that of a VPN that is down, is no reason to
// issue it again.
func coversNames(cert *x509.Certificate, dns []string, ips []net.IP) bool {
	if strings.Join(sanList(cert.DNSNames, nil), ",") != strings.Join(sanList(dns, nil), ",") {
		return false
	}
	for _, want := range ips {
		found := false
		for _, have := range cert.IPAddresses {
			found = found || have.Equal(want)
		}
		if !found {
			return false
		}
	}
	return true
}

// sanList is a certificate's names and addresses in one fixed order, to
// tell whether two sets are the same.
func sanList(dns []string, ips []net.IP) []string {
	out := append([]string(nil), dns...)
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

func certNames(cert *x509.Certificate) []string {
	return sanList(cert.DNSNames, cert.IPAddresses)
}

// checkTLSNames validates tls_names from a config file.
func checkTLSNames(names []string) error {
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, " /:@") && net.ParseIP(name) == nil {
			return fmt.Errorf("tls_names: %q is not a host name or an IP address", name)
		}
	}
	return nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// loadOrMakeKey reads the private key in path, or makes one and keeps it
// there. A key that is there but cannot be read is an error, not a reason
// to replace it: everything issued so far depends on it.
func loadOrMakeKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s holds no PEM private key; fix or remove it", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w; fix or remove it", path, err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an ECDSA key; fix or remove it", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	log.Printf("console TLS: made the private key %s", path)
	return key, nil
}

// readCert returns the certificate in path, or nil if there is none that
// can be read.
func readCert(path string) *x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// issue signs tpl for pub with the parent's key and keeps the certificate
// in path. The key identifiers come from the keys, so they stay the same
// through renewals.
func issue(tpl, parent *x509.Certificate, pub crypto.PublicKey, signer *ecdsa.PrivateKey, path string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tpl.SerialNumber = serial
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	id := sha1.Sum(pubDER)
	tpl.SubjectKeyId = id[:]
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// writeFileAtomic replaces path with data in one step.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pf-simple-tls-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// certFiles serves the certificate in two files and reads them again when
// either changes. A change that cannot be read is logged and the old
// certificate stays in use.
type certFiles struct {
	certPath, keyPath string

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   [2]time.Time // the files' modification times when cert was read
	checked time.Time
}

func (f *certFiles) stamps() (s [2]time.Time, err error) {
	for i, path := range []string{f.certPath, f.keyPath} {
		info, err := os.Stat(path)
		if err != nil {
			return s, err
		}
		s[i] = info.ModTime()
	}
	return s, nil
}

func (f *certFiles) load() (*tls.Certificate, error) {
	stamp, err := f.stamps()
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(f.certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(f.keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := parseKeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s and %s: %w", f.certPath, f.keyPath, err)
	}
	f.mu.Lock()
	f.cert, f.stamp, f.checked = cert, stamp, time.Now()
	f.mu.Unlock()
	return cert, nil
}

func (f *certFiles) peek() *tls.Certificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cert
}

func (f *certFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	cert, due := f.cert, time.Since(f.checked) >= certRecheck
	if due {
		f.checked = time.Now()
	}
	stamp := f.stamp
	f.mu.Unlock()
	if !due {
		return cert, nil
	}
	if now, err := f.stamps(); err == nil && now == stamp {
		return cert, nil
	}
	fresh, err := f.load()
	if err != nil {
		log.Printf("console TLS: keeping the certificate in use; the files could not be read again: %v", err)
		return cert, nil
	}
	log.Printf("console TLS: read the certificate again from %s, valid until %s, SHA-256 %s", f.certPath, fresh.Leaf.NotAfter.Format("2006-01-02"), tunnel.Fingerprint(fresh.Leaf))
	changes.notify()
	return fresh, nil
}

// ---------- console API ----------

func (s *consoleServer) handleTLS(w http.ResponseWriter, r *http.Request) {
	if s.tls == nil {
		writeError(w, http.StatusNotFound, "this server has no TLS settings")
		return
	}
	writeJSON(w, s.tls.snapshot())
}

// handleSetTLS changes the listener's TLS. The answer still travels the
// way the request came; connections made after it get the new mode.
func (s *consoleServer) handleSetTLS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode  string   `json:"mode"`
		Dir   string   `json:"dir"`
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body")
		return
	}
	if s.tls == nil {
		writeError(w, http.StatusNotFound, "this server has no TLS settings")
		return
	}
	mode, err := checkTLSMode(body.Mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dir := strings.TrimSpace(body.Dir)
	if len(dir) > 1024 || strings.ContainsRune(dir, 0) {
		writeError(w, http.StatusBadRequest, "bad directory")
		return
	}
	names := []string{}
	for _, name := range body.Names {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) > 64 {
		writeError(w, http.StatusBadRequest, "at most 64 names")
		return
	}
	if err := checkTLSNames(names); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var setup *tlsSetupError
	switch err := s.tls.set(mode, dir, names); {
	case err == nil:
		writeJSON(w, s.tls.snapshot())
	case errors.Is(err, errTLSFixed):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.As(err, &setup):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
