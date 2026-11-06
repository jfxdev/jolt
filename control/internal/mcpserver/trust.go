package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxRootBytes = 64 << 10
const maxTrustedRoots = 8

// Where the Control Tower serves its public root. The next root exists only
// while a root rotation is under way, and only on the plain-HTTP listener.
const (
	currentRootPath = "/.well-known/jolt/ca.pem"
	nextRootPath    = "/ca/next.pem"
)

// DefaultCAFile is where `trust` stores the roots and where the server looks
// for them when JOLT_MCP_CA_FILE is not set. It is empty when the user has no
// configuration directory.
func DefaultCAFile() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "jolt-mcp", "ca.pem")
}

// TrustOptions says what to fetch and where to keep it.
type TrustOptions struct {
	URL         string
	Fingerprint string
	CAFile      string
	// Next fetches the root a rotation is about to promote.
	Next bool
	// Replace drops the roots already stored; otherwise they stay until they
	// expire, so a rotation never leaves the agent without a valid root.
	Replace bool
	// Now is the clock; zero means time.Now.
	Now func() time.Time
}

// TrustResult reports what ended up in the file.
type TrustResult struct {
	Fingerprint string
	Subject     string
	NotAfter    time.Time
	CAFile      string
	Added       bool
	Roots       int
}

// Trust downloads a root certificate, checks it against the fingerprint the
// operator got over another channel and stores it. Nothing is stored unless
// the hash matches, so the download itself needs no authentication.
func Trust(ctx context.Context, options TrustOptions) (*TrustResult, error) {
	expected, err := NormalizeFingerprint(options.Fingerprint)
	if err != nil {
		return nil, err
	}
	if options.CAFile == "" {
		return nil, errors.New("no CA file: set --ca-file or JOLT_MCP_CA_FILE")
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	target, err := rootURL(options.URL, options.Next)
	if err != nil {
		return nil, err
	}
	data, err := download(ctx, target)
	if err != nil {
		return nil, err
	}
	root, err := parseRoot(data)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(root.Raw)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(expected)) != 1 {
		return nil, fmt.Errorf("the certificate served has fingerprint %s, not the one given", hex.EncodeToString(sum[:]))
	}
	if !now().Before(root.NotAfter) {
		return nil, errors.New("the root certificate has expired")
	}
	if now().Before(root.NotBefore.Add(-24 * time.Hour)) {
		return nil, errors.New("the root certificate is not valid yet; check the clock")
	}
	kept, err := keptRoots(options.CAFile, options.Replace, now())
	if err != nil {
		return nil, err
	}
	result := &TrustResult{Fingerprint: hex.EncodeToString(sum[:]), Subject: root.Subject.CommonName, NotAfter: root.NotAfter, CAFile: options.CAFile, Added: true}
	roots := kept[:0:0]
	for _, existing := range kept {
		if bytes.Equal(existing.Raw, root.Raw) {
			result.Added = false
			continue
		}
		roots = append(roots, existing)
	}
	roots = append(roots, root)
	if len(roots) > maxTrustedRoots {
		return nil, fmt.Errorf("the file would hold more than %d roots; use --replace", maxTrustedRoots)
	}
	if err := writeRoots(options.CAFile, roots); err != nil {
		return nil, err
	}
	result.Roots = len(roots)
	return result, nil
}

// NormalizeFingerprint accepts the SHA-256 as the Control Tower shows it
// (pairs separated by colons, upper case) or as plain hex.
func NormalizeFingerprint(value string) (string, error) {
	plain := strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(value)))
	decoded, err := hex.DecodeString(plain)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("the fingerprint must be a SHA-256 in hexadecimal, with or without colons")
	}
	return plain, nil
}

func rootURL(raw string, next bool) (string, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || (base.Scheme != "http" && base.Scheme != "https") {
		return "", errors.New("the URL must be http:// or https:// with a host and no path, credentials or query")
	}
	target := *base
	target.Path = currentRootPath
	if next {
		target.Path = nextRootPath
	}
	return target.String(), nil
}

// download fetches a URL whose content is authenticated by the fingerprint, not
// by the channel: that is the one place TLS verification is skipped, because the
// Control Tower's own certificate cannot be trusted before its root is.
func download(ctx context.Context, target string) (data []byte, err error) {
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // #nosec G402 -- the content is checked against a fingerprint
			Proxy:           nil,
		},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("could not create the request")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("could not reach the Control Tower")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errors.New("the Control Tower does not serve that root (is a root rotation under way?)")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Control Tower answered HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, maxRootBytes+1))
	if err != nil || len(data) > maxRootBytes {
		return nil, errors.New("the root certificate is unreadable or too large")
	}
	return data, nil
}

// parseRoot accepts exactly one self-signed CA certificate.
func parseRoot(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one PEM certificate")
	}
	return checkRoot(block.Bytes)
}

func checkRoot(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("the certificate is not valid")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.CheckSignatureFrom(cert) != nil || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, errors.New("the certificate is not a self-signed root")
	}
	return cert, nil
}

// keptRoots reads the roots already stored and drops the expired ones. A
// missing file is an empty store.
func keptRoots(filename string, replace bool, now time.Time) ([]*x509.Certificate, error) {
	if replace {
		return nil, nil
	}
	roots, err := LoadRoots(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kept := roots[:0]
	for _, root := range roots {
		if now.Before(root.NotAfter) {
			kept = append(kept, root)
		}
	}
	return kept, nil
}

// LoadRoots reads a store of roots. It refuses a file other users can write,
// anything but certificates, and anything that is not a self-signed CA: the
// store is the only thing the server trusts, so it has to be what `trust` wrote.
func LoadRoots(filename string) ([]*x509.Certificate, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0) || info.Size() > maxTrustedRoots*maxRootBytes {
		return nil, errors.New("the CA file must be a regular file that only its owner can write")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var roots []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("the CA file holds something other than certificates")
		}
		root, err := checkRoot(block.Bytes)
		if err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	if len(bytes.TrimSpace(data)) != 0 || len(roots) == 0 || len(roots) > maxTrustedRoots {
		return nil, errors.New("the CA file must hold between one and a few PEM root certificates")
	}
	return roots, nil
}

// writeRoots replaces the store atomically, so a crash never leaves half a
// file for the server to refuse.
func writeRoots(filename string, roots []*x509.Certificate) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("could not create the CA file directory")
	}
	var buffer bytes.Buffer
	for _, root := range roots {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}); err != nil {
			return err
		}
	}
	temp, err := os.CreateTemp(dir, ".ca-*.tmp")
	if err != nil {
		return errors.New("could not write the CA file")
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return errors.New("could not write the CA file")
	}
	if _, err := temp.Write(buffer.Bytes()); err != nil {
		temp.Close()
		return errors.New("could not write the CA file")
	}
	if err := temp.Close(); err != nil {
		return errors.New("could not write the CA file")
	}
	if err := os.Rename(name, filename); err != nil {
		return errors.New("could not write the CA file")
	}
	return nil
}
