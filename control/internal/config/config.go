package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/workload"
)

// SigningSource supplies the key that signs authorization contexts and the
// keys a context may have been signed with, when they are not fixed for the
// life of the process. The Control Tower's own certificate authority rotates
// them while it runs.
type SigningSource interface {
	Current() (id string, key ed25519.PrivateKey)
	Public() map[string]ed25519.PublicKey
}

const (
	// TLSManual is the default: the operator supplies keys and certificates.
	TLSManual = "manual"
	// TLSManaged lets the Control Tower run its own certificate authority.
	TLSManaged = "managed"
)

type Config struct {
	// TLSMode is TLSManual or TLSManaged.
	TLSMode string
	// TLSNames are the extra DNS names and IP addresses the managed HTTPS
	// certificate covers, beside localhost and the host of the public URL.
	TLSNames []string
	// CertificateValidity is how long a managed leaf certificate lives; zero
	// means the default.
	CertificateValidity time.Duration
	// EnrollmentApproval is "auto" (a valid join token enrolls a node without
	// further ado) or "manual" (a person approves each enrollment). A token can
	// ask for manual when this is auto, never the other way round.
	EnrollmentApproval string
	// CAAddress is where the plain-HTTP page with the public root certificate
	// listens in managed mode.
	CAAddress string
	// SigningSource, when set, replaces AuthorizationSigningKey and its ID.
	SigningSource SigningSource `json:"-"`
	// Authority is the Control Tower's own certificate authority, built by the
	// caller in managed mode.
	Authority *pki.Manager `json:"-"`

	WorkloadProviders         *workload.ProviderSet `json:"-"`
	AuthorizationSigningKeyID string
	AuthorizationSigningKey   ed25519.PrivateKey `json:"-"`
	SignedLocalReads          bool
	SignedLocalJobs           bool
	TypedPolicies             bool
	Approvals                 bool
	ApprovalWebhookURL        string
	SignedUploads             bool
	AuditRetentionDays        int
	AuditHashChain            bool
	AuditSearchQuery          bool
	TrustedProxies            []netip.Prefix
	Address                   string
	DataDir                   string
	StaticDir                 string
	AdminUsername             string
	AdminPassword             string
	EncryptionKey             []byte
	SecureCookies             bool
	TransferMaxSourcePaths    int
	NodeCAFile                string
	NodeClientCertFile        string
	NodeClientKeyFile         string
	PublicBaseURL             string
	MetricsToken              string
}

func Load() (Config, error) {
	cfg := Config{
		AuditRetentionDays:     intValue("CONTROL_TOWER_AUDIT_RETENTION_DAYS", 0),
		AuditHashChain:         boolValue("CONTROL_TOWER_AUDIT_HASH_CHAIN", false),
		AuditSearchQuery:       boolValue("CONTROL_TOWER_AUDIT_SEARCH_QUERY", false),
		Address:                value("CONTROL_TOWER_ADDRESS", ":8090"),
		DataDir:                value("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		StaticDir:              value("CONTROL_TOWER_STATIC_DIR", "./frontend/dist"),
		AdminUsername:          value("CONTROL_TOWER_ADMIN_USERNAME", "admin"),
		SecureCookies:          boolValue("CONTROL_TOWER_SECURE_COOKIES", true),
		TransferMaxSourcePaths: intValue("TRANSFER_MAX_SOURCE_PATHS", 1000),
		NodeCAFile:             value("CONTROL_TOWER_NODE_CA_FILE", ""),
		NodeClientCertFile:     value("CONTROL_TOWER_NODE_CLIENT_CERT_FILE", ""),
		NodeClientKeyFile:      value("CONTROL_TOWER_NODE_CLIENT_KEY_FILE", ""),
		PublicBaseURL:          strings.TrimRight(value("CONTROL_TOWER_PUBLIC_BASE_URL", ""), "/"),
	}
	var err error
	if providerFile := strings.TrimSpace(os.Getenv("CONTROL_TOWER_WORKLOAD_PROVIDERS_FILE")); providerFile != "" {
		cfg.WorkloadProviders, err = workload.LoadProviders(providerFile)
		if err != nil {
			return Config{}, errors.New("CONTROL_TOWER_WORKLOAD_PROVIDERS_FILE is invalid")
		}
	}
	cfg.TLSMode = strings.ToLower(value("CONTROL_TOWER_TLS_MODE", TLSManual))
	if cfg.TLSMode != TLSManual && cfg.TLSMode != TLSManaged {
		return Config{}, errors.New("CONTROL_TOWER_TLS_MODE must be manual or managed")
	}
	managed := cfg.TLSMode == TLSManaged
	if managed {
		cfg.EnrollmentApproval = strings.ToLower(value("CONTROL_TOWER_ENROLLMENT_APPROVAL", "auto"))
		if cfg.EnrollmentApproval != "auto" && cfg.EnrollmentApproval != "manual" {
			return Config{}, errors.New("CONTROL_TOWER_ENROLLMENT_APPROVAL must be auto or manual")
		}
		cfg.CAAddress = value("CONTROL_TOWER_CA_ADDRESS", ":8091")
		if cfg.CAAddress == "off" {
			cfg.CAAddress = ""
		}
		if names, err := managedNames(cfg.PublicBaseURL, os.Getenv("CONTROL_TOWER_TLS_NAMES")); err != nil {
			return Config{}, err
		} else {
			cfg.TLSNames = names
		}
		if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_CERTIFICATE_VALIDITY_DAYS")); raw != "" {
			days, err := strconv.Atoi(raw)
			if err != nil || days < 7 || days > 180 {
				return Config{}, errors.New("CONTROL_TOWER_CERTIFICATE_VALIDITY_DAYS must be between 7 and 180")
			}
			cfg.CertificateValidity = time.Duration(days) * 24 * time.Hour
		}
	} else {
		for _, name := range []string{"CONTROL_TOWER_TLS_NAMES", "CONTROL_TOWER_CA_ADDRESS", "CONTROL_TOWER_CERTIFICATE_VALIDITY_DAYS", "CONTROL_TOWER_ENROLLMENT_APPROVAL"} {
			if strings.TrimSpace(os.Getenv(name)) != "" {
				return Config{}, errors.New(name + " requires CONTROL_TOWER_TLS_MODE=managed")
			}
		}
	}
	cfg.AuthorizationSigningKeyID = strings.TrimSpace(os.Getenv("CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_ID"))
	keyFile := strings.TrimSpace(os.Getenv("CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_FILE"))
	if managed && (cfg.AuthorizationSigningKeyID != "" || keyFile != "") {
		return Config{}, errors.New("CONTROL_TOWER_TLS_MODE=managed generates the authorization signing key; remove CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_ID and _FILE")
	}
	if cfg.AuthorizationSigningKeyID != "" || keyFile != "" {
		cfg.AuthorizationSigningKey, err = readAuthorizationSigningKey(cfg.AuthorizationSigningKeyID, keyFile)
		if err != nil {
			return Config{}, err
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_SIGNED_LOCAL_READS")); raw != "" {
		cfg.SignedLocalReads, err = strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("CONTROL_TOWER_SIGNED_LOCAL_READS must be a boolean")
		}
	}
	if cfg.SignedLocalReads && !(managed || len(cfg.AuthorizationSigningKey) == ed25519.PrivateKeySize) {
		return Config{}, errors.New("CONTROL_TOWER_SIGNED_LOCAL_READS requires an authorization signing key")
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_SIGNED_LOCAL_JOBS")); raw != "" {
		cfg.SignedLocalJobs, err = strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("CONTROL_TOWER_SIGNED_LOCAL_JOBS must be a boolean")
		}
	}
	if cfg.SignedLocalJobs && !(managed || len(cfg.AuthorizationSigningKey) == ed25519.PrivateKeySize) {
		return Config{}, errors.New("CONTROL_TOWER_SIGNED_LOCAL_JOBS requires an authorization signing key")
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_TYPED_POLICIES")); raw != "" {
		cfg.TypedPolicies, err = strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("CONTROL_TOWER_TYPED_POLICIES must be a boolean")
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_APPROVALS")); raw != "" {
		cfg.Approvals, err = strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("CONTROL_TOWER_APPROVALS must be a boolean")
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_APPROVAL_WEBHOOK_URL")); raw != "" {
		parsed, parseErr := url.Parse(raw)
		loopback := parsed != nil && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
		if parseErr != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback)) {
			return Config{}, errors.New("CONTROL_TOWER_APPROVAL_WEBHOOK_URL must be an https URL without credentials")
		}
		if !cfg.Approvals {
			return Config{}, errors.New("CONTROL_TOWER_APPROVAL_WEBHOOK_URL requires CONTROL_TOWER_APPROVALS")
		}
		cfg.ApprovalWebhookURL = raw
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_SIGNED_UPLOADS")); raw != "" {
		cfg.SignedUploads, err = strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("CONTROL_TOWER_SIGNED_UPLOADS must be a boolean")
		}
	}
	if cfg.SignedUploads && !(managed || len(cfg.AuthorizationSigningKey) == ed25519.PrivateKeySize) {
		return Config{}, errors.New("CONTROL_TOWER_SIGNED_UPLOADS requires an authorization signing key")
	}
	// A typed rule is enforced by the node on a signed context. Allow it only
	// when every operation that reaches a file carries one, so no route can
	// read, write or move what a typed rule hides.
	if cfg.TypedPolicies && (!cfg.SignedLocalReads || !cfg.SignedUploads || !cfg.SignedLocalJobs || !(managed || len(cfg.AuthorizationSigningKey) == ed25519.PrivateKeySize)) {
		return Config{}, errors.New("CONTROL_TOWER_TYPED_POLICIES requires CONTROL_TOWER_SIGNED_LOCAL_READS, CONTROL_TOWER_SIGNED_UPLOADS, CONTROL_TOWER_SIGNED_LOCAL_JOBS and an authorization signing key")
	}
	if raw := strings.TrimSpace(os.Getenv("CONTROL_TOWER_TRUSTED_PROXIES")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(part))
			if parseErr != nil {
				return Config{}, errors.New("CONTROL_TOWER_TRUSTED_PROXIES must contain valid CIDRs")
			}
			cfg.TrustedProxies = append(cfg.TrustedProxies, prefix.Masked())
		}
	}
	if cfg.AdminPassword, err = SecretValue("CONTROL_TOWER_ADMIN_PASSWORD"); err != nil {
		return Config{}, err
	}
	if cfg.MetricsToken, err = SecretValue("CONTROL_TOWER_METRICS_TOKEN"); err != nil {
		return Config{}, err
	}
	if cfg.MetricsToken != "" && len(cfg.MetricsToken) < 16 {
		return Config{}, errors.New("CONTROL_TOWER_METRICS_TOKEN must contain at least 16 characters")
	}
	if (cfg.NodeClientCertFile == "") != (cfg.NodeClientKeyFile == "") {
		return Config{}, errors.New("CONTROL_TOWER_NODE_CLIENT_CERT_FILE and CONTROL_TOWER_NODE_CLIENT_KEY_FILE must be set together")
	}
	for name, path := range map[string]string{
		"CONTROL_TOWER_NODE_CA_FILE":          cfg.NodeCAFile,
		"CONTROL_TOWER_NODE_CLIENT_CERT_FILE": cfg.NodeClientCertFile,
		"CONTROL_TOWER_NODE_CLIENT_KEY_FILE":  cfg.NodeClientKeyFile,
	} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return Config{}, errors.New(name + " is unreadable: " + err.Error())
		}
	}
	if cfg.PublicBaseURL != "" {
		parsed, err := url.Parse(cfg.PublicBaseURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return Config{}, errors.New("CONTROL_TOWER_PUBLIC_BASE_URL must be an absolute http or https URL")
		}
	}
	if len(cfg.AdminPassword) < 12 {
		return Config{}, errors.New("CONTROL_TOWER_ADMIN_PASSWORD must contain at least 12 characters")
	}
	if cfg.TransferMaxSourcePaths < 1 || cfg.TransferMaxSourcePaths > 100000 {
		return Config{}, errors.New("TRANSFER_MAX_SOURCE_PATHS must be between 1 and 100000")
	}
	if cfg.AuditRetentionDays < 0 || cfg.AuditRetentionDays > 36500 {
		return Config{}, errors.New("CONTROL_TOWER_AUDIT_RETENTION_DAYS must be between 0 and 36500")
	}
	cfg.EncryptionKey, err = LoadEncryptionKey()
	if err != nil {
		return Config{}, err
	}
	absolute, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return Config{}, err
	}
	cfg.DataDir = absolute
	return cfg, nil
}

// readAuthorizationSigningKey accepts a single unencrypted Ed25519 PKCS#8
// private key from a file; it never stores the key in the database.
// managedNames lists the names the managed HTTPS certificate covers: the host
// of the public URL and the comma-separated extra names, each a DNS name or an
// IP address.
func managedNames(publicBaseURL, extra string) ([]string, error) {
	var names []string
	if publicBaseURL != "" {
		if parsed, err := url.Parse(publicBaseURL); err == nil && parsed.Hostname() != "" {
			names = append(names, parsed.Hostname())
		}
	}
	for _, part := range strings.Split(extra, ",") {
		if name := strings.TrimSpace(part); name != "" {
			names = append(names, name)
		}
	}
	for _, name := range names {
		if net.ParseIP(name) != nil {
			continue
		}
		if len(name) > 253 || strings.ContainsAny(name, " /\\:@?#\x00") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
			return nil, errors.New("CONTROL_TOWER_TLS_NAMES must hold DNS names or IP addresses")
		}
	}
	return names, nil
}

func readAuthorizationSigningKey(id, file string) (ed25519.PrivateKey, error) {
	if !signedauth.ValidKeyID(id) || file == "" {
		return nil, errors.New("authorization signing key ID and file are both required")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open authorization signing key: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, errors.New("cannot read authorization signing key")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("authorization signing key must be one unencrypted PKCS#8 PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid authorization signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("authorization signing key must be Ed25519")
	}
	return key, nil
}

func SecretValue(key string) (string, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	file := strings.TrimSpace(os.Getenv(key + "_FILE"))
	if raw != "" && file != "" {
		return "", errors.New("set only one of " + key + " and " + key + "_FILE")
	}
	if file == "" {
		return raw, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", key, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func LoadEncryptionKey() ([]byte, error) {
	rawKey, err := SecretValue("CONTROL_TOWER_DB_ENCRYPTION_KEY")
	if err != nil {
		return nil, err
	}
	return ParseEncryptionKey(rawKey)
}

func ParseEncryptionKey(rawKey string) ([]byte, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, errors.New("CONTROL_TOWER_DB_ENCRYPTION_KEY is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(rawKey); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(rawKey) < 32 {
		return nil, errors.New("CONTROL_TOWER_DB_ENCRYPTION_KEY must be a base64 32-byte key or at least 32 characters")
	}
	sum := sha256.Sum256([]byte(rawKey))
	return sum[:], nil
}

func ValidateNodeEndpoint(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", errors.New("node endpoint must be an absolute http or https URL")
	}
	parsed.Path, parsed.RawQuery, parsed.Fragment = "", "", ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func value(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func boolValue(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}

func intValue(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return -1
	}
	return value
}
