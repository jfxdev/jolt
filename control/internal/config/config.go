package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Address                string
	DataDir                string
	StaticDir              string
	AdminUsername          string
	AdminPassword          string
	EncryptionKey          []byte
	SecureCookies          bool
	TransferMaxSourcePaths int
	NodeCAFile             string
	NodeClientCertFile     string
	NodeClientKeyFile      string
	PublicBaseURL          string
	MetricsToken           string
}

func Load() (Config, error) {
	cfg := Config{
		Address:                value("CONTROL_TOWER_ADDRESS", ":8090"),
		DataDir:                value("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		StaticDir:              value("CONTROL_TOWER_STATIC_DIR", "./frontend/dist"),
		AdminUsername:          value("CONTROL_TOWER_ADMIN_USERNAME", "admin"),
		AdminPassword:          os.Getenv("CONTROL_TOWER_ADMIN_PASSWORD"),
		SecureCookies:          boolValue("CONTROL_TOWER_SECURE_COOKIES", true),
		TransferMaxSourcePaths: intValue("TRANSFER_MAX_SOURCE_PATHS", 1000),
		NodeCAFile:             value("CONTROL_TOWER_NODE_CA_FILE", ""),
		NodeClientCertFile:     value("CONTROL_TOWER_NODE_CLIENT_CERT_FILE", ""),
		NodeClientKeyFile:      value("CONTROL_TOWER_NODE_CLIENT_KEY_FILE", ""),
		PublicBaseURL:          strings.TrimRight(value("CONTROL_TOWER_PUBLIC_BASE_URL", ""), "/"),
		MetricsToken:           strings.TrimSpace(os.Getenv("CONTROL_TOWER_METRICS_TOKEN")),
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
	rawKey := strings.TrimSpace(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	encryptionKey, err := ParseEncryptionKey(rawKey)
	if err != nil {
		return Config{}, err
	}
	cfg.EncryptionKey = encryptionKey
	absolute, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return Config{}, err
	}
	cfg.DataDir = absolute
	return cfg, nil
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
