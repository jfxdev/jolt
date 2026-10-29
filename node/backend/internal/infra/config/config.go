package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/yamlutil"
	"go.yaml.in/yaml/v3"
)

type MountConfig struct {
	ID        string `yaml:"id"`
	Name      string `yaml:"name"`
	LocalPath string `yaml:"local_path"`
	Mode      string `yaml:"mode"`
	Published bool   `yaml:"published"`
	Enabled   bool   `yaml:"enabled"`
}
type GrantConfig struct {
	ID               string                    `yaml:"id"`
	PeerNodeID       string                    `yaml:"peer_node_id"`
	MountID          string                    `yaml:"mount_id"`
	Path             string                    `yaml:"path"`
	Direction        string                    `yaml:"direction"`
	Permissions      entities.GrantPermissions `yaml:"permissions"`
	ConflictPolicies []string                  `yaml:"conflict_policies"`
	VisibleToPeer    bool                      `yaml:"visible_to_peer"`
	Enabled          bool                      `yaml:"enabled"`
}
type Config struct {
	Version                  int           `yaml:"version"`
	Mounts                   []MountConfig `yaml:"mounts"`
	TransferGrants           []GrantConfig `yaml:"transfer_grants"`
	FilePath                 string        `yaml:"-"`
	Revision                 string        `yaml:"-"`
	PublicYAML               string        `yaml:"-"`
	UploadMaxBytes           int64         `yaml:"upload_max_bytes"`
	UploadMinFreeBytes       int64         `yaml:"upload_min_free_bytes"`
	UploadMaxSessions        int           `yaml:"upload_max_sessions"`
	UploadMaxReservedBytes   int64         `yaml:"upload_max_reserved_bytes"`
	NodeName                 string        `yaml:"node_name"`
	APIAddress               string        `yaml:"api_address"`
	APITLSCertFile           string        `yaml:"api_tls_cert_file"`
	APITLSKeyFile            string        `yaml:"api_tls_key_file"`
	APITLSClientCAFile       string        `yaml:"api_tls_client_ca_file"`
	MTLSAddress              string        `yaml:"mtls_address"`
	MTLSPublicEndpoint       string        `yaml:"mtls_public_endpoint"`
	DataDir                  string        `yaml:"data_dir"`
	KeysDir                  string        `yaml:"keys_dir"`
	ControlTowerToken        string        `yaml:"-"`
	MetricsToken             string        `yaml:"-"`
	EncryptionKey            []byte        `yaml:"-"`
	PublicHealth             bool          `yaml:"public_healthcheck"`
	ShutdownTimeout          time.Duration `yaml:"shutdown_timeout"`
	MaxConcurrentJobs        int           `yaml:"max_concurrent_jobs"`
	JobMaxAttempts           int           `yaml:"job_max_attempts"`
	CopyChunkSize            int64         `yaml:"copy_chunk_size_bytes"`
	NodeBandwidthLimit       int64         `yaml:"node_bandwidth_limit_bytes_per_second"`
	MaxParallelFilesPerJob   int           `yaml:"max_parallel_files_per_job"`
	MaxParallelChunksPerFile int           `yaml:"max_parallel_chunks_per_file"`
	TransferConnectTimeout   time.Duration `yaml:"transfer_connect_timeout"`
	TransferIdleReadTimeout  time.Duration `yaml:"transfer_idle_read_timeout"`
	TransferChunkTimeout     time.Duration `yaml:"transfer_chunk_timeout"`
	JobValidationTimeout     time.Duration `yaml:"job_validation_timeout"`
	JobNoProgressTimeout     time.Duration `yaml:"job_no_progress_timeout"`
	PeerHeartbeatInterval    time.Duration `yaml:"peer_heartbeat_interval"`
	PeerHeartbeatTimeout     time.Duration `yaml:"peer_heartbeat_timeout"`
	PeerFailureThreshold     int           `yaml:"peer_failure_threshold"`
	SearchMaxResults         int           `yaml:"search_max_results"`
	SearchMaxEntries         int           `yaml:"search_max_entries"`
	SearchTimeout            time.Duration `yaml:"search_timeout"`
	DiskUsageMaxEntries      int           `yaml:"disk_usage_max_entries"`
	DiskUsageTimeout         time.Duration `yaml:"disk_usage_timeout"`
	ArchiveMaxEntries        int           `yaml:"archive_max_entries"`
	ArchiveMaxBytes          int64         `yaml:"archive_max_bytes"`
	UploadSessionTTL         time.Duration `yaml:"upload_session_ttl"`
}

func (c Config) APITLSEnabled() bool { return c.APITLSCertFile != "" && c.APITLSKeyFile != "" }
func Defaults() Config {
	return Config{UploadMaxBytes: 100 << 30,
		UploadMinFreeBytes:       1 << 30,
		UploadMaxSessions:        32,
		UploadMaxReservedBytes:   400 << 30,
		NodeName:                 "jolt-node",
		APIAddress:               ":8080",
		APITLSCertFile:           "",
		APITLSKeyFile:            "",
		APITLSClientCAFile:       "",
		MTLSAddress:              ":8443",
		MTLSPublicEndpoint:       "",
		DataDir:                  "./.jolt/data",
		KeysDir:                  "./.jolt/keys",
		PublicHealth:             true,
		ShutdownTimeout:          15 * time.Second,
		MaxConcurrentJobs:        2,
		JobMaxAttempts:           3,
		CopyChunkSize:            16 << 20,
		NodeBandwidthLimit:       0,
		MaxParallelFilesPerJob:   2,
		MaxParallelChunksPerFile: 1,
		TransferConnectTimeout:   10 * time.Second,
		TransferIdleReadTimeout:  60 * time.Second,
		TransferChunkTimeout:     5 * time.Minute,
		JobValidationTimeout:     2 * time.Minute,
		JobNoProgressTimeout:     10 * time.Minute,
		PeerHeartbeatInterval:    15 * time.Second,
		PeerHeartbeatTimeout:     5 * time.Second,
		PeerFailureThreshold:     3,
		SearchMaxResults:         500,
		SearchMaxEntries:         200_000,
		SearchTimeout:            15 * time.Second,
		DiskUsageMaxEntries:      1_000_000,
		DiskUsageTimeout:         2 * time.Minute,
		ArchiveMaxEntries:        50_000,
		ArchiveMaxBytes:          100 << 30,
		UploadSessionTTL:         24 * time.Hour}
}

func Load(paths ...string) (Config, error) {
	file := os.Getenv("JOLT_CONFIG_FILE")
	if len(paths) > 0 && paths[0] != "" {
		file = paths[0]
	}
	if file == "" {
		file = "./node.yaml"
	}
	c, err := Read(file)
	if err != nil {
		return Config{}, err
	}
	c.ControlTowerToken = strings.TrimSpace(os.Getenv("CONTROL_TOWER_TOKEN"))
	if c.ControlTowerToken == "" {
		return Config{}, errors.New("CONTROL_TOWER_TOKEN is required")
	}
	c.MetricsToken = strings.TrimSpace(os.Getenv("METRICS_TOKEN"))
	if c.MetricsToken != "" && len(c.MetricsToken) < 16 {
		return Config{}, errors.New("METRICS_TOKEN must contain at least 16 characters")
	}
	c.EncryptionKey, err = LoadEncryptionKey()
	return c, err
}

// Read validates public configuration without requiring runtime credentials.
func Read(file string) (Config, error) {
	c := Defaults()
	raw, err := os.ReadFile(file)
	if err != nil {
		return c, fmt.Errorf("read node configuration: %w", err)
	}
	if len(raw) > 4<<20 {
		return c, errors.New("node configuration exceeds 4 MiB")
	}
	if err = yamlutil.DecodeConfiguration(raw, &c); err != nil {
		return c, fmt.Errorf("%s: %w", file, err)
	}
	var source yaml.Node
	_ = yaml.Unmarshal(raw, &source)
	fail := func(field, message string) error {
		return fmt.Errorf("%s: line %d: %s: %s", file, fieldLine(&source, field), field, message)
	}
	if c.Version != 1 {
		return c, fail("version", "must be 1")
	}
	if c.UploadMaxBytes < 1 || c.UploadMaxBytes > 1<<50 {
		return c, fail("upload_max_bytes", "value outside supported limits")
	}
	if c.UploadMinFreeBytes < 0 || c.UploadMinFreeBytes > 1<<50 {
		return c, fail("upload_min_free_bytes", "value outside supported limits")
	}
	if c.UploadMaxSessions < 1 || c.UploadMaxSessions > 10000 {
		return c, fail("upload_max_sessions", "value outside supported limits")
	}
	if c.UploadMaxReservedBytes < 1 || c.UploadMaxReservedBytes > 1<<50 {
		return c, fail("upload_max_reserved_bytes", "value outside supported limits")
	}
	if c.ShutdownTimeout < time.Second || c.ShutdownTimeout > 5*time.Minute {
		return c, fail("shutdown_timeout", "value outside supported limits")
	}
	if c.MaxConcurrentJobs < 1 || c.MaxConcurrentJobs > 32 {
		return c, fail("max_concurrent_jobs", "value outside supported limits")
	}
	if c.JobMaxAttempts < 1 || c.JobMaxAttempts > 20 {
		return c, fail("job_max_attempts", "value outside supported limits")
	}
	if c.CopyChunkSize < 64<<10 || c.CopyChunkSize > 1<<30 {
		return c, fail("copy_chunk_size_bytes", "value outside supported limits")
	}
	if c.NodeBandwidthLimit < 0 || c.NodeBandwidthLimit > 1<<40 {
		return c, fail("node_bandwidth_limit_bytes_per_second", "value outside supported limits")
	}
	if c.MaxParallelFilesPerJob < 1 || c.MaxParallelFilesPerJob > 32 {
		return c, fail("max_parallel_files_per_job", "value outside supported limits")
	}
	if c.MaxParallelChunksPerFile < 1 || c.MaxParallelChunksPerFile > 16 {
		return c, fail("max_parallel_chunks_per_file", "value outside supported limits")
	}
	if c.TransferConnectTimeout < time.Second || c.TransferConnectTimeout > 5*time.Minute {
		return c, fail("transfer_connect_timeout", "value outside supported limits")
	}
	if c.TransferIdleReadTimeout < time.Second || c.TransferIdleReadTimeout > 30*time.Minute {
		return c, fail("transfer_idle_read_timeout", "value outside supported limits")
	}
	if c.TransferChunkTimeout < time.Second || c.TransferChunkTimeout > 24*time.Hour {
		return c, fail("transfer_chunk_timeout", "value outside supported limits")
	}
	if c.JobValidationTimeout < time.Second || c.JobValidationTimeout > 30*time.Minute {
		return c, fail("job_validation_timeout", "value outside supported limits")
	}
	if c.JobNoProgressTimeout < time.Second || c.JobNoProgressTimeout > 24*time.Hour {
		return c, fail("job_no_progress_timeout", "value outside supported limits")
	}
	if c.PeerHeartbeatInterval < time.Second || c.PeerHeartbeatInterval > 10*time.Minute {
		return c, fail("peer_heartbeat_interval", "value outside supported limits")
	}
	if c.PeerHeartbeatTimeout < time.Second || c.PeerHeartbeatTimeout > time.Minute {
		return c, fail("peer_heartbeat_timeout", "value outside supported limits")
	}
	if c.PeerFailureThreshold < 1 || c.PeerFailureThreshold > 20 {
		return c, fail("peer_failure_threshold", "value outside supported limits")
	}
	if c.SearchMaxResults < 1 || c.SearchMaxResults > 10_000 {
		return c, fail("search_max_results", "value outside supported limits")
	}
	if c.SearchMaxEntries < 1_000 || c.SearchMaxEntries > 5_000_000 {
		return c, fail("search_max_entries", "value outside supported limits")
	}
	if c.SearchTimeout < time.Second || c.SearchTimeout > 5*time.Minute {
		return c, fail("search_timeout", "value outside supported limits")
	}
	if c.DiskUsageMaxEntries < 1_000 || c.DiskUsageMaxEntries > 10_000_000 {
		return c, fail("disk_usage_max_entries", "value outside supported limits")
	}
	if c.DiskUsageTimeout < time.Second || c.DiskUsageTimeout > 30*time.Minute {
		return c, fail("disk_usage_timeout", "value outside supported limits")
	}
	if c.ArchiveMaxEntries < 1 || c.ArchiveMaxEntries > 1_000_000 {
		return c, fail("archive_max_entries", "value outside supported limits")
	}
	if c.ArchiveMaxBytes < 1<<20 || c.ArchiveMaxBytes > 1<<50 {
		return c, fail("archive_max_bytes", "value outside supported limits")
	}
	if c.UploadSessionTTL < time.Minute || c.UploadSessionTTL > 30*24*time.Hour {
		return c, fail("upload_session_ttl", "value outside supported limits")
	}

	c.FilePath, err = filepath.Abs(file)
	if err != nil {
		return c, err
	}
	for _, entry := range []struct {
		name  string
		value *string
	}{{"data_dir", &c.DataDir}, {"keys_dir", &c.KeysDir}} {
		if *entry.value == "" {
			return c, fail(entry.name, "must not be empty")
		}
		*entry.value, err = filepath.Abs(*entry.value)
		if err != nil {
			return c, err
		}
		*entry.value, err = canonicalPath(*entry.value)
		if err != nil {
			return c, fail(entry.name, "cannot resolve directory")
		}
	}
	if overlaps(c.DataDir, c.KeysDir) {
		return c, fail("keys_dir", "data and keys directories must not overlap")
	}
	if err = ValidateEncryptionKeyLocation(c.DataDir, c.KeysDir); err != nil {
		return c, err
	}
	if strings.TrimSpace(c.NodeName) == "" || c.APIAddress == "" || c.MTLSAddress == "" {
		return c, fail("node_name", "name and listener addresses are required")
	}
	c.MTLSPublicEndpoint = strings.TrimRight(c.MTLSPublicEndpoint, "/")
	if c.MTLSPublicEndpoint != "" {
		endpoint, e := url.Parse(c.MTLSPublicEndpoint)
		if e != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
			return c, fail("mtls_public_endpoint", "must be an absolute https URL")
		}
	}
	if (c.APITLSCertFile == "") != (c.APITLSKeyFile == "") {
		return c, fail("api_tls_cert_file", "certificate and key must be set together")
	}
	if c.APITLSClientCAFile != "" && !c.APITLSEnabled() {
		return c, fail("api_tls_client_ca_file", "requires API TLS")
	}
	for _, path := range []string{c.APITLSCertFile, c.APITLSKeyFile, c.APITLSClientCAFile} {
		if path != "" {
			if _, err = os.Stat(path); err != nil {
				return c, fail("api_tls_cert_file", "TLS file is unreadable")
			}
		}
	}
	mounts := map[string]MountConfig{}
	paths := map[string]bool{}
	for i, m := range c.Mounts {
		if !validID(m.ID) || strings.TrimSpace(m.Name) == "" {
			return c, fail(fmt.Sprintf("mounts[%d]", i), "each mount requires a valid id and name")
		}
		if _, ok := mounts[m.ID]; ok {
			return c, fail(fmt.Sprintf("mounts[%d]", i), "duplicate mount id "+m.ID)
		}
		if !filepath.IsAbs(m.LocalPath) {
			return c, fail(fmt.Sprintf("mounts[%d]", i), "local_path must be absolute")
		}
		m.LocalPath, err = canonicalPath(m.LocalPath)
		if err != nil {
			return c, fail(fmt.Sprintf("mounts[%d]", i), err.Error())
		}
		if paths[m.LocalPath] {
			return c, fail(fmt.Sprintf("mounts[%d]", i), "duplicate local_path")
		}
		paths[m.LocalPath] = true
		for _, protected := range c.ProtectedPaths() {
			protected, err = filepath.Abs(protected)
			if err != nil {
				return c, err
			}
			root, e := canonicalPath(protected)
			if e != nil {
				return c, e
			}
			if overlaps(root, m.LocalPath) {
				return c, fail(fmt.Sprintf("mounts[%d]", i), "mount overlaps a protected internal path")
			}
		}
		if info, e := os.Stat(m.LocalPath); e == nil && !info.IsDir() {
			return c, fail(fmt.Sprintf("mounts[%d]", i), "mount target must be a directory")
		}
		if m.Mode != "read_only" && m.Mode != "read_write" {
			return c, fail(fmt.Sprintf("mounts[%d]", i), "mode must be read_only or read_write")
		}
		mounts[m.ID] = m
		c.Mounts[i] = m
	}
	grants := map[string]bool{}
	tuples := map[string]bool{}
	for i, g := range c.TransferGrants {
		if !validID(g.ID) || !validID(g.PeerNodeID) {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "grant and peer IDs must be explicit valid identifiers")
		}
		if grants[g.ID] {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "duplicate grant id")
		}
		grants[g.ID] = true
		m, ok := mounts[g.MountID]
		if !ok {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "unknown mount_id "+g.MountID)
		}
		g.Path = strings.ReplaceAll(g.Path, "\\", "/")
		if g.Path == "" {
			g.Path = "."
		}
		if filepath.IsAbs(g.Path) || !filepath.IsLocal(g.Path) || strings.Contains(g.Path, "\x00") {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "path must stay relative to its mount")
		}
		g.Path = filepath.ToSlash(filepath.Clean(g.Path))
		switch g.Direction {
		case "send":
			if !g.Permissions.Read || g.Permissions.Write || g.Permissions.Rename {
				return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "send requires read and may additionally permit delete")
			}
		case "receive":
			if !g.Permissions.Write {
				return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "receive requires write")
			}
		case "send_receive":
			if !g.Permissions.Read || !g.Permissions.Write {
				return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "send_receive requires read and write")
			}
		default:
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "invalid direction")
		}
		if m.Mode != "read_write" && (g.Permissions.Write || g.Permissions.Delete || g.Permissions.Rename || g.Direction != "send") {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "write capabilities require a read_write mount")
		}
		if g.VisibleToPeer && !m.Published {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "visible grant requires a published mount")
		}
		if g.Direction == "send" && len(g.ConflictPolicies) > 0 {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "conflict policies apply only to receiving grants")
		}
		if g.Direction != "send" && len(g.ConflictPolicies) == 0 {
			g.ConflictPolicies = []string{"fail"}
		}
		for _, policy := range g.ConflictPolicies {
			switch policy {
			case "skip", "overwrite", "rename", "fail", "ask", "checksum":
			default:
				return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "invalid conflict policy")
			}
		}
		target, e := canonicalPath(filepath.Join(m.LocalPath, filepath.FromSlash(g.Path)))
		if e != nil {
			return c, e
		}
		relative, e := filepath.Rel(m.LocalPath, target)
		if e != nil || !filepath.IsLocal(relative) {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "path escapes the mount through a symlink")
		}
		tuple := g.PeerNodeID + "\x00" + g.MountID + "\x00" + g.Path + "\x00" + g.Direction
		if tuples[tuple] {
			return c, fail(fmt.Sprintf("transfer_grants[%d]", i), "duplicate authorization")
		}
		tuples[tuple] = true
		c.TransferGrants[i] = g
	}
	canonical, err := yaml.Marshal(c)
	if err != nil {
		return c, err
	}
	digest := sha256.Sum256(canonical)
	c.Revision = hex.EncodeToString(digest[:])
	c.PublicYAML = string(canonical)
	return c, nil
}
func (c Config) Resources() ([]entities.Mount, []entities.TransferPathGrant) {
	mounts := make([]entities.Mount, 0, len(c.Mounts))
	grants := make([]entities.TransferPathGrant, 0, len(c.TransferGrants))
	for _, m := range c.Mounts {
		mounts = append(mounts, entities.Mount{ID: m.ID, Name: m.Name, LocalPath: m.LocalPath, TargetType: "directory", Mode: m.Mode, Published: m.Published, Enabled: m.Enabled})
	}
	for _, g := range c.TransferGrants {
		grants = append(grants, entities.TransferPathGrant{ID: g.ID, PeerNodeID: g.PeerNodeID, MountID: g.MountID, Path: g.Path, Direction: g.Direction, Permissions: g.Permissions, ConflictPolicies: g.ConflictPolicies, VisibleToPeer: g.VisibleToPeer, Enabled: g.Enabled})
	}
	return mounts, grants
}

func (c Config) ProtectedPaths() []string {
	paths := []string{c.DataDir, c.KeysDir, c.FilePath}
	for _, secret := range []string{os.Getenv("JOLT_STATE_ENCRYPTION_KEY_FILE"), c.APITLSKeyFile} {
		if strings.TrimSpace(secret) != "" {
			paths = append(paths, secret)
		}
	}
	return paths
}
func LoadEncryptionKey() ([]byte, error) {
	raw, file := strings.TrimSpace(os.Getenv("JOLT_STATE_ENCRYPTION_KEY")), strings.TrimSpace(os.Getenv("JOLT_STATE_ENCRYPTION_KEY_FILE"))
	if raw != "" && file != "" {
		return nil, errors.New("set only one of JOLT_STATE_ENCRYPTION_KEY and JOLT_STATE_ENCRYPTION_KEY_FILE")
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read state encryption key: %w", err)
		}
		raw = string(data)
	}
	return ParseEncryptionKey(raw)
}

// The external key must never become part of a state or identity backup.
func ValidateEncryptionKeyLocation(dirs ...string) error {
	file := strings.TrimSpace(os.Getenv("JOLT_STATE_ENCRYPTION_KEY_FILE"))
	if file == "" {
		return nil
	}
	file, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	file, err = canonicalPath(file)
	if err != nil {
		return errors.New("cannot resolve external state key file")
	}
	for _, dir := range dirs {
		root, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		root, err = canonicalPath(root)
		if err != nil {
			return err
		}
		if overlaps(root, file) {
			return errors.New("JOLT_STATE_ENCRYPTION_KEY_FILE must be outside the state and identity directories")
		}
	}
	return nil
}
func ParseEncryptionKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != 32 {
		return nil, errors.New("JOLT_STATE_ENCRYPTION_KEY must be a Base64 encoded 32-byte random key")
	}
	return key, nil
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func validID(id string) bool { return idPattern.MatchString(id) }
func overlaps(a, b string) bool {
	r, e := filepath.Rel(a, b)
	if e == nil && filepath.IsLocal(r) {
		return true
	}
	r, e = filepath.Rel(b, a)
	return e == nil && filepath.IsLocal(r)
}
func canonicalPath(path string) (string, error) {
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err = canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}
func fieldLine(n *yaml.Node, field string) int {
	if base, index, ok := strings.Cut(field, "["); ok {
		var position int
		if _, err := fmt.Sscanf(index, "%d]", &position); err == nil {
			for n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
				n = n.Content[0]
			}
			if n.Kind == yaml.MappingNode {
				for i := 0; i < len(n.Content); i += 2 {
					if n.Content[i].Value == base && n.Content[i+1].Kind == yaml.SequenceNode && position < len(n.Content[i+1].Content) {
						return n.Content[i+1].Content[position].Line
					}
				}
			}
		}
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == field {
				return n.Content[i].Line
			}
		}
	}
	for _, child := range n.Content {
		if line := fieldLine(child, field); line > 0 {
			return line
		}
	}
	return 0
}
