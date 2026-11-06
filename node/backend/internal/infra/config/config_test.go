package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestYAMLConfigurationAndPrecedence(t *testing.T) {
	t.Setenv("CONTROL_TOWER_TOKEN", "test-token")
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("JOLT_CONFIG_FILE", writeConfig(t, "version: 1\nnode_name: environment\n"))
	t.Setenv("COPY_CHUNK_SIZE_BYTES", "1024")
	file := writeConfig(t, "version: 1\nnode_name: explicit\ncopy_chunk_size_bytes: 65536\npeer_heartbeat_interval: 30s\ntransfer_connect_timeout: 3s\nmax_parallel_files_per_job: 6\n")
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeName != "explicit" || cfg.CopyChunkSize != 65536 || cfg.PeerHeartbeatInterval != 30*time.Second || cfg.TransferConnectTimeout != 3*time.Second || cfg.MaxParallelFilesPerJob != 6 {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
	if err := os.WriteFile(file, []byte("version: 1\nnode_name: changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg.NodeName != "explicit" {
		t.Fatal("configuration changed without restart")
	}
}
func TestStrictYAMLConfiguration(t *testing.T) {
	cases := []string{"", "version: 2\n", "version: 1\nunknown: true\n", "version: 1\nversion: 1\n", "version: 1\nnode_name: &name node\n", "version: 1\n---\nversion: 1\n", "version: 1\ncopy_chunk_size_bytes: 1024\n", "version: 1\nmax_concurrent_jobs: 0\n", "version: 1\ntransfer_connect_timeout: nonsense\n", "version: 1\napi_tls_key_file: /missing\n", "version: 1\ncontrol_tower_token: secret\n"}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			_, err := Read(writeConfig(t, body))
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if !strings.Contains(err.Error(), "node.yaml") {
				t.Fatalf("missing source context: %v", err)
			}
		})
	}
	for _, field := range []string{"node_name: 123", "public_healthcheck: yes", "max_concurrent_jobs: null", "max_concurrent_jobs: 2.0", "version: '1'", "mounts: {}"} {
		if _, err := Read(writeConfig(t, "version: 1\n"+field+"\n")); err == nil {
			t.Fatalf("coerced invalid field %s", field)
		}
	}
}

func TestAuthorizationPublicKeys(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	key := base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	body := "version: 1\nauthorization_public_keys:\n  - id: old\n    key: " + key + "\n  - id: current\n    key: " + key + "\n"
	cfg, err := Read(writeConfig(t, body))
	if err != nil || len(cfg.AuthorizationKeys) != 2 || len(cfg.AuthorizationKeys["current"]) != 32 {
		t.Fatalf("keys=%v error=%v", cfg.AuthorizationKeys, err)
	}
	binding := signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "read", RequestID: "request", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "."}
	claims := signedauth.Claims{Version: signedauth.Version, KeyID: "current", Binding: binding, IssuedAt: 1700000000, ExpiresAt: 1700000030, Context: json.RawMessage(`{"version":1,"rules":[]}`)}
	token, err := signedauth.Sign(claims, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := signedauth.Verify(token, cfg.AuthorizationKeys, binding, "node", time.Unix(claims.IssuedAt, 0)); err != nil {
		t.Fatalf("configured key failed verification: %v", err)
	}
	for _, invalid := range []string{
		"  - id: old\n    key: bad\n",
		"  - id: 'invalid/id'\n    key: " + key + "\n",
		"  - id: same\n    key: " + key + "\n  - id: same\n    key: " + key + "\n",
		"  - id: old\n    key: 123\n",
	} {
		if _, err := Read(writeConfig(t, "version: 1\nauthorization_public_keys:\n"+invalid)); err == nil {
			t.Fatalf("invalid key accepted: %s", invalid)
		}
	}
}

func TestUploadInspectionConfiguration(t *testing.T) {
	defaults, err := Read(writeConfig(t, "version: 1\n"))
	if err != nil || defaults.UploadInspection.Enabled || !defaults.UploadInspection.BlockExecutables {
		t.Fatalf("defaults: %+v %v", defaults.UploadInspection, err)
	}
	cfg, err := Read(writeConfig(t, "version: 1\nupload_inspection:\n  enabled: true\n  allowed_media_types: ['TEXT/PLAIN', 'application/pdf']\n"))
	if err != nil || !cfg.UploadInspection.Enabled || cfg.UploadInspection.AllowedMediaTypes[0] != "text/plain" || !cfg.UploadInspection.BlockExecutables {
		t.Fatalf("inspection: %+v %v", cfg.UploadInspection, err)
	}
	for _, invalid := range []string{"['text/*']", "['text/plain; charset=utf-8']", "['text/plain', 'TEXT/PLAIN']", "['invalid']"} {
		if _, err := Read(writeConfig(t, "version: 1\nupload_inspection:\n  allowed_media_types: "+invalid+"\n")); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
}

func TestExternalKeyCannotBeIncludedInBackup(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "state.key")
	if err := os.WriteFile(file, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY_FILE", file)
	if err := ValidateEncryptionKeyLocation(root); err == nil {
		t.Fatal("key inside backup accepted")
	}
	link := filepath.Join(t.TempDir(), "external")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEncryptionKeyLocation(link); err == nil {
		t.Fatal("key inside symlinked backup accepted")
	}
	if err := ValidateEncryptionKeyLocation(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
func TestResourceValidationAndUnavailableMount(t *testing.T) {
	root := t.TempDir()
	mount := filepath.Join(root, "not-mounted-yet")
	base := "version: 1\nmounts:\n  - id: files\n    name: Files\n    local_path: " + mount + "\n    mode: read_write\n    enabled: true\n    published: true\n"
	grant := "transfer_grants:\n  - id: send\n    peer_node_id: peer-a\n    mount_id: files\n    path: .\n    direction: send\n    permissions: {read: true}\n    enabled: true\n"
	cfg, err := Read(writeConfig(t, base+grant))
	if err != nil {
		t.Fatal(err)
	}
	mounts, grants := cfg.Resources()
	if len(mounts) != 1 || len(grants) != 1 {
		t.Fatal("resources missing")
	}
	if _, err := os.Stat(mount); !os.IsNotExist(err) {
		t.Fatal("missing mount was created")
	}
	for _, body := range []string{strings.Replace(base+grant, "mount_id: files", "mount_id: absent", 1), strings.Replace(base+grant, "path: .", "path: ../escape", 1), strings.Replace(base+grant, "path: .", "path: /absolute", 1), strings.Replace(base+grant, "{read: true}", "{write: true}", 1), strings.Replace(base+grant, "mode: read_write", "mode: invalid", 1), strings.Replace(base, "local_path: "+mount, "local_path: relative", 1)} {
		if _, err := Read(writeConfig(t, body)); err == nil {
			t.Fatal("invalid resource accepted")
		}
	}
}

func TestHiddenPatternsConfiguration(t *testing.T) {
	root := t.TempDir()
	base := "version: 1\nmounts:\n  - id: files\n    name: Files\n    local_path: " + root + "\n    mode: read_only\n    hidden_patterns: "
	cfg, err := Read(writeConfig(t, base+"['.env', '*.pem']\n"))
	if err != nil {
		t.Fatal(err)
	}
	mounts, _ := cfg.Resources()
	if len(mounts) != 1 || len(mounts[0].HiddenPatterns) != 2 {
		t.Fatalf("patterns missing from resource: %+v", mounts)
	}
	for _, invalid := range []string{"['[']", "['dir/file']", "['']"} {
		if _, err := Read(writeConfig(t, base+invalid+"\n")); err == nil {
			t.Fatalf("accepted invalid patterns: %s", invalid)
		}
	}
}

func TestGrantExcludePatternsConfiguration(t *testing.T) {
	root := t.TempDir()
	base := "version: 1\nmounts:\n  - id: files\n    name: Files\n    local_path: " + root + "\n    mode: read_only\n    enabled: true\ntransfer_grants:\n  - id: send\n    peer_node_id: peer\n    mount_id: files\n    path: .\n    direction: send\n    permissions: {read: true}\n    enabled: true\n    exclude: "
	cfg, err := Read(writeConfig(t, base+"['*.pem', 'private']\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, grants := cfg.Resources()
	if len(grants) != 1 || len(grants[0].Exclude) != 2 {
		t.Fatalf("exclude not persisted: %+v", grants)
	}
	for _, invalid := range []string{"['[invalid']", "['dir/file']", "['']"} {
		if _, err := Read(writeConfig(t, base+invalid+"\n")); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
}

func TestCanaryPathsConfiguration(t *testing.T) {
	root := t.TempDir()
	base := "version: 1\nmounts:\n  - id: files\n    name: Files\n    local_path: " + root + "\n    mode: read_only\n    canary_paths: "
	cfg, err := Read(writeConfig(t, base+"['decoys/token.txt']\n"))
	if err != nil {
		t.Fatal(err)
	}
	mounts, _ := cfg.Resources()
	if len(mounts) != 1 || len(mounts[0].CanaryPaths) != 1 {
		t.Fatalf("canary paths missing: %+v", mounts)
	}
	for _, invalid := range []string{"['../secret']", "['/absolute']", "['.']", "['a/../b']", "['a', 'a']"} {
		if _, err := Read(writeConfig(t, base+invalid+"\n")); err == nil {
			t.Fatalf("accepted invalid canary: %s", invalid)
		}
	}
}
func TestProtectedAndSymlinkPaths(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "private")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(data, link); err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{root, data, link, filepath.Join(link, "missing")} {
		body := "version: 1\ndata_dir: " + data + "\nmounts:\n - id: files\n   name: Files\n   mode: read_only\n   local_path: " + mount + "\n"
		if _, err := Read(writeConfig(t, body)); err == nil {
			t.Fatal("protected path accepted")
		}
	}
}
func TestEncryptionKeySources(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY", key)
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY_FILE", "")
	if _, err := LoadEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	file := writeConfig(t, key)
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY_FILE", file)
	if _, err := LoadEncryptionKey(); err == nil {
		t.Fatal("ambiguous key source accepted")
	}
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY", "")
	if _, err := LoadEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "this-is-a-passphrase-longer-than-32-characters", "AA=="} {
		if _, err := ParseEncryptionKey(raw); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}

func TestSecretValueSources(t *testing.T) {
	const key = "JOLT_TEST_SECRET"
	t.Setenv(key, " environment-secret \n")
	t.Setenv(key+"_FILE", "")
	value, err := SecretValue(key)
	if err != nil || value != "environment-secret" {
		t.Fatalf("environment secret = %q, %v", value, err)
	}
	file := writeConfig(t, " file-secret\n")
	t.Setenv(key+"_FILE", file)
	if _, err := SecretValue(key); err == nil {
		t.Fatal("ambiguous secret source accepted")
	}
	t.Setenv(key, "")
	value, err = SecretValue(key)
	if err != nil || value != "file-secret" {
		t.Fatalf("file secret = %q, %v", value, err)
	}
	t.Setenv(key+"_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := SecretValue(key); err == nil {
		t.Fatal("missing secret file accepted")
	}
}

func TestSymlinkedStateAndIdentityDirectoriesMustRemainSeparate(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	file := writeConfig(t, "version: 1\ndata_dir: "+root+"\nkeys_dir: "+filepath.Join(alias, "keys")+"\n")
	if _, err := Read(file); err == nil {
		t.Fatal("overlapping canonical internal directories accepted")
	}
}

func TestDuplicateResourceIDsAndIncompatiblePermissions(t *testing.T) {
	mount := t.TempDir()
	mountItem := "  - id: files\n    name: Files\n    local_path: " + mount + "\n    mode: read_write\n    enabled: true\n"
	grant := "  - id: send\n    peer_node_id: peer\n    mount_id: files\n    path: .\n    direction: send\n    permissions: {read: true}\n    enabled: true\n"
	base := "version: 1\nmounts:\n" + mountItem
	for _, body := range []string{base + mountItem, base + "transfer_grants:\n" + grant + grant, strings.Replace(base, "read_write", "read_only", 1) + "transfer_grants:\n" + strings.Replace(grant, "{read: true}", "{read: true, delete: true}", 1)} {
		if _, err := Read(writeConfig(t, body)); err == nil {
			t.Fatal("invalid duplicate or permission accepted")
		}
	}
}

func TestTrashConfiguration(t *testing.T) {
	root := t.TempDir()
	mount := func(mode, trash string) string {
		return "version: 1\nmounts:\n  - id: files\n    name: Files\n    local_path: " + root + "\n    mode: " + mode + "\n    enabled: true\n" + trash
	}
	cfg, err := Read(writeConfig(t, mount("read_write", "    trash: {enabled: true}\n")))
	if err != nil {
		t.Fatal(err)
	}
	mounts, _ := cfg.Resources()
	if mounts[0].Trash == nil || !mounts[0].Trash.Enabled || mounts[0].Trash.RetentionDays != DefaultTrashRetentionDays {
		t.Fatalf("default retention: %+v", mounts[0].Trash)
	}
	cfg, err = Read(writeConfig(t, mount("read_write", "    trash: {enabled: true, retention_days: 7}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if mounts, _ := cfg.Resources(); mounts[0].Trash.RetentionDays != 7 {
		t.Fatalf("retention: %+v", mounts[0].Trash)
	}
	if cfg, err := Read(writeConfig(t, mount("read_write", ""))); err != nil {
		t.Fatal(err)
	} else if mounts, _ := cfg.Resources(); mounts[0].Trash != nil {
		t.Fatalf("trash appeared without being asked for: %+v", mounts[0].Trash)
	}
	for name, text := range map[string]string{
		"read-only mount":     mount("read_only", "    trash: {enabled: true}\n"),
		"retention too long":  mount("read_write", "    trash: {enabled: true, retention_days: 366}\n"),
		"negative retention":  mount("read_write", "    trash: {enabled: true, retention_days: -1}\n"),
		"unknown trash field": mount("read_write", "    trash: {enabled: true, forever: true}\n"),
		"negative cap":        mount("read_write", "    trash: {enabled: true, max_bytes: -1}\n"),
		"absurd cap":          mount("read_write", "    trash: {enabled: true, max_bytes: 9007199254740993000}\n"),
	} {
		if _, err := Read(writeConfig(t, text)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	cfg, err = Read(writeConfig(t, mount("read_write", "    trash: {enabled: true, max_bytes: 1073741824}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if mounts, _ := cfg.Resources(); mounts[0].Trash.MaxBytes != 1<<30 {
		t.Fatalf("cap: %+v", mounts[0].Trash)
	}
	// Turned off on a read-only mount is harmless.
	if _, err := Read(writeConfig(t, mount("read_only", "    trash: {enabled: false}\n"))); err != nil {
		t.Fatalf("disabled trash on a read-only mount: %v", err)
	}
}

func managedBody(extra string) string {
	return "version: 1\nnode_name: n\ntls_mode: managed\napi_public_endpoint: https://node.lan:8080\n" + extra
}

func TestManualIsTheDefaultAndManagedSettingsNeedManagedMode(t *testing.T) {
	cfg, err := Read(writeConfig(t, "version: 1\nnode_name: n\n"))
	if err != nil || cfg.TLSMode != TLSManual || cfg.APIPublicEndpoint != "" {
		t.Fatalf("default: %+v %v", cfg, err)
	}
	if _, err := Read(writeConfig(t, "version: 1\nnode_name: n\napi_public_endpoint: https://node.lan:8080\n")); err == nil {
		t.Fatal("api_public_endpoint was accepted without managed mode")
	}
	if _, err := Read(writeConfig(t, "version: 1\nnode_name: n\ntls_mode: automatic\n")); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
}

func TestManagedModeNeedsAnHTTPSEndpointAndRefusesHandMadeTLSFiles(t *testing.T) {
	cfg, err := Read(writeConfig(t, managedBody("")))
	if err != nil || cfg.TLSMode != TLSManaged || cfg.APIPublicEndpoint != "https://node.lan:8080" {
		t.Fatalf("managed: %+v %v", cfg, err)
	}
	for name, body := range map[string]string{
		"no endpoint":        "version: 1\nnode_name: n\ntls_mode: managed\n",
		"http endpoint":      "version: 1\nnode_name: n\ntls_mode: managed\napi_public_endpoint: http://node.lan:8080\n",
		"endpoint with path": "version: 1\nnode_name: n\ntls_mode: managed\napi_public_endpoint: https://node.lan:8080/api\n",
		"endpoint with user": "version: 1\nnode_name: n\ntls_mode: managed\napi_public_endpoint: https://user@node.lan:8080\n",
		"hand-made cert":     managedBody("api_tls_cert_file: /x\napi_tls_key_file: /y\n"),
		"client CA":          managedBody("api_tls_client_ca_file: /z\n"),
	} {
		if _, err := Read(writeConfig(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAManagedNodeDoesNotNeedTheSharedTokenButAManualOneDoes(t *testing.T) {
	t.Setenv("JOLT_STATE_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("CONTROL_TOWER_TOKEN", "")
	if _, err := Load(writeConfig(t, "version: 1\nnode_name: n\n")); err == nil {
		t.Fatal("a manual node started without CONTROL_TOWER_TOKEN")
	}
	t.Setenv("JOLT_JOIN_TOKEN", "jolt-join:v1:x")
	if _, err := Load(writeConfig(t, "version: 1\nnode_name: n\n")); err == nil || !strings.Contains(err.Error(), "JOLT_JOIN_TOKEN") {
		t.Fatalf("a join token on a manual node: %v", err)
	}
	cfg, err := Load(writeConfig(t, managedBody("")))
	if err != nil || cfg.JoinToken != "jolt-join:v1:x" || cfg.ControlTowerToken != "" {
		t.Fatalf("managed node: %+v %v", cfg, err)
	}
}
