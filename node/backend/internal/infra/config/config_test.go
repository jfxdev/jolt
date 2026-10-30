package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
