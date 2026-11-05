package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

type realNode struct {
	name, root, mount, address, token, configPath string
	apiPort, mtlsPort                             int
	process                                       *exec.Cmd
	id                                            string
}

// Optional real-process test: two node binaries paired through the Control
// Tower plan, run and stop a signed node-to-node copy for a non-admin user.
// Entries hidden by file type are covered at the node level: the Control
// Tower's own authorization still refuses typed rules, so they cannot be
// exercised through it yet.
func TestSignedTransferAgainstTwoNodeProcesses(t *testing.T) {
	binary := os.Getenv("JOLT_SIGNED_COPY_NODE_BINARY")
	if binary == "" {
		t.Skip("set JOLT_SIGNED_COPY_NODE_BINARY to a node binary")
	}
	freePort := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	root := t.TempDir()
	newNode := func(name string, tokenByte string) *realNode {
		n := &realNode{name: name, root: filepath.Join(root, name), apiPort: freePort(), mtlsPort: freePort(), token: strings.Repeat(tokenByte, 64)}
		n.mount = filepath.Join(n.root, "files")
		if err := os.MkdirAll(n.mount, 0o700); err != nil {
			t.Fatal(err)
		}
		n.address = fmt.Sprintf("http://127.0.0.1:%d", n.apiPort)
		n.configPath = filepath.Join(n.root, "node.yaml")
		return n
	}
	source, destination := newNode("source", "a"), newNode("destination", "b")
	write := func(n *realNode, config string) {
		if err := os.WriteFile(n.configPath, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configuration := func(n *realNode, grants string) string {
		return fmt.Sprintf("version: 1\nnode_name: %s\ncopy_chunk_size_bytes: 65536\napi_address: %q\nmtls_address: %q\nmtls_public_endpoint: %q\ndata_dir: %q\nkeys_dir: %q\nauthorization_public_keys:\n  - id: key\n    key: %q\nmounts:\n  - id: files\n    name: Files\n    local_path: %q\n    mode: read_write\n    published: true\n    enabled: true\ntransfer_grants: %s\n",
			n.name, fmt.Sprintf("127.0.0.1:%d", n.apiPort), fmt.Sprintf("127.0.0.1:%d", n.mtlsPort), fmt.Sprintf("https://127.0.0.1:%d", n.mtlsPort),
			filepath.Join(n.root, "state"), filepath.Join(n.root, "keys"), public, n.mount, grants)
	}
	var environment []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "JOLT_") && !strings.HasPrefix(value, "CONTROL_TOWER_") {
			environment = append(environment, value)
		}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	start := func(n *realNode) {
		t.Helper()
		command := exec.Command(binary, "--config", n.configPath)
		command.Env = append(append([]string(nil), environment...), "CONTROL_TOWER_TOKEN="+n.token, "JOLT_STATE_ENCRYPTION_KEY="+base64.StdEncoding.EncodeToString(make([]byte, 32)))
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		n.process = command
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			r, _ := http.NewRequest(http.MethodGet, n.address+"/api/v1/node", nil)
			r.Header.Set("Authorization", "Bearer "+n.token)
			if response, err := client.Do(r); err == nil {
				var info struct {
					NodeID string `json:"node_id"`
				}
				if response.StatusCode == http.StatusOK {
					_ = json.NewDecoder(response.Body).Decode(&info)
				}
				response.Body.Close()
				if info.NodeID != "" {
					n.id = info.NodeID
					return
				}
			}
		}
		t.Fatalf("%s did not become ready", n.name)
	}
	stop := func(n *realNode) {
		_ = n.process.Process.Kill()
		_ = n.process.Wait()
	}
	// First start only to learn each node's identity; grants name the peer.
	write(source, configuration(source, "[]"))
	write(destination, configuration(destination, "[]"))
	start(source)
	start(destination)
	stop(source)
	stop(destination)
	write(source, configuration(source, fmt.Sprintf(`
  - {id: out, peer_node_id: %s, mount_id: files, path: ".", direction: send, permissions: {read: true}, visible_to_peer: true, enabled: true}`, destination.id)))
	write(destination, configuration(destination, fmt.Sprintf(`
  - {id: in, peer_node_id: %s, mount_id: files, path: ".", direction: receive, permissions: {write: true}, conflict_policies: [fail, overwrite, rename, skip, checksum], visible_to_peer: true, enabled: true}`, source.id)))
	idBefore := [2]string{source.id, destination.id}
	start(source)
	start(destination)
	if idBefore != [2]string{source.id, destination.id} {
		t.Fatal("a node changed identity across a restart")
	}

	ctx, now := context.Background(), time.Now().UTC()
	storage, err := store.Open(filepath.Join(root, "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	for _, user := range []store.User{
		{ID: "admin", Username: "admin", PasswordHash: "unused", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "operator", Username: "operator", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	sessions := map[string]string{"admin": "admin-session", "operator": "operator-session"}
	for user, session := range sessions {
		if err := storage.CreateSession(ctx, security.Digest(session), user, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []*realNode{source, destination} {
		encrypted, err := security.Encrypt(make([]byte, 32), n.token)
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.SaveNode(ctx, store.Node{ID: n.id, Name: n.name, Endpoint: n.address, TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	srcBase, dstBase := "nodes/"+source.id+"/files/mounts/files", "nodes/"+destination.id+"/files/mounts/files"
	policy := store.Policy{ID: "operator-transfer", Name: "operator-transfer", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/" + destination.id + "/transfers", Capabilities: []string{"execute", "create"}},
		{Path: srcBase + "/**", Capabilities: []string{"read", "list"}},
		{Path: dstBase + "/**", Capabilities: []string{"read", "list", "create", "update"}},
	}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "user", "operator", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	server, handler := newServerHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalJobs: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	call := func(user, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		r := authenticatedRequest(method, path, sessions[user], encoded)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	// Pair the nodes through the Control Tower, as an administrator would.
	paired := call("admin", http.MethodPost, "/api/v1/control-tower/connections", map[string]any{
		"issuer_node_id": source.id, "target_node_id": destination.id, "transfer_mode": "dual_channel", "issuer_role": "sender_receiver", "invitee_role": "sender_receiver",
	}, nil)
	var connection struct {
		Request struct {
			ID string `json:"id"`
		} `json:"request"`
		Status           string `json:"status"`
		TrustEstablished bool   `json:"trust_established"`
	}
	if paired.Code != http.StatusCreated || json.Unmarshal(paired.Body.Bytes(), &connection) != nil || !connection.TrustEstablished {
		t.Fatalf("pairing: %d %s", paired.Code, paired.Body)
	}

	content := func(name string) string {
		data, err := os.ReadFile(filepath.Join(destination.mount, name))
		if err != nil {
			return ""
		}
		return string(data)
	}
	put := func(n *realNode, name, data string) {
		target := filepath.Join(n.mount, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(source, "tree/public.txt", "public data")
	put(source, "tree/notes.md", "notes")
	put(source, "tree/deep/inner.txt", "inner data")
	body := func(selection string) map[string]any {
		return map[string]any{
			"operation":       "copy",
			"source":          map[string]any{"node_id": source.id, "mount_id": "files", "paths": []string{selection}},
			"destination":     map[string]any{"mount_id": "files", "path": ""},
			"conflict_policy": "fail",
		}
	}
	destinationNode, err := storage.GetNode(ctx, destination.id)
	if err != nil {
		t.Fatal(err)
	}
	waitJob := func(id string, timeout time.Duration, done func(state, phase string) bool) (state, phase, message string) {
		t.Helper()
		for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			var current struct {
				State string `json:"state"`
				Phase string `json:"phase"`
				Error string `json:"error"`
			}
			if err := server.callNodeJSON(ctx, destinationNode, http.MethodGet, "/api/v1/jobs/"+id, nil, &current, ""); err == nil && done(current.State, current.Phase) {
				return current.State, current.Phase, current.Error
			}
		}
		t.Fatalf("job %s did not reach the expected state", id)
		return "", "", ""
	}
	transfers := "/api/v1/nodes/" + destination.id + "/transfers"

	// The preview runs under the operator's own policy on the destination node.
	preview := call("operator", http.MethodPost, transfers+"/plan", body("tree"), nil)
	var previewBody struct {
		Plan struct {
			FilesTotal     int `json:"files_total"`
			SourcesOmitted int `json:"sources_omitted"`
		} `json:"plan"`
	}
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &previewBody) != nil || previewBody.Plan.FilesTotal != 3 || previewBody.Plan.SourcesOmitted != 0 {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body)
	}
	if direct := call("operator", http.MethodPost, "/api/v1/nodes/"+destination.id+"/transfers/pull/batch", map[string]any{}, nil); direct.Code != http.StatusConflict {
		t.Fatalf("direct pull: %d %s", direct.Code, direct.Body)
	}

	// The copy runs on the destination node under a renewed lease.
	created := call("operator", http.MethodPost, transfers, body("tree"), map[string]string{"Idempotency-Key": "copy-1"})
	var job struct {
		ID string `json:"job_id"`
	}
	if created.Code != http.StatusAccepted || json.Unmarshal(created.Body.Bytes(), &job) != nil || !strings.HasPrefix(job.ID, "xfer-") {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	state, _, message := waitJob(job.ID, 30*time.Second, func(state, _ string) bool {
		return state == "completed" || state == "completed_with_warnings" || state == "failed"
	})
	if state != "completed" {
		t.Fatalf("job %s: %s", state, message)
	}
	if content("tree/public.txt") != "public data" || content("tree/deep/inner.txt") != "inner data" || content("tree/notes.md") != "notes" {
		t.Fatal("the tree was not copied")
	}
	if retry := call("operator", http.MethodPost, transfers, body("tree"), map[string]string{"Idempotency-Key": "copy-1"}); retry.Header().Get("Location") != created.Header().Get("Location") {
		t.Fatalf("retry reached another job: %s", retry.Body)
	}
	server.renewActiveSignedJobs(ctx)
	if active, err := storage.ListActiveJobAuthorizationLinks(ctx, 10); err != nil || len(active) != 0 {
		t.Fatalf("a finished transfer is still renewed: %d %v", len(active), err)
	}

	// Revoking the operator's session stops a copy that is still running.
	put(source, "big.bin", string(bytes.Repeat([]byte("0123456789abcdef"), (2<<20)/16)))
	slow := body("big.bin")
	slow["bandwidth_limit_bytes_per_second"] = 32 << 10
	big := call("operator", http.MethodPost, transfers, slow, map[string]string{"Idempotency-Key": "copy-2"})
	if big.Code != http.StatusAccepted || json.Unmarshal(big.Body.Bytes(), &job) != nil {
		t.Fatalf("create slow: %d %s", big.Code, big.Body)
	}
	waitJob(job.ID, 20*time.Second, func(state, phase string) bool { return state == "running" && phase == "transfer" })
	server.renewActiveSignedJobs(ctx) // a renewal keeps it alive
	if err := storage.DeleteSession(ctx, security.Digest(sessions["operator"])); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	server.renewActiveSignedJobs(ctx) // refused: the session is gone
	waitJob(job.ID, 45*time.Second, func(state, phase string) bool {
		return state == "waiting_validation" && phase == "waiting_authorization"
	})
	if elapsed := time.Since(revoked); elapsed > 40*time.Second {
		t.Fatalf("the copy stopped %v after the revocation", elapsed)
	}
	if _, err := os.Stat(filepath.Join(destination.mount, "big.bin")); !os.IsNotExist(err) {
		t.Fatalf("a revoked copy published its destination: %v", err)
	}
}
