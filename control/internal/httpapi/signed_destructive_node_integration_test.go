package httpapi

import (
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
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

// Optional real-process test: a node binary and a Control Tower handler plan,
// confirm and run directory deletes and moves, and refuse the direct routes.
func TestDestructivePlansAgainstNodeProcess(t *testing.T) {
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
	root := t.TempDir()
	mount := filepath.Join(root, "files")
	write := func(name, content string) {
		t.Helper()
		target := filepath.Join(mount, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{"gone/a.txt": "alpha", "gone/sub/b.txt": "beta", "from/c.txt": "gamma", "stale/d.txt": "delta", "direct/e.txt": "epsilon", "loose.txt": "file"} {
		write(name, content)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	apiPort, mtlsPort := freePort(), freePort()
	address := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	token := strings.Repeat("b", 64)
	configuration := fmt.Sprintf("version: 1\nnode_name: plan-test\napi_address: %q\nmtls_address: %q\nmtls_public_endpoint: %q\ndata_dir: %q\nkeys_dir: %q\nauthorization_public_keys:\n  - id: key\n    key: %q\nmounts:\n  - id: files\n    name: Files\n    local_path: %q\n    mode: read_write\n    published: true\n    enabled: true\ntransfer_grants: []\n", fmt.Sprintf("127.0.0.1:%d", apiPort), fmt.Sprintf("127.0.0.1:%d", mtlsPort), fmt.Sprintf("https://127.0.0.1:%d", mtlsPort), filepath.Join(root, "state"), filepath.Join(root, "keys"), base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), mount)
	configPath := filepath.Join(root, "node.yaml")
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	var processEnv []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "JOLT_") && !strings.HasPrefix(value, "CONTROL_TOWER_") {
			processEnv = append(processEnv, value)
		}
	}
	processEnv = append(processEnv, "CONTROL_TOWER_TOKEN="+token, "JOLT_STATE_ENCRYPTION_KEY="+base64.StdEncoding.EncodeToString(make([]byte, 32)))
	command := exec.Command(binary, "--config", configPath)
	command.Env = processEnv
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	client := &http.Client{Timeout: 5 * time.Second}
	nodeID := ""
	for deadline := time.Now().Add(15 * time.Second); nodeID == "" && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		r, _ := http.NewRequest(http.MethodGet, address+"/api/v1/node", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if response, err := client.Do(r); err == nil {
			var info struct {
				NodeID string `json:"node_id"`
			}
			if response.StatusCode == http.StatusOK {
				_ = json.NewDecoder(response.Body).Decode(&info)
			}
			response.Body.Close()
			nodeID = info.NodeID
		}
	}
	if nodeID == "" {
		t.Fatal("node did not become ready")
	}
	ctx, now := context.Background(), time.Now().UTC()
	storage, err := store.Open(filepath.Join(root, "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	if err := storage.CreateUser(ctx, store.User{ID: "admin", Username: "admin", PasswordHash: "unused", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session := "destructive-plan-test-session"
	if err := storage.CreateSession(ctx, security.Digest(session), "admin", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	encrypted, err := security.Encrypt(make([]byte, 32), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(ctx, store.Node{ID: nodeID, Name: "real node", Endpoint: address, TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	server, handler := newServerHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalJobs: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	node, err := storage.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/nodes/" + nodeID + "/mounts/files/files"
	call := func(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		r := authenticatedRequest(method, path, session, encoded)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	waitJob := func(id string) (state, message string) {
		t.Helper()
		for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			var current struct {
				State string `json:"state"`
				Error string `json:"error"`
			}
			if err := server.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/"+id, nil, &current, ""); err == nil && (current.State == "completed" || current.State == "failed" || current.State == "canceled") {
				return current.State, current.Error
			}
		}
		t.Fatalf("job %s did not finish", id)
		return "", ""
	}
	type plan struct {
		ID    string `json:"plan_id"`
		Token string `json:"token"`
		Files int64  `json:"files"`
	}
	makePlan := func(body map[string]any) plan {
		t.Helper()
		w := call(http.MethodPost, base+"/destructive-plans", body, nil)
		var created plan
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.ID == "" || created.Token == "" {
			t.Fatalf("plan %v: %d %s", body, w.Code, w.Body)
		}
		return created
	}
	confirm := func(p plan, token, key string) *httptest.ResponseRecorder {
		return call(http.MethodPost, base+"/destructive-plans/"+p.ID+"/confirm", map[string]any{"token": token}, map[string]string{"Idempotency-Key": key})
	}
	jobID := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var job struct {
			ID string `json:"job_id"`
		}
		if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &job) != nil || job.ID == "" {
			t.Fatalf("confirm: %d %s", w.Code, w.Body)
		}
		return job.ID
	}

	// Directories cannot take the direct routes; files still can.
	if w := call(http.MethodDelete, base+"?path=direct&recursive=true", nil, nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "plan_required") {
		t.Fatalf("direct recursive delete of a directory: %d %s", w.Code, w.Body)
	}
	if w := call(http.MethodPost, base+"/move", map[string]any{"source_path": "direct", "destination_path": "elsewhere"}, nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "plan_required") {
		t.Fatalf("direct move of a directory: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(mount, "direct/e.txt")); err != nil {
		t.Fatalf("a refused request changed the tree: %v", err)
	}
	if w := call(http.MethodDelete, base+"?path=loose.txt", nil, nil); w.Code != http.StatusAccepted {
		t.Fatalf("direct delete of a file: %d %s", w.Code, w.Body)
	}

	// Delete: plan, wrong token, confirmation, run.
	deletion := makePlan(map[string]any{"operation": "delete", "source_path": "gone"})
	if deletion.Files != 2 {
		t.Fatalf("plan counted %d files", deletion.Files)
	}
	if w := confirm(deletion, "not-the-token", "k-wrong"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong token: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(mount, "gone/a.txt")); err != nil {
		t.Fatalf("a rejected confirmation changed the tree: %v", err)
	}
	confirmed := confirm(deletion, deletion.Token, "k-delete")
	id := jobID(confirmed)
	if state, message := waitJob(id); state != "completed" {
		t.Fatalf("delete job %s: %s", state, message)
	}
	if _, err := os.Stat(filepath.Join(mount, "gone")); !os.IsNotExist(err) {
		t.Fatalf("confirmed tree still present: %v", err)
	}
	if again := confirm(deletion, deletion.Token, "k-delete"); jobID(again) != id {
		t.Fatalf("repeated confirmation created another job: %s", again.Body)
	}
	if w := confirm(deletion, deletion.Token, "k-other"); w.Code < 400 {
		t.Fatalf("a consumed plan was reused: %d %s", w.Code, w.Body)
	}

	// Move.
	moving := makePlan(map[string]any{"operation": "move", "source_path": "from", "destination_path": "moved"})
	moved := jobID(confirm(moving, moving.Token, "k-move"))
	if state, message := waitJob(moved); state != "completed" {
		t.Fatalf("move job %s: %s", state, message)
	}
	if got, err := os.ReadFile(filepath.Join(mount, "moved/c.txt")); err != nil || string(got) != "gamma" {
		t.Fatalf("moved content %q %v", got, err)
	}

	// A tree that changed after the plan is refused and left alone.
	stale := makePlan(map[string]any{"operation": "delete", "source_path": "stale"})
	write("stale/new.txt", "added after the plan")
	if w := confirm(stale, stale.Token, "k-stale"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "tree_changed") {
		t.Fatalf("changed tree: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(mount, "stale/d.txt")); err != nil {
		t.Fatalf("a changed tree was deleted: %v", err)
	}

	// Finished jobs stop being renewed.
	server.renewActiveSignedJobs(ctx)
	if active, err := storage.ListActiveJobAuthorizationLinks(ctx, 10); err != nil || len(active) != 0 {
		t.Fatalf("finished jobs still renewed: %+v %v", active, err)
	}
}
