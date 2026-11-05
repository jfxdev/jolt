package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

// Optional real-process contract test. It creates only temporary state and
// requires a separately built node binary and access to loopback ports.
func TestSignedCopyAgainstNodeProcess(t *testing.T) {
	binary := os.Getenv("JOLT_SIGNED_COPY_NODE_BINARY")
	if binary == "" {
		t.Skip("set JOLT_SIGNED_COPY_NODE_BINARY to a node binary")
	}
	freePort := func() int {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		return port
	}
	root := t.TempDir()
	mount := filepath.Join(root, "files")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, "source"), []byte("private test data"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	apiPort, mtlsPort := freePort(), freePort()
	address := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	token := strings.Repeat("a", 64)
	configuration := fmt.Sprintf("version: 1\nnode_name: copy-test\napi_address: %q\nmtls_address: %q\nmtls_public_endpoint: %q\ndata_dir: %q\nkeys_dir: %q\nauthorization_public_keys:\n  - id: key\n    key: %q\nmounts:\n  - id: files\n    name: Files\n    local_path: %q\n    mode: read_write\n    published: true\n    enabled: true\ntransfer_grants: []\n", fmt.Sprintf("127.0.0.1:%d", apiPort), fmt.Sprintf("127.0.0.1:%d", mtlsPort), fmt.Sprintf("https://127.0.0.1:%d", mtlsPort), filepath.Join(root, "state"), filepath.Join(root, "keys"), public, mount)
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
	startNode := func() *exec.Cmd {
		t.Helper()
		command := exec.Command(binary, "--config", configPath)
		command.Env = processEnv
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := startNode()
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	client := &http.Client{Timeout: 3 * time.Second}
	waitNode := func() string {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			r, _ := http.NewRequest(http.MethodGet, address+"/api/v1/node", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			response, err := client.Do(r)
			if err == nil {
				var info struct {
					NodeID string `json:"node_id"`
				}
				if response.StatusCode == http.StatusOK {
					_ = json.NewDecoder(response.Body).Decode(&info)
				}
				response.Body.Close()
				if info.NodeID != "" {
					return info.NodeID
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("node did not become ready")
		return ""
	}
	nodeID := waitNode()
	var loseFirst atomic.Bool
	loseFirst.Store(true)
	transport := &http.Client{Timeout: 5 * time.Second, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := http.DefaultTransport.RoundTrip(r)
		if err == nil && r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs/signed-local-copy" && loseFirst.CompareAndSwap(true, false) {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			return nil, errors.New("simulated lost response after node acceptance")
		}
		return response, err
	})}
	ctx, now := context.Background(), time.Now().UTC()
	controlFile := filepath.Join(root, "control.db")
	storage, err := store.Open(controlFile, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	if err := storage.CreateUser(ctx, store.User{ID: "admin", Username: "admin", PasswordHash: "unused", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session := "real-process-test-session"
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
	s := &Server{store: storage, client: transport, config: config.Config{EncryptionKey: make([]byte, 32), AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodPost, "/", session, nil))
	if request == nil {
		t.Fatal("session was not authenticated")
	}
	input := store.SignedCopyRequest{MountID: "files", Source: "source", Destination: "destination"}
	if _, err := s.createSignedLocalCopy(request, nodeID, "request", input); err == nil {
		t.Fatal("lost response was reported as success")
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = store.Open(controlFile, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.store = storage
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	command = startNode()
	if restartedID := waitNode(); restartedID != nodeID {
		t.Fatalf("node identity changed after restart: %s", restartedID)
	}
	jobID, err := s.createSignedLocalCopy(request, nodeID, "request", input)
	if err != nil || jobID == "" {
		t.Fatalf("recovery job=%q err=%v", jobID, err)
	}
	node, err := storage.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := s.stageSignedLocalJobLease(request, nodeID, jobID); err != nil || revision != 1 {
		t.Fatalf("stage revision=%d err=%v", revision, err)
	}
	if state, err := s.deliverPendingSignedJobLease(request, nodeID, jobID); err != nil || state != signedJobConfirmed {
		t.Fatalf("delivery state=%v err=%v", state, err)
	}
	status, err := s.signedJobStatus(request, node, jobID)
	if err != nil || status.Revision != 1 {
		t.Fatalf("node status=%+v err=%v", status, err)
	}
	var actual signedLocalJob
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/"+jobID, nil, &actual, ""); err != nil || actual.State != "waiting_validation" {
		t.Fatalf("node job=%+v err=%v", actual, err)
	}
	if _, err := os.Stat(filepath.Join(mount, "destination")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("job executed without runtime enforcement: %v", err)
	}
}
