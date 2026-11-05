package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// Large and paced so the job is still running when its authorization is
	// revoked: 2 MiB in 64 KiB chunks at 32 KiB/s takes over a minute.
	if err := os.WriteFile(filepath.Join(mount, "source"), bytes.Repeat([]byte("private test data\n"), (2<<20)/18+1), 0o600); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	apiPort, mtlsPort := freePort(), freePort()
	address := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	token := strings.Repeat("a", 64)
	configuration := fmt.Sprintf("version: 1\nnode_name: copy-test\ncopy_chunk_size_bytes: 65536\napi_address: %q\nmtls_address: %q\nmtls_public_endpoint: %q\ndata_dir: %q\nkeys_dir: %q\nauthorization_public_keys:\n  - id: key\n    key: %q\nmounts:\n  - id: files\n    name: Files\n    local_path: %q\n    mode: read_write\n    published: true\n    enabled: true\ntransfer_grants: []\n", fmt.Sprintf("127.0.0.1:%d", apiPort), fmt.Sprintf("127.0.0.1:%d", mtlsPort), fmt.Sprintf("https://127.0.0.1:%d", mtlsPort), filepath.Join(root, "state"), filepath.Join(root, "keys"), public, mount)
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
	s := &Server{store: storage, client: transport, log: slog.New(slog.NewTextHandler(io.Discard, nil)), config: config.Config{EncryptionKey: make([]byte, 32), AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodPost, "/", session, nil))
	if request == nil {
		t.Fatal("session was not authenticated")
	}
	input := store.SignedCopyRequest{MountID: "files", Source: "source", Destination: "destination", BandwidthLimit: 32 << 10}
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
	if err := s.renewSignedLocalJob(ctx, nodeID, jobID); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	status, err = s.signedJobStatus(request, node, jobID)
	if err != nil || status.Revision != 2 {
		t.Fatalf("renewed node status=%+v err=%v", status, err)
	}
	type nodeJob struct {
		State string `json:"state"`
		Phase string `json:"phase"`
		Error string `json:"error"`
	}
	waitJob := func(timeout time.Duration, done func(nodeJob) bool) nodeJob {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for {
			var current nodeJob
			if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/"+jobID, nil, &current, ""); err == nil && done(current) {
				return current
			}
			if time.Now().After(deadline) {
				var mounts json.RawMessage
				_ = s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/mounts", nil, &mounts, "")
				var events json.RawMessage
				_ = s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/events?job_id="+jobID, nil, &events, "")
				t.Fatalf("job did not reach the expected state: %+v mounts=%s events=%s", current, mounts, events)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	waitJob(15*time.Second, func(j nodeJob) bool { return j.State == "running" && j.Phase == "transfer" })
	// The renewal loop keeps a running job authorized.
	s.renewActiveSignedJobs(ctx)
	if status, err = s.signedJobStatus(request, node, jobID); err != nil || status.Revision != 3 {
		t.Fatalf("loop renewal status=%+v err=%v", status, err)
	}
	// The same flow through the public route: a small copy runs to completion
	// and its link stops being renewed once the job is final.
	if err := os.WriteFile(filepath.Join(mount, "small.txt"), []byte("routed copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, handler := newServerHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalJobs: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), transport)
	routed := httptest.NewRecorder()
	routedRequest := authenticatedRequest(http.MethodPost, "/api/v1/nodes/"+nodeID+"/mounts/files/files/copy", session, []byte(`{"source_path":"small.txt","destination_path":"routed.txt"}`))
	routedRequest.Header.Set("Idempotency-Key", "routed-copy")
	handler.ServeHTTP(routed, routedRequest)
	var routedJob nodeJob
	if routed.Code != http.StatusAccepted || json.Unmarshal(routed.Body.Bytes(), &routedJob) != nil || routedJob.State == "" {
		t.Fatalf("routed copy: %d %s", routed.Code, routed.Body)
	}
	var created struct {
		ID string `json:"job_id"`
	}
	_ = json.Unmarshal(routed.Body.Bytes(), &created)
	routedDeadline := time.Now().Add(20 * time.Second)
	for {
		var current nodeJob
		if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/"+created.ID, nil, &current, ""); err == nil && current.State == "completed" {
			break
		} else if err == nil && (current.State == "failed" || current.State == "canceled") || time.Now().After(routedDeadline) {
			t.Fatalf("routed job did not complete: %+v err=%v", current, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if got, err := os.ReadFile(filepath.Join(mount, "routed.txt")); err != nil || string(got) != "routed copy" {
		t.Fatalf("routed copy content=%q err=%v", got, err)
	}
	s.renewActiveSignedJobs(ctx)
	if active, err := storage.ListActiveJobAuthorizationLinks(ctx, 10); err != nil || len(active) != 1 || active[0].JobID != jobID {
		t.Fatalf("finished routed job is still renewed: %+v err=%v", active, err)
	}
	if err := storage.DeleteSession(ctx, security.Digest(session)); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	if err := s.renewSignedLocalJob(ctx, nodeID, jobID); err == nil {
		t.Fatal("revoked session renewed job")
	}
	s.renewActiveSignedJobs(ctx)
	// Revision 4 came from the loop pass that finished the routed job.
	if status, err = s.signedJobStatus(request, node, jobID); err != nil || status.Revision != 4 {
		t.Fatalf("revoked renewal changed node status=%+v err=%v", status, err)
	}
	// Without a renewal the lease lapses within 30 s and the running copy
	// stops, keeping its checkpoint and publishing nothing.
	stopped := waitJob(45*time.Second, func(j nodeJob) bool { return j.State == "waiting_validation" && j.Phase == "waiting_authorization" })
	if elapsed := time.Since(revoked); stopped.State == "" || elapsed > 40*time.Second {
		t.Fatalf("job stopped %v after revocation", elapsed)
	}
	if _, err := os.Stat(filepath.Join(mount, "destination")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked job published its destination: %v", err)
	}
}
