package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"io"
	"log/slog"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	handler, _ := testComponents(t)
	return handler
}

func testComponents(t *testing.T) (http.Handler, *jobs.Service) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config.Config{ControlTowerToken: "secret", PublicHealth: true, NodeName: "test", APIAddress: ":0", MTLSAddress: ":0"}
	identity := entities.Identity{NodeID: "node", Fingerprint: "AA:BB"}
	files := filesystem.New(store)
	jobService := jobs.New(store, files)
	return New(cfg, identity, files, jobService, pairing.New(store, identity), grants.New(store, files), slog.New(slog.NewTextHandler(io.Discard, nil))), jobService
}

func TestTextEditorContentIsLimitedTo512KB(t *testing.T) {
	handler := testHandler(t)
	mountPath := t.TempDir()
	create := httptest.NewRequest(http.MethodPost, "/api/v1/mounts", strings.NewReader(
		`{"name":"editor","local_path":"`+mountPath+`","mode":"read_write"}`))
	create.Header.Set("Authorization", "Bearer secret")
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create mount status=%d body=%s", created.Code, created.Body.String())
	}
	var mount entities.Mount
	if err := json.Unmarshal(created.Body.Bytes(), &mount); err != nil {
		t.Fatal(err)
	}

	call := func(method, path string, body io.Reader) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, body)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	tooLarge := strings.Repeat("a", 512*1024+1)
	upload := call(http.MethodPut,
		"/api/v1/mounts/"+mount.ID+"/files/content?path=note.txt&editor=true&overwrite=true", strings.NewReader(tooLarge))
	if upload.Code != http.StatusRequestEntityTooLarge || !strings.Contains(upload.Body.String(), "editor_content_too_large") {
		t.Fatalf("upload status=%d body=%s", upload.Code, upload.Body.String())
	}

	if err := os.WriteFile(filepath.Join(mountPath, "large.txt"), []byte(tooLarge), 0o600); err != nil {
		t.Fatal(err)
	}
	download := call(http.MethodGet,
		"/api/v1/mounts/"+mount.ID+"/files/content?path=large.txt&editor=true", nil)
	if download.Code != http.StatusRequestEntityTooLarge || !strings.Contains(download.Body.String(), "editor_content_too_large") {
		t.Fatalf("download status=%d body=%s", download.Code, download.Body.String())
	}
}

func TestRevokePeerAPIBlocksTrust(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	identity := entities.Identity{NodeID: "node", Fingerprint: "AA:BB"}
	files := filesystem.New(store)
	jobService := jobs.New(store, files)
	pairingService := pairing.New(store, identity)
	invite, token, err := pairingService.CreateInvite(context.Background(), pairing.InviteInput{
		TargetNodeID: "peer", TransferMode: "dual_channel",
		IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairingService.ApproveInvite(context.Background(), invite.ID, pairing.ApproveInviteInput{
		InviteToken: token, PeerNodeID: "peer", PeerName: "Peer", PeerFingerprint: "CC:DD",
		PeerEndpoint: "https://peer.test", PeerMTLSEndpoint: "https://peer.test:8443",
	}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{ControlTowerToken: "secret", PublicHealth: true, NodeName: "test", APIAddress: ":0", MTLSAddress: ":0"}
	handler := New(cfg, identity, files, jobService, pairingService, grants.New(store, files),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	updateRequest := httptest.NewRequest(http.MethodPatch, "/api/v1/peers/peer",
		strings.NewReader(`{"endpoint":"http://peer-new.test:8080/","mtls_endpoint":"https://peer-new.test:8443/"}`))
	updateRequest.Header.Set("Authorization", "Bearer secret")
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	handler.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK ||
		!strings.Contains(updateResponse.Body.String(), `"endpoint":"http://peer-new.test:8080"`) ||
		!strings.Contains(updateResponse.Body.String(), `"state":"unknown"`) {
		t.Fatalf("update status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/peers/peer", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Correlation-ID", "cor-api-revoke")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"revoked"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	peer, err := store.GetPeer(context.Background(), "peer")
	if err != nil || peer.State != "revoked" || peer.CorrelationID != "cor-api-revoke" {
		t.Fatalf("peer=%+v err=%v", peer, err)
	}
}

func TestOperationalTokenRotationHasSafeTwoPhaseCutover(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := config.Config{ControlTowerToken: "old-operational-token-with-at-least-32-characters", PublicHealth: false, NodeName: "test"}
	identity := entities.Identity{NodeID: "node", Fingerprint: "AA:BB"}
	files := filesystem.New(store)
	jobService := jobs.New(store, files)
	handler := New(cfg, identity, files, jobService, pairing.New(store, identity), grants.New(store, files),
		slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	const newToken = "new-operational-token-with-at-least-32-characters"
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := call(http.MethodPost, "/api/v1/crypto/operational-token/prepare",
		cfg.ControlTowerToken, `{"new_token":"`+cfg.ControlTowerToken+`"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("unchanged token status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/api/v1/crypto/operational-token/prepare",
		cfg.ControlTowerToken, `{"new_token":"`+newToken+`"}`); response.Code != http.StatusAccepted {
		t.Fatalf("prepare status=%d body=%s", response.Code, response.Body.String())
	}
	for _, token := range []string{cfg.ControlTowerToken, newToken} {
		if response := call(http.MethodGet, "/api/v1/node", token, ""); response.Code != http.StatusOK {
			t.Fatalf("staged token rejected: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if response := call(http.MethodPost, "/api/v1/crypto/operational-token/commit",
		newToken, ""); response.Code != http.StatusOK {
		t.Fatalf("commit status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/api/v1/node", cfg.ControlTowerToken, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("old token remained valid: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/api/v1/node", newToken, ""); response.Code != http.StatusOK {
		t.Fatalf("new token rejected after commit: status=%d body=%s", response.Code, response.Body.String())
	}
	state, err := store.GetOperationalTokenState(context.Background())
	if err != nil || !state.EnvTokenDisabled || state.ActiveHash == "" || state.ActiveHash == newToken ||
		state.StagedHash != "" {
		t.Fatalf("unsafe token state=%+v err=%v", state, err)
	}
}

func TestMTLSCertificateLifecycleAPI(t *testing.T) {
	dataDir, keysDir := t.TempDir(), t.TempDir()
	store, err := db.Open(filepath.Join(dataDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	identity, err := joltcrypto.LoadOrCreate(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := joltcrypto.LoadOrCreateCertificateManager(keysDir, identity, store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		ControlTowerToken: "secret", PublicHealth: true, NodeName: "test",
		APIAddress: ":0", MTLSAddress: ":0", KeysDir: keysDir,
	}
	files := filesystem.New(store, keysDir, dataDir)
	jobService := jobs.New(store, files)
	handler := New(cfg, identity, files, jobService, pairing.New(store, identity), grants.New(store, files), slog.New(slog.NewTextHandler(io.Discard, nil)), manager)

	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer secret")
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	status := call(http.MethodGet, "/api/v1/crypto/mtls", "")
	if status.Code != http.StatusOK || strings.Contains(status.Body.String(), "PRIVATE KEY") {
		t.Fatalf("unsafe or failed status response: code=%d body=%s", status.Code, status.Body.String())
	}
	rotate := call(http.MethodPost, "/api/v1/crypto/mtls/rotate", `{"validity_days":2}`)
	if rotate.Code != http.StatusCreated {
		t.Fatalf("rotate code=%d body=%s", rotate.Code, rotate.Body.String())
	}
	promote := call(http.MethodPost, "/api/v1/crypto/mtls/promote", `{"grace_hours":2}`)
	if promote.Code != http.StatusOK {
		t.Fatalf("promote code=%d body=%s", promote.Code, promote.Body.String())
	}
	rollback := call(http.MethodPost, "/api/v1/crypto/mtls/rollback", "")
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback code=%d body=%s", rollback.Code, rollback.Body.String())
	}
	promote = call(http.MethodPost, "/api/v1/crypto/mtls/promote", `{"grace_hours":2}`)
	if promote.Code != http.StatusOK {
		t.Fatalf("promote after rollback code=%d body=%s", promote.Code, promote.Body.String())
	}
	previous := manager.Snapshot().Previous
	revoke := call(http.MethodPost, "/api/v1/crypto/mtls/revoke", `{"serial":"`+previous.Serial+`","reason":"retired"}`)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke code=%d body=%s", revoke.Code, revoke.Body.String())
	}
	identityState := call(http.MethodGet, "/api/v1/crypto/identity", "")
	if identityState.Code != http.StatusOK ||
		!strings.Contains(identityState.Body.String(), identity.Fingerprint) ||
		strings.Contains(identityState.Body.String(), "private_key") {
		t.Fatalf("identity state code=%d body=%s", identityState.Code, identityState.Body.String())
	}
	rejectedIdentity := call(http.MethodPost, "/api/v1/crypto/identity/rotate",
		`{"confirmed_fingerprint":"WRONG"}`)
	if rejectedIdentity.Code != http.StatusConflict {
		t.Fatalf("identity mismatch code=%d body=%s", rejectedIdentity.Code, rejectedIdentity.Body.String())
	}
	rotateIdentity := call(http.MethodPost, "/api/v1/crypto/identity/rotate",
		`{"confirmed_fingerprint":"`+identity.Fingerprint+`"}`)
	if rotateIdentity.Code != http.StatusAccepted ||
		!strings.Contains(rotateIdentity.Body.String(), `"restart_required":true`) ||
		strings.Contains(rotateIdentity.Body.String(), "private_key") {
		t.Fatalf("identity rotation code=%d body=%s", rotateIdentity.Code, rotateIdentity.Body.String())
	}
}

func TestJobEventStreamResumesAfterLastEventID(t *testing.T) {
	handler, jobService := testComponents(t)
	job, _, err := jobService.CreateInline(context.Background(), jobs.CreateRequest{
		Type: "upload", MountID: "mount", Destination: "movie.bin", CorrelationID: "cor-test",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := jobService.Complete(context.Background(), &job, 1024, nil); err != nil {
		t.Fatal(err)
	}
	events, err := jobService.ListEvents(context.Background(), 0, job.ID, 10)
	if err != nil || len(events) < 2 {
		t.Fatalf("events=%+v err=%v", events, err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/events?job_id="+job.ID, nil)
	requestContext, cancel := context.WithCancel(request.Context())
	request = request.WithContext(requestContext)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("Last-Event-ID", strconv.FormatInt(events[0].ID, 10))
	recorder := newStreamRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(done)
	}()
	select {
	case <-recorder.eventWritten:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("timed out waiting for SSE event")
	}
	cancel()
	<-done
	status, contentType, body := recorder.snapshot()
	if status != http.StatusOK || !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("status=%d content-type=%q", status, contentType)
	}
	var idLine, dataLine string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "id: ") {
			idLine = line
		}
		if strings.HasPrefix(line, "data: ") {
			dataLine = line
			break
		}
	}
	expectedID := "id: " + strconv.FormatInt(events[1].ID, 10)
	if idLine != expectedID || !strings.Contains(dataLine, `"job_id":"`+job.ID+`"`) {
		t.Fatalf("id=%q data=%q", idLine, dataLine)
	}
}

type streamRecorder struct {
	mu           sync.Mutex
	header       http.Header
	body         bytes.Buffer
	status       int
	eventWritten chan struct{}
	once         sync.Once
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{header: make(http.Header), eventWritten: make(chan struct{})}
}

func (r *streamRecorder) Header() http.Header { return r.header }

func (r *streamRecorder) WriteHeader(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = status
	}
}

func (r *streamRecorder) Write(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = http.StatusOK
	}
	written, err := r.body.Write(buffer)
	if bytes.Contains(r.body.Bytes(), []byte("\ndata: ")) || bytes.HasPrefix(r.body.Bytes(), []byte("data: ")) {
		r.once.Do(func() { close(r.eventWritten) })
	}
	return written, err
}

func (r *streamRecorder) Flush() {}

func (r *streamRecorder) snapshot() (int, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status, r.header.Get("Content-Type"), r.body.String()
}

func TestAPIRequiresToken(t *testing.T) {
	handler := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/node", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestHealthCanBePublic(t *testing.T) {
	handler := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestAPIAcceptsBearerToken(t *testing.T) {
	handler := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/node", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Correlation-ID") == "" {
		t.Fatal("missing correlation id")
	}
}
