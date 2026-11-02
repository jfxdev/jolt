package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	"github.com/jfxdev/jolt/backend/internal/infra/metrics"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedResponseRecorder struct{ *httptest.ResponseRecorder }

func (w *signedResponseRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestSignedLocalReadsAndUnsupportedRoutes(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{"good.txt": "hello", "secret.pem": "secret", "blocked.lock": "blocked"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	files := filesystem.New(store)
	if _, err := files.SaveMount(context.Background(), entities.Mount{ID: "editor", Name: "editor", LocalPath: root, Mode: "read_write", Enabled: true, Published: true, CanaryPaths: []string{"secret.pem"}}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	identity := entities.Identity{NodeID: "node"}
	cfg := config.Config{ControlTowerToken: "secret", AuthorizationKeys: map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, SearchMaxResults: 200, SearchMaxEntries: 10000, SearchTimeout: 10 * time.Second, DiskUsageMaxEntries: 10000, DiskUsageTimeout: 10 * time.Second, ArchiveMaxEntries: 1000, ArchiveMaxBytes: 1 << 20}
	handler := New(cfg, identity, files, jobs.New(store, files), pairing.New(store, identity), grants.New(store, files), slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.NewRegistry())
	contextJSON := json.RawMessage(`{"version":1,"rules":[{"policy_id":"allow","path":"nodes/node/files/mounts/editor/**","capabilities":["list","read"]},{"policy_id":"hidden","path":"nodes/node/files/mounts/editor/**","capabilities":["deny","read"],"file_types":{"extensions":["pem"]}},{"policy_id":"visible","path":"nodes/node/files/mounts/editor/**","capabilities":["deny","read"],"file_types":{"extensions":["lock"]},"visibility":"visible"}]}`)
	sign := func(operation, mount, root string) string {
		now := time.Now().Unix()
		claims := signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 20, Context: contextJSON, Binding: signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: operation, RequestID: "request", SourceNodeID: "node", SourceMountID: mount, SourceRoot: root}}
		token, err := signedauth.Sign(claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	call := func(method, target, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Header.Set("Authorization", "Bearer secret")
		if token != "" {
			r.Header.Set(signedAuthorizationHeader, token)
		}
		w := &signedResponseRecorder{httptest.NewRecorder()}
		handler.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	if node := call("GET", "/api/v1/node", ""); node.Code != 200 || !strings.Contains(node.Body.String(), "signed_local_read_v1") || !strings.Contains(node.Body.String(), "signed_local_tree_read_v1") {
		t.Fatalf("configured node capability: %d %s", node.Code, node.Body)
	}
	list := call("GET", "/api/v1/mounts/editor/files", sign("list", "editor", "."))
	if list.Code != 200 || list.Header().Get("X-Jolt-Access-Applied") != "v1" || strings.Contains(list.Body.String(), "secret.pem") || !strings.Contains(list.Body.String(), "good.txt") || !strings.Contains(list.Body.String(), `"blocked":true`) {
		t.Fatalf("list %d %s", list.Code, list.Body)
	}
	for _, tc := range []struct {
		operation, target, root string
		want                    int
	}{
		{"metadata", "/api/v1/mounts/editor/files/metadata?path=secret.pem", "secret.pem", 404},
		{"content", "/api/v1/mounts/editor/files/content?path=secret.pem", "secret.pem", 404},
		{"content", "/api/v1/mounts/editor/files/content?path=blocked.lock", "blocked.lock", 403},
		{"content", "/api/v1/mounts/editor/files/content?path=good.txt", "good.txt", 200},
		{"content", "/api/v1/mounts/editor/files/content?path=good.txt", "secret.pem", 403},
		{"metadata", "/api/v1/mounts/editor/files/content?path=good.txt", "good.txt", 403},
	} {
		w := call("GET", tc.target, sign(tc.operation, "editor", tc.root))
		if w.Code != tc.want {
			t.Fatalf("%s: %d want %d %s", tc.target, w.Code, tc.want, w.Body)
		}
	}
	hidden := call("GET", "/api/v1/mounts/editor/files/content?path=secret.pem", sign("content", "editor", "secret.pem"))
	missing := call("GET", "/api/v1/mounts/editor/files/content?path=missing.pem", sign("content", "editor", "missing.pem"))
	var hiddenPayload, missingPayload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(hidden.Body.Bytes(), &hiddenPayload) != nil || json.Unmarshal(missing.Body.Bytes(), &missingPayload) != nil || hidden.Code != 404 || missing.Code != 404 || hiddenPayload.Error != missingPayload.Error {
		t.Fatalf("hidden response differs from missing: %s vs %s", hidden.Body, missing.Body)
	}
	canaryRequest := httptest.NewRequest(http.MethodGet, "/api/v1/mounts/editor/files/content?path=secret.pem", nil)
	canaryRequest.Header.Set("Authorization", "Bearer secret")
	canaryRequest.Header.Set(signedAuthorizationHeader, sign("content", "editor", "secret.pem"))
	canaryRequest.Header.Set("X-Jolt-Internal-Canary", "1")
	canaryResponse := &signedResponseRecorder{httptest.NewRecorder()}
	handler.ServeHTTP(canaryResponse, canaryRequest)
	if canaryResponse.Code != 404 || canaryResponse.Header().Get("X-Jolt-Canary") != "1" {
		t.Fatalf("hidden canary: %d %s", canaryResponse.Code, canaryResponse.Body)
	}
	for _, route := range []string{"/api/v1/mounts/editor/files/uploads", "/api/v1/mounts/editor/files/archive/unknown", "/api/v1/jobs"} {
		if w := call("GET", route, sign("list", "editor", ".")); w.Code != 409 {
			t.Fatalf("unsupported %s: %d", route, w.Code)
		}
	}
	search := call("GET", "/api/v1/mounts/editor/files/search?path=.&query=.", sign("search", "editor", "."))
	if search.Code != 200 || strings.Contains(search.Body.String(), "secret.pem") || !strings.Contains(search.Body.String(), "good.txt") || !strings.Contains(search.Body.String(), `"blocked":true`) {
		t.Fatalf("filtered search: %d %s", search.Code, search.Body)
	}
	var searchCounts struct {
		Scanned int `json:"scanned"`
	}
	if err := json.Unmarshal(search.Body.Bytes(), &searchCounts); err != nil || searchCounts.Scanned != 2 {
		t.Fatalf("hidden entry leaked in search count: %+v %v", searchCounts, err)
	}
	usage := call("GET", "/api/v1/mounts/editor/files/disk-usage?path=.", sign("disk_usage", "editor", "."))
	if usage.Code != 200 || strings.Contains(usage.Body.String(), "secret.pem") || strings.Contains(usage.Body.String(), "blocked.lock") || !strings.Contains(usage.Body.String(), "good.txt") {
		t.Fatalf("filtered usage: %d %s", usage.Code, usage.Body)
	}
	var usageCounts struct {
		Scanned int `json:"scanned"`
	}
	if err := json.Unmarshal(usage.Body.Bytes(), &usageCounts); err != nil || usageCounts.Scanned != 1 {
		t.Fatalf("hidden entry leaked in usage count: %+v %v", usageCounts, err)
	}
	plan := call("GET", "/api/v1/mounts/editor/files/archive/plan?path=.", sign("archive_plan", "editor", "."))
	if plan.Code != 200 || !strings.Contains(plan.Body.String(), `"files":1`) {
		t.Fatalf("filtered archive plan: %d %s", plan.Code, plan.Body)
	}
	archive := call("GET", "/api/v1/mounts/editor/files/archive?path=.", sign("archive", "editor", "."))
	reader, err := zip.NewReader(bytes.NewReader(archive.Body.Bytes()), int64(archive.Body.Len()))
	if archive.Code != 200 || err != nil || len(reader.File) != 1 || reader.File[0].Name != "good.txt" {
		t.Fatalf("filtered archive: status=%d entries=%v error=%v", archive.Code, reader, err)
	}
	if w := call("GET", "/api/v1/mounts/editor/files/archive?path=.&name=secret.pem", sign("archive", "editor", ".")); w.Code != 404 {
		t.Fatalf("hidden archive selection: %d %s", w.Code, w.Body)
	}
	if w := call("GET", "/api/v1/mounts/editor/files/archive/plan?path=.", sign("archive", "editor", ".")); w.Code != 403 {
		t.Fatalf("archive token replayed for plan: %d %s", w.Code, w.Body)
	}
	if w := call("DELETE", "/api/v1/mounts/editor/files?path=good.txt", sign("list", "editor", ".")); w.Code != 409 {
		t.Fatalf("signed mutation was not refused: %d", w.Code)
	}
	if w := call("GET", "/api/v1/mounts/editor/files/content?path=%20good.txt", sign("content", "editor", "good.txt")); w.Code != 400 {
		t.Fatalf("ambiguous signed path was not refused: %d", w.Code)
	}
	if w := call("GET", "/api/v1/mounts/editor/files/content?path=secret.pem", ""); w.Code != 200 {
		t.Fatalf("legacy route: %d %s", w.Code, w.Body)
	}
	// Exercise the real net/http response writer and its write deadline through
	// the metrics wrapper, including Range requests.
	server := httptest.NewServer(handler)
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/mounts/editor/files/content?path=good.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set(signedAuthorizationHeader, sign("content", "editor", "good.txt"))
	req.Header.Set("Range", "bytes=0-1")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusPartialContent || string(data) != "he" || response.Header.Get("X-Jolt-Access-Applied") != "v1" {
		t.Fatalf("real HTTP range: status=%d body=%q err=%v", response.StatusCode, data, err)
	}
}

func TestSignedReadCapabilityRequiresConfiguredKeys(t *testing.T) {
	handler := testHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/node", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "signed_local_read_v1") || strings.Contains(w.Body.String(), "signed_local_tree_read_v1") {
		t.Fatalf("unconfigured node capability: %d %s", w.Code, w.Body)
	}
}

func TestSignedReadStopsWritesAtExpiry(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{identity: entities.Identity{NodeID: "node"}, config: config.Config{AuthorizationKeys: map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}}}
	now := time.Now().Unix()
	claims := signedauth.Claims{Version: 1, KeyID: "key", IssuedAt: now, ExpiresAt: now + 2, Context: json.RawMessage(`{"version":1,"rules":[]}`), Binding: signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "content", RequestID: "request", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "file"}}
	token, err := signedauth.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/mounts/mount/files/content?path=file", nil)
	request.SetPathValue("mountID", "mount")
	request.Header.Set(signedAuthorizationHeader, token)
	call := s.signedLocalRead("content", func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		if _, err := w.Write([]byte("must not be written")); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("write after expiry: %v", err)
		}
	})
	w := &signedResponseRecorder{httptest.NewRecorder()}
	func() {
		defer func() {
			if recovered := recover(); recovered != http.ErrAbortHandler {
				t.Errorf("expected aborted stream, got %v", recovered)
			}
		}()
		call(w, request)
	}()
	if w.Body.Len() != 0 {
		t.Fatalf("wrote after expiry: %q", w.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/mounts/mount/files/content?path=file", nil)
	request.SetPathValue("mountID", "mount")
	now = time.Now().Unix()
	claims.IssuedAt, claims.ExpiresAt = now, now+20
	token, err = signedauth.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(signedAuthorizationHeader, token)
	noDeadline := httptest.NewRecorder()
	call(noDeadline, request)
	if noDeadline.Code != http.StatusServiceUnavailable {
		t.Fatalf("writer without deadlines: %d", noDeadline.Code)
	}
}
