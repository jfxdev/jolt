package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func TestSignedLocalCopyOperationalCreation(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	root := t.TempDir()
	files := filesystem.New(storage)
	if _, err := files.SaveMount(context.Background(), entities.Mount{ID: "mount", Name: "mount", LocalPath: root, Mode: "read_write", Enabled: true, Published: true}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	var logs bytes.Buffer
	handler := New(config.Config{ControlTowerToken: "secret", AuthorizationKeys: keys}, entities.Identity{NodeID: "node"}, files, jobs.New(storage, files), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)), storage)
	preparePath, createPath := "/api/v1/jobs/signed-local-copy/prepare", "/api/v1/jobs/signed-local-copy"
	body := `{"mount_id":"mount","source_path":"source","destination_path":"destination"}`
	call := func(path, body, bearer string, headers map[string][]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		for name, values := range headers {
			for _, value := range values {
				r.Header.Add(name, value)
			}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call(preparePath, body, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("without bearer: %d %s", w.Code, w.Body)
	}
	infoRequest := httptest.NewRequest(http.MethodGet, "/api/v1/node", nil)
	infoRequest.Header.Set("Authorization", "Bearer secret")
	info := httptest.NewRecorder()
	handler.ServeHTTP(info, infoRequest)
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), "signed_local_copy_creation_v1") {
		t.Fatalf("capability: %d %s", info.Code, info.Body)
	}
	withoutKeys := New(config.Config{ControlTowerToken: "secret"}, entities.Identity{NodeID: "node"}, files, jobs.New(storage, files), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)), storage)
	noKeysInfo := httptest.NewRecorder()
	withoutKeys.ServeHTTP(noKeysInfo, infoRequest)
	if strings.Contains(noKeysInfo.Body.String(), "signed_local_copy_creation_v1") {
		t.Fatal("capability advertised without signing keys")
	}
	noKeysRequest := httptest.NewRequest(http.MethodPost, preparePath, strings.NewReader(body))
	noKeysRequest.Header.Set("Authorization", "Bearer secret")
	noKeys := httptest.NewRecorder()
	withoutKeys.ServeHTTP(noKeys, noKeysRequest)
	if noKeys.Code != http.StatusServiceUnavailable {
		t.Fatalf("prepare without keys: %d %s", noKeys.Code, noKeys.Body)
	}
	for _, invalid := range []string{`{"mount_id":"mount","mount_id":"other"}`, body + `{}`, strings.Repeat("x", 64*1024+1), `{"unknown":true}`} {
		if w := call(preparePath, invalid, "secret", nil); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid body: %d %s", w.Code, w.Body)
		}
	}
	response := call(preparePath, body, "secret", nil)
	if response.Code != http.StatusOK || response.Header().Get("X-Jolt-Signed-Job-Preparation") != "v1" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("prepare: %d %s", response.Code, response.Body)
	}
	var prepared struct {
		Options   signedauth.JobOptions `json:"options"`
		Digest    string                `json:"options_digest"`
		Execution bool                  `json:"execution_enabled"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &prepared); err != nil || prepared.Execution || prepared.Digest != signedauth.JobOptionsDigest(prepared.Options) {
		t.Fatalf("preparation=%+v err=%v", prepared, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	binding := signedauth.Binding{ActorID: "private-actor", CredentialID: "private-credential", Operation: "copy_local", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "source", DestinationNodeID: "node", DestinationMountID: "mount", DestinationRoot: "destination", PlanID: "job", JobOptionsDigest: prepared.Digest}
	sign := func(b signedauth.Binding) string {
		t.Helper()
		b, err := signedauth.JobLeaseBinding(b, 1)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := signedauth.Sign(signedauth.Claims{Version: 1, KeyID: "key", Binding: b, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[]}`)}, key)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	envelope := sign(binding)
	headers := map[string][]string{signedAuthorizationHeader: {envelope}, "Idempotency-Key": {"request"}}
	if w := call(preparePath, body, "secret", headers); w.Code != http.StatusConflict {
		t.Fatalf("signed prepare should be rejected: %d %s", w.Code, w.Body)
	}
	if w := call(createPath, body, "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("missing signed context: %d %s", w.Code, w.Body)
	}
	if w := call(createPath, body, "", headers); w.Code != http.StatusUnauthorized {
		t.Fatalf("creation without bearer: %d %s", w.Code, w.Body)
	}
	if w := call(createPath, body, "secret", map[string][]string{signedAuthorizationHeader: {envelope, envelope}, "Idempotency-Key": {"request"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate context: %d %s", w.Code, w.Body)
	}
	if w := call(createPath, strings.Replace(body, `"source"`, `"other"`, 1), "secret", headers); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong path: %d %s", w.Code, w.Body)
	}
	w := call(createPath, body, "secret", headers)
	if w.Code != http.StatusAccepted || w.Header().Get("X-Jolt-Signed-Job-Creation") != "v1" || !strings.Contains(w.Body.String(), `"execution_enabled":false`) || strings.Contains(w.Body.String(), envelope) || strings.Contains(w.Body.String(), "private-actor") {
		t.Fatalf("creation: %d %s", w.Code, w.Body)
	}
	if w := call(createPath, body, "secret", headers); w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	if w := call("/api/v1/jobs/job/authorization", "", "secret", headers); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revision":1`) {
		t.Fatalf("register authorization: %d %s", w.Code, w.Body)
	}
	if w := call(createPath, body, "secret", headers); w.Code != http.StatusOK {
		t.Fatalf("retry after registration: %d %s", w.Code, w.Body)
	}
	other := binding
	other.ActorID = "other"
	if w := call(createPath, body, "secret", map[string][]string{signedAuthorizationHeader: {sign(other)}, "Idempotency-Key": {"request"}}); w.Code != http.StatusConflict {
		t.Fatalf("other actor reused request: %d %s", w.Code, w.Body)
	}
	stored, err := storage.GetJob(context.Background(), "job")
	if err != nil || stored.State != "waiting_validation" || !stored.RequiresSignedAuth || !stored.SignedAuthBound || stored.SignedAuthActorID != binding.ActorID {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	if _, err := storage.ClaimNextJob(context.Background(), now); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("job executed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "destination")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination changed: %v", err)
	}
	if strings.Contains(logs.String(), envelope) || strings.Contains(logs.String(), "private-actor") {
		t.Fatal("private authorization leaked to logs")
	}
}
