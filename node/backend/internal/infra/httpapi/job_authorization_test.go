package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func TestJobAuthorizationEndpointVerifiesAndPersistsWithoutExecuting(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job := entities.Job{ID: "job", Type: "copy_local", State: "queued", MountID: "mount", SourcePath: "source", Destination: "destination", CreatedAt: now, UpdatedAt: now}
	if _, _, err := storage.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	identity := entities.Identity{NodeID: "node"}
	files := filesystem.New(storage)
	var logs bytes.Buffer
	h := New(config.Config{ControlTowerToken: "secret", AuthorizationKeys: keys}, identity, files, jobs.New(storage, files), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)), storage)
	binding := signedauth.Binding{ActorID: "private-actor", CredentialID: "private-credential", Operation: job.Type, SourceNodeID: "node", SourceMountID: job.MountID, SourceRoot: job.SourcePath, DestinationNodeID: "node", DestinationMountID: job.MountID, DestinationRoot: job.Destination, PlanID: job.ID}
	sign := func(b signedauth.Binding, revision uint64, issued time.Time) string {
		t.Helper()
		b, err := signedauth.JobLeaseBinding(b, revision)
		if err != nil {
			t.Fatal(err)
		}
		claims := signedauth.Claims{Version: signedauth.Version, KeyID: "key", Binding: b, IssuedAt: issued.Unix(), ExpiresAt: issued.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/node/files/mounts/mount/**","capabilities":["read","create"]}]}`)}
		token, err := signedauth.Sign(claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	call := func(path string, tokens ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set("Authorization", "Bearer secret")
		for _, token := range tokens {
			r.Header.Add(signedAuthorizationHeader, token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	path := "/api/v1/jobs/job/authorization"
	first := sign(binding, 1, now)
	unauthorized := httptest.NewRequest("POST", path, nil)
	unauthorized.Header.Set(signedAuthorizationHeader, first)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, unauthorized)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing operational token: %d %s", w.Code, w.Body)
	}
	if w := call(path); w.Code != http.StatusBadRequest {
		t.Fatalf("missing authorization: %d %s", w.Code, w.Body)
	}
	if w := call(path, first, first); w.Code != http.StatusBadRequest {
		t.Fatalf("multiple authorizations: %d %s", w.Code, w.Body)
	}
	if w := call(path, first+"x"); w.Code != http.StatusForbidden {
		t.Fatalf("tampered authorization: %d %s", w.Code, w.Body)
	}
	if w := call("/api/v1/jobs/other/authorization", first); w.Code != http.StatusForbidden {
		t.Fatalf("other job: %d %s", w.Code, w.Body)
	}
	expired := sign(binding, 1, now.Add(-time.Minute))
	if w := call(path, expired); w.Code != http.StatusForbidden {
		t.Fatalf("expired authorization: %d %s", w.Code, w.Body)
	}
	badRevision := binding
	badRevision.RequestID = "unrelated-request"
	badClaims := signedauth.Claims{Version: signedauth.Version, KeyID: "key", Binding: badRevision, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[]}`)}
	badToken, err := signedauth.Sign(badClaims, key)
	if err != nil {
		t.Fatal(err)
	}
	if w := call(path, badToken); w.Code != http.StatusForbidden {
		t.Fatalf("signed but wrong revision accepted: %d %s", w.Code, w.Body)
	}
	w = call(path, first)
	if w.Code != http.StatusOK || w.Header().Get("X-Jolt-Job-Authorization-Applied") != "v1" || !strings.Contains(w.Body.String(), `"revision":1`) || !strings.Contains(w.Body.String(), `"execution_enabled":false`) || strings.Contains(w.Body.String(), first) || strings.Contains(w.Body.String(), "private-actor") {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	stored, err := storage.GetJob(ctx, job.ID)
	if err != nil || stored.State != "waiting_validation" || !stored.SignedAuthBound {
		t.Fatalf("job=%+v err=%v", stored, err)
	}
	if _, err := storage.ClaimNextJob(ctx, now); err == nil {
		t.Fatal("job executed without integration")
	}
	if w := call(path, first); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revision":1`) {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	second := sign(binding, 2, now)
	if w := call(path, second); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revision":2`) {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	if w := call(path, first); w.Code != http.StatusForbidden {
		t.Fatalf("old revision: %d %s", w.Code, w.Body)
	}
	changed := binding
	changed.ActorID = "other"
	if w := call(path, sign(changed, 3, now)); w.Code != http.StatusForbidden {
		t.Fatalf("changed actor: %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest("GET", "/api/v1/node", nil)
	r.Header.Set("Authorization", "Bearer secret")
	info := httptest.NewRecorder()
	h.ServeHTTP(info, r)
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), "signed_job_authorization_registration_v1") {
		t.Fatalf("capability: %d %s", info.Code, info.Body)
	}
	if strings.Contains(logs.String(), first) || strings.Contains(logs.String(), second) || strings.Contains(logs.String(), "private-actor") {
		t.Fatal("authorization exposed in logs")
	}
	withoutKeys := New(config.Config{ControlTowerToken: "secret"}, identity, files, jobs.New(storage, files), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)), storage)
	noKeysRequest := httptest.NewRequest("POST", path, nil)
	noKeysRequest.Header.Set("Authorization", "Bearer secret")
	noKeysRequest.Header.Set(signedAuthorizationHeader, first)
	noKeysResponse := httptest.NewRecorder()
	withoutKeys.ServeHTTP(noKeysResponse, noKeysRequest)
	if noKeysResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing keys: %d %s", noKeysResponse.Code, noKeysResponse.Body)
	}
}
