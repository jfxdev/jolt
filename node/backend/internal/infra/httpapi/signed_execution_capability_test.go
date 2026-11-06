package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
)

func TestSignedExecutionIsAdvertisedOnlyWhenConfigured(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	if _, err := files.SaveMount(context.Background(), entities.Mount{ID: "mount", Name: "mount", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true, Published: true}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	for _, enabled := range []bool{false, true} {
		service := jobs.New(storage, files)
		if enabled {
			service.ConfigureSignedExecution(storage, "node", keys)
		}
		var logs bytes.Buffer
		handler := New(config.Config{ControlTowerToken: "secret", AuthorizationKeys: keys}, entities.Identity{NodeID: "node"}, files, service, nil, nil, slog.New(slog.NewTextHandler(&logs, nil)), storage)
		call := func(method, path, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer secret")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		}
		info := call(http.MethodGet, "/api/v1/node", "")
		if info.Code != http.StatusOK || strings.Contains(info.Body.String(), "signed_local_copy_execution_v1") != enabled {
			t.Fatalf("enabled=%v capability: %d %s", enabled, info.Code, info.Body)
		}
		prepare := call(http.MethodPost, "/api/v1/jobs/signed-local-copy/prepare", `{"mount_id":"mount","source_path":"source","destination_path":"destination"}`)
		want := `"execution_enabled":false`
		if enabled {
			want = `"execution_enabled":true`
		}
		if prepare.Code != http.StatusOK || !strings.Contains(prepare.Body.String(), want) {
			t.Fatalf("enabled=%v prepare: %d %s", enabled, prepare.Code, prepare.Body)
		}
		ask := call(http.MethodPost, "/api/v1/jobs/signed-local-copy/prepare", `{"mount_id":"mount","source_path":"source","destination_path":"destination","conflict_policy":"ask"}`)
		if ask.Code != http.StatusBadRequest {
			t.Fatalf("enabled=%v ask policy accepted: %d %s", enabled, ask.Code, ask.Body)
		}
	}
}

// The guard that refuses signed contexts on unsupported routes must let the
// signed pull routes through: they verify the envelope themselves.
func TestSignedContextGuardAllowsTheSignedPullRoutes(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	var logs bytes.Buffer
	handler := New(config.Config{ControlTowerToken: "secret", AuthorizationKeys: keys}, entities.Identity{NodeID: "node"}, files, jobs.New(storage, files), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)), storage)
	for _, path := range []string{"/api/v1/transfers/signed-pull/batch", "/api/v1/transfers/signed-pull/batch/plan"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set(signedAuthorizationHeader, "envelope")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "signed_context_unsupported") {
			t.Fatalf("%s: the guard refused the signed header: %d %s", path, w.Code, w.Body)
		}
	}
	other := httptest.NewRequest(http.MethodPost, "/api/v1/mounts/m/files/move", strings.NewReader(`{}`))
	other.Header.Set("Authorization", "Bearer secret")
	other.Header.Set(signedAuthorizationHeader, "envelope")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, other)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "signed_context_unsupported") {
		t.Fatalf("an unsupported route accepted a signed header: %d %s", w.Code, w.Body)
	}
}
