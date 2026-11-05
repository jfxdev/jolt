package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
)

func TestDestructivePlanEndpoints(t *testing.T) {
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
	if err := os.MkdirAll(filepath.Join(root, "tree/sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tree/sub/a.txt"), []byte("alpha"), 0o600); err != nil {
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
		call := func(path, body, bearer string, headers map[string]string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			if bearer != "" {
				r.Header.Set("Authorization", "Bearer "+bearer)
			}
			for name, value := range headers {
				r.Header.Set(name, value)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		}
		plans := "/api/v1/mounts/mount/files/destructive-plans"
		body := `{"subject_type":"user","subject_id":"actor","operation":"delete","source_path":"tree"}`
		if w := call(plans, body, "", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("enabled=%v without bearer: %d", enabled, w.Code)
		}
		if !enabled {
			if w := call(plans, body, "secret", nil); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("plan created on a node that does not run signed jobs: %d %s", w.Code, w.Body)
			}
			continue
		}
		created := call(plans, body, "secret", nil)
		var plan struct {
			ID, Token string
			Files     int64
			Bytes     int64
		}
		var raw map[string]any
		_ = json.Unmarshal(created.Body.Bytes(), &raw)
		plan.ID, _ = raw["plan_id"].(string)
		plan.Token, _ = raw["token"].(string)
		if created.Code != http.StatusCreated || plan.ID == "" || plan.Token == "" || raw["files"] != float64(1) || raw["bytes"] != float64(5) {
			t.Fatalf("plan: %d %s", created.Code, created.Body)
		}
		accept := plans + "/" + plan.ID + "/accept"
		acceptBody := func(token string) string {
			return `{"subject_type":"user","subject_id":"actor","token":"` + token + `"}`
		}
		if w := call(accept, acceptBody(plan.Token), "secret", nil); w.Code != http.StatusBadRequest {
			t.Fatalf("accept without idempotency key: %d %s", w.Code, w.Body)
		}
		if w := call(accept, acceptBody("wrong"), "secret", map[string]string{"Idempotency-Key": "k"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "plan_rejected") {
			t.Fatalf("wrong token: %d %s", w.Code, w.Body)
		}
		first := call(accept, acceptBody(plan.Token), "secret", map[string]string{"Idempotency-Key": "k"})
		if first.Code != http.StatusAccepted || !strings.Contains(first.Body.String(), `"state":"waiting_validation"`) {
			t.Fatalf("accept: %d %s", first.Code, first.Body)
		}
		if strings.Contains(first.Body.String(), plan.Token) {
			t.Fatal("the confirmation token was echoed in the job")
		}
		if again := call(accept, acceptBody(plan.Token), "secret", map[string]string{"Idempotency-Key": "k"}); again.Code != http.StatusOK || again.Body.String() != first.Body.String() {
			t.Fatalf("repeat: %d %s", again.Code, again.Body)
		}
		if other := call(accept, acceptBody(plan.Token), "secret", map[string]string{"Idempotency-Key": "other"}); other.Code != http.StatusConflict && other.Code != http.StatusForbidden {
			t.Fatalf("consumed plan reused: %d %s", other.Code, other.Body)
		}
		if w := call(plans, `{"subject_type":"user","subject_id":"actor","operation":"delete","source_path":"tree/sub/a.txt"}`, "secret", nil); w.Code != http.StatusBadRequest {
			t.Fatalf("file planned as a tree: %d %s", w.Code, w.Body)
		}
		if w := call(plans, `{"subject_type":"user","subject_id":"actor","operation":"delete","source_path":"tree","extra":1}`, "secret", nil); w.Code != http.StatusBadRequest {
			t.Fatalf("unknown field accepted: %d", w.Code)
		}
		info := httptest.NewRequest(http.MethodGet, "/api/v1/node", nil)
		info.Header.Set("Authorization", "Bearer secret")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, info)
		if !strings.Contains(recorder.Body.String(), "destructive_plans_v1") {
			t.Fatalf("capability missing: %s", recorder.Body)
		}
		if _, err := os.Stat(filepath.Join(root, "tree/sub/a.txt")); err != nil {
			t.Fatalf("planning or accepting changed the tree: %v", err)
		}
	}
}
