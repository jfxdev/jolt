package httpapi

import (
	"context"
	"encoding/json"
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
)

func TestDeletingOnATrashMountKeepsTheEntryAndTheRoutesManageIt(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "plan.txt"), []byte("plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	files := filesystem.New(store)
	if _, err := files.SaveMount(ctx, entities.Mount{ID: "editor", Name: "editor", LocalPath: root, Mode: "read_write", Enabled: true, Published: true, Trash: &entities.TrashConfig{Enabled: true, RetentionDays: 30}}); err != nil {
		t.Fatal(err)
	}
	if _, err := files.SaveMount(ctx, entities.Mount{ID: "plain", Name: "plain", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true, Published: true}); err != nil {
		t.Fatal(err)
	}
	identity := entities.Identity{NodeID: "node"}
	jobService := jobs.New(store, files)
	jobContext, stop := context.WithCancel(ctx)
	defer stop()
	if _, err := jobService.Start(jobContext, 2); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{ControlTowerToken: "secret", PublicHealth: true, NodeName: "test", APIAddress: ":0", MTLSAddress: ":0"}
	handler := New(cfg, identity, files, jobService, pairing.New(store, identity), grants.New(store, files), slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.NewRegistry())
	call := func(method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer secret")
		request.Header.Set("Idempotency-Key", "k-"+path)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if node := call(http.MethodGet, "/api/v1/node"); !strings.Contains(node.Body.String(), `"trash_v1"`) {
		t.Fatalf("the capability is not advertised: %s", node.Body)
	}
	if mount := call(http.MethodGet, "/api/v1/mounts/editor"); !strings.Contains(mount.Body.String(), `"trash":{"enabled":true,"retention_days":30}`) {
		t.Fatalf("the mount does not say it has a trash: %s", mount.Body)
	}
	deleted := call(http.MethodDelete, "/api/v1/mounts/editor/files?path=docs/plan.txt")
	var job struct {
		ID string `json:"job_id"`
	}
	if deleted.Code != http.StatusAccepted || json.Unmarshal(deleted.Body.Bytes(), &job) != nil {
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		current := call(http.MethodGet, "/api/v1/jobs/"+job.ID)
		if strings.Contains(current.Body.String(), `"state":"completed"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the delete job did not finish: %s", current.Body)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "plan.txt")); !os.IsNotExist(err) {
		t.Fatalf("the file is still there: %v", err)
	}
	var list struct {
		Items []entities.TrashItem `json:"items"`
	}
	listed := call(http.MethodGet, "/api/v1/mounts/editor/trash")
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &list) != nil || len(list.Items) != 1 || list.Items[0].Path != "docs/plan.txt" {
		t.Fatalf("list: %d %s", listed.Code, listed.Body)
	}
	id := list.Items[0].ID
	if one := call(http.MethodGet, "/api/v1/mounts/editor/trash/"+id); one.Code != http.StatusOK {
		t.Fatalf("get: %d %s", one.Code, one.Body)
	}
	// The listing of the mount never shows the folder, and it cannot be read by name.
	if browse := call(http.MethodGet, "/api/v1/mounts/editor/files"); strings.Contains(browse.Body.String(), "jolt-trash") {
		t.Fatalf("the trash folder is listed: %s", browse.Body)
	}
	if read := call(http.MethodGet, "/api/v1/mounts/editor/files/content?path=.jolt-trash/"+id+"/docs/plan.txt"); read.Code != http.StatusNotFound {
		t.Fatalf("the kept bytes are readable by name: %d", read.Code)
	}
	// Another mount has no such entry.
	if other := call(http.MethodGet, "/api/v1/mounts/plain/trash/"+id); other.Code != http.StatusNotFound || !strings.Contains(other.Body.String(), "trash_not_found") {
		t.Fatalf("foreign mount: %d %s", other.Code, other.Body)
	}
	if call(http.MethodPost, "/api/v1/mounts/editor/trash/"+id+"/restore").Code != http.StatusOK {
		t.Fatal("restore failed")
	}
	if data, err := os.ReadFile(filepath.Join(root, "docs", "plan.txt")); err != nil || string(data) != "plan" {
		t.Fatalf("restored: %q %v", data, err)
	}
	if again := call(http.MethodPost, "/api/v1/mounts/editor/trash/"+id+"/restore"); again.Code != http.StatusNotFound {
		t.Fatalf("restoring twice: %d", again.Code)
	}
	if purge := call(http.MethodDelete, "/api/v1/mounts/editor/trash/tr_0_000000000000"); purge.Code != http.StatusNotFound {
		t.Fatalf("purging an unknown entry: %d", purge.Code)
	}
}
