package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	"github.com/jfxdev/jolt/backend/internal/infra/metrics"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type receiptFailure struct {
	contracts.Store
	fail bool
}

func (s *receiptFailure) UpdateUploadSession(ctx context.Context, v entities.UploadSession) error {
	if v.State == "completed" && s.fail {
		s.fail = false
		return errors.New("simulated loss before receipt commit")
	}
	return s.Store.UpdateUploadSession(ctx, v)
}
func continuityHandler(storage contracts.Store) http.Handler {
	files := filesystem.New(storage)
	identity := entities.Identity{NodeID: "test"}
	return New(config.Config{ControlTowerToken: "test-token", UploadSessionTTL: time.Hour}, identity, files, jobs.New(storage, files), pairing.New(storage, identity), grants.New(storage, files), slog.New(slog.NewTextHandler(io.Discard, nil)), storage, metrics.NewRegistry())
}
func uploadCall(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-token")
	r.Header.Set("Content-Type", "application/json")
	if method == http.MethodPatch {
		r.Header.Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestUploadPublicationRecoversAcrossRestartAndReturnsStableReceipt(t *testing.T) {
	for _, boundary := range []string{"intent", "published", "empty-published"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := context.Background()
			dir := filepath.Join(t.TempDir(), "state")
			root := t.TempDir()
			storage, err := db.Open(dir, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { storage.Close() }()
			files := filesystem.New(storage)
			mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_write", Enabled: true, Published: true})
			if err != nil {
				t.Fatal(err)
			}
			failing := &receiptFailure{Store: storage, fail: true}
			h := continuityHandler(failing)
			content := "synthetic upload payload"
			if boundary == "empty-published" {
				content = ""
			}
			base := "/api/v1/mounts/" + mount.ID + "/files/uploads"
			created := uploadCall(h, "POST", base, fmt.Sprintf(`{"path":"result.txt","size":%d}`, len(content)))
			var session entities.UploadSession
			if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil {
				t.Fatalf("create: %d %s", created.Code, created.Body)
			}
			if content != "" {
				w := uploadCall(h, "PATCH", base+"/"+session.ID, content)
				if w.Code != 200 {
					t.Fatalf("append: %d %s", w.Code, w.Body)
				}
			}
			if boundary == "intent" {
				digest, err := files.PrepareUpload(ctx, session)
				if err != nil {
					t.Fatal(err)
				}
				session.State = "publishing"
				session.PublishChecksum = digest
				if err := storage.UpdateUploadSession(ctx, session); err != nil {
					t.Fatal(err)
				}
			} else {
				w := uploadCall(h, "POST", base+"/"+session.ID+"/complete", "{}")
				if w.Code != 500 {
					t.Fatalf("receipt fault=%d %s", w.Code, w.Body)
				}
			}
			storage.Close()
			storage, err = db.Open(dir, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			h = continuityHandler(storage)
			first := uploadCall(h, "POST", base+"/"+session.ID+"/complete", "{}")
			if first.Code != 201 {
				t.Fatalf("recover: %d %s", first.Code, first.Body)
			}
			digest := sha256.Sum256([]byte(content))
			if !strings.Contains(first.Body.String(), hex.EncodeToString(digest[:])) {
				t.Fatal("receipt lacks verified checksum")
			}
			// A later external replacement must never be touched by a completion retry.
			if err := os.WriteFile(filepath.Join(root, "result.txt"), []byte("external replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			again := uploadCall(h, "POST", base+"/"+session.ID+"/complete", "{}")
			if again.Code != 201 || again.Body.String() != first.Body.String() {
				t.Fatalf("unstable receipt: %d %s", again.Code, again.Body)
			}
			bytes, err := os.ReadFile(filepath.Join(root, "result.txt"))
			if err != nil || string(bytes) != "external replacement" {
				t.Fatal("retry overwrote destination")
			}
			sessions, err := storage.ListUploadSessions(ctx, mount.ID)
			if err != nil || len(sessions) != 0 {
				t.Fatal("receipt occupied active upload reservation")
			}
			if w := uploadCall(h, "DELETE", base+"/"+session.ID, ""); w.Code != 204 {
				t.Fatal(w.Body)
			}
			if _, err := os.Stat(filepath.Join(root, "result.txt")); err != nil {
				t.Fatal("discard removed published destination")
			}
		})
	}
}

func TestUploadVerificationBindsToDurablePartial(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	mount, err := files.SaveMount(context.Background(), entities.Mount{Name: "files", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true, Published: true})
	if err != nil {
		t.Fatal(err)
	}
	h := continuityHandler(storage)
	base := "/api/v1/mounts/" + mount.ID + "/files/uploads"
	created := uploadCall(h, "POST", base, `{"path":"file.txt","size":7}`)
	var session entities.UploadSession
	if err := json.Unmarshal(created.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if w := uploadCall(h, "PATCH", base+"/"+session.ID, "payload"); w.Code != 200 {
		t.Fatal(w.Body)
	}
	w := uploadCall(h, "GET", base+"/"+session.ID+"/verification", "")
	var page entities.UploadVerification
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Offset != 7 || len(page.Blocks) != 1 {
		t.Fatalf("verify: %d %s", w.Code, w.Body)
	}
	hash := sha256.Sum256([]byte("payload"))
	if page.Blocks[0].SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("wrong prefix hash")
	}
	if w := uploadCall(h, "GET", base+"/"+session.ID+"/verification?after=1", ""); w.Code != 400 {
		t.Fatalf("unaligned cursor accepted: %d", w.Code)
	}
}

func TestJobItemPagePreservesMissingJobStatus(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	response := uploadCall(continuityHandler(storage), "GET", "/api/v1/jobs/missing/items?after=20", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
}
