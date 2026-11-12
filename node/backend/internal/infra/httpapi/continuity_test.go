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

func TestAgentSearchAppliesDepthLimitAndSignalsSupport(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	root := t.TempDir()
	parts := make([]string, 17)
	for i := range parts {
		parts[i] = "directory"
	}
	deep := filepath.Join(append([]string{root}, parts...)...)
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "match.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_only", Enabled: true, Published: true})
	if err != nil {
		t.Fatal(err)
	}
	identity := entities.Identity{NodeID: "test"}
	handler := New(config.Config{ControlTowerToken: "test-token", SearchMaxResults: 500, SearchMaxEntries: 200000, SearchTimeout: 15 * time.Second}, identity, files, jobs.New(storage, files), pairing.New(storage, identity), grants.New(storage, files), slog.New(slog.NewTextHandler(io.Discard, nil)), storage, metrics.NewRegistry())
	request := httptest.NewRequest("GET", "/api/v1/mounts/"+mount.ID+"/files/search?query=match", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("X-Jolt-Agent-Search", "1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result filesystem.SearchResult
	if response.Code != 200 || response.Header().Get("X-Jolt-Agent-Search-Applied") != "1" || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.Truncated || result.TruncatedReason != "depth" || len(result.Entries) != 0 {
		t.Fatalf("agent search: %d %s %+v", response.Code, response.Body.String(), result)
	}
}

func TestAgentScanChecksPrefixForRangeAndArchive(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	root := t.TempDir()
	secret := "-----BEGIN PRIVATE KEY-----"
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte(secret+strings.Repeat("x", 200)), 0600); err != nil {
		t.Fatal(err)
	}
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_only", Enabled: true, Published: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := continuityHandler(storage)
	for _, suffix := range []string{"/content?path=secret.txt", "/archive?path=."} {
		request := httptest.NewRequest("GET", "/api/v1/mounts/"+mount.ID+"/files"+suffix, nil)
		request.Header.Set("Authorization", "Bearer test-token")
		request.Header.Set("X-Jolt-Scan", "secrets")
		request.Header.Set("Range", "bytes=100-110")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || response.Header().Get("X-Jolt-Scan-Applied") != "secrets" || response.Header().Get("X-Jolt-Secret-Kind") != "private_key" || !strings.Contains(response.Body.String(), "secret_detected") || strings.Contains(response.Body.String(), secret) {
			t.Fatalf("%s: %d %s %v", suffix, response.Code, response.Body.String(), response.Header())
		}
	}
}

func TestRejectedUploadRecoveryNeverReportsPublished(t *testing.T) {
	for _, tc := range []struct{ partialExists, createNew bool }{{false, false}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("partial=%t/create=%t", tc.partialExists, tc.createNew), func(t *testing.T) {
			ctx := context.Background()
			stateDir, root := filepath.Join(t.TempDir(), "state"), t.TempDir()
			storage, err := db.Open(stateDir, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			files := filesystem.New(storage)
			mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_write", Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			payload := "MZxx"
			if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte(payload), 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(payload))
			now := time.Now().UTC()
			session := entities.UploadSession{ID: "rejected-upload", MountID: mount.ID, Destination: "file.txt", State: "rejected", Size: 4, Overwrite: true, PublishChecksum: hex.EncodeToString(digest[:]), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if err := storage.CreateUploadSession(ctx, session); err != nil {
				t.Fatal(err)
			}
			if tc.partialExists {
				if _, err := files.AppendUpload(ctx, mount.ID, session.Destination, session.ID, 0, 4, strings.NewReader(payload)); err != nil {
					t.Fatal(err)
				}
			}
			if err := storage.Close(); err != nil {
				t.Fatal(err)
			}
			storage, err = db.Open(stateDir, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Close()
			handler := continuityHandler(storage)
			base := "/api/v1/mounts/" + mount.ID + "/files/uploads"
			if tc.createNew {
				response := uploadCall(handler, "POST", base, `{"path":"file.txt","size":4,"overwrite":true}`)
				if response.Code != http.StatusCreated {
					t.Fatalf("new upload after rejection: %d %s", response.Code, response.Body.String())
				}
			} else {
				response := uploadCall(handler, "POST", base+"/"+session.ID+"/complete", `{}`)
				if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "upload_content_rejected") {
					t.Fatalf("recovery: %d %s", response.Code, response.Body.String())
				}
			}
			if _, err := storage.GetUploadSession(ctx, session.ID); err == nil {
				t.Fatal("rejected session remains")
			}
			data, err := os.ReadFile(filepath.Join(root, "file.txt"))
			if err != nil || string(data) != payload {
				t.Fatalf("existing destination changed: %q %v", data, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 {
				t.Fatalf("rejected partial remains: %+v %v", entries, err)
			}
		})
	}
}

func TestUploadSessionIsHiddenAfterMountPolicyChange(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true, Published: true})
	if err != nil {
		t.Fatal(err)
	}
	h := continuityHandler(storage)
	base := "/api/v1/mounts/" + mount.ID + "/files/uploads"
	created := uploadCall(h, "POST", base, `{"path":"secret.pem","size":3}`)
	var session entities.UploadSession
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	if response := uploadCall(h, "PATCH", base+"/"+session.ID, "abc"); response.Code != 200 {
		t.Fatalf("append: %d %s", response.Code, response.Body)
	}
	mount.HiddenPatterns = []string{"*.pem"}
	if _, err := files.SaveMount(ctx, mount); err != nil {
		t.Fatal(err)
	}
	if response := uploadCall(h, "GET", base, ""); response.Code != 200 || strings.Contains(response.Body.String(), "secret.pem") {
		t.Fatalf("list exposed upload: %d %s", response.Code, response.Body)
	}
	for _, target := range []string{base + "/" + session.ID, base + "/" + session.ID + "/complete"} {
		method := "GET"
		if strings.HasSuffix(target, "/complete") {
			method = "POST"
		}
		if response := uploadCall(h, method, target, "{}"); response.Code != 404 {
			t.Fatalf("hidden session: %d %s", response.Code, response.Body)
		}
	}
	if err := files.AbortUpload(ctx, mount.ID, session.Destination, session.ID); err != nil {
		t.Fatalf("internal cleanup: %v", err)
	}
}

func TestCanarySignalsReadsAndArchivesWithoutOverridingHiddenRules(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	root := t.TempDir()
	for _, name := range []string{"honey.txt", "hidden.pem"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("decoy"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_only", Enabled: true, Published: true, CanaryPaths: []string{"honey.txt", "hidden.pem"}, HiddenPatterns: []string{"*.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	h := continuityHandler(storage)
	base := "/api/v1/mounts/" + mount.ID + "/files"
	for _, tc := range []struct {
		path   string
		status int
	}{
		{base + "/metadata?path=honey.txt", 200}, {base + "/content?path=honey.txt", 200},
		{base + "/content?path=hidden.pem", 404}, {base + "/archive?path=.", 200},
	} {
		request := httptest.NewRequest("GET", tc.path, nil)
		request.Header.Set("Authorization", "Bearer test-token")
		request.Header.Set("X-Jolt-Internal-Canary", "1")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != tc.status || response.Header().Get("X-Jolt-Canary") != "1" {
			t.Fatalf("%s: %d header=%q body=%s", tc.path, response.Code, response.Header().Get("X-Jolt-Canary"), response.Body)
		}
	}
	if response := uploadCall(h, "GET", base+"/content?path=honey.txt", ""); response.Header().Get("X-Jolt-Canary") != "" {
		t.Fatal("canary signal exposed to a normal node API request")
	}
}

func TestHiddenNamesFailBeforeJobsAreCreated(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true, Published: true, HiddenPatterns: []string{"*.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	h := continuityHandler(storage)
	base := "/api/v1/mounts/" + mount.ID + "/files"
	for _, tc := range []struct {
		method, path, body string
		status             int
		code               string
	}{
		{"POST", base + "/directories", `{"path":"secret.pem"}`, 422, "hidden_name"},
		{"POST", base + "/move", `{"source_path":"secret.pem","destination_path":"open"}`, 404, "not_found"},
		{"PUT", base + "/content?path=secret.pem", "abc", 422, "hidden_name"},
		{"POST", base + "/uploads", `{"path":"secret.pem","size":3}`, 422, "hidden_name"},
	} {
		response := uploadCall(h, tc.method, tc.path, tc.body)
		if response.Code != tc.status || !strings.Contains(response.Body.String(), tc.code) {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, response.Code, response.Body)
		}
	}
	jobs, err := storage.ListJobs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("hidden requests created jobs: %+v", jobs)
	}
}

func TestHistoricalJobsDoNotRevealNewlyHiddenPaths(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true, Published: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	job := entities.Job{ID: "old-job", Type: "copy_local", MountID: mount.ID, SourcePath: "secret.pem", Destination: "copy.txt", State: "completed", CreatedAt: now, UpdatedAt: now}
	if _, _, err := storage.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	mount.HiddenPatterns = []string{"*.pem"}
	if _, err := files.SaveMount(ctx, mount); err != nil {
		t.Fatal(err)
	}
	h := continuityHandler(storage)
	if response := uploadCall(h, "GET", "/api/v1/jobs", ""); response.Code != 200 || strings.Contains(response.Body.String(), "secret.pem") {
		t.Fatalf("job list exposed path: %d %s", response.Code, response.Body)
	}
	if response := uploadCall(h, "GET", "/api/v1/jobs/old-job", ""); response.Code != 404 {
		t.Fatalf("job detail: %d %s", response.Code, response.Body)
	}
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

func TestUploadRecoveryRejectsChangedPublication(t *testing.T) {
	for _, boundary := range []string{"partial", "destination"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := context.Background()
			storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Close()
			files := filesystem.New(storage)
			root := t.TempDir()
			mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_write", Enabled: true, Published: true})
			if err != nil {
				t.Fatal(err)
			}
			h := continuityHandler(&receiptFailure{Store: storage, fail: true})
			base := "/api/v1/mounts/" + mount.ID + "/files/uploads"
			created := uploadCall(h, "POST", base, `{"path":"file.txt","size":7}`)
			var session entities.UploadSession
			if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil {
				t.Fatalf("create: %d %s", created.Code, created.Body)
			}
			if w := uploadCall(h, "PATCH", base+"/"+session.ID, "payload"); w.Code != 200 {
				t.Fatal(w.Body)
			}
			if boundary == "partial" {
				digest, err := files.PrepareUpload(ctx, session)
				if err != nil {
					t.Fatal(err)
				}
				session.State, session.PublishChecksum = "publishing", digest
				if err := storage.UpdateUploadSession(ctx, session); err != nil {
					t.Fatal(err)
				}
				partials, err := filepath.Glob(filepath.Join(root, "*.partial"))
				if err != nil || len(partials) != 1 {
					t.Fatalf("partials: %v %v", partials, err)
				}
				if err := os.WriteFile(partials[0], []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if w := uploadCall(h, "POST", base+"/"+session.ID+"/complete", "{}"); w.Code != 500 {
					t.Fatalf("receipt fault: %d %s", w.Code, w.Body)
				}
				if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := uploadCall(continuityHandler(storage), "POST", base+"/"+session.ID+"/complete", "{}")
			if boundary == "partial" {
				if w.Code != 400 {
					t.Fatalf("changed partial accepted: %d %s", w.Code, w.Body)
				}
				if _, err := os.Stat(filepath.Join(root, "file.txt")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("changed partial published: %v", err)
				}
			} else {
				if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"upload_destination_changed"`) {
					t.Fatalf("changed destination: %d %s", w.Code, w.Body)
				}
				content, err := os.ReadFile(filepath.Join(root, "file.txt"))
				if err != nil || string(content) != "changed" {
					t.Fatalf("replacement changed: %q %v", content, err)
				}
			}
		})
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

func TestDiskUsageEndpointReturnsAllocatedUsageInDescendingOrder(t *testing.T) {
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	root := t.TempDir()
	files := filesystem.New(storage)
	mount, err := files.SaveMount(context.Background(), entities.Mount{Name: "files", LocalPath: root, Mode: "read_only", Enabled: true, Published: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "large"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "large", "payload.bin"), make([]byte, 64*1024), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "small.txt"), []byte("small"), 0600); err != nil {
		t.Fatal(err)
	}

	response := uploadCall(continuityHandler(storage), "GET", "/api/v1/mounts/"+mount.ID+"/files/disk-usage?path=.", "")
	var result filesystem.DiskUsageResult
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("disk usage: %d %s", response.Code, response.Body)
	}
	if result.Path != "" || len(result.Entries) != 2 || result.Entries[0].Name != "large" {
		t.Fatalf("unexpected disk usage result: %+v", result)
	}
	if result.Entries[0].DiskUsage <= result.Entries[1].DiskUsage || result.TotalBytes < result.Entries[0].DiskUsage+result.Entries[1].DiskUsage {
		t.Fatalf("invalid allocated usage: %+v", result)
	}
}

func TestLockedMountServesMetadataOnly(t *testing.T) {
	ctx := context.Background()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	files := filesystem.New(storage)
	mount, err := files.SaveMount(ctx, entities.Mount{Name: "files", LocalPath: root, Mode: "read_write", Enabled: true, Published: true, Locked: true})
	if err != nil {
		t.Fatal(err)
	}
	h := continuityHandler(storage)
	base := "/api/v1/mounts/" + mount.ID + "/files"

	for _, path := range []string{base, base + "/metadata?path=a.txt", base + "/search?query=a", base + "/disk-usage"} {
		if response := uploadCall(h, "GET", path, ""); response.Code != 200 {
			t.Fatalf("GET %s: %d %s", path, response.Code, response.Body)
		}
	}
	if response := uploadCall(h, "GET", "/api/v1/mounts/"+mount.ID, ""); response.Code != 200 || !strings.Contains(response.Body.String(), `"locked":true`) {
		t.Fatalf("the mount must report locked: %d %s", response.Code, response.Body)
	}
	for _, tc := range []struct{ method, path, body string }{
		{"GET", base + "/content?path=a.txt", ""},
		{"GET", base + "/archive?path=", ""},
		{"GET", base + "/archive/plan?path=", ""},
		{"PUT", base + "/content?path=new.txt", "abc"},
		{"POST", base + "/uploads", `{"path":"new.txt","size":3}`},
		{"POST", base + "/directories", `{"path":"dir"}`},
		{"POST", base + "/move", `{"source_path":"a.txt","destination_path":"b.txt"}`},
		{"POST", base + "/copy", `{"source_path":"a.txt","destination_path":"b.txt"}`},
		{"DELETE", base + "?path=a.txt", ""},
	} {
		response := uploadCall(h, tc.method, tc.path, tc.body)
		if response.Code != 403 || !strings.Contains(response.Body.String(), "mount_locked") {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, response.Code, response.Body)
		}
	}
	jobs, err := storage.ListJobs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("locked requests created jobs: %+v", jobs)
	}
	if data, err := os.ReadFile(filepath.Join(root, "a.txt")); err != nil || string(data) != "secret" {
		t.Fatalf("file changed: %q, %v", data, err)
	}
	for _, name := range []string{"new.txt", "dir", "b.txt"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was created on a locked mount: %v", name, err)
		}
	}
}
