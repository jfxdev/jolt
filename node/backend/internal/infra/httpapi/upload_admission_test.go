package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	"github.com/jfxdev/jolt/backend/internal/infra/metrics"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
)

func admissionFixture(t *testing.T, cfg config.Config) (http.Handler, string) {
	t.Helper()
	storage, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	files := filesystem.New(storage)
	mount, err := files.SaveMount(context.Background(), entities.Mount{Name: "files", LocalPath: t.TempDir(), Mode: "read_write", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	identity := entities.Identity{NodeID: "node"}
	cfg.ControlTowerToken = "secret"
	h := New(cfg, identity, files, jobs.New(storage, files), pairing.New(storage, identity), grants.New(storage, files), slog.New(slog.NewTextHandler(io.Discard, nil)), storage, metrics.NewRegistry())
	return h, "/api/v1/mounts/" + mount.ID + "/files"
}

func uploadRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestConcurrentSessionAdmissionRespectsLimitAndReleasesAbortedSlot(t *testing.T) {
	h, base := admissionFixture(t, config.Config{UploadMaxBytes: 8, UploadMaxSessions: 1, UploadMaxReservedBytes: 16})
	gate := make(chan struct{})
	out := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for _, path := range []string{"one.txt", "two.txt"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			<-gate
			out <- uploadRequest(h, http.MethodPost, base+"/uploads", `{"path":"`+path+`","size":4}`)
		}(path)
	}
	close(gate)
	wg.Wait()
	close(out)
	wins, limited := 0, 0
	var session entities.UploadSession
	for response := range out {
		switch response.Code {
		case 201:
			wins++
			if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
				t.Fatal(err)
			}
		case 429:
			limited++
		default:
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if wins != 1 || limited != 1 {
		t.Fatalf("wins=%d limited=%d", wins, limited)
	}
	if response := uploadRequest(h, http.MethodDelete, base+"/uploads/"+session.ID, ""); response.Code != 204 {
		t.Fatalf("abort=%d %s", response.Code, response.Body.String())
	}
	if response := uploadRequest(h, http.MethodPost, base+"/uploads", `{"path":"three.txt","size":4}`); response.Code != 201 {
		t.Fatalf("new=%d %s", response.Code, response.Body.String())
	}
}

func TestUploadAdmissionRejectsOversizeAndReservationExhaustion(t *testing.T) {
	h, base := admissionFixture(t, config.Config{UploadMaxBytes: 4, UploadMaxSessions: 8, UploadMaxReservedBytes: 6})
	for _, tc := range []struct {
		path, body string
		want       int
	}{
		{base + "/uploads", `{"path":"large","size":5}`, 413},
		{base + "/uploads", `{"path":"first","size":4}`, 201},
		{base + "/uploads", `{"path":"second","size":3}`, 507},
	} {
		if r := uploadRequest(h, http.MethodPost, tc.path, tc.body); r.Code != tc.want {
			t.Fatalf("status=%d want=%d body=%s", r.Code, tc.want, r.Body.String())
		}
	}
}

func TestStreamingUploadWithoutContentLengthStillEnforcesSize(t *testing.T) {
	h, base := admissionFixture(t, config.Config{UploadMaxBytes: 4})
	r := httptest.NewRequest(http.MethodPut, base+"/content?path=large.bin", io.NopCloser(strings.NewReader("12345")))
	r.Header.Set("Authorization", "Bearer secret")
	if r.ContentLength > 0 {
		t.Fatal("fixture unexpectedly declares its size")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestChunkLargerThanAdvertisedLimitIsRejectedBeforeWriting(t *testing.T) {
	h, base := admissionFixture(t, config.Config{UploadMaxBytes: 4, CopyChunkSize: 2})
	created := uploadRequest(h, http.MethodPost, base+"/uploads", `{"path":"chunk.bin","size":4}`)
	var session entities.UploadSession
	if err := json.Unmarshal(created.Body.Bytes(), &session); err != nil || created.Code != 201 {
		t.Fatalf("status=%d body=%s", created.Code, created.Body.String())
	}
	r := httptest.NewRequest(http.MethodPatch, base+"/uploads/"+session.ID, strings.NewReader("123"))
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Content-Range", "bytes 0-2/4")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	current := uploadRequest(h, http.MethodGet, base+"/uploads/"+session.ID, "")
	if err := json.Unmarshal(current.Body.Bytes(), &session); err != nil || session.Offset != 0 {
		t.Fatalf("offset=%d error=%v", session.Offset, err)
	}
}
