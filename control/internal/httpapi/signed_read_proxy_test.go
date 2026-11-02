package httpapi

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

type deadlineRecorder struct{ *httptest.ResponseRecorder }

func (w *deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestSignedProxyReadsRequireNodeEnforcement(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var identity = "n1"
	var capabilities = `["signed_local_read_v1","signed_local_tree_read_v1"]`
	var confirmation = true
	var calls int
	var expectedActor = "admin"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/node" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"node_id":"` + identity + `","capabilities":` + capabilities + `}`))}, nil
		}
		calls++
		operation := signedReadOperation(strings.TrimPrefix(r.URL.Path, "/api/v1/"), r.Method)
		root := r.URL.Query().Get("path")
		if root == "" {
			root = "."
		}
		claims, _, err := signedauth.VerifyLocalRead(r.Header.Get(signedAuthorizationHeader), map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", operation, "m", root, time.Now())
		if err != nil || claims.Binding.ActorID != expectedActor || strings.Contains(r.Header.Get(signedAuthorizationHeader), "client-supplied") {
			t.Errorf("invalid node authorization: %+v %v", claims, err)
		}
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if confirmation {
			header.Set("X-Jolt-Access-Applied", "v1")
		}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(`{"items":[]}`))}, nil
	})}
	f := setupAgentWithScanStub(t, store.DefaultAgentLimits(), client, false)
	h := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalReads: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}, f.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	for _, suffix := range []string{"", "/metadata", "/content", "/search", "/disk-usage", "/archive", "/archive/plan"} {
		r := authenticatedRequest(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files"+suffix+"?path=folder", f.adminSession, nil)
		r.Header.Set(signedAuthorizationHeader, "client-supplied")
		w := &deadlineRecorder{httptest.NewRecorder()}
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.String() != `{"items":[]}` {
			t.Fatalf("%s: %d %s", suffix, w.Code, w.Body.String())
		}
	}
	if calls != 7 {
		t.Fatalf("node reads = %d", calls)
	}
	expectedActor = f.accountID
	agent := &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(agent, f.request(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files?path=folder"))
	if agent.Code != http.StatusOK {
		t.Fatalf("agent signed listing: %d %s", agent.Code, agent.Body.String())
	}
	expectedActor = "admin"
	confirmation = false
	w := &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, authenticatedRequest(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files", f.adminSession, nil))
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("missing confirmation: %d %s", w.Code, w.Body.String())
	}
	confirmation = true
	capabilities = `["signed_local_read_v1"]`
	w = &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, authenticatedRequest(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/search", f.adminSession, nil))
	if w.Code != http.StatusConflict || calls != 9 {
		t.Fatalf("missing capability: %d calls=%d", w.Code, calls)
	}
	identity = "other"
	w = &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, authenticatedRequest(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files", f.adminSession, nil))
	if w.Code != http.StatusConflict || calls != 9 {
		t.Fatalf("wrong node: %d calls=%d", w.Code, calls)
	}
}

type slowDeadlineWriter struct {
	header   http.Header
	deadline time.Time
	status   int
	body     string
}

func (w *slowDeadlineWriter) Header() http.Header    { return w.header }
func (w *slowDeadlineWriter) WriteHeader(status int) { w.status = status }
func (w *slowDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}
func (w *slowDeadlineWriter) Write(p []byte) (int, error) {
	if w.deadline.IsZero() {
		w.body = string(p)
		return len(p), nil
	}
	timer := time.NewTimer(time.Until(w.deadline))
	defer timer.Stop()
	<-timer.C
	return 0, context.DeadlineExceeded
}

func TestSignedProxyReadStopsSlowClientAtSessionExpiry(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/node" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"node_id":"n1","capabilities":["signed_local_read_v1"]}`))}, nil
		}
		header := http.Header{"X-Jolt-Access-Applied": []string{"v1"}}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader("content"))}, nil
	})}
	f := setupAgentWithScanStub(t, store.DefaultAgentLimits(), client, false)
	const session = "short-signed-read-session"
	expires := time.Now().UTC().Add(2 * time.Second)
	if err := f.storage.CreateSession(context.Background(), security.Digest(session), "admin", expires); err != nil {
		t.Fatal(err)
	}
	h := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalReads: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}, f.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	w := &slowDeadlineWriter{header: make(http.Header)}
	start := time.Now()
	var aborted any
	func() {
		defer func() { aborted = recover() }()
		h.ServeHTTP(w, authenticatedRequest(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/content?path=file.txt", session, nil))
	}()
	if aborted != http.ErrAbortHandler || time.Since(start) > 4*time.Second || w.deadline.After(expires) {
		t.Fatalf("slow response not aborted at expiry: panic=%v elapsed=%v deadline=%v expiry=%v status=%d body=%s", aborted, time.Since(start), w.deadline, expires, w.status, w.body)
	}
}

type failedBody struct{}

func (failedBody) Read([]byte) (int, error) { return 0, errors.New("upstream interrupted") }
func (failedBody) Close() error             { return nil }

func TestSignedProxyReadAbortsOnUpstreamFailure(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/node" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"node_id":"n1","capabilities":["signed_local_read_v1"]}`))}, nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"X-Jolt-Access-Applied": []string{"v1"}}, Body: failedBody{}}, nil
	})}
	f := setupAgentWithScanStub(t, store.DefaultAgentLimits(), client, false)
	h := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalReads: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}, f.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	var aborted any
	func() {
		defer func() { aborted = recover() }()
		h.ServeHTTP(&deadlineRecorder{httptest.NewRecorder()}, authenticatedRequest(http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/content?path=file.txt", f.adminSession, nil))
	}()
	if aborted != http.ErrAbortHandler {
		t.Fatalf("upstream failure was not aborted: %v", aborted)
	}
}
