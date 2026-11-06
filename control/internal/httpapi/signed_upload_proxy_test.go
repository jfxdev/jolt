package httpapi

import (
	"crypto/ed25519"
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

func TestSignedUploadProxyRequiresCapabilityAndConfirmation(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	capability, confirmation := true, true
	mutations := 0
	session := ""
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/node" {
			caps := `[]`
			if capability {
				caps = `["signed_upload_sessions_v1","signed_upload_reauthorize_v1","signed_simple_upload_v1"]`
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"node_id":"n1","capabilities":` + caps + `}`))}, nil
		}
		if r.Method == http.MethodGet {
			body := `{"upload_id":"upl","mount_id":"m","destination_path":"file.txt","overwrite":false}`
			if r.Header.Get("X-Jolt-Internal-Upload-Binding") == "1" {
				body = `{"upload_id":"upl","mount_id":"m","destination_path":"file.txt","overwrite":false,"authorization_actor_id":"admin","authorization_credential_id":"old","authorization_revision":2}`
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		mutations++
		operation, id := signedUploadOperation(strings.TrimPrefix(r.URL.Path, "/api/v1/"), r.Method)
		keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
		var err error
		if operation == "upload_create" {
			body, _ := io.ReadAll(r.Body)
			_, _, err = signedauth.VerifyUploadAdmission(r.Header.Get(signedAuthorizationHeader), keys, "n1", "m", "file.txt", body, time.Now())
		} else if operation == "upload_simple" {
			_, _, err = signedauth.VerifySimpleUpload(r.Header.Get(signedAuthorizationHeader), keys, "n1", "m", "file.txt", r.URL.RawQuery, r.Header.Get("Idempotency-Key"), time.Now())
		} else if operation == "upload_reauthorize" {
			_, _, err = signedauth.VerifyUploadReauthorization(r.Header.Get(signedAuthorizationHeader), keys, "admin", "old", "n1", "m", "file.txt", id, 2, time.Now())
		} else {
			// The credential ID is established by the browser session middleware.
			_, _, verifyErr := signedauth.VerifyLocalUpload(r.Header.Get(signedAuthorizationHeader), keys, "admin", "session-"+security.Digest("jolt-signed-session:"+session), "n1", operation, "m", "file.txt", id, time.Now())
			err = verifyErr
		}
		if err != nil {
			t.Errorf("invalid signed upload: %v", err)
		}
		header := make(http.Header)
		if confirmation {
			header.Set("X-Jolt-Access-Applied", "v1")
		}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgentWithScanStub(t, store.DefaultAgentLimits(), client, false)
	session = f.adminSession
	h := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedUploads: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, f.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	base := "/api/v1/nodes/n1/mounts/m/files/uploads"
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/v1/nodes/n1/mounts/m/files/content?path=file.txt", "new"},
		{http.MethodPost, base, `{"path":"file.txt","size":3}`},
		{http.MethodPatch, base + "/upl", "new"},
		{http.MethodPost, base + "/upl/complete", `{}`},
		{http.MethodDelete, base + "/upl", ""},
		{http.MethodPost, base + "/upl/authorize", `{}`},
	} {
		r := authenticatedRequest(tc.method, tc.path, session, []byte(tc.body))
		r.Header.Set(signedAuthorizationHeader, "forged")
		w := &deadlineRecorder{httptest.NewRecorder()}
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	capability = false
	w := &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, authenticatedRequest(http.MethodPost, base, session, []byte(`{"path":"file.txt","size":3}`)))
	if w.Code != http.StatusConflict || mutations != 6 {
		t.Fatalf("missing capability: %d mutations=%d", w.Code, mutations)
	}
	capability, confirmation = true, false
	w = &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, authenticatedRequest(http.MethodPost, base, session, []byte(`{"path":"file.txt","size":3}`)))
	if w.Code != http.StatusConflict || mutations != 7 {
		t.Fatalf("missing confirmation: %d mutations=%d", w.Code, mutations)
	}
	w = &deadlineRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, f.request(http.MethodPost, base))
	if w.Code != http.StatusForbidden || mutations != 7 {
		t.Fatalf("agent write: %d mutations=%d", w.Code, mutations)
	}
}
