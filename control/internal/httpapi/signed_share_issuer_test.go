package httpapi

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

func TestSignedShareRechecksCreatorAndRequiresNodeConfirmation(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	share, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "public/a.txt", "kind": "file", "max_downloads": 1,
	})
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	confirmation, capability := true, true
	var calls int
	expectedShare := share.ID
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/node" {
			caps := `[]`
			if capability {
				caps = `["signed_local_read_v1","signed_local_tree_read_v1"]`
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"node_id":"nod_a","capabilities":` + caps + `}`))}, nil
		}
		calls++
		if calls == 1 && r.Header.Get("Range") != "bytes=0-3" {
			t.Errorf("range not forwarded: %q", r.Header.Get("Range"))
		}
		claims, _, err := signedauth.VerifyLocalRead(r.Header.Get(signedAuthorizationHeader), map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, "nod_a", "content", "media", "public/a.txt", time.Now())
		if err != nil || claims.Binding.ActorID != "usr_owner" || claims.Binding.CredentialID != "share-"+expectedShare {
			t.Errorf("share token: %+v %v", claims, err)
		}
		header := make(http.Header)
		if confirmation {
			header.Set("X-Jolt-Access-Applied", "v1")
		}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader("data"))}, nil
	})}
	harness.handler = newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalReads: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, harness.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/public/shares/"+token+"/content", nil)
	request.Header.Set("Range", "bytes=0-3")
	w := &deadlineRecorder{httptest.NewRecorder()}
	harness.handler.ServeHTTP(w, request)
	if w.Code != http.StatusOK || w.Body.String() != "data" || calls != 1 {
		t.Fatalf("last permitted download: %d %s calls=%d", w.Code, w.Body, calls)
	}
	nextShare, next := createShareFor(t, harness, map[string]any{"node_id": "nod_a", "mount_id": "media", "path": "public/a.txt", "kind": "file", "max_downloads": 1})
	expectedShare = nextShare.ID
	capability = false
	w = &deadlineRecorder{httptest.NewRecorder()}
	harness.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/public/shares/"+next+"/content", nil))
	if w.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("old node: %d %s calls=%d", w.Code, w.Body, calls)
	}
	capability, confirmation = true, false
	w = &deadlineRecorder{httptest.NewRecorder()}
	harness.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/public/shares/"+next+"/content", nil))
	if w.Code != http.StatusConflict || calls != 2 || strings.Contains(w.Body.String(), "data") {
		t.Fatalf("missing confirmation: %d %s calls=%d", w.Code, w.Body, calls)
	}
	current, err := harness.storage.GetShare(context.Background(), nextShare.ID)
	if err != nil || current.DownloadCount != 0 {
		t.Fatalf("failed enforcement consumed download quota: %+v %v", current, err)
	}
	if err := harness.storage.SetSubjectPolicies(context.Background(), "user", "usr_owner", nil); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "/content"} {
		w = &deadlineRecorder{httptest.NewRecorder()}
		harness.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/public/shares/"+next+suffix, nil))
		if w.Code != http.StatusGone || calls != 2 {
			t.Fatalf("revoked creator %s: %d %s calls=%d", suffix, w.Code, w.Body, calls)
		}
	}
}

func TestSignedShareIssuerBindsCurrentShareAndScope(t *testing.T) {
	h := newShareHarness(t, fullAccessRules())
	share, _ := createShareFor(t, h, map[string]any{"node_id": "nod_a", "mount_id": "media", "path": "public", "kind": "directory"})
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: h.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	now := time.Now().UTC().Truncate(time.Second)
	token, err := s.issueSignedShareRead(r, share, "public/sub", "list", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, "nod_a", "list", "media", "public/sub", now)
	if err != nil || claims.Binding.ActorID != "usr_owner" || claims.Binding.CredentialID != "share-"+share.ID || claims.ExpiresAt-claims.IssuedAt != 30 {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	for _, path := range []string{"other", "public/../other", "/public", "public//sub"} {
		if _, err := s.issueSignedShareRead(r, share, path, "content", now); err == nil {
			t.Fatalf("share escaped its root: %q", path)
		}
	}
	changed := share
	changed.MountID = "other"
	if _, err := s.issueSignedShareRead(r, changed, "public/sub", "content", now); err == nil {
		t.Fatal("share redirected to another mount")
	}
	if err := h.storage.RevokeShare(context.Background(), share.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedShareRead(r, share, "public/sub", "content", now); err == nil {
		t.Fatal("revoked share issued a token")
	}
}
