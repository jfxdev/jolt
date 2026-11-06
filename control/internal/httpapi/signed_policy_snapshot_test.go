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
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

func TestSignedAuthorizationsEndWithTemporaryPolicy(t *testing.T) {
	rules := []rbac.Rule{
		{Path: "control-tower/shares", Capabilities: []string{"create", "list"}},
		{Path: "nodes/nod_a/files/mounts/media/**", Capabilities: []string{"read", "list", "create", "update"}},
	}
	h := newShareHarness(t, rules)
	share, _ := createShareFor(t, h, map[string]any{"node_id": "nod_a", "mount_id": "media", "path": "public/a.txt", "kind": "file"})
	ctx := context.Background()
	if err := h.storage.SetSubjectPolicies(ctx, "user", "usr_owner", nil); err != nil {
		t.Fatal(err)
	}
	grant, err := h.storage.GrantTemporaryPolicy(ctx, "user", "usr_owner", "pol_share", "admin", "user", "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	s := &Server{store: h.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var authenticated *http.Request
	handler := s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { authenticated = r }))
	handler.ServeHTTP(httptest.NewRecorder(), authenticatedRequest("GET", "/", h.session, nil))
	if authenticated == nil {
		t.Fatal("missing authenticated request")
	}
	now := time.Now().UTC().Truncate(time.Second)
	read, err := s.issueSignedLocalRead(authenticated, "nod_a", "media", "public/a.txt", "content", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := signedauth.VerifyLocalRead(read, keys, "nod_a", "content", "media", "public/a.txt", now)
	if err != nil || claims.ExpiresAt != grant.ExpiresAt.Unix() {
		t.Fatalf("read expiry=%d grant=%d error=%v", claims.ExpiresAt, grant.ExpiresAt.Unix(), err)
	}
	body := []byte(`{"path":"public/a.txt","size":1}`)
	upload, err := s.issueSignedAccess(authenticated, "nod_a", "media", "public/a.txt", "upload_create", signedauth.UploadAdmissionBodyID(body), "", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err = signedauth.VerifyUploadAdmission(upload, keys, "nod_a", "media", "public/a.txt", body, now)
	if err != nil || claims.ExpiresAt != grant.ExpiresAt.Unix() {
		t.Fatalf("upload expiry=%d grant=%d error=%v", claims.ExpiresAt, grant.ExpiresAt.Unix(), err)
	}
	public := httptest.NewRequest("GET", "/", nil)
	shareToken, err := s.issueSignedShareRead(public, share, "public/a.txt", "content", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err = signedauth.VerifyLocalRead(shareToken, keys, "nod_a", "content", "media", "public/a.txt", now)
	if err != nil || claims.ExpiresAt != grant.ExpiresAt.Unix() {
		t.Fatalf("share expiry=%d grant=%d error=%v", claims.ExpiresAt, grant.ExpiresAt.Unix(), err)
	}
	deadline := time.Unix(grant.ExpiresAt.Unix(), 0)
	if _, _, err := signedauth.VerifyLocalRead(read, keys, "nod_a", "content", "media", "public/a.txt", deadline); err == nil {
		t.Fatal("read accepted at temporary grant deadline")
	}
	if _, _, err := signedauth.VerifyUploadAdmission(upload, keys, "nod_a", "media", "public/a.txt", body, deadline); err == nil {
		t.Fatal("upload accepted at temporary grant deadline")
	}
	if _, _, err := signedauth.VerifyLocalRead(shareToken, keys, "nod_a", "content", "media", "public/a.txt", deadline); err == nil {
		t.Fatal("share accepted at temporary grant deadline")
	}
	if err := h.storage.RevokeTemporaryPolicy(ctx, "user", "usr_owner", "pol_share", "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(authenticated, "nod_a", "media", "public/a.txt", "content", now); err == nil {
		t.Fatal("new read signed after revocation")
	}
	if _, err := s.issueSignedShareRead(public, share, "public/a.txt", "content", now); err == nil {
		t.Fatal("new share signed after revocation")
	}
}

func TestSignedPolicySnapshotSerializesTemporaryGrantChanges(t *testing.T) {
	h := newShareHarness(t, fullAccessRules())
	ctx := context.Background()
	if err := h.storage.SetSubjectPolicies(ctx, "user", "usr_owner", nil); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: h.storage}
	errors := make(chan error, 1)
	go func() {
		for i := 0; i < 40; i++ {
			s.agentMu.Lock()
			_, err := h.storage.GrantTemporaryPolicy(ctx, "user", "usr_owner", "pol_share", "admin", "user", "", time.Minute)
			s.agentMu.Unlock()
			if err == nil {
				s.agentMu.Lock()
				err = h.storage.RevokeTemporaryPolicy(ctx, "user", "usr_owner", "pol_share", "admin", "user", "")
				s.agentMu.Unlock()
			}
			if err != nil {
				errors <- err
				return
			}
		}
		errors <- nil
	}()
	for i := 0; i < 80; i++ {
		policies, expiry, err := s.signedPolicySnapshot(ctx, "user", "usr_owner")
		if err != nil {
			t.Fatal(err)
		}
		if len(policies) > 0 && expiry == nil {
			t.Fatal("temporary policy was captured without its expiry")
		}
	}
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
}

func TestSignedProxyStopsAtTemporaryPolicyExpiry(t *testing.T) {
	h := newShareHarness(t, fullAccessRules())
	ctx := context.Background()
	if err := h.storage.SetSubjectPolicies(ctx, "user", "usr_owner", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.storage.GrantTemporaryPolicy(ctx, "user", "usr_owner", "pol_share", "admin", "user", "", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/node" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"node_id":"nod_a","capabilities":["signed_local_read_v1"]}`))}, nil
		}
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"X-Jolt-Access-Applied": []string{"v1"}, "Content-Type": []string{"application/octet-stream"}}, Body: &cancelBody{ctx: r.Context(), ready: ready}}, nil
	})}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	h.handler = newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalReads: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, h.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		r := authenticatedRequest("GET", "/api/v1/nodes/nod_a/mounts/media/files/content?path=public/a.txt", h.session, nil).WithContext(requestCtx)
		h.handler.ServeHTTP(&deadlineRecorder{httptest.NewRecorder()}, r)
	}()
	select {
	case <-ready:
	case <-requestCtx.Done():
		t.Fatal("signed stream did not start")
	}
	select {
	case result := <-done:
		if !errors.Is(asError(result), http.ErrAbortHandler) {
			t.Fatalf("signed stream did not abort: %v", result)
		}
	case <-requestCtx.Done():
		t.Fatal("signed stream outlived temporary grant")
	}
	w := &deadlineRecorder{httptest.NewRecorder()}
	h.handler.ServeHTTP(w, authenticatedRequest("GET", "/api/v1/nodes/nod_a/mounts/media/files/content?path=public/a.txt", h.session, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("expired grant allowed next request: %d %s", w.Code, w.Body)
	}
}
