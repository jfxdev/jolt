package httpapi

import (
	"context"
	"crypto/ed25519"
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

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/metrics"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
	"github.com/jfxdev/jolt/control/internal/workload"
)

func TestWorkloadShareExpiryAndCurrentMapping(t *testing.T) {
	h := newShareHarness(t, fullAccessRules())
	ctx, now := context.Background(), time.Now().UTC()
	account := store.ServiceAccount{ID: "workload-account", Name: "workload", Kind: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now}
	group := store.AccessGroup{ID: "workload-group", Name: "workload-group", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := h.storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.CreateAccessGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetAccessGroupNodes(ctx, group.ID, []string{h.nodeID}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetAccessGroupPolicies(ctx, group.ID, []string{"pol_share"}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetServiceAccountGroups(ctx, account.ID, []string{group.ID}); err != nil {
		t.Fatal(err)
	}
	identity := store.WorkloadIdentity{CredentialID: "workload-credential", ServiceAccountID: account.ID, ProviderID: "issuer", Issuer: "https://issuer.example", Subject: "workload", Audience: "jolt"}
	if err := h.storage.CreateWorkloadIdentity(ctx, identity, nil, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "providers.json")
	data := `{"version":1,"providers":[{"id":"issuer","type":"jwt","issuer":"https://issuer.example","audience":"jolt","jwks_url":"https://issuer.example/jwks","algorithms":["RS256"]}]}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := workload.LoadProviders(file)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: h.storage, config: config.Config{WorkloadProviders: providers}, registry: metrics.NewRegistry(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	expiry := now.Add(30 * time.Second).Truncate(time.Second)
	verified := workload.Identity{ProviderID: identity.ProviderID, Issuer: identity.Issuer, Subject: identity.Subject, Audience: identity.Audience, ExpiresAt: expiry}
	requestCtx := context.WithValue(ctx, userKey, store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: true})
	requestCtx = context.WithValue(requestCtx, actorTypeKey, "service_account")
	requestCtx = context.WithValue(requestCtx, groupKey, []string{group.ID})
	requestCtx = context.WithValue(requestCtx, credentialKey, "token-"+identity.CredentialID)
	requestCtx = context.WithValue(requestCtx, workloadIdentityKey, verified)
	body := `{"node_id":"nod_a","mount_id":"media","path":"a.txt","kind":"file","expires_in_seconds":3600}`
	request := httptest.NewRequest("POST", "/api/v1/control-tower/shares", strings.NewReader(body)).WithContext(requestCtx)
	response := httptest.NewRecorder()
	s.createShare(response, request)
	var created struct {
		Share store.Share `json:"share"`
		Token string      `json:"token"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.Share.ExpiresAt == nil || !created.Share.ExpiresAt.Equal(expiry) {
		t.Fatalf("share expiry: %d %s", response.Code, response.Body)
	}
	stored, err := h.storage.GetShare(ctx, created.Share.ID)
	if err != nil || stored.CreatedCredentialID != identity.CredentialID || stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(expiry) {
		t.Fatalf("stored share=%+v err=%v", stored, err)
	}
	if _, _, _, err := s.currentShareCreator(request, stored, now); err != nil {
		t.Fatalf("valid mapping: %v", err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s.config.AuthorizationSigningKeyID, s.config.AuthorizationSigningKey = "key", private
	envelope, err := s.issueSignedShareRead(request, stored, "a.txt", "content", now)
	if err != nil {
		t.Fatalf("signed share: %v", err)
	}
	claims, _, err := signedauth.VerifyLocalRead(envelope, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, h.nodeID, "content", "media", "a.txt", now)
	if err != nil || claims.ExpiresAt != expiry.Unix() {
		t.Fatalf("signed share expiry: %+v %v", claims, err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("content"))}, nil
	})}
	h.handler = newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), WorkloadProviders: providers}, h.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	publicPath := "/api/v1/public/shares/" + created.Token + "/content"
	if w := h.public(t, "GET", publicPath, nil); w.Code != http.StatusOK {
		t.Fatalf("public share: %d %s", w.Code, w.Body)
	}
	s.config.WorkloadProviders = nil
	if _, _, _, err := s.currentShareCreator(request, stored, now); err == nil {
		t.Fatal("share survived provider removal")
	}
	s.config.WorkloadProviders = providers
	if err := h.storage.SetWorkloadIdentityEnabled(ctx, account.ID, identity.CredentialID, false, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.currentShareCreator(request, stored, now); err == nil {
		t.Fatal("share survived mapping disable")
	}
	if w := h.public(t, "GET", publicPath, nil); w.Code != http.StatusGone {
		t.Fatalf("public share survived mapping disable: %d %s", w.Code, w.Body)
	}
}
