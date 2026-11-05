package httpapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestSignedJobRenewalReconstructsOnlyCurrentCredentials(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	s := &Server{store: f.storage}
	ctx, now := context.Background(), time.Now().UTC()
	userLink := store.JobAuthorizationLink{ActorType: "user", ActorID: "admin", CredentialID: "session-" + security.Digest("jolt-signed-session:"+f.adminSession), CredentialDigest: security.Digest(f.adminSession)}
	r, err := s.signedJobRenewalRequest(ctx, userLink)
	if err != nil || currentUser(r).ID != "admin" || currentActorType(r) != "user" || r.Header.Get("Authorization") != "" {
		t.Fatalf("user renewal context: %v", err)
	}
	wrong := userLink
	wrong.ActorID = "other"
	if _, err := s.signedJobRenewalRequest(ctx, wrong); err == nil {
		t.Fatal("session reassigned to another user")
	}
	if err := f.storage.DeleteSession(ctx, userLink.CredentialDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.signedJobRenewalRequest(ctx, userLink); err == nil {
		t.Fatal("revoked session reconstructed")
	}
	account := store.ServiceAccount{ID: "automation", Name: "automation", Kind: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := f.storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	token := store.ServiceAccountToken{ID: "token", ServiceAccountID: account.ID, Name: "token", TokenHash: security.Digest("automation-secret"), CreatedAt: now}
	if err := f.storage.CreateServiceAccountToken(ctx, token, false); err != nil {
		t.Fatal(err)
	}
	serviceLink := store.JobAuthorizationLink{ActorType: "service_account", ActorID: account.ID, CredentialID: "token-" + token.ID, CredentialDigest: token.TokenHash}
	r, err = s.signedJobRenewalRequest(ctx, serviceLink)
	if err != nil || currentUser(r).ID != account.ID || currentActorType(r) != "service_account" || r.Header.Get("Authorization") != "" {
		t.Fatalf("automation renewal context: %v", err)
	}
	agent := store.JobAuthorizationLink{ActorType: "service_account", ActorID: f.accountID, CredentialID: "token-" + f.tokenID, CredentialDigest: security.Digest(f.token)}
	if _, err := s.signedJobRenewalRequest(ctx, agent); err == nil {
		t.Fatal("agent reconstructed for a write job")
	}
	if err := f.storage.RevokeServiceAccountToken(ctx, account.ID, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.signedJobRenewalRequest(ctx, serviceLink); err == nil {
		t.Fatal("revoked automation credential reconstructed")
	}
}
