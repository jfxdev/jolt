package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
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

func TestSignedJobRenewalLoopFollowsTheNodeJob(t *testing.T) {
	for _, mode := range []string{"running", "completed", "failed", "canceled", "gone", "node down", "cancel requested"} {
		t.Run(mode, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			job := signedLocalJob{ID: "job", Type: "copy_local", State: mode, MountID: "m", Source: "source", Destination: "destination"}
			var delivered []string
			var expiry time.Time
			var pending string
			remoteRevision := 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				header := make(http.Header)
				body, status := "", http.StatusOK
				switch r.URL.Path {
				case "/api/v1/node":
					body = `{"node_id":"n1","capabilities":["signed_job_authorization_status_v1","signed_job_authorization_registration_v1","signed_job_options_binding_v1"]}`
				case "/api/v1/jobs/job":
					switch mode {
					case "node down":
						return nil, errors.New("connection refused")
					case "gone":
						status, body = http.StatusNotFound, `{"error":{"code":"job_not_found"}}`
					default:
						current := job
						if mode == "cancel requested" {
							current.State = "cancel_requested"
						}
						encoded, _ := json.Marshal(current)
						body = string(encoded)
					}
				case "/api/v1/jobs/job/authorization":
					if r.Method == http.MethodGet {
						header.Set("X-Jolt-Job-Authorization-Status", "v1")
						body = `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":true}`
						if remoteRevision > 0 {
							body = fmt.Sprintf(`{"revision":%d,"expires_at":%q,"envelope_digest":%q,"execution_enabled":true}`, remoteRevision, expiry.Format(time.RFC3339), security.Digest(pending))
						}
					} else {
						delivered = append(delivered, r.Header.Get(signedAuthorizationHeader))
						remoteRevision++
						pending = r.Header.Get(signedAuthorizationHeader)
						// Report the expiry of the lease actually sent.
						sent, err := signedauth.VerifiedJobLeaseBinding(pending, keys, "n1", time.Now().UTC())
						if err != nil {
							t.Errorf("sent lease did not verify: %v", err)
						} else if sentClaims, _, err := signedauth.VerifyJobLease(pending, keys, sent, "n1", uint64(remoteRevision), time.Now().UTC()); err != nil {
							t.Errorf("sent lease revision: %v", err)
						} else {
							expiry = time.Unix(sentClaims.ExpiresAt, 0).UTC()
						}
						header.Set("X-Jolt-Job-Authorization-Applied", "v1")
						body = fmt.Sprintf(`{"revision":%d,"expires_at":%q,"execution_enabled":true}`, remoteRevision, expiry.Format(time.RFC3339))
					}
				default:
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			f := setupAgent(t, store.DefaultAgentLimits(), client)
			s := &Server{store: f.storage, client: client, log: slog.New(slog.NewTextHandler(io.Discard, nil)), config: config.Config{EncryptionKey: make([]byte, 32), AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
			var request *http.Request
			s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodGet, "/", f.adminSession, nil))
			ctx, now := request.Context(), time.Now().UTC().Truncate(time.Second)
			// Seed the link with the lease the node would hold for revision 1.
			first, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := signedauth.VerifiedJobLeaseBinding(first, keys, "n1", now)
			if err != nil {
				t.Fatal(err)
			}
			claims, _, err := signedauth.VerifyJobLease(first, keys, binding, "n1", 1, now)
			if err != nil {
				t.Fatal(err)
			}
			expiry = time.Unix(claims.ExpiresAt, 0).UTC()
			link := store.JobAuthorizationLink{NodeID: "n1", JobID: job.ID, ActorType: "user", ActorID: "admin", CredentialID: binding.CredentialID, CredentialDigest: security.Digest(f.adminSession), Binding: binding}
			if err := f.storage.CreateJobAuthorizationLink(ctx, link, now); err != nil {
				t.Fatal(err)
			}
			s.renewActiveSignedJobs(ctx)
			active, err := f.storage.ListActiveJobAuthorizationLinks(ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "running":
				if len(active) != 1 || len(delivered) != 1 {
					t.Fatalf("running job: active=%d delivered=%d", len(active), len(delivered))
				}
				stored, err := f.storage.GetJobAuthorizationLink(ctx, "n1", job.ID)
				if err != nil || stored.ConfirmedRevision != 1 {
					t.Fatalf("lease not confirmed: %+v %v", stored, err)
				}
			case "completed", "failed", "canceled", "gone":
				if len(active) != 0 || len(delivered) != 0 {
					t.Fatalf("%s job kept renewing: active=%d delivered=%d", mode, len(active), len(delivered))
				}
			default: // node down, cancel requested: nothing sent, link kept
				if len(active) != 1 || len(delivered) != 0 {
					t.Fatalf("%s: active=%d delivered=%d", mode, len(active), len(delivered))
				}
			}
		})
	}
}
