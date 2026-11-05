package httpapi

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func TestDeliverPendingSignedJobLease(t *testing.T) {
	for _, mode := range []string{"success", "lost response", "changed context", "revoked", "changed job", "missing registration capability", "wrong confirmation"} {
		t.Run(mode, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			job := signedLocalJob{ID: "job", Type: "copy_local", MountID: "m", Source: "source", Destination: "destination"}
			var pending string
			var expiry time.Time
			remoteRevision, posts := 0, 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer node-token" {
					t.Error("incorrect operational token")
				}
				header := make(http.Header)
				body := ""
				switch r.URL.Path {
				case "/api/v1/node":
					caps := `["signed_job_authorization_status_v1","signed_job_authorization_registration_v1"]`
					if mode == "missing registration capability" {
						caps = `["signed_job_authorization_status_v1"]`
					}
					body = fmt.Sprintf(`{"node_id":"n1","capabilities":%s}`, caps)
				case "/api/v1/jobs/job":
					current := job
					if mode == "changed job" {
						current.Source = "other"
					}
					encoded, _ := json.Marshal(current)
					body = string(encoded)
				case "/api/v1/jobs/job/authorization":
					if r.Method == http.MethodGet {
						header.Set("X-Jolt-Job-Authorization-Status", "v1")
						body = `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":false}`
						if remoteRevision == 1 {
							body = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, expiry.Format(time.RFC3339), security.Digest(pending))
						}
					} else {
						posts++
						if r.Header.Get(signedAuthorizationHeader) != pending {
							t.Error("delivery did not use exact pending envelope")
						}
						remoteRevision = 1
						if mode == "lost response" {
							return nil, errors.New("connection closed after acceptance")
						}
						header.Set("X-Jolt-Job-Authorization-Applied", "v1")
						revision := 1
						if mode == "wrong confirmation" {
							revision = 2
						}
						body = fmt.Sprintf(`{"revision":%d,"expires_at":%q,"execution_enabled":false}`, revision, expiry.Format(time.RFC3339))
					}
				default:
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			f := setupAgent(t, store.DefaultAgentLimits(), client)
			s := &Server{store: f.storage, client: client, config: config.Config{EncryptionKey: make([]byte, 32), AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
			var request *http.Request
			s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodGet, "/", f.adminSession, nil))
			if request == nil {
				t.Fatal("session not authenticated")
			}
			ctx, now := request.Context(), time.Now().UTC().Truncate(time.Second)
			node, err := f.storage.GetNode(ctx, "n1")
			if err != nil {
				t.Fatal(err)
			}
			pending, err = s.issueSignedLocalJobLease(request, node.ID, job, 1, now)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := signedauth.VerifiedJobLeaseBinding(pending, keys, node.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			claims, _, err := signedauth.VerifyJobLease(pending, keys, binding, node.ID, 1, now)
			if err != nil {
				t.Fatal(err)
			}
			expiry = time.Unix(claims.ExpiresAt, 0).UTC()
			if mode == "changed context" {
				claims.Context = json.RawMessage(`{"version":1,"rules":[]}`)
				pending, err = signedauth.Sign(claims, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			link := store.JobAuthorizationLink{NodeID: node.ID, JobID: job.ID, ActorType: "user", ActorID: "admin", CredentialID: binding.CredentialID, CredentialDigest: security.Digest(f.adminSession), Binding: binding}
			if err := f.storage.CreateJobAuthorizationLink(ctx, link, now); err != nil {
				t.Fatal(err)
			}
			if _, err := f.storage.StageJobAuthorization(ctx, node.ID, job.ID, 1, pending, keys, now); err != nil {
				t.Fatal(err)
			}
			if mode == "revoked" {
				if err := f.storage.DeleteSession(ctx, link.CredentialDigest); err != nil {
					t.Fatal(err)
				}
			}
			state, err := s.deliverPendingSignedJobLease(request, node.ID, job.ID)
			switch mode {
			case "success":
				if err != nil || state != signedJobConfirmed || posts != 1 {
					t.Fatalf("state=%v posts=%d err=%v", state, posts, err)
				}
			case "lost response", "wrong confirmation":
				if err == nil || posts != 1 {
					t.Fatalf("delivery should await reconciliation: posts=%d err=%v", posts, err)
				}
				state, err = s.deliverPendingSignedJobLease(request, node.ID, job.ID)
				if err != nil || state != signedJobConfirmed || posts != 1 {
					t.Fatalf("reconciled state=%v posts=%d err=%v", state, posts, err)
				}
			default:
				if err == nil || posts != 0 {
					t.Fatalf("unsafe delivery posts=%d err=%v", posts, err)
				}
			}
		})
	}
}
