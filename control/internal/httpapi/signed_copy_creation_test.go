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

func TestCreateSignedLocalCopyPersistsBeforeDelivery(t *testing.T) {
	for _, mode := range []string{"success", "expired intent", "lost response", "bad digest", "bad preparation", "invalid options", "missing capability", "missing status capability", "missing execution capability", "capability lost", "bad creation confirmation", "execution disabled", "wrong receipt", "duplicate response", "changed input", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
			input := store.SignedCopyRequest{MountID: "m", Source: "source", Destination: "destination"}
			var f agentFixture
			var delivered string
			var expiredEnvelope string
			var nodeJob signedLocalJob
			posts, infoCalls := 0, 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer node-token" {
					t.Error("incorrect operational credential")
				}
				header := make(http.Header)
				body := ""
				switch r.URL.Path {
				case "/api/v1/node":
					infoCalls++
					caps := `["signed_job_authorization_registration_v1","signed_job_options_binding_v1","signed_local_copy_creation_v1","signed_job_authorization_status_v1","signed_local_copy_execution_v1"]`
					if mode == "missing capability" || mode == "capability lost" && infoCalls > 1 {
						caps = `["signed_job_authorization_registration_v1","signed_job_options_binding_v1","signed_job_authorization_status_v1","signed_local_copy_execution_v1"]`
					}
					if mode == "missing status capability" {
						caps = `["signed_job_authorization_registration_v1","signed_job_options_binding_v1","signed_local_copy_creation_v1","signed_local_copy_execution_v1"]`
					}
					if mode == "missing execution capability" {
						caps = `["signed_job_authorization_registration_v1","signed_job_options_binding_v1","signed_local_copy_creation_v1","signed_job_authorization_status_v1"]`
					}
					body = fmt.Sprintf(`{"node_id":"n1","capabilities":%s}`, caps)
				case "/api/v1/jobs/signed-local-copy/prepare":
					if r.Header.Get(signedAuthorizationHeader) != "" {
						t.Error("client context forwarded to preparation")
					}
					header.Set("X-Jolt-Signed-Job-Preparation", "v1")
					preparedOptions := options
					if mode == "invalid options" {
						preparedOptions.Overwrite = true
					}
					encoded, _ := json.Marshal(preparedOptions)
					digest := signedauth.JobOptionsDigest(preparedOptions)
					if mode == "bad digest" {
						digest = security.Digest("other")
					}
					body = fmt.Sprintf(`{"options":%s,"options_digest":%q,"execution_enabled":true}`, encoded, digest)
					if mode == "bad preparation" {
						body = `{"options":{},"options_digest":"invalid","execution_enabled":true}`
					}
				case "/api/v1/jobs/signed-local-copy":
					posts++
					envelope := r.Header.Get(signedAuthorizationHeader)
					if mode == "expired intent" && envelope == expiredEnvelope {
						t.Error("expired envelope was retransmitted")
					}
					if r.Header.Get("Idempotency-Key") != "request" || envelope == "" || envelope == "client-supplied" {
						t.Error("invalid creation headers")
					}
					binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, "n1", time.Now())
					if err != nil {
						t.Errorf("invalid envelope: %v", err)
					}
					stored, err := f.storage.LoadSignedCopyIntent(r.Context(), "n1", "user", "admin", binding.CredentialID, security.Digest(f.adminSession), "request", keys, time.Now())
					if err != nil || stored.Link.JobID != binding.PlanID || stored.Envelope != envelope {
						t.Errorf("intent absent before delivery: %+v %v", stored, err)
					}
					if delivered != "" && delivered != envelope {
						t.Error("retry changed envelope")
					}
					delivered = envelope
					nodeJob = copyIntentJob(binding.PlanID, input, options)
					nodeJob.State = "waiting_validation"
					if (mode == "lost response" || mode == "changed input" || mode == "revoked") && posts == 1 {
						return nil, errors.New("response lost after acceptance")
					}
					if mode != "bad creation confirmation" {
						header.Set("X-Jolt-Signed-Job-Creation", "v1")
					}
					if mode == "wrong receipt" {
						nodeJob.Destination = "other"
					}
					jobJSON, _ := json.Marshal(nodeJob)
					execution := mode != "execution disabled"
					body = fmt.Sprintf(`{"job":%s,"execution_enabled":%t}`, jobJSON, execution)
					if mode == "duplicate response" {
						body = fmt.Sprintf(`{"job":%s,"execution_enabled":false,"execution_enabled":true}`, jobJSON)
					}
				default:
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			f = setupAgent(t, store.DefaultAgentLimits(), client)
			s := &Server{store: f.storage, client: client, config: config.Config{EncryptionKey: make([]byte, 32), AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
			var request *http.Request
			s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodPost, "/", f.adminSession, nil))
			if request == nil {
				t.Fatal("session not authenticated")
			}
			request.Header.Set(signedAuthorizationHeader, "client-supplied")
			if mode == "expired intent" {
				past := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
				job := copyIntentJob("old-job", input, options)
				var err error
				expiredEnvelope, err = s.issueSignedLocalJobLease(request, "n1", job, 1, past)
				if err != nil {
					t.Fatal(err)
				}
				binding, err := signedauth.VerifiedJobLeaseBinding(expiredEnvelope, keys, "n1", past)
				if err != nil {
					t.Fatal(err)
				}
				link := store.JobAuthorizationLink{NodeID: "n1", JobID: job.ID, ActorType: "user", ActorID: "admin", CredentialID: binding.CredentialID, CredentialDigest: security.Digest(f.adminSession), Binding: binding}
				body, _ := json.Marshal(input)
				if _, _, err := f.storage.CreateSignedCopyIntent(request.Context(), link, "request", body, options, expiredEnvelope, keys, past); err != nil {
					t.Fatal(err)
				}
			}
			id, err := s.createSignedLocalCopy(request, "n1", "request", input)
			switch mode {
			case "success", "expired intent":
				if err != nil || id == "" || posts != 1 {
					t.Fatalf("id=%q posts=%d err=%v", id, posts, err)
				}
				if id2, err := s.createSignedLocalCopy(request, "n1", "request", input); err != nil || id2 != id || posts != 1 {
					t.Fatalf("repeat id=%q posts=%d err=%v", id2, posts, err)
				}
			case "lost response":
				if err == nil || posts != 1 {
					t.Fatalf("expected lost response: posts=%d err=%v", posts, err)
				}
				id, err = s.createSignedLocalCopy(request, "n1", "request", input)
				if err != nil || id == "" || id != nodeJob.ID || posts != 2 {
					t.Fatalf("retry id=%q posts=%d err=%v", id, posts, err)
				}
			case "changed input":
				if err == nil || posts != 1 {
					t.Fatalf("expected lost response: posts=%d err=%v", posts, err)
				}
				input.Source = "other"
				if _, err := s.createSignedLocalCopy(request, "n1", "request", input); err == nil || posts != 1 {
					t.Fatalf("changed request accepted: posts=%d err=%v", posts, err)
				}
			case "revoked":
				if err == nil || posts != 1 {
					t.Fatalf("expected lost response: posts=%d err=%v", posts, err)
				}
				if err := f.storage.DeleteSession(request.Context(), security.Digest(f.adminSession)); err != nil {
					t.Fatal(err)
				}
				if _, err := s.createSignedLocalCopy(request, "n1", "request", input); err == nil || posts != 1 {
					t.Fatalf("revoked request delivered: posts=%d err=%v", posts, err)
				}
			case "bad creation confirmation", "execution disabled", "wrong receipt", "duplicate response":
				if err == nil || posts != 1 {
					t.Fatalf("invalid confirmation accepted: posts=%d err=%v", posts, err)
				}
			default:
				if err == nil || posts != 0 {
					t.Fatalf("invalid preparation delivered: posts=%d err=%v", posts, err)
				}
			}
			if mode == "success" || mode == "expired intent" || mode == "lost response" {
				link, err := f.storage.GetJobAuthorizationLink(request.Context(), "n1", id)
				if err != nil || link.ActorID != "admin" || link.Binding.JobOptionsDigest != signedauth.JobOptionsDigest(options) {
					t.Fatalf("durable link=%+v err=%v", link, err)
				}
			}
		})
	}
}
