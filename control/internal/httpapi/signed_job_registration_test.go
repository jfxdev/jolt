package httpapi

import (
	"crypto/ed25519"
	"encoding/json"
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

func TestRegisterSignedLocalJobLeaseRequiresNodeConfirmation(t *testing.T) {
	placeholder := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), placeholder)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	mode, posts := "success", 0
	job := signedLocalJob{ID: "job", Type: "copy_local", MountID: "m", Source: "source", Destination: "folder/destination"}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer node-token" {
			t.Error("operational token not used")
		}
		header := make(http.Header)
		body := ""
		status := http.StatusOK
		switch r.URL.Path {
		case "/api/v1/node":
			id, caps := "n1", `["signed_job_authorization_registration_v1"]`
			if mode == "wrong node" {
				id = "other"
			}
			if mode == "missing capability" {
				caps = `[]`
			}
			body = fmt.Sprintf(`{"node_id":%q,"capabilities":%s}`, id, caps)
		case "/api/v1/jobs/job":
			current := job
			if mode == "wrong job" {
				current.ID = "other"
			}
			encoded, _ := json.Marshal(current)
			body = string(encoded)
		case "/api/v1/jobs/job/authorization":
			posts++
			if r.Method != http.MethodPost {
				t.Error("wrong registration method")
			}
			envelope := r.Header.Get(signedAuthorizationHeader)
			if envelope == "client-supplied" || envelope == "" {
				t.Error("client context forwarded")
			}
			expected := signedauth.Binding{ActorID: "admin", CredentialID: "session-" + security.Digest("jolt-signed-session:"+f.adminSession), Operation: job.Type, SourceNodeID: "n1", SourceMountID: "m", SourceRoot: job.Source, DestinationNodeID: "n1", DestinationMountID: "m", DestinationRoot: job.Destination, PlanID: job.ID}
			claims, _, err := signedauth.VerifyJobLease(envelope, keys, expected, "n1", 1, time.Now())
			if err != nil {
				t.Errorf("node received invalid lease: %v", err)
			}
			if mode != "missing confirmation" {
				header.Set("X-Jolt-Job-Authorization-Applied", "v1")
			}
			if mode == "duplicate confirmation" {
				header.Add("X-Jolt-Job-Authorization-Applied", "v1")
			}
			revision, execution := 1, false
			if mode == "wrong revision" {
				revision = 2
			}
			if mode == "execution enabled" {
				execution = true
			}
			expiry := claims.ExpiresAt
			if mode == "wrong expiry" {
				expiry--
			}
			body = fmt.Sprintf(`{"revision":%d,"expires_at":%q,"execution_enabled":%t}`, revision, time.Unix(expiry, 0).UTC().Format(time.RFC3339), execution)
			if mode == "missing execution flag" {
				body = fmt.Sprintf(`{"revision":1,"expires_at":%q}`, time.Unix(expiry, 0).UTC().Format(time.RFC3339))
			}
			if mode == "node rejected" {
				status = http.StatusForbidden
			}
			if mode == "duplicate field" {
				body = `{"revision":1,"revision":2}`
			}
			if mode == "oversized" {
				body = strings.Repeat("x", 64*1024+1)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	s := &Server{store: f.storage, client: client, config: config.Config{EncryptionKey: make([]byte, 32), AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest("GET", "/", f.adminSession, nil))
	if request == nil {
		t.Fatal("session not authenticated")
	}
	request.Header.Set(signedAuthorizationHeader, "client-supplied")
	node, err := f.storage.GetNode(request.Context(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if expiry, err := s.registerSignedLocalJobLease(request, node, job.ID, 1); err != nil || !expiry.After(time.Now()) || posts != 1 {
		t.Fatalf("register expiry=%v posts=%d err=%v", expiry, posts, err)
	}
	for _, failure := range []string{"wrong node", "missing capability", "wrong job", "missing confirmation", "duplicate confirmation", "wrong revision", "wrong expiry", "execution enabled", "missing execution flag", "node rejected", "duplicate field", "oversized"} {
		mode = failure
		before := posts
		if _, err := s.registerSignedLocalJobLease(request, node, job.ID, 1); err == nil {
			t.Fatalf("%s accepted", failure)
		}
		if (failure == "wrong node" || failure == "missing capability" || failure == "wrong job") && posts != before {
			t.Fatalf("%s reached registration", failure)
		}
	}
}
