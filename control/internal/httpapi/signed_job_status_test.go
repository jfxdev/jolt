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

func TestSignedJobStatusValidatesNodeAndResponse(t *testing.T) {
	placeholder := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), placeholder)
	mode, statusRequests := "initial", 0
	expiry := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	digest := security.Digest("private-envelope")
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer node-token" || r.Header.Get(signedAuthorizationHeader) != "" {
			t.Error("incorrect node credentials or client context forwarded")
		}
		header := make(http.Header)
		body, code := "", http.StatusOK
		switch r.URL.Path {
		case "/api/v1/node":
			id, caps := "n1", `["signed_job_authorization_status_v1"]`
			if mode == "wrong node" {
				id = "other"
			}
			if mode == "missing capability" {
				caps = `[]`
			}
			body = fmt.Sprintf(`{"node_id":%q,"capabilities":%s}`, id, caps)
		case "/api/v1/jobs/job/authorization":
			statusRequests++
			if r.Method != http.MethodGet {
				t.Error("wrong status method")
			}
			if mode != "missing header" {
				header.Set("X-Jolt-Job-Authorization-Status", "v1")
			}
			if mode == "duplicate header" {
				header.Add("X-Jolt-Job-Authorization-Status", "v1")
			}
			body = `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":false}`
			if mode == "expired" {
				body = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, expiry.Format(time.RFC3339), digest)
			}
			switch mode {
			case "missing revision":
				body = `{"expires_at":null,"envelope_digest":"","execution_enabled":false}`
			case "missing expiry":
				body = `{"revision":0,"envelope_digest":"","execution_enabled":false}`
			case "missing digest":
				body = `{"revision":0,"expires_at":null,"execution_enabled":false}`
			case "missing execution":
				body = `{"revision":0,"expires_at":null,"envelope_digest":""}`
			case "execution enabled":
				body = `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":true}`
			case "zero with digest":
				body = fmt.Sprintf(`{"revision":0,"expires_at":null,"envelope_digest":%q,"execution_enabled":false}`, digest)
			case "zero with expiry":
				body = fmt.Sprintf(`{"revision":0,"expires_at":%q,"envelope_digest":"","execution_enabled":false}`, expiry.Format(time.RFC3339))
			case "invalid digest":
				body = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":"invalid","execution_enabled":false}`, expiry.Format(time.RFC3339))
			case "null expiry":
				body = fmt.Sprintf(`{"revision":1,"expires_at":null,"envelope_digest":%q,"execution_enabled":false}`, digest)
			case "extra field":
				body = `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":false,"other":1}`
			case "duplicate field":
				body = `{"revision":0,"revision":1,"expires_at":null,"envelope_digest":"","execution_enabled":false}`
			case "oversized":
				body = strings.Repeat("x", 64*1024+1)
			case "rejected":
				code = http.StatusForbidden
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	s := &Server{store: f.storage, client: client, config: config.Config{EncryptionKey: make([]byte, 32)}}
	node, err := f.storage.GetNode(t.Context(), "n1")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(signedAuthorizationHeader, "client-supplied")
	if result, err := s.signedJobStatus(request, node, "job"); err != nil || result.Revision != 0 || !result.Expiry.IsZero() || result.Digest != "" {
		t.Fatalf("initial status %+v %v", result, err)
	}
	mode = "expired"
	if result, err := s.signedJobStatus(request, node, "job"); err != nil || result.Revision != 1 || !result.Expiry.Equal(expiry) || result.Digest != digest {
		t.Fatalf("expired status %+v %v", result, err)
	}
	for _, failure := range []string{"wrong node", "missing capability", "missing header", "duplicate header", "missing revision", "missing expiry", "missing digest", "missing execution", "execution enabled", "zero with digest", "zero with expiry", "invalid digest", "null expiry", "extra field", "duplicate field", "oversized", "rejected"} {
		mode = failure
		before := statusRequests
		if _, err := s.signedJobStatus(request, node, "job"); err == nil {
			t.Fatalf("%s accepted", failure)
		}
		if (failure == "wrong node" || failure == "missing capability") && statusRequests != before {
			t.Fatalf("%s reached status endpoint", failure)
		}
	}
}

func TestReconcileSignedJobAuthorization(t *testing.T) {
	statusBody := `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":false}`
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		body := `{"node_id":"n1","capabilities":["signed_job_authorization_status_v1"]}`
		if strings.HasSuffix(r.URL.Path, "/authorization") {
			header.Set("X-Jolt-Job-Authorization-Status", "v1")
			body = statusBody
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	s := &Server{store: f.storage, client: client, config: config.Config{EncryptionKey: make([]byte, 32)}}
	ctx, now := t.Context(), time.Now().UTC().Truncate(time.Second)
	node, err := f.storage.GetNode(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	credential := "session-" + security.Digest("jolt-signed-session:"+f.adminSession)
	binding := signedauth.Binding{ActorID: "admin", CredentialID: credential, Operation: "copy_local", SourceNodeID: "n1", SourceMountID: "m", SourceRoot: "source", DestinationNodeID: "n1", DestinationMountID: "m", DestinationRoot: "destination", PlanID: "job"}
	link := store.JobAuthorizationLink{NodeID: node.ID, JobID: "job", ActorType: "user", ActorID: "admin", CredentialID: credential, CredentialDigest: security.Digest(f.adminSession), Binding: binding}
	if err := f.storage.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if state, err := s.reconcileSignedJobAuthorization(request, node, "job"); err != nil || state != signedJobSynchronized {
		t.Fatalf("initial state=%v err=%v", state, err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	bound, err := signedauth.JobLeaseBinding(binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	claims := signedauth.Claims{Version: 1, KeyID: "key", Binding: bound, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/n1/files/mounts/m/**","capabilities":["read","create"]}]}`)}
	envelope, err := signedauth.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.storage.StageJobAuthorization(ctx, node.ID, "job", 1, envelope, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatal(err)
	}
	if state, err := s.reconcileSignedJobAuthorization(request, node, "job"); err != nil || state != signedJobPendingDelivery {
		t.Fatalf("pending state=%v err=%v", state, err)
	}
	expiry := now.Add(30 * time.Second).Format(time.RFC3339)
	statusBody = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, expiry, security.Digest("different"))
	if _, err := s.reconcileSignedJobAuthorization(request, node, "job"); err == nil {
		t.Fatal("mismatched envelope accepted")
	}
	statusBody = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, now.Add(29*time.Second).Format(time.RFC3339), security.Digest(envelope))
	if _, err := s.reconcileSignedJobAuthorization(request, node, "job"); err == nil {
		t.Fatal("mismatched expiry accepted")
	}
	statusBody = fmt.Sprintf(`{"revision":2,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, expiry, security.Digest(envelope))
	if _, err := s.reconcileSignedJobAuthorization(request, node, "job"); err == nil {
		t.Fatal("mismatched revision accepted")
	}
	statusBody = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, expiry, security.Digest(envelope))
	if state, err := s.reconcileSignedJobAuthorization(request, node, "job"); err != nil || state != signedJobConfirmed {
		t.Fatalf("confirmed state=%v err=%v", state, err)
	}
	if state, err := s.reconcileSignedJobAuthorization(request, node, "job"); err != nil || state != signedJobSynchronized {
		t.Fatalf("repeated state=%v err=%v", state, err)
	}
	stored, err := f.storage.GetJobAuthorizationLink(ctx, node.ID, "job")
	if err != nil || stored.PendingRevision != 0 || stored.ConfirmedRevision != 1 || stored.ConfirmedDigest != security.Digest(envelope) {
		t.Fatalf("stored link=%+v err=%v", stored, err)
	}
	bound, err = signedauth.JobLeaseBinding(binding, 2)
	if err != nil {
		t.Fatal(err)
	}
	claims.Binding = bound
	second, err := signedauth.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.storage.StageJobAuthorization(ctx, node.ID, "job", 2, second, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.DeleteSession(ctx, link.CredentialDigest); err != nil {
		t.Fatal(err)
	}
	statusBody = fmt.Sprintf(`{"revision":2,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, expiry, security.Digest(second))
	if _, err := s.reconcileSignedJobAuthorization(request, node, "job"); err == nil {
		t.Fatal("revoked credential confirmed")
	}
}

func TestReconcileExpiredSignedJobAuthorization(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(fmt.Sprintf("delivered_%t", delivered), func(t *testing.T) {
			statusBody := `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":false}`
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				header := make(http.Header)
				body := `{"node_id":"n1","capabilities":["signed_job_authorization_status_v1"]}`
				if strings.HasSuffix(r.URL.Path, "/authorization") {
					header.Set("X-Jolt-Job-Authorization-Status", "v1")
					body = statusBody
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			f := setupAgent(t, store.DefaultAgentLimits(), client)
			s := &Server{store: f.storage, client: client, config: config.Config{EncryptionKey: make([]byte, 32)}}
			ctx, issued := t.Context(), time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
			node, err := f.storage.GetNode(ctx, "n1")
			if err != nil {
				t.Fatal(err)
			}
			credential := "session-" + security.Digest("jolt-signed-session:"+f.adminSession)
			binding := signedauth.Binding{ActorID: "admin", CredentialID: credential, Operation: "copy_local", SourceNodeID: "n1", SourceMountID: "m", SourceRoot: "source", DestinationNodeID: "n1", DestinationMountID: "m", DestinationRoot: "destination", PlanID: "job"}
			link := store.JobAuthorizationLink{NodeID: node.ID, JobID: "job", ActorType: "user", ActorID: "admin", CredentialID: credential, CredentialDigest: security.Digest(f.adminSession), Binding: binding}
			if err := f.storage.CreateJobAuthorizationLink(ctx, link, issued); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			bound, err := signedauth.JobLeaseBinding(binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			claims := signedauth.Claims{Version: 1, KeyID: "key", Binding: bound, IssuedAt: issued.Unix(), ExpiresAt: issued.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/n1/files/mounts/m/**","capabilities":["read","create"]}]}`)}
			envelope, err := signedauth.Sign(claims, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.storage.StageJobAuthorization(ctx, node.ID, "job", 1, envelope, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, issued); err != nil {
				t.Fatal(err)
			}
			if delivered {
				statusBody = fmt.Sprintf(`{"revision":1,"expires_at":%q,"envelope_digest":%q,"execution_enabled":false}`, issued.Add(30*time.Second).Format(time.RFC3339), security.Digest(envelope))
			}
			state, err := s.reconcileSignedJobAuthorization(httptest.NewRequest(http.MethodGet, "/", nil), node, "job")
			if err != nil || state != signedJobExpiredResolved {
				t.Fatalf("state=%v err=%v", state, err)
			}
			stored, err := f.storage.GetJobAuthorizationLink(ctx, node.ID, "job")
			wantRevision := uint64(0)
			if delivered {
				wantRevision = 1
			}
			if err != nil || stored.PendingRevision != 0 || stored.ConfirmedRevision != wantRevision {
				t.Fatalf("stored=%+v err=%v", stored, err)
			}
		})
	}
}
