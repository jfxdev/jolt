package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

type transferFake struct {
	mu                  sync.Mutex
	calls               []string
	createHeaders       []http.Header
	moving              bool
	previewBodies       []map[string]any
	previewHeaders      []http.Header
	unsignedPlans       int
	createBodies        []map[string]any
	deliveries          []string
	canceled            []string
	sourceIdentity      string
	destinationCaps     string
	failLinkAfterCreate bool
	remoteRevision      int
	expiry              time.Time
	lastEnvelope        string
	keys                map[string]ed25519.PublicKey
}

const transferCaps = `["signed_transfer_pull_v1","signed_local_copy_execution_v1","signed_job_authorization_registration_v1","signed_job_options_binding_v1","signed_job_authorization_status_v1"]`

func (f *transferFake) jobType() string {
	if f.moving {
		return "transfer_move_batch"
	}
	return "transfer_pull_batch"
}

func (f *transferFake) job(id string, options signedauth.JobOptions) string {
	encoded, _ := json.Marshal(map[string]any{
		"job_id": id, "type": f.jobType(), "state": "waiting_validation", "mount_id": "incoming", "source_path": "exports", "destination_path": "imports/archive",
		"overwrite": options.Overwrite, "recursive": options.Recursive, "conflict_policy": options.ConflictPolicy, "source_change_policy": options.SourceChangePolicy,
		"verify_checksum": options.VerifyChecksum, "bandwidth_limit_bytes_per_second": options.BandwidthLimit, "max_parallel_files": options.MaxParallelFiles,
		"max_parallel_chunks": options.MaxParallelChunks, "max_attempts": options.MaxAttempts,
		"peer_node_id": f.sourceIdentity, "source_grant_id": "source-grant", "destination_grant_id": "destination-grant",
	})
	return string(encoded)
}

func (f *transferFake) handle(t *testing.T, r *http.Request) (int, http.Header, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	f.calls = append(f.calls, r.Method+" "+r.URL.Host+r.URL.Path)
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", Recursive: true, MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	jobPath := "/api/v1/jobs/"
	switch {
	case r.URL.Path == "/api/v1/node":
		if r.URL.Host == "source.test" {
			return 200, header, `{"node_id":"` + f.sourceIdentity + `","fingerprint":"FP"}`
		}
		return 200, header, `{"node_id":"destination","fingerprint":"FP","capabilities":` + f.destinationCaps + `}`
	case r.URL.Path == "/api/v1/grants":
		if r.URL.Host == "source.test" {
			return 200, header, `{"items":[{"grant_id":"source-grant","peer_node_id":"destination","mount_id":"source-media","path":"exports","direction":"send","enabled":true,"permissions":{"read":true,"delete":true}}]}`
		}
		return 200, header, `{"items":[{"grant_id":"destination-grant","peer_node_id":"` + f.sourceIdentity + `","mount_id":"incoming","path":"imports","direction":"receive","enabled":true,"permissions":{"write":true},"conflict_policies":["fail","rename"]}]}`
	case r.URL.Path == "/api/v1/mounts":
		return 200, header, `{"items":[{"mount_id":"incoming","name":"Incoming","enabled":true,"state":"available","writable":true}]}`
	case strings.HasSuffix(r.URL.Path, "/files/metadata"):
		return 200, header, `{"name":"item","path":"item","type":"file"}`
	case r.URL.Path == "/api/v1/transfers/signed-pull/batch/prepare":
		encoded, _ := json.Marshal(options)
		return 200, header, fmt.Sprintf(`{"options":%s,"options_digest":%q,"execution_enabled":true}`, encoded, signedauth.JobOptionsDigest(options))
	case r.URL.Path == "/api/v1/transfers/pull/batch/plan":
		f.unsignedPlans++
		return 200, header, `{"files_total":99}`
	case r.URL.Path == "/api/v1/transfers/signed-pull/batch/plan":
		f.previewHeaders = append(f.previewHeaders, r.Header.Clone())
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.previewBodies = append(f.previewBodies, body)
		header.Set("X-Jolt-Signed-Transfer-Plan", "v1")
		if body["operation"] == "move" {
			return 200, header, `{"files_total":2,"bytes_total":12,"copy_count":2,"items":[],"move_plan":{"plan_id":"plan_1","token":"one-use","expires_at":"2099-01-01T00:00:00Z"}}`
		}
		return 200, header, `{"files_total":2,"bytes_total":12,"copy_count":2,"sources_omitted":3,"items":[]}`
	case r.URL.Path == "/api/v1/transfers/signed-pull/batch":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.createHeaders = append(f.createHeaders, r.Header.Clone())
		f.createBodies = append(f.createBodies, body)
		header.Set("X-Jolt-Signed-Transfer-Creation", "v1")
		id := r.Header.Get("Idempotency-Key")
		return 202, header, `{"job":` + f.job(id, options) + `,"execution_enabled":true}`
	case strings.HasPrefix(r.URL.Path, jobPath) && strings.HasSuffix(r.URL.Path, "/cancel"):
		f.canceled = append(f.canceled, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, jobPath), "/cancel"))
		return 200, header, `{}`
	case strings.HasPrefix(r.URL.Path, jobPath) && strings.HasSuffix(r.URL.Path, "/authorization"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, jobPath), "/authorization")
		_ = id
		if r.Method == http.MethodGet {
			header.Set("X-Jolt-Job-Authorization-Status", "v1")
			if f.remoteRevision == 0 {
				return 200, header, `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":true}`
			}
			return 200, header, fmt.Sprintf(`{"revision":%d,"expires_at":%q,"envelope_digest":%q,"execution_enabled":true}`, f.remoteRevision, f.expiry.Format(time.RFC3339), security.Digest(f.lastEnvelope))
		}
		envelope := r.Header.Get(signedAuthorizationHeader)
		binding, err := signedauth.VerifiedJobLeaseBinding(envelope, f.keys, "destination", time.Now().UTC())
		if err != nil {
			t.Errorf("delivered an unverifiable lease: %v", err)
			return 403, header, `{}`
		}
		f.remoteRevision++
		claims, _, err := signedauth.VerifyJobLease(envelope, f.keys, binding, "destination", uint64(f.remoteRevision), time.Now().UTC())
		if err != nil {
			t.Errorf("delivered lease revision: %v", err)
			return 403, header, `{}`
		}
		f.expiry, f.lastEnvelope = time.Unix(claims.ExpiresAt, 0).UTC(), envelope
		f.deliveries = append(f.deliveries, envelope)
		header.Set("X-Jolt-Job-Authorization-Applied", "v1")
		return 200, header, fmt.Sprintf(`{"revision":%d,"expires_at":%q,"execution_enabled":true}`, f.remoteRevision, f.expiry.Format(time.RFC3339))
	case strings.HasPrefix(r.URL.Path, jobPath):
		return 200, header, f.job(strings.TrimPrefix(r.URL.Path, jobPath), options)
	}
	t.Errorf("unexpected call %s %s%s", r.Method, r.URL.Host, r.URL.Path)
	return 404, header, `{"error":{"code":"not_found","message":"not found"}}`
}

func transferRouteHarness(t *testing.T, fake *transferFake) (http.Handler, *Server, *store.Store, string) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	if err := storage.CreateUser(ctx, store.User{ID: "admin", Username: "admin", PasswordHash: "unused", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session := "transfer-route-session"
	if err := storage.CreateSession(ctx, security.Digest(session), "admin", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "destination", Name: "Destination", Endpoint: "http://destination.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	fake.keys = map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status, header, body := fake.handle(t, r)
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	server, handler := newServerHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalJobs: true, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	return handler, server, storage, session
}

const transferPayload = `{"operation":"copy","source":{"node_id":"source","mount_id":"source-media","paths":["exports/one.txt","exports/folder"]},"destination":{"mount_id":"incoming","path":"imports/archive"},"conflict_policy":"fail"}`

func TestSignedLogicalTransferCreatesALeasedJobAndRetriesToTheSameOne(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps}
	handler, server, storage, session := transferRouteHarness(t, fake)
	post := func(key string) *httptest.ResponseRecorder {
		r := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", session, []byte(transferPayload))
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	first := post("client-key")
	if first.Code != http.StatusAccepted || !strings.Contains(first.Header().Get("Location"), "/api/v1/nodes/destination/jobs/xfer-") {
		t.Fatalf("create: %d %s", first.Code, first.Body)
	}
	jobID := strings.TrimPrefix(first.Header().Get("Location"), "/api/v1/nodes/destination/jobs/")
	if len(fake.createHeaders) != 1 || fake.createHeaders[0].Get("Idempotency-Key") != jobID || fake.createHeaders[0].Get(signedAuthorizationHeader) == "" {
		t.Fatalf("node creation headers: %+v", fake.createHeaders)
	}
	body := fake.createBodies[0]
	paths, _ := body["source_paths"].([]any)
	if body["peer_node_id"] != "source" || body["source_grant_id"] != "source-grant" || body["destination_grant_id"] != "destination-grant" || body["destination_path"] != "archive" || len(paths) != 2 || paths[0] != "folder" || paths[1] != "one.txt" {
		t.Fatalf("node payload: %+v", body)
	}
	// The envelope names the real scope and covers both mounts.
	envelope := fake.createHeaders[0].Get(signedAuthorizationHeader)
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, fake.keys, "destination", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if binding.Operation != "transfer_pull_batch" || binding.SourceNodeID != "source" || binding.SourceGrantID != "source-grant" || binding.SourceMountID != "source-media" || binding.SourceRoot != "exports" ||
		binding.DestinationNodeID != "destination" || binding.DestinationGrantID != "destination-grant" || binding.DestinationMountID != "incoming" || binding.DestinationRoot != "imports/archive" || binding.PlanID != jobID {
		t.Fatalf("binding: %+v", binding)
	}
	_, filter, err := signedauth.VerifyJobLease(envelope, fake.keys, binding, "destination", 1, time.Now().UTC())
	if err != nil || !filter.Evaluate("nodes/source/files/mounts/source-media/exports/one.txt", "read", "file").Allowed ||
		!filter.Evaluate("nodes/destination/files/mounts/incoming/imports/archive/x", "create", "file").Allowed {
		t.Fatalf("filter=%v err=%v", filter, err)
	}
	// The link, the scope and the first lease are in place.
	link, err := storage.GetJobAuthorizationLink(context.Background(), "destination", jobID)
	if err != nil || link.ActorID != "admin" || link.Binding.Operation != "transfer_pull_batch" || link.ConfirmedRevision != 1 {
		t.Fatalf("link=%+v err=%v", link, err)
	}
	raw, err := storage.GetJobAuthorizationScope(context.Background(), "destination", jobID)
	var scope transferScope
	if err != nil || json.Unmarshal(raw, &scope) != nil || scope.SourceGrantRoot != "exports" || scope.DestinationPath != "imports/archive" || len(scope.SourcePaths) != 2 {
		t.Fatalf("scope=%s err=%v", raw, err)
	}
	if len(fake.deliveries) != 1 {
		t.Fatalf("first lease deliveries=%d", len(fake.deliveries))
	}
	// A retry with the same key reaches the same job and does not duplicate it.
	retry := post("client-key")
	if retry.Code != http.StatusAccepted || retry.Header().Get("Location") != first.Header().Get("Location") {
		t.Fatalf("retry: %d %s", retry.Code, retry.Body)
	}
	if active, err := storage.ListActiveJobAuthorizationLinks(context.Background(), 10); err != nil || len(active) != 1 {
		t.Fatalf("links=%d err=%v", len(active), err)
	}
	if other := post("another-key"); other.Header().Get("Location") == first.Header().Get("Location") {
		t.Fatal("different keys produced the same job")
	}
	// Renewal re-issues from the saved scope, for the transfer's own job, and a
	// node that reports a different job than the scope describes gets nothing.
	before := len(fake.deliveries)
	if finished, err := server.renewSignedLocalJobLease(context.Background(), "destination", jobID); err != nil || finished {
		t.Fatalf("renewal finished=%v err=%v", finished, err)
	}
	if len(fake.deliveries) != before+1 || fake.remoteRevision != before+1 {
		t.Fatalf("renewal deliveries=%d revision=%d", len(fake.deliveries), fake.remoteRevision)
	}
	renewed, err := signedauth.VerifiedJobLeaseBinding(fake.deliveries[len(fake.deliveries)-1], fake.keys, "destination", time.Now().UTC())
	if err != nil || renewed.PlanID != jobID || renewed.SourceMountID != "source-media" || renewed.SourceRoot != "exports" {
		t.Fatalf("renewed binding=%+v err=%v", renewed, err)
	}
}

func TestSignedLogicalTransferFailsClosed(t *testing.T) {
	for name, test := range map[string]struct {
		fake   *transferFake
		status int
		code   string
	}{
		"destination without the capability": {&transferFake{sourceIdentity: "source", destinationCaps: `["signed_local_copy_execution_v1"]`}, http.StatusConflict, "node_upgrade_required"},
		"source reports another identity":    {&transferFake{sourceIdentity: "source-current", destinationCaps: transferCaps}, http.StatusConflict, "node_identity_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			fake := test.fake
			handler, _, storage, session := transferRouteHarness(t, fake)
			r := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", session, []byte(transferPayload))
			r.Header.Set("Idempotency-Key", "k")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status || !strings.Contains(w.Body.String(), test.code) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if len(fake.createHeaders) != 0 || len(fake.deliveries) != 0 {
				t.Fatal("a job was created although the request must fail closed")
			}
			if active, err := storage.ListActiveJobAuthorizationLinks(context.Background(), 10); err != nil || len(active) != 0 {
				t.Fatalf("links=%d err=%v", len(active), err)
			}
		})
	}
}

func TestSignedModeRefusesDirectPullsAndSignedPullThroughTheProxy(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps}
	handler, _, _, session := transferRouteHarness(t, fake)
	for _, test := range []struct {
		path   string
		status int
		code   string
	}{
		{"/api/v1/nodes/destination/transfers/pull", http.StatusConflict, "use_logical_transfer"},
		{"/api/v1/nodes/destination/transfers/pull/directory", http.StatusConflict, "use_logical_transfer"},
		{"/api/v1/nodes/destination/transfers/pull/batch", http.StatusConflict, "use_logical_transfer"},
		{"/api/v1/nodes/destination/transfers/signed-pull/batch", http.StatusNotFound, "resource_not_found"},
		{"/api/v1/nodes/destination/transfers/signed-pull/batch/prepare", http.StatusNotFound, "resource_not_found"},
	} {
		r := authenticatedRequest(http.MethodPost, test.path, session, []byte(`{}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.status || !strings.Contains(w.Body.String(), test.code) {
			t.Fatalf("%s: %d %s", test.path, w.Code, w.Body)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("the node was reached: %v", fake.calls)
	}
}

func TestSignedLogicalTransferPreviewUsesTheCallersPolicyAndCreatesNothing(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps}
	handler, _, storage, session := transferRouteHarness(t, fake)
	r := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/plan", session, []byte(transferPayload))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var body struct {
		Plan struct {
			FilesTotal     int `json:"files_total"`
			SourcesOmitted int `json:"sources_omitted"`
		} `json:"plan"`
		Max int `json:"max_source_paths"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Plan.FilesTotal != 2 || body.Plan.SourcesOmitted != 3 || body.Max != 1000 {
		t.Fatalf("preview: %d %s", w.Code, w.Body)
	}
	if fake.unsignedPlans != 0 {
		t.Fatal("the unfiltered plan was used")
	}
	if len(fake.previewHeaders) != 1 {
		t.Fatalf("preview calls=%d", len(fake.previewHeaders))
	}
	binding, err := signedauth.VerifiedJobLeaseBinding(fake.previewHeaders[0].Get(signedAuthorizationHeader), fake.keys, "destination", time.Now().UTC())
	if err != nil || !strings.HasPrefix(binding.PlanID, "preview-") || binding.SourceMountID != "source-media" {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	// A preview is not a job: no link, no node job, no first lease.
	if len(fake.createHeaders) != 0 || len(fake.deliveries) != 0 {
		t.Fatal("previewing created or authorized a job")
	}
	if active, err := storage.ListActiveJobAuthorizationLinks(context.Background(), 10); err != nil || len(active) != 0 {
		t.Fatalf("links=%d err=%v", len(active), err)
	}
	// Each preview gets its own throwaway id.
	again := httptest.NewRecorder()
	handler.ServeHTTP(again, authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/plan", session, []byte(transferPayload)))
	second, err := signedauth.VerifiedJobLeaseBinding(fake.previewHeaders[1].Get(signedAuthorizationHeader), fake.keys, "destination", time.Now().UTC())
	if again.Code != http.StatusOK || err != nil || second.PlanID == binding.PlanID {
		t.Fatalf("second preview: %d %v", again.Code, err)
	}
}

func TestSignedLogicalTransferPreviewFailsClosed(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: `["signed_local_copy_execution_v1"]`}
	handler, _, _, session := transferRouteHarness(t, fake)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/plan", session, []byte(transferPayload)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "node_upgrade_required") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if fake.unsignedPlans != 0 || len(fake.previewHeaders) != 0 {
		t.Fatal("an unprotected preview was offered instead")
	}
}

const movePayload = `{"operation":"move","source":{"node_id":"source","mount_id":"source-media","paths":["exports/one.txt","exports/folder"]},"destination":{"mount_id":"incoming","path":"imports/archive"},"conflict_policy":"fail"}`
const confirmedMovePayload = `{"operation":"move","source":{"node_id":"source","mount_id":"source-media","paths":["exports/one.txt","exports/folder"]},"destination":{"mount_id":"incoming","path":"imports/archive"},"conflict_policy":"fail","move_plan":{"plan_id":"plan_1","token":"one-use"}}`

func TestSignedMoveNeedsAPreviewedPlanAndCarriesItsConfirmation(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps, moving: true}
	handler, server, storage, session := transferRouteHarness(t, fake)
	post := func(path, payload, key string) *httptest.ResponseRecorder {
		r := authenticatedRequest(http.MethodPost, path, session, []byte(payload))
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	transfers := "/api/v1/nodes/destination/transfers"
	// Creating a move without a confirmation is refused before the node is asked.
	if w := post(transfers, movePayload, "k0"); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "plan_required") {
		t.Fatalf("a move without a plan: %d %s", w.Code, w.Body)
	}
	if len(fake.createHeaders) != 0 {
		t.Fatal("the node was asked to create an unconfirmed move")
	}
	// The preview runs under the caller's policy, names the subject and returns
	// the confirmation to present.
	preview := post(transfers+"/plan", movePayload, "")
	var body struct {
		Plan struct {
			MovePlan struct {
				PlanID string `json:"plan_id"`
				Token  string `json:"token"`
			} `json:"move_plan"`
		} `json:"plan"`
	}
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &body) != nil || body.Plan.MovePlan.Token != "one-use" {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body)
	}
	if fake.previewBodies[0]["subject_type"] != "user" || fake.previewBodies[0]["operation"] != "move" || fake.previewBodies[0]["plan_token"] != nil {
		t.Fatalf("preview payload: %+v", fake.previewBodies[0])
	}
	// Creating with the confirmation hands it to the node with a move lease.
	created := post(transfers, confirmedMovePayload, "move-key")
	if created.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	jobID := strings.TrimPrefix(created.Header().Get("Location"), "/api/v1/nodes/destination/jobs/")
	payload := fake.createBodies[0]
	if payload["operation"] != "move" || payload["plan_id"] != "plan_1" || payload["plan_token"] != "one-use" || payload["subject_type"] != "user" {
		t.Fatalf("create payload: %+v", payload)
	}
	binding, err := signedauth.VerifiedJobLeaseBinding(fake.createHeaders[0].Get(signedAuthorizationHeader), fake.keys, "destination", time.Now().UTC())
	if err != nil || binding.Operation != "transfer_move_batch" || binding.PlanID != jobID {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	_, filter, err := signedauth.VerifyJobLease(fake.createHeaders[0].Get(signedAuthorizationHeader), fake.keys, binding, "destination", 1, time.Now().UTC())
	if err != nil || !filter.Evaluate("nodes/source/files/mounts/source-media/exports/one.txt", "delete", "file").Allowed {
		t.Fatalf("the move lease does not grant delete on the source: %v", err)
	}
	raw, err := storage.GetJobAuthorizationScope(context.Background(), "destination", jobID)
	var scope transferScope
	if err != nil || json.Unmarshal(raw, &scope) != nil || scope.Operation != "move" {
		t.Fatalf("scope=%s err=%v", raw, err)
	}
	// Renewal reissues a move lease from that scope.
	before := len(fake.deliveries)
	if _, err := server.renewSignedLocalJobLease(context.Background(), "destination", jobID); err != nil || len(fake.deliveries) != before+1 {
		t.Fatalf("renewal err=%v deliveries=%d", err, len(fake.deliveries))
	}
	renewed, err := signedauth.VerifiedJobLeaseBinding(fake.deliveries[len(fake.deliveries)-1], fake.keys, "destination", time.Now().UTC())
	if err != nil || renewed.Operation != "transfer_move_batch" {
		t.Fatalf("renewed=%+v err=%v", renewed, err)
	}
}

func TestMoveLeaseNeedsUpdateAndDeleteOnEverySourceRoot(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	operator := store.User{ID: "mover", Username: "mover", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := f.storage.CreateUser(ctx, operator); err != nil {
		t.Fatal(err)
	}
	const session = "move-lease-session"
	if err := f.storage.CreateSession(ctx, security.Digest(session), operator.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	source, destination := "nodes/src/files/mounts/media", "nodes/dst/files/mounts/inbox"
	policy := store.Policy{ID: "mover", Name: "mover", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/dst/transfers", Capabilities: []string{"execute"}},
		{Path: source + "/movies/**", Capabilities: []string{"read", "list", "update", "delete"}},
		{Path: destination + "/incoming/**", Capabilities: []string{"create", "update", "list", "read"}},
	}}
	if err := f.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetSubjectPolicies(ctx, "user", operator.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest("GET", "/", session, nil))
	job := signedLocalJob{ID: "xfer", Type: "transfer_move_batch", MountID: "inbox", Source: "library", Destination: "incoming/archive", PeerNodeID: "src", SourceGrantID: "sg", DestinationGrantID: "dg", MaxAttempts: 3}
	scope := transferScope{SourceNodeID: "src", SourceMountID: "media", SourceGrantRoot: "library", SourcePaths: []string{"movies/a"}, DestinationPath: "incoming/archive", Operation: "move"}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, scope, 1, now); err != nil {
		t.Fatalf("a mover with every capability was refused: %v", err)
	}
	// Dropping delete (or update) from the source refuses the lease.
	for name, capabilities := range map[string][]string{"no delete": {"read", "list", "update"}, "no update": {"read", "list", "delete"}} {
		policy.Rules[1].Capabilities = capabilities
		if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
			t.Fatal(err)
		}
		if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, scope, 1, now); err == nil {
			t.Fatalf("%s: a move lease was issued", name)
		}
	}
	// The same actor may still copy: a copy needs only read.
	copyJob, copyScope := job, scope
	copyJob.Type, copyScope.Operation = "transfer_pull_batch", "copy"
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", copyJob, copyScope, 1, now); err != nil {
		t.Fatalf("a copy was refused: %v", err)
	}
	// A move job must match a move scope, and the other way around.
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, copyScope, 1, now); err == nil {
		t.Fatal("a move job was leased from a copy scope")
	}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", copyJob, scope, 1, now); err == nil {
		t.Fatal("a copy job was leased from a move scope")
	}
}
