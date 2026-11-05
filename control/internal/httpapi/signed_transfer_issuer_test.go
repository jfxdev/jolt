package httpapi

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestSignedTransferLeaseCoversBothMountsAndEveryRootTheCallerMayRead(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	operator := store.User{ID: "operator", Username: "operator", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := f.storage.CreateUser(ctx, operator); err != nil {
		t.Fatal(err)
	}
	const session = "transfer-test-session"
	if err := f.storage.CreateSession(ctx, security.Digest(session), operator.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	source, destination := "nodes/src/files/mounts/media", "nodes/dst/files/mounts/inbox"
	policy := store.Policy{ID: "transfer-policy", Name: "transfer-policy", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/dst/transfers", Capabilities: []string{"execute"}},
		{Path: source + "/movies/**", Capabilities: []string{"read", "list"}},
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
	if request == nil {
		t.Fatal("session was not authenticated")
	}
	job := signedLocalJob{ID: "xfer", Type: "transfer_pull_batch", MountID: "inbox", Source: "library", Destination: "incoming/archive", PeerNodeID: "src", SourceGrantID: "sg", DestinationGrantID: "dg", MaxAttempts: 3}
	scope := transferScope{SourceNodeID: "src", SourceMountID: "media", SourceGrantRoot: "library", SourcePaths: []string{"movies/a", "movies/b"}, DestinationPath: "incoming/archive"}
	token, err := s.issueSignedTransferLeaseFor(request, "dst", job, scope, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	expected := signedauth.Binding{
		ActorID: operator.ID, CredentialID: "session-" + security.Digest("jolt-signed-session:"+session), Operation: "transfer_pull_batch",
		SourceNodeID: "src", SourceGrantID: "sg", SourceMountID: "media", SourceRoot: "library",
		DestinationNodeID: "dst", DestinationGrantID: "dg", DestinationMountID: "inbox", DestinationRoot: "incoming/archive",
		PlanID: "xfer", JobOptionsDigest: job.optionsDigest(),
	}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	claims, filter, err := signedauth.VerifyJobLease(token, keys, expected, "dst", 1, now)
	if err != nil || claims.ExpiresAt != now.Add(30*time.Second).Unix() {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	for _, check := range []struct {
		path, capability string
		allowed          bool
	}{
		{source + "/movies/a/clip.mkv", "read", true},
		{source + "/music/song.mp3", "read", false}, // outside the policy
		{destination + "/incoming/archive/a", "create", true},
		{destination + "/elsewhere/a", "create", false},
		{source + "/movies/a/clip.mkv", "create", false}, // the source stays read-only
	} {
		if got := filter.Evaluate(check.path, check.capability, "file").Allowed; got != check.allowed {
			t.Fatalf("%s %s: allowed=%v want %v", check.path, check.capability, got, check.allowed)
		}
	}
	if _, _, err := signedauth.VerifyJobLease(token, keys, expected, "dst", 2, now); err == nil {
		t.Fatal("old revision accepted")
	}

	// The job must describe exactly the saved scope.
	for name, mutate := range map[string]func(*signedLocalJob){
		"other peer":        func(j *signedLocalJob) { j.PeerNodeID = "other" },
		"other source root": func(j *signedLocalJob) { j.Source = "elsewhere" },
		"other destination": func(j *signedLocalJob) { j.Destination = "incoming/other" },
		"missing grant":     func(j *signedLocalJob) { j.SourceGrantID = "" },
		"local type":        func(j *signedLocalJob) { j.Type = "copy_local" },
	} {
		changed := job
		mutate(&changed)
		if _, err := s.issueSignedTransferLeaseFor(request, "dst", changed, scope, 1, now); err == nil {
			t.Fatalf("%s: a lease was issued", name)
		}
	}
	// A root outside what the caller may read refuses the lease.
	outside := scope
	outside.SourcePaths = []string{"movies/a", "music"}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, outside, 1, now); err == nil {
		t.Fatal("a root the caller cannot read was authorized")
	}
	// Overwriting needs update on the destination.
	overwrite := scope
	overwrite.MayOverwrite = true
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, overwrite, 1, now); err != nil {
		t.Fatalf("update is granted but the lease was refused: %v", err)
	}
	policy.Rules[2].Capabilities = []string{"create", "list", "read"}
	if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, overwrite, 1, now); err == nil {
		t.Fatal("overwrite without update permission was authorized")
	}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, scope, 1, now); err != nil {
		t.Fatalf("a plain copy still needs only create: %v", err)
	}
	// Losing the right to run transfers on the destination refuses every lease.
	policy.Rules[0].Capabilities = []string{"list"}
	if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, scope, 1, now); err == nil {
		t.Fatal("a lease was issued without permission to execute transfers")
	}
	policy.Rules[0].Capabilities = []string{"execute"}
	if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.DeleteSession(ctx, security.Digest(session)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedTransferLeaseFor(request, "dst", job, scope, 1, now); err == nil {
		t.Fatal("a revoked session received a lease")
	}
}

func TestTransferScopeIsSavedOnceAndKeptWithTheLink(t *testing.T) {
	f := setupAgent(t, store.DefaultAgentLimits(), &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})})
	ctx := context.Background()
	if err := f.storage.SaveJobAuthorizationScope(ctx, "n1", "job", []byte(`{"a":1}`), time.Now()); err == nil {
		t.Fatal("a scope was saved without a link")
	}
	if _, err := f.storage.GetJobAuthorizationScope(ctx, "n1", "job"); err == nil {
		t.Fatal("an unknown scope was returned")
	}
}
