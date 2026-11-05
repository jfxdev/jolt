package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

func newJobLinkFixture(t *testing.T) (*Store, string, JobAuthorizationLink, ed25519.PrivateKey, time.Time) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(file, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	user := User{ID: "private-user", Username: "operator", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, security.Digest("session-secret"), user.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNode(ctx, Node{ID: "node", Name: "node", Endpoint: "http://node.invalid", TokenEncrypted: "encrypted", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	binding := signedauth.Binding{ActorID: user.ID, CredentialID: "session-" + security.Digest("jolt-signed-session:session-secret"), Operation: "copy_local", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "source", DestinationNodeID: "node", DestinationMountID: "mount", DestinationRoot: "destination", PlanID: "job"}
	link := JobAuthorizationLink{NodeID: "node", JobID: "job", ActorType: "user", ActorID: user.ID, CredentialID: binding.CredentialID, CredentialDigest: security.Digest("session-secret"), Binding: binding}
	return s, file, link, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), now
}

func signedLinkEnvelope(t *testing.T, link JobAuthorizationLink, key ed25519.PrivateKey, revision uint64, now time.Time, ttl time.Duration) string {
	t.Helper()
	binding, err := signedauth.JobLeaseBinding(link.Binding, revision)
	if err != nil {
		t.Fatal(err)
	}
	claims := signedauth.Claims{Version: 1, KeyID: "key", Binding: binding, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), Context: json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/node/files/mounts/mount/**","capabilities":["read","create"]}]}`)}
	token, err := signedauth.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestJobAuthorizationLinkPersistsAndReconcilesRetries(t *testing.T) {
	s, file, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err != nil || version != "5" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	if err := s.CreateJobAuthorizationLink(ctx, link, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate link: %v", err)
	}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	first := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	for _, mutate := range []func(*JobAuthorizationLink){
		func(value *JobAuthorizationLink) { value.Binding.ActorID = "other" },
		func(value *JobAuthorizationLink) { value.Binding.CredentialID = "other" },
		func(value *JobAuthorizationLink) { value.Binding.SourceRoot = "other" },
		func(value *JobAuthorizationLink) { value.Binding.DestinationRoot = "other" },
	} {
		changed := link
		mutate(&changed)
		forged := signedLinkEnvelope(t, changed, key, 1, now, 30*time.Second)
		if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, forged, keys, now); !errors.Is(err, ErrConflict) {
			t.Fatalf("mismatched authorization accepted: %v", err)
		}
	}
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 2, first, keys, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong revision: %v", err)
	}
	staged, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, first, keys, now)
	if err != nil || staged.PendingRevision != 1 || staged.PendingEnvelope != first {
		t.Fatalf("staged=%+v err=%v", staged, err)
	}
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, first, keys, now); err != nil {
		t.Fatalf("stage retry: %v", err)
	}
	other := signedLinkEnvelope(t, link, key, 1, now.Add(time.Second), 30*time.Second)
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, other, keys, now.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed pending envelope accepted: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(file, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	staged, err = s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID)
	if err != nil || staged.PendingEnvelope != first || staged.PendingRevision != 1 {
		t.Fatalf("recovered=%+v err=%v", staged, err)
	}
	expiry := now.Add(30 * time.Second)
	if err := s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 1, security.Digest("wrong"), expiry, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong confirmation accepted: %v", err)
	}
	if err := s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 1, security.Digest(first), expiry, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 1, security.Digest(first), expiry, now); err != nil {
		t.Fatalf("confirmation retry: %v", err)
	}
	confirmed, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID)
	if err != nil || confirmed.ConfirmedRevision != 1 || confirmed.PendingRevision != 0 || confirmed.PendingEnvelope != "" || !confirmed.ConfirmedExpiry.Equal(expiry) {
		t.Fatalf("confirmed=%+v err=%v", confirmed, err)
	}
	second := signedLinkEnvelope(t, link, key, 2, now, 30*time.Second)
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 2, second, keys, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, link.CredentialDigest); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 2, security.Digest(second), expiry, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session confirmed: %v", err)
	}
	encoded, err := json.Marshal(staged)
	if err != nil || strings.Contains(string(encoded), "private-user") || strings.Contains(string(encoded), first) {
		t.Fatalf("link exposed by JSON: %s %v", encoded, err)
	}
	for _, name := range []string{file, file + "-wal"} {
		data, err := os.ReadFile(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private-user") || strings.Contains(string(data), first) || strings.Contains(string(data), link.CredentialDigest) {
			t.Fatalf("link exposed in %s", name)
		}
	}
}

func TestJobAuthorizationLinkConcurrentStageAndConfirm(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, envelope, keys, now)
			results <- err
		}()
	}
	wg.Wait()
	for i := 0; i < cap(results); i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 1, security.Digest(envelope), now.Add(30*time.Second), now)
		}()
	}
	wg.Wait()
	for i := 0; i < cap(results); i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID)
	if err != nil || got.ConfirmedRevision != 1 || got.PendingRevision != 0 {
		t.Fatalf("link=%+v err=%v", got, err)
	}
}

func TestJobAuthorizationLinkCannotOutliveSession(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.DeleteSession(ctx, link.CredentialDigest); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, link.CredentialDigest, link.ActorID, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	long := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, long, keys, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("lease outlived session: %v", err)
	}
	short := signedLinkEnvelope(t, link, key, 1, now, 10*time.Second)
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, short, keys, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 1, security.Digest(short), now.Add(10*time.Second), now.Add(10*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session accepted: %v", err)
	}
}

func TestPreviousControlReaderRejectsJobLinks(t *testing.T) {
	checker := os.Getenv("JOLT_VERSION4_CONTROL_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_VERSION4_CONTROL_CHECKER to the previous control reader")
	}
	s, file, link, _, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.SetMetadata(ctx, "minimum_security_version", "4"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, file).CombinedOutput(); err != nil {
		t.Fatalf("previous reader rejected v4: %v %s", err, out)
	}
	s, err := Open(file, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, file).CombinedOutput(); err == nil || !strings.Contains(string(out), "security version") {
		t.Fatalf("previous reader accepted v5: %v %s", err, out)
	}
}

func TestJobAuthorizationLinkRechecksStaticAutomationAndRejectsAgent(t *testing.T) {
	s, _, base, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	account := ServiceAccount{ID: "automation", Name: "automation", Kind: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	token := ServiceAccountToken{ID: "automation-token", ServiceAccountID: account.ID, Name: "token", TokenHash: security.Digest("automation-secret"), CreatedAt: now}
	if err := s.CreateServiceAccountToken(ctx, token, false); err != nil {
		t.Fatal(err)
	}
	link := base
	link.JobID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest = "automation-job", "service_account", account.ID, "token-"+token.ID, token.TokenHash
	link.Binding.ActorID, link.Binding.CredentialID, link.Binding.PlanID = link.ActorID, link.CredentialID, link.JobID
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	if _, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, envelope, keys, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeServiceAccountToken(ctx, account.ID, token.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmJobAuthorization(ctx, link.NodeID, link.JobID, 1, security.Digest(envelope), now.Add(30*time.Second), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked credential confirmed: %v", err)
	}
	agent := ServiceAccount{ID: "agent", Name: "agent", Kind: "agent", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateServiceAccount(ctx, agent); err != nil {
		t.Fatal(err)
	}
	agentToken := ServiceAccountToken{ID: "agent-token", ServiceAccountID: agent.ID, Name: "token", TokenHash: security.Digest("agent-secret"), CreatedAt: now}
	if err := s.CreateServiceAccountToken(ctx, agentToken, false); err != nil {
		t.Fatal(err)
	}
	link.JobID, link.ActorID, link.CredentialID, link.CredentialDigest = "agent-job", agent.ID, "token-"+agentToken.ID, agentToken.TokenHash
	link.Binding.ActorID, link.Binding.CredentialID, link.Binding.PlanID = link.ActorID, link.CredentialID, link.JobID
	if err := s.CreateJobAuthorizationLink(ctx, link, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("agent job link accepted: %v", err)
	}
}

func TestJobAuthorizationLinkRejectsConcurrentDifferentEnvelopes(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	tokens := []string{signedLinkEnvelope(t, link, key, 1, now, 20*time.Second), signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)}
	results := make(chan error, 2)
	for _, envelope := range tokens {
		go func(token string) {
			_, err := s.StageJobAuthorization(ctx, link.NodeID, link.JobID, 1, token, keys, now)
			results <- err
		}(envelope)
	}
	accepted := 0
	for range tokens {
		err := <-results
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	stored, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID)
	if err != nil || accepted != 1 || stored.PendingRevision != 1 || (stored.PendingEnvelope != tokens[0] && stored.PendingEnvelope != tokens[1]) {
		t.Fatalf("accepted=%d link=%+v err=%v", accepted, stored, err)
	}
}

func TestJobAuthorizationLinkAuditFailureRollsBackVersion(t *testing.T) {
	s, _, link, _, now := newJobLinkFixture(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err == nil {
		t.Fatal("link created without audit")
	}
	if _, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link survived rollback: %v", err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err == nil && version == "5" {
		t.Fatalf("version survived rollback: %q", version)
	}
}

func TestJobAuthorizationLinkRejectsInconsistentStoredState(t *testing.T) {
	s, _, link, _, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	binding, err := json.Marshal(link.Binding)
	if err != nil {
		t.Fatal(err)
	}
	invalidBinding := strings.TrimSuffix(string(binding), "}") + `,"unknown":true}`
	if _, err := s.db.ExecContext(ctx, `UPDATE job_authorization_links SET binding=? WHERE node_id=? AND job_id=?`, invalidBinding, link.NodeID, link.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown binding field accepted: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE job_authorization_links SET binding=?,pending_revision=1 WHERE node_id=? AND job_id=?`, string(binding), link.NodeID, link.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID); !errors.Is(err, ErrConflict) {
		t.Fatalf("incomplete pending revision accepted: %v", err)
	}
}
