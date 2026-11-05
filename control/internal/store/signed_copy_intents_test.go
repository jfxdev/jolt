package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
)

func TestSignedCopyIntentPersistsIdempotentlyAndFailsClosed(t *testing.T) {
	s, file, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	link.Binding.JobOptionsDigest = signedauth.JobOptionsDigest(options)
	body := []byte(`{"mount_id":"mount","source_path":"source","destination_path":"destination"}`)
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	if err := s.SetMetadata(ctx, "minimum_security_version", "6"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	checker := os.Getenv("JOLT_VERSION6_CONTROL_CHECKER")
	if checker != "" {
		if out, err := exec.Command(checker, file).CombinedOutput(); err != nil {
			t.Fatalf("previous reader rejected v6: %v %s", err, out)
		}
	}
	s, err := Open(file, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	create := func(link JobAuthorizationLink, body []byte, options signedauth.JobOptions, envelope string, at time.Time) (SignedCopyIntent, bool, error) {
		return s.CreateSignedCopyIntent(ctx, link, "request-key", body, options, envelope, keys, at)
	}
	for _, invalid := range []struct {
		body    []byte
		options signedauth.JobOptions
		token   string
	}{
		{[]byte(`{"mount_id":"mount","mount_id":"other"}`), options, envelope},
		{[]byte(`{"mount_id":"mount","source_path":"other","destination_path":"destination"}`), options, envelope},
		{body, signedauth.JobOptions{}, envelope},
		{body, options, envelope + "x"},
	} {
		if _, _, err := create(link, invalid.body, invalid.options, invalid.token, now); !errors.Is(err, ErrConflict) {
			t.Fatalf("invalid intent accepted: %v", err)
		}
	}
	intent, repeated, err := create(link, body, options, envelope, now)
	if err != nil || repeated || intent.Link.JobID != link.JobID || intent.Envelope != envelope || !intent.Expiry.Equal(now.Add(30*time.Second)) || intent.Accepted {
		t.Fatalf("intent=%+v repeated=%v err=%v", intent, repeated, err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err != nil || version != "7" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	other := link
	other.JobID, other.Binding.PlanID = "new-job", "new-job"
	otherEnvelope := signedLinkEnvelope(t, other, key, 1, now, 30*time.Second)
	if result, repeated, err := create(other, body, options, otherEnvelope, now); err != nil || !repeated || result.Link.JobID != link.JobID || result.Envelope != envelope {
		t.Fatalf("retry=%+v repeated=%v err=%v", result, repeated, err)
	}
	changed := link
	changed.Binding.SourceRoot = "other"
	changedEnvelope := signedLinkEnvelope(t, changed, key, 1, now, 30*time.Second)
	if _, _, err := create(changed, []byte(`{"mount_id":"mount","source_path":"other","destination_path":"destination"}`), options, changedEnvelope, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request reused key: %v", err)
	}
	encoded, err := json.Marshal(intent)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("intent exposed by JSON: %s %v", encoded, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if checker != "" {
		if out, err := exec.Command(checker, file).CombinedOutput(); err == nil || !strings.Contains(string(out), "security version") {
			t.Fatalf("previous reader accepted v7: %v %s", err, out)
		}
	}
	s, err = Open(file, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	recovered, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", keys, now.Add(31*time.Second))
	if err != nil || recovered.Link.JobID != link.JobID || recovered.Envelope != envelope || !recovered.Expiry.Before(now.Add(31*time.Second)) {
		t.Fatalf("expired intent recovery=%+v err=%v", recovered, err)
	}
	if _, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", map[string]ed25519.PublicKey{}, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown signing key accepted: %v", err)
	}
	if _, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, "other", link.CredentialDigest, "request-key", keys, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("other credential read intent: %v", err)
	}
	if result, repeated, err := create(other, body, options, otherEnvelope, now); err != nil || !repeated || result.Link.JobID != link.JobID || result.Envelope != envelope {
		t.Fatalf("recovered=%+v repeated=%v err=%v", result, repeated, err)
	}
	refresh := func(token string, at time.Time) (SignedCopyIntent, error) {
		return s.RefreshSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", token, keys, at)
	}
	freshAt := now.Add(31 * time.Second)
	fresh := signedLinkEnvelope(t, link, key, 1, freshAt, 30*time.Second)
	if _, err := refresh(fresh, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("unexpired intent replaced: %v", err)
	}
	if _, err := refresh(signedLinkEnvelope(t, changed, key, 1, freshAt, 30*time.Second), freshAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("different scope refreshed: %v", err)
	}
	updated, err := refresh(fresh, freshAt)
	if err != nil || updated.Envelope != fresh || !updated.Expiry.Equal(freshAt.Add(30*time.Second)) {
		t.Fatalf("refreshed=%+v err=%v", updated, err)
	}
	if updated, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", keys, freshAt); err != nil || updated.Envelope != fresh {
		t.Fatalf("reloaded refresh=%+v err=%v", updated, err)
	}
	receipt := SignedCopyReceipt{JobID: link.JobID, Type: "copy_local", State: "waiting_validation", MountID: "mount", Source: "source", Destination: "destination", Options: options}
	complete := func(receipt SignedCopyReceipt) error {
		return s.CompleteSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", receipt, keys, freshAt)
	}
	badReceipt := receipt
	badReceipt.Options.Overwrite = true
	if err := complete(badReceipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong receipt accepted: %v", err)
	}
	badReceipt = receipt
	badReceipt.State = "running"
	if err := complete(badReceipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("running job accepted: %v", err)
	}
	if err := complete(receipt); err != nil {
		t.Fatal(err)
	}
	if err := complete(receipt); err != nil {
		t.Fatalf("acceptance retry: %v", err)
	}
	accepted, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", keys, freshAt)
	if err != nil || !accepted.Accepted {
		t.Fatalf("acceptance not durable: %+v %v", accepted, err)
	}
	storedLink, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID)
	if err != nil || storedLink.Binding != link.Binding || storedLink.CredentialDigest != link.CredentialDigest {
		t.Fatalf("accepted link=%+v err=%v", storedLink, err)
	}
	if _, err := refresh(signedLinkEnvelope(t, link, key, 1, freshAt.Add(31*time.Second), 30*time.Second), freshAt.Add(31*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted intent refreshed: %v", err)
	}
	for _, path := range []string{file, file + "-wal"} {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), envelope) || strings.Contains(string(data), "private-user") || strings.Contains(string(data), string(body)) {
			t.Fatalf("private intent exposed in %s", path)
		}
	}
	if err := s.DeleteSession(ctx, link.CredentialDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "request-key", keys, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked credential read intent: %v", err)
	}
	if _, err := refresh(fresh, freshAt.Add(31*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked credential refreshed intent: %v", err)
	}
	if _, _, err := create(link, body, options, envelope, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked credential accepted: %v", err)
	}
}

func TestSignedCopyIntentConcurrentCreation(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	link.Binding.JobOptionsDigest = signedauth.JobOptionsDigest(options)
	body := []byte(`{"mount_id":"mount","source_path":"source","destination_path":"destination"}`)
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	const count = 8
	var wg sync.WaitGroup
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.CreateSignedCopyIntent(ctx, link, "key", body, options, envelope, keys, now)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignedCopyIntentAuditRollback(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	link.Binding.JobOptionsDigest = signedauth.JobOptionsDigest(options)
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateSignedCopyIntent(ctx, link, "key", []byte(`{"mount_id":"mount","source_path":"source","destination_path":"destination"}`), options, envelope, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, now); err == nil {
		t.Fatal("intent committed without audit")
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM signed_copy_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err == nil && version == "7" {
		t.Fatalf("version survived rollback: %q", version)
	}
}

func TestSignedCopyIntentRefreshAuditRollback(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	link.Binding.JobOptionsDigest = signedauth.JobOptionsDigest(options)
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	if _, _, err := s.CreateSignedCopyIntent(ctx, link, "key", []byte(`{"mount_id":"mount","source_path":"source","destination_path":"destination"}`), options, envelope, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	freshAt := now.Add(31 * time.Second)
	fresh := signedLinkEnvelope(t, link, key, 1, freshAt, 30*time.Second)
	if _, err := s.RefreshSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "key", fresh, keys, freshAt); err == nil {
		t.Fatal("refresh committed without audit")
	}
	stored, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "key", keys, freshAt)
	if err != nil || stored.Envelope != envelope {
		t.Fatalf("refresh survived rollback: %+v %v", stored, err)
	}
}

func TestSignedCopyIntentAcceptanceAuditRollback(t *testing.T) {
	s, _, link, key, now := newJobLinkFixture(t)
	ctx := context.Background()
	options := signedauth.JobOptions{ConflictPolicy: "fail", SourceChangePolicy: "fail", MaxParallelFiles: 2, MaxParallelChunks: 1, MaxAttempts: 3}
	link.Binding.JobOptionsDigest = signedauth.JobOptionsDigest(options)
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	envelope := signedLinkEnvelope(t, link, key, 1, now, 30*time.Second)
	if _, _, err := s.CreateSignedCopyIntent(ctx, link, "key", []byte(`{"mount_id":"mount","source_path":"source","destination_path":"destination"}`), options, envelope, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	receipt := SignedCopyReceipt{JobID: link.JobID, Type: "copy_local", State: "waiting_validation", MountID: "mount", Source: "source", Destination: "destination", Options: options}
	if err := s.CompleteSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "key", receipt, keys, now); err == nil {
		t.Fatal("acceptance committed without audit")
	}
	if _, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link survived rollback: %v", err)
	}
	intent, err := s.LoadSignedCopyIntent(ctx, link.NodeID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, "key", keys, now)
	if err != nil || intent.Accepted {
		t.Fatalf("acceptance survived rollback: %+v %v", intent, err)
	}
}
