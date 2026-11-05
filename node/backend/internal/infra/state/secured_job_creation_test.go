package state

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

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func TestCreateJobAwaitingAuthorization(t *testing.T) {
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	binding.JobOptionsDigest = signedauth.JobOptionsDigest(signedauth.JobOptions{})
	created, repeated, err := s.CreateJobAwaitingAuthorization(ctx, job, binding.ActorID, binding.CredentialID, "request-key", "request-hash")
	if err != nil || repeated || created.State != "waiting_validation" || !created.RequiresSignedAuth || created.SignedAuthBound || s.envelopeVersion != 6 {
		t.Fatalf("created=%+v repeated=%v err=%v", created, repeated, err)
	}
	other := job
	other.ID = "different-job"
	if got, repeated, err := s.CreateJobAwaitingAuthorization(ctx, other, binding.ActorID, binding.CredentialID, "request-key", "request-hash"); err != nil || !repeated || got.ID != job.ID {
		t.Fatalf("retry=%+v repeated=%v err=%v", got, repeated, err)
	}
	if _, _, err := s.CreateJobAwaitingAuthorization(ctx, other, "other", binding.CredentialID, "request-key", "request-hash"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("other actor: %v", err)
	}
	if _, _, err := s.CreateJobAwaitingAuthorization(ctx, other, binding.ActorID, "other", "request-key", "request-hash"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("other credential: %v", err)
	}
	if _, _, err := s.CreateJobAwaitingAuthorization(ctx, other, binding.ActorID, binding.CredentialID, "request-key", "different-hash"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("other request: %v", err)
	}
	if _, _, err := s.CreateJob(ctx, other, "request-key"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("generic retry: %v", err)
	}
	for _, change := range []func(*entities.Job){func(j *entities.Job) { j.State = "queued" }, func(j *entities.Job) { j.RequiresSignedAuth = false }, func(j *entities.Job) { j.SignedAuthActorID = "other" }, func(j *entities.Job) { j.SignedAuthCredentialID = "other" }, func(j *entities.Job) { j.Destination = "other" }, func(j *entities.Job) { j.BandwidthLimit++ }, func(j *entities.Job) { j.MaxParallelFiles++ }, func(j *entities.Job) { j.MaxParallelChunks++ }, func(j *entities.Job) { j.MaxAttempts++ }} {
		mutated := created
		change(&mutated)
		if err := s.UpdateJob(ctx, mutated); !errors.Is(err, ErrInUse) {
			t.Fatalf("unsafe update accepted: %v", err)
		}
	}
	if err := s.ReplaceJobItems(ctx, job.ID, []entities.JobItem{{RelativePath: "other"}}); !errors.Is(err, ErrInUse) {
		t.Fatalf("job items replaced: %v", err)
	}
	if _, err := s.ClaimNextJob(ctx, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unverified job claimed: %v", err)
	}
	if revision, expiry, digest, err := s.JobAuthorizationStatus(ctx, job.ID); err != nil || revision != 0 || !expiry.IsZero() || digest != "" {
		t.Fatalf("initial status=%d %v %q err=%v", revision, expiry, digest, err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	wrong := binding
	wrong.ActorID = "other"
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, wrong, 1, now), wrong, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("wrong actor accepted: %v", err)
	}
	wrong = binding
	wrong.CredentialID = "other"
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, wrong, 1, now), wrong, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("wrong credential accepted: %v", err)
	}
	wrong = binding
	wrong.JobOptionsDigest = signedauth.JobOptionsDigest(signedauth.JobOptions{Overwrite: true})
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, wrong, 1, now), wrong, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("wrong job options accepted: %v", err)
	}
	wrong = binding
	wrong.JobOptionsDigest = ""
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, wrong, 1, now), wrong, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("missing job options accepted: %v", err)
	}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, filter, err := s.ValidateJobAuthorization(ctx, job.ID, "node", keys, now); err != nil || filter == nil {
		t.Fatalf("bound options did not survive storage: filter=%v err=%v", filter, err)
	}
	if _, err := s.ClaimNextJob(ctx, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job executed before runtime integration: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if checker := os.Getenv("JOLT_VERSION5_STATE_CHECKER"); checker != "" {
		if output, err := exec.Command(checker, dir).CombinedOutput(); err == nil || !strings.Contains(string(output), "state envelope identity mismatch") {
			t.Fatalf("old reader accepted version 6: %v %s", err, output)
		}
	}
	s, err = Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stored, err := s.GetJob(ctx, job.ID)
	if err != nil || !stored.RequiresSignedAuth || !stored.SignedAuthBound || stored.State != "waiting_validation" || stored.SignedAuthActorID != binding.ActorID || stored.SignedAuthCredentialID != binding.CredentialID {
		t.Fatalf("recovered=%+v err=%v", stored, err)
	}
	encoded, err := json.Marshal(stored)
	if err != nil || strings.Contains(string(encoded), binding.ActorID) || strings.Contains(string(encoded), binding.CredentialID) || strings.Contains(string(encoded), "requires_signed_authorization") {
		t.Fatalf("private identity exposed: %s %v", encoded, err)
	}
}

func TestCreateJobAwaitingAuthorizationConcurrentIdempotency(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	ctx, now := context.Background(), time.Now().UTC()
	job, binding := testAuthorizedJob(now)
	const count = 8
	results := make(chan entities.Job, count)
	errorsOut := make(chan error, count)
	var group sync.WaitGroup
	for i := 0; i < count; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			created, _, err := s.CreateJobAwaitingAuthorization(ctx, job, binding.ActorID, binding.CredentialID, "request-key", "request-hash")
			results <- created
			errorsOut <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if result.ID != job.ID || result.State != "waiting_validation" || !result.RequiresSignedAuth {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestVersionFiveReaderRejectsAwaitingAuthorization(t *testing.T) {
	checker := os.Getenv("JOLT_VERSION5_STATE_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_VERSION5_STATE_CHECKER to the previous node state reader")
	}
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(checker, dir).CombinedOutput(); err != nil {
		t.Fatalf("old reader rejected version 5: %v %s", err, output)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	job.ID = "another-job"
	if _, _, err := s.CreateJobAwaitingAuthorization(ctx, job, binding.ActorID, binding.CredentialID, "request-key", "request-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(checker, dir).CombinedOutput(); err == nil || !strings.Contains(string(output), "state envelope identity mismatch") {
		t.Fatalf("old reader accepted version 6: %v %s", err, output)
	}
}
