package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestClaimNextSecuredJobRequiresValidLease(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	if _, err := s.ClaimNextSecuredJob(ctx, "node", keys, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbound job claimed: %v", err)
	}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNextJob(ctx, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("generic claim started a secured job: %v", err)
	}
	if _, err := s.ClaimNextSecuredJob(ctx, "other-node", keys, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job claimed for another node: %v", err)
	}
	stored, err := s.GetJob(ctx, job.ID)
	if err != nil || stored.State != "waiting_validation" || stored.Phase != "waiting_authorization" {
		t.Fatalf("job with an unusable lease was not parked: %+v %v", stored, err)
	}
	if _, err := s.ClaimNextSecuredJob(ctx, "node", keys, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("parked job claimed: %v", err)
	}
	// A newer lease queues the parked job again without an explicit resume.
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 2, now), binding, keys, now); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimNextSecuredJob(ctx, "node", keys, now)
	if err != nil || claimed.ID != job.ID || claimed.State != "running" || claimed.Attempt != 1 || claimed.StartedAt == nil {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err := s.ClaimNextSecuredJob(ctx, "node", keys, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("running job claimed again: %v", err)
	}
	// The claimed executor may finish the job, but nothing restarts it by a
	// generic update.
	done := claimed
	done.State = "completed"
	if err := s.UpdateJob(ctx, done); err != nil {
		t.Fatalf("claimed job could not finish: %v", err)
	}
	again := done
	again.State = "queued"
	if err := s.UpdateJob(ctx, again); !errors.Is(err, ErrInUse) {
		t.Fatalf("completed secured job restarted: %v", err)
	}
}

func TestClaimNextSecuredJobExpiredLeaseWaitsForRenewal(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNextSecuredJob(ctx, "node", keys, now.Add(31*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired lease claimed: %v", err)
	}
	stored, err := s.GetJob(ctx, job.ID)
	if err != nil || stored.State != "waiting_validation" || stored.Phase != "waiting_authorization" || stored.Error == "" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	later := now.Add(31 * time.Second)
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 2, later), binding, keys, later); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s.ClaimNextSecuredJob(ctx, "node", keys, later); err != nil || claimed.ID != job.ID {
		t.Fatalf("renewed job not claimed: %+v %v", claimed, err)
	}
}

func TestRenewalDoesNotResumeOperatorOrRecoveryStops(t *testing.T) {
	for name, prepare := range map[string]func(*Store, context.Context, string, time.Time) error{
		"paused": func(s *Store, ctx context.Context, id string, _ time.Time) error {
			job, err := s.GetJob(ctx, id)
			if err != nil {
				return err
			}
			job.State, job.Phase = "paused", "paused"
			return s.UpdateJob(ctx, job)
		},
		"recovery": func(s *Store, ctx context.Context, id string, _ time.Time) error {
			job, err := s.GetJob(ctx, id)
			if err != nil {
				return err
			}
			job.State, job.Phase = "waiting_validation", "waiting_validation"
			return s.UpdateJob(ctx, job)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := openTest(t)
			ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
			job, binding := testAuthorizedJob(now)
			if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); err != nil {
				t.Fatal(err)
			}
			if err := prepare(s, ctx, job.ID, now); err != nil {
				t.Fatal(err)
			}
			before, _ := s.GetJob(ctx, job.ID)
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 2, now), binding, keys, now); err != nil {
				t.Fatal(err)
			}
			after, err := s.GetJob(ctx, job.ID)
			if err != nil || after.State != before.State || after.State == "queued" {
				t.Fatalf("renewal changed %s job: before=%s after=%+v err=%v", name, before.State, after, err)
			}
			if _, err := s.ClaimNextSecuredJob(ctx, "node", keys, now); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s job claimed: %v", name, err)
			}
		})
	}
}
