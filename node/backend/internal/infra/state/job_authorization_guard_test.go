package state

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func TestGuardJobAuthorization(t *testing.T) {
	for _, mode := range []string{"expires", "renewed", "policy changed", "paused"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := openTest(t)
			defer s.Close()
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			job, binding := testAuthorizedJob(now)
			if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			policy := json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/node/files/mounts/mount/**","capabilities":["read","create"]}]}`)
			sign := func(revision uint64, expiry time.Time, contextJSON json.RawMessage) string {
				t.Helper()
				bound, err := signedauth.JobLeaseBinding(binding, revision)
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := signedauth.Sign(signedauth.Claims{Version: 1, KeyID: "key", Binding: bound, IssuedAt: now.Unix(), ExpiresAt: expiry.Unix(), Context: contextJSON}, key)
				if err != nil {
					t.Fatal(err)
				}
				return envelope
			}
			firstExpiry := now.Add(2 * time.Second)
			first := sign(1, firstExpiry, policy)
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, keys, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := s.guardJobAuthorization(ctx, job.ID, "node", map[string]ed25519.PublicKey{}, 20*time.Millisecond); !errors.Is(err, ErrJobAuthorizationUnavailable) {
				t.Fatalf("guard accepted removed key: %v", err)
			}
			guarded, filter, cancel, err := s.guardJobAuthorization(ctx, job.ID, "node", keys, 20*time.Millisecond)
			if err != nil || filter == nil {
				t.Fatalf("guard filter=%v err=%v", filter, err)
			}
			defer cancel()
			switch mode {
			case "renewed":
				second := sign(2, now.Add(5*time.Second), policy)
				if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", second, binding, keys, time.Now()); err != nil {
					t.Fatal(err)
				}
				select {
				case <-guarded.Done():
					t.Fatalf("unchanged policy interrupted: %v", context.Cause(guarded))
				case <-time.After(time.Until(firstExpiry) + 100*time.Millisecond):
				}
			case "policy changed":
				second := sign(2, now.Add(5*time.Second), json.RawMessage(`{"version":1,"rules":[]}`))
				if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", second, binding, keys, time.Now()); err != nil {
					t.Fatal(err)
				}
				select {
				case <-guarded.Done():
					if !errors.Is(context.Cause(guarded), ErrJobAuthorizationChanged) {
						t.Fatalf("cause=%v", context.Cause(guarded))
					}
				case <-time.After(time.Second):
					t.Fatal("policy change did not interrupt guard")
				}
			case "paused":
				stored, err := s.GetJob(ctx, job.ID)
				if err != nil {
					t.Fatal(err)
				}
				stored.State = "paused"
				if err := s.UpdateJob(ctx, stored); err != nil {
					t.Fatal(err)
				}
				select {
				case <-guarded.Done():
					if !errors.Is(context.Cause(guarded), ErrJobAuthorizationUnavailable) {
						t.Fatalf("cause=%v", context.Cause(guarded))
					}
				case <-time.After(time.Second):
					t.Fatal("paused job did not interrupt guard")
				}
			case "expires":
				select {
				case <-guarded.Done():
					if !errors.Is(context.Cause(guarded), ErrJobAuthorizationUnavailable) {
						t.Fatalf("cause=%v", context.Cause(guarded))
					}
				case <-time.After(3 * time.Second):
					t.Fatal("expired authorization did not interrupt guard")
				}
			}
		})
	}
}
