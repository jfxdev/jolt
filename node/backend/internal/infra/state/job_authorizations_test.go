package state

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

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func testJobLease(t *testing.T, key ed25519.PrivateKey, binding signedauth.Binding, revision uint64, now time.Time) string {
	t.Helper()
	bound, err := signedauth.JobLeaseBinding(binding, revision)
	if err != nil {
		t.Fatal(err)
	}
	claims := signedauth.Claims{Version: signedauth.Version, KeyID: "key", Binding: bound, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), Context: json.RawMessage(`{"version":1,"rules":[{"policy_id":"p","path":"nodes/node/files/mounts/mount/**","capabilities":["read","create"]}]}`)}
	token, err := signedauth.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testAuthorizedJob(now time.Time) (entities.Job, signedauth.Binding) {
	job := entities.Job{ID: "job", Type: "copy_local", State: "queued", MountID: "mount", SourcePath: "private-source", Destination: "destination", CreatedAt: now, UpdatedAt: now}
	binding := signedauth.Binding{ActorID: "private-actor", CredentialID: "private-credential", Operation: job.Type, SourceNodeID: "node", SourceMountID: job.MountID, SourceRoot: job.SourcePath, DestinationNodeID: "node", DestinationMountID: job.MountID, DestinationRoot: job.Destination, PlanID: job.ID}
	return job, binding
}

func TestJobAuthorizationRevisionAndDurability(t *testing.T) {
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	forged := job
	forged.SignedAuthBound = true
	if _, _, err := s.CreateJob(ctx, forged, ""); !errors.Is(err, ErrInUse) {
		t.Fatalf("generic creation forged an authorization binding: %v", err)
	}
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateJob(ctx, forged); !errors.Is(err, ErrInUse) {
		t.Fatalf("generic update forged an authorization binding: %v", err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	first := testJobLease(t, key, binding, 1, now)
	auth, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, keys, now)
	if err != nil || auth.Revision != 1 || !auth.ExpiresAt.Equal(now.Add(30*time.Second)) || s.envelopeVersion != 5 {
		t.Fatalf("initial auth=%+v version=%d err=%v", auth, s.envelopeVersion, err)
	}
	stored, err := s.GetJob(ctx, job.ID)
	if err != nil || !stored.SignedAuthBound || stored.State != "waiting_validation" {
		t.Fatalf("job=%+v err=%v", stored, err)
	}
	if _, err := s.ClaimNextJob(ctx, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unvalidated job claimed: %v", err)
	}
	for _, mutate := range []func(*entities.Job){func(j *entities.Job) { j.State = "queued" }, func(j *entities.Job) { j.SignedAuthBound = false }, func(j *entities.Job) { j.SourcePath = "other" }} {
		changed := stored
		mutate(&changed)
		if err := s.UpdateJob(ctx, changed); !errors.Is(err, ErrInUse) {
			t.Fatalf("unsafe job update: %v", err)
		}
	}
	if retried, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, keys, now); err != nil || retried.Revision != 1 || !retried.ExpiresAt.Equal(auth.ExpiresAt) {
		t.Fatalf("identical renewal was not idempotent: %+v %v", retried, err)
	}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, keys, now.Add(30*time.Second)); !errors.Is(err, ErrInUse) {
		t.Fatalf("expired retry accepted: %v", err)
	}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, map[string]ed25519.PublicKey{}, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("retry accepted after signing key removal: %v", err)
	}
	changed := binding
	changed.ActorID = "other"
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, changed, 2, now), changed, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("actor changed: %v", err)
	}
	changed = binding
	changed.CredentialID = "other-credential"
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, changed, 2, now), changed, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("credential changed without reauthorization: %v", err)
	}
	second := testJobLease(t, key, binding, 2, now)
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", second, binding, keys, now.Add(30*time.Second)); !errors.Is(err, ErrInUse) {
		t.Fatalf("expired renewal accepted: %v", err)
	}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", second, binding, keys, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("old revision replay accepted: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	auth, err = s.GetJobAuthorization(ctx, job.ID)
	if err != nil || auth.Revision != 2 || auth.Binding != binding || auth.Envelope != second {
		t.Fatalf("recovered auth=%+v err=%v", auth, err)
	}
	stored, err = s.GetJob(ctx, job.ID)
	if err != nil || !stored.SignedAuthBound || stored.State != "waiting_validation" {
		t.Fatalf("recovered job=%+v err=%v", stored, err)
	}
	jobJSON, err := json.Marshal(stored)
	if err != nil || strings.Contains(string(jobJSON), "has_signed_authorization") || strings.Contains(string(jobJSON), "private-actor") || strings.Contains(string(jobJSON), second) {
		t.Fatalf("private authorization exposed in job JSON: %s %v", jobJSON, err)
	}
	if _, _, err := signedauth.VerifyJobLease(auth.Envelope, keys, auth.Binding, "node", auth.Revision, now); err != nil {
		t.Fatalf("recovered signature: %v", err)
	}
	encoded, err := json.Marshal(auth)
	if err != nil || strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), second) {
		t.Fatalf("auth exposed by JSON: %s %v", encoded, err)
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "private-actor") || strings.Contains(string(data), second) {
			t.Errorf("authorization exposed in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentJobRenewalIsIdempotent(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	token := testJobLease(t, key, binding, 1, now)
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RenewJobAuthorization(ctx, job.ID, "node", token, binding, keys, now)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			t.Fatal(err)
		}
	}
	stored, err := s.GetJobAuthorization(ctx, job.ID)
	if err != nil || accepted != cap(results) || stored.Revision != 1 {
		t.Fatalf("accepted %d renewals, revision=%d error=%v", accepted, stored.Revision, err)
	}
}

func TestJobAuthorizationRejectsChangedScope(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	job, binding := testAuthorizedJob(now)
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	for i, mutate := range []func(*signedauth.Binding){
		func(b *signedauth.Binding) { b.SourceRoot = "other" },
		func(b *signedauth.Binding) { b.DestinationRoot = "other" },
		func(b *signedauth.Binding) { b.PlanID = "other" },
		func(b *signedauth.Binding) { b.Operation = "move_local" },
	} {
		changed := binding
		mutate(&changed)
		token := testJobLease(t, key, changed, 1, now)
		if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", token, changed, keys, now); !errors.Is(err, ErrInUse) {
			t.Fatalf("scope %d accepted: %v", i, err)
		}
	}
	if _, err := s.GetJobAuthorization(ctx, job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authorization recorded on failure: %v", err)
	}
}

func TestVersionFourReaderRejectsJobAuthorization(t *testing.T) {
	checker := os.Getenv("JOLT_VERSION4_STATE_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_VERSION4_STATE_CHECKER to the previous node state reader")
	}
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	plan, _ := testDestructivePlan(now)
	if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	job, binding := testAuthorizedJob(now)
	if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err != nil {
		t.Fatalf("version 4 state rejected: %v %s", err, out)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err == nil || !strings.Contains(string(out), "state envelope identity mismatch") {
		t.Fatalf("old reader accepted version 5: %v %s", err, out)
	}
}

func TestPlanBoundJobAuthorizationKeepsOriginalSubject(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	plan, job := testDestructivePlan(now)
	if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AcceptDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, plan.TreeDigest, false, "", job, "key", strings.Repeat("c", 64), now); err != nil {
		t.Fatal(err)
	}
	binding := signedauth.Binding{ActorID: "other", CredentialID: "credential", Operation: "delete", SourceNodeID: "node", SourceMountID: job.MountID, SourceRoot: job.SourcePath, PlanID: job.ID}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("different plan subject accepted: %v", err)
	}
	binding.ActorID = plan.SubjectID
	if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", testJobLease(t, key, binding, 1, now), binding, keys, now); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetJob(ctx, job.ID)
	if err != nil || stored.State != "waiting_validation" || stored.DestructivePlanID != plan.ID || !stored.SignedAuthBound {
		t.Fatalf("bound job=%+v err=%v", stored, err)
	}
}

func TestJobAuthorizationRenewalRecoversAtomically(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
			job, binding := testAuthorizedJob(now)
			if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			first, second := testJobLease(t, key, binding, 1, now), testJobLease(t, key, binding, 2, now)
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", first, binding, keys, now); err != nil {
				t.Fatal(err)
			}
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected power loss")
				}
				return nil
			}
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", second, binding, keys, now); err == nil {
				t.Fatal("fault not injected")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err := Open(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			recovered, err := s.GetJobAuthorization(ctx, job.ID)
			wantRevision := uint64(1)
			if point == "after_rename" || point == "after_directory_sync" {
				wantRevision = 2
			}
			if err != nil || recovered.Revision != wantRevision {
				t.Fatalf("recovered revision=%d want=%d err=%v", recovered.Revision, wantRevision, err)
			}
			latest, err := s.RenewJobAuthorization(ctx, job.ID, "node", second, binding, keys, now)
			if err != nil || latest.Revision != 2 {
				t.Fatalf("retry revision=%d err=%v", latest.Revision, err)
			}
			stored, err := s.GetJob(ctx, job.ID)
			if err != nil || !stored.SignedAuthBound || stored.State != "waiting_validation" {
				t.Fatalf("inconsistent job=%+v err=%v", stored, err)
			}
		})
	}
}

func TestJobAuthorizationVersionUpgradeRecoversAfterFault(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
			plan, _ := testDestructivePlan(now)
			if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
				t.Fatal(err)
			}
			job, binding := testAuthorizedJob(now)
			if _, _, err := s.CreateJob(ctx, job, ""); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
			token := testJobLease(t, key, binding, 1, now)
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected power loss")
				}
				return nil
			}
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", token, binding, keys, now); err == nil {
				t.Fatal("fault not injected")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err := Open(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			want := 4
			if point == "after_rename" || point == "after_directory_sync" {
				want = 5
			}
			if s.envelopeVersion != want {
				t.Fatalf("version=%d want=%d", s.envelopeVersion, want)
			}
			if _, err := s.GetJobAuthorization(ctx, job.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("partial authorization: %v", err)
			}
			stored, err := s.GetJob(ctx, job.ID)
			if err != nil || stored.SignedAuthBound || stored.State != "queued" {
				t.Fatalf("partial binding=%+v err=%v", stored, err)
			}
			if _, err := s.RenewJobAuthorization(ctx, job.ID, "node", token, binding, keys, now); err != nil {
				t.Fatalf("retry: %v", err)
			}
		})
	}
}
