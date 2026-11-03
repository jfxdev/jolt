package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func testDestructivePlan(now time.Time) (DestructivePlan, entities.Job) {
	plan := DestructivePlan{ID: "plan", TokenHash: strings.Repeat("a", 64), SubjectType: "user", SubjectID: "private-actor", Operation: "delete", MountID: "mount", Source: "private-tree", TreeDigest: strings.Repeat("b", 64)}
	job := entities.Job{ID: "job", Type: "delete", State: "queued", MountID: plan.MountID, SourcePath: plan.Source, Recursive: true, CreatedAt: now, UpdatedAt: now}
	return plan, job
}

func TestDestructivePlanIsOneUseAndIdempotentAcrossRestart(t *testing.T) {
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	plan, job := testDestructivePlan(now)
	if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	if s.envelopeVersion != 4 {
		t.Fatalf("security version=%d", s.envelopeVersion)
	}
	if _, err := s.GetDestructivePlan(ctx, plan.ID, plan.SubjectType, "other", plan.TokenHash, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("plan visible to wrong subject: %v", err)
	}
	if _, err := s.GetDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, now.Add(5*time.Minute)); !errors.Is(err, ErrInUse) {
		t.Fatalf("expired plan visible: %v", err)
	}
	requestHash := strings.Repeat("c", 64)
	accept := func(subject, token, tree, key, hash string, at time.Time) (entities.Job, bool, error) {
		return s.AcceptDestructivePlan(ctx, plan.ID, "user", subject, token, tree, false, "", job, key, hash, at)
	}
	for _, tc := range []struct{ subject, token, tree string }{
		{"other", plan.TokenHash, plan.TreeDigest},
		{plan.SubjectID, strings.Repeat("d", 64), plan.TreeDigest},
		{plan.SubjectID, plan.TokenHash, strings.Repeat("e", 64)},
	} {
		if _, _, err := accept(tc.subject, tc.token, tc.tree, "key", requestHash, now); !errors.Is(err, ErrInUse) {
			t.Fatalf("mismatch accepted: %v", err)
		}
	}
	if _, _, err := accept(plan.SubjectID, plan.TokenHash, plan.TreeDigest, "key", requestHash, now.Add(5*time.Minute)); !errors.Is(err, ErrInUse) {
		t.Fatalf("expired plan accepted: %v", err)
	}
	accepted, repeated, err := accept(plan.SubjectID, plan.TokenHash, plan.TreeDigest, "key", requestHash, now.Add(time.Second))
	if err != nil || repeated || accepted.ID != job.ID {
		t.Fatalf("accept=%+v repeated=%v err=%v", accepted, repeated, err)
	}
	otherPlan := plan
	otherPlan.ID = "other-plan"
	otherJob := job
	otherJob.ID = "other-job"
	if err := s.CreateDestructivePlan(ctx, otherPlan, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AcceptDestructivePlan(ctx, otherPlan.ID, otherPlan.SubjectType, otherPlan.SubjectID, otherPlan.TokenHash, otherPlan.TreeDigest, false, "", otherJob, "key", requestHash, now); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency key accepted for another plan: %v", err)
	}
	if _, _, err := accept(plan.SubjectID, plan.TokenHash, plan.TreeDigest, "other", requestHash, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("token reuse accepted: %v", err)
	}
	if _, _, err := accept(plan.SubjectID, plan.TokenHash, plan.TreeDigest, "key", strings.Repeat("d", 64), now); !errors.Is(err, ErrInUse) {
		t.Fatalf("changed request accepted: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	accepted, repeated, err = s.AcceptDestructivePlan(ctx, plan.ID, "user", plan.SubjectID, plan.TokenHash, plan.TreeDigest, false, "", job, "key", requestHash, now.Add(10*time.Minute))
	if err != nil || !repeated || accepted.ID != job.ID {
		t.Fatalf("retry after restart=%+v repeated=%v err=%v", accepted, repeated, err)
	}
	if recovered, err := s.GetDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, now.Add(10*time.Minute)); err != nil || recovered.ConsumedJobID != job.ID {
		t.Fatalf("consumed plan unavailable for retry: %+v %v", recovered, err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), plan.SubjectID) || strings.Contains(string(encoded), plan.TokenHash) {
		t.Fatalf("plan leaked in JSON: %s %v", encoded, err)
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), plan.SubjectID) || strings.Contains(string(data), plan.TokenHash) || strings.Contains(string(data), plan.Source) {
			t.Errorf("plan leaked in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDestructivePlanConcurrentConfirmationCreatesOneJob(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	plan, original := testDestructivePlan(now)
	if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 24)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			job := original
			job.ID = fmt.Sprintf("job-%d", i)
			_, _, err := s.AcceptDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, plan.TreeDigest, false, "", job, fmt.Sprintf("key-%d", i), strings.Repeat("c", 64), now)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrInUse) {
			t.Fatal(err)
		}
	}
	jobs, err := s.ListJobs(ctx, -1)
	if err != nil || success != 1 || len(jobs) != 1 {
		t.Fatalf("success=%d jobs=%d err=%v", success, len(jobs), err)
	}
}

func TestDestructiveMovePlanBindsDestinationAndOverwrite(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	plan, job := testDestructivePlan(now)
	plan.Operation, plan.Destination, plan.Overwrite, plan.DestinationExists, plan.DestinationDigest = "move", "destination", true, true, strings.Repeat("d", 64)
	job.Type, job.Destination, job.Overwrite, job.Recursive = "move_local", plan.Destination, true, false
	if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	for _, state := range []struct {
		exists bool
		digest string
	}{{false, ""}, {true, strings.Repeat("e", 64)}} {
		if _, _, err := s.AcceptDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, plan.TreeDigest, state.exists, state.digest, job, "key", strings.Repeat("c", 64), now); !errors.Is(err, ErrInUse) {
			t.Fatalf("changed destination accepted: %v", err)
		}
	}
	if _, _, err := s.AcceptDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, plan.TreeDigest, true, plan.DestinationDigest, job, "key", strings.Repeat("c", 64), now); err != nil {
		t.Fatal(err)
	}
}

func TestPreviousStateReaderRejectsDestructivePlans(t *testing.T) {
	checker := os.Getenv("JOLT_VERSION3_STATE_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_VERSION3_STATE_CHECKER to a reader built before destructive plans")
	}
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	if err := s.CreateUploadSession(ctx, entities.UploadSession{ID: "legacy", MountID: "mount", Destination: "file", AuthorizationActorID: "actor", AuthorizationCredentialID: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReauthorizeUploadSession(ctx, "legacy", "actor", "new", signedauth.UploadReauthorizationRequestID("legacy", "old", 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err != nil {
		t.Fatalf("previous reader rejected legacy state: %v %s", err, out)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := testDestructivePlan(now)
	if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, dir).CombinedOutput(); err == nil || !strings.Contains(string(out), "state envelope identity mismatch") {
		t.Fatalf("previous reader accepted version 4 state: %v %s", err, out)
	}
}

func TestDestructivePlanAcceptanceRecoversAtomically(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx, now := context.Background(), time.Now().UTC()
			plan, job := testDestructivePlan(now)
			if err := s.CreateDestructivePlan(ctx, plan, now); err != nil {
				t.Fatal(err)
			}
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected power loss")
				}
				return nil
			}
			hash := strings.Repeat("c", 64)
			if _, _, err := s.AcceptDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, plan.TreeDigest, false, "", job, "key", hash, now); err == nil {
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
			_, jobErr := s.GetJob(ctx, job.ID)
			wantCommitted := point == "after_rename" || point == "after_directory_sync"
			if (jobErr == nil) != wantCommitted {
				t.Fatalf("job after recovery=%v want committed=%v", jobErr, wantCommitted)
			}
			accepted, repeated, err := s.AcceptDestructivePlan(ctx, plan.ID, plan.SubjectType, plan.SubjectID, plan.TokenHash, plan.TreeDigest, false, "", job, "key", hash, now)
			if err != nil || repeated != wantCommitted || accepted.ID != job.ID {
				t.Fatalf("retry accepted=%+v repeated=%v error=%v", accepted, repeated, err)
			}
			jobs, err := s.ListJobs(ctx, -1)
			if err != nil || len(jobs) != 1 {
				t.Fatalf("non-atomic recovery: %d jobs, %v", len(jobs), err)
			}
		})
	}
}

func TestDestructivePlanPurgeKeepsConsumedRetries(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	consumed, job := testDestructivePlan(now)
	unused := consumed
	unused.ID = "unused"
	if err := s.CreateDestructivePlan(ctx, consumed, now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDestructivePlan(ctx, unused, now); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("c", 64)
	if _, _, err := s.AcceptDestructivePlan(ctx, consumed.ID, consumed.SubjectType, consumed.SubjectID, consumed.TokenHash, consumed.TreeDigest, false, "", job, "key", hash, now); err != nil {
		t.Fatal(err)
	}
	count, err := s.PurgeExpiredDestructivePlans(ctx, now.Add(5*time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("purge=%d err=%v", count, err)
	}
	if _, err := s.GetDestructivePlan(ctx, unused.ID, unused.SubjectType, unused.SubjectID, unused.TokenHash, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unused plan remains: %v", err)
	}
	got, repeated, err := s.AcceptDestructivePlan(ctx, consumed.ID, consumed.SubjectType, consumed.SubjectID, consumed.TokenHash, consumed.TreeDigest, false, "", job, "key", hash, now.Add(6*time.Minute))
	if err != nil || !repeated || got.ID != job.ID {
		t.Fatalf("consumed plan lost: %+v repeated=%v err=%v", got, repeated, err)
	}
}

func TestDestructivePlanRejectsInvalidBindings(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	base, job := testDestructivePlan(now)
	for _, mutate := range []func(*DestructivePlan){
		func(p *DestructivePlan) { p.Source = "a/../private-tree" },
		func(p *DestructivePlan) { p.Source = "/absolute" },
		func(p *DestructivePlan) { p.SubjectType = "unknown" },
		func(p *DestructivePlan) { p.TokenHash = "invalid" },
		func(p *DestructivePlan) { p.Operation, p.Destination = "move", "private-tree/child" },
		func(p *DestructivePlan) {
			p.Operation, p.Destination, p.DestinationExists = "move", "destination", true
		},
	} {
		invalid := base
		mutate(&invalid)
		if err := s.CreateDestructivePlan(ctx, invalid, now); err == nil {
			t.Fatalf("invalid plan accepted: %+v", invalid)
		}
	}
	if s.envelopeVersion != 1 {
		t.Fatalf("invalid plan upgraded state: %d", s.envelopeVersion)
	}
	if err := s.CreateDestructivePlan(ctx, base, now); err != nil {
		t.Fatal(err)
	}
	job.Recursive = false
	if _, _, err := s.AcceptDestructivePlan(ctx, base.ID, base.SubjectType, base.SubjectID, base.TokenHash, base.TreeDigest, false, "", job, "key", strings.Repeat("c", 64), now); !errors.Is(err, ErrInUse) {
		t.Fatalf("different operation accepted: %v", err)
	}
}
