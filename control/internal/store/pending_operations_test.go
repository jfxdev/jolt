package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
)

func openPendingStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func sampleOperation(body string) PendingOperation {
	return PendingOperation{RequesterType: "user", RequesterID: "op", Method: "DELETE", NodeID: "n", Resource: "mounts/m/files", RawQuery: "path=a.txt", Body: []byte(body),
		Summary: []byte(`{"operation":"delete"}`), Requirements: []PendingRequirement{{Path: "nodes/n/files/mounts/m/a.txt", Capability: "delete"}}}
}

func TestApprovalMarksPersistAndRaiseTheSecurityVersion(t *testing.T) {
	ctx := context.Background()
	s, path := openPendingStore(t)
	now := time.Now().UTC()
	if _, err := s.Metadata(ctx, "minimum_security_version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version set too early: %v", err)
	}
	plain := Policy{ID: "plain", Name: "plain", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n/files/mounts/m/**", Capabilities: []string{"delete"}}}}
	if err := s.CreatePolicy(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Metadata(ctx, "minimum_security_version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a rule without marks raised the version: %v", err)
	}
	marked := Policy{ID: "marked", Name: "marked", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n/files/mounts/m/**", Capabilities: []string{"read", "delete"}, NeedsApproval: []string{"delete"}}}}
	if err := s.CreatePolicy(ctx, marked); err != nil {
		t.Fatal(err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err != nil || version != "8" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	for name, rules := range map[string][]rbac.Rule{
		"mark not granted": {{Path: "nodes/n/files/mounts/m", Capabilities: []string{"read"}, NeedsApproval: []string{"delete"}}},
		"mark on a denial": {{Path: "nodes/n/files/mounts/m", Capabilities: []string{"deny", "delete"}, NeedsApproval: []string{"delete"}}},
	} {
		if err := s.CreatePolicy(ctx, Policy{ID: "bad-" + name, Name: "bad-" + name, CreatedAt: now, UpdatedAt: now, Rules: rules}); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetPolicy(ctx, "marked")
	if err != nil || !reflect.DeepEqual(got.Rules, marked.Rules) {
		t.Fatalf("rules=%+v err=%v", got.Rules, err)
	}
	// A binary that supports only the previous version must refuse this database.
	if err := s.SetMetadata(ctx, "minimum_security_version", "9"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(path, testDatabaseKey); err == nil {
		t.Fatal("a database from a newer version was opened")
	}
}

func TestPendingOperationLifecycle(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	now := time.Now().UTC()
	op, existing, err := s.CreatePendingOperation(ctx, sampleOperation(`{"a":1}`), 3, now)
	if err != nil || existing || op.State != PendingState || op.ExpiresAt.Sub(op.CreatedAt) != PendingLifetime || op.BodySHA256 == "" {
		t.Fatalf("create: %+v existing=%v err=%v", op, existing, err)
	}
	// The same request again returns the same entry instead of queueing another.
	again, existing, err := s.CreatePendingOperation(ctx, sampleOperation(`{"a":1}`), 3, now.Add(time.Second))
	if err != nil || !existing || again.ID != op.ID {
		t.Fatalf("duplicate: %+v existing=%v err=%v", again, existing, err)
	}
	other, _, err := s.CreatePendingOperation(ctx, sampleOperation(`{"a":2}`), 3, now)
	if err != nil || other.ID == op.ID {
		t.Fatalf("a different body shared an entry: %+v %v", other, err)
	}
	claimed, err := s.ClaimPendingOperation(ctx, op.ID, "user", "admin", now.Add(time.Minute))
	if err != nil || claimed.State != PendingExecuting || claimed.DecidedByID != "admin" || string(claimed.Body) != `{"a":1}` {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if _, err := s.ClaimPendingOperation(ctx, op.ID, "user", "admin2", now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second claim: %v", err)
	}
	if _, err := s.RejectPendingOperation(ctx, op.ID, "user", "admin", "no", now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("rejecting an executing request: %v", err)
	}
	if err := s.FinishPendingOperation(ctx, op.ID, 202, `{"job_id":"j"}`, now); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishPendingOperation(ctx, op.ID, 500, `x`, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("a finished request finished again: %v", err)
	}
	done, err := s.GetPendingOperation(ctx, op.ID, now)
	if err != nil || done.State != PendingExecuted || done.ResultStatus != 202 || done.ResultBody != `{"job_id":"j"}` {
		t.Fatalf("result: %+v %v", done, err)
	}
	rejected, err := s.RejectPendingOperation(ctx, other.ID, "user", "admin", "not now", now)
	if err != nil || rejected.State != PendingRejected || rejected.Note != "not now" {
		t.Fatalf("reject: %+v %v", rejected, err)
	}
	if _, err := s.ClaimPendingOperation(ctx, other.ID, "user", "admin", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("claiming a rejected request: %v", err)
	}
	if _, err := s.GetPendingOperation(ctx, "pop_missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	failed, _, _ := s.CreatePendingOperation(ctx, sampleOperation(`{"a":3}`), 3, now)
	if _, err := s.ClaimPendingOperation(ctx, failed.ID, "user", "admin", now); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishPendingOperation(ctx, failed.ID, 403, `denied`, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetPendingOperation(ctx, failed.ID, now); got.State != PendingFailed {
		t.Fatalf("an error answer was not recorded as failed: %+v", got)
	}
}

func TestPendingOperationsExpireAreCappedAndSurviveNoReplay(t *testing.T) {
	ctx := context.Background()
	s, path := openPendingStore(t)
	now := time.Now().UTC()
	first, _, err := s.CreatePendingOperation(ctx, sampleOperation(`1`), 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreatePendingOperation(ctx, sampleOperation(`2`), 2, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreatePendingOperation(ctx, sampleOperation(`3`), 2, now); !errors.Is(err, ErrPendingTooMany) {
		t.Fatalf("cap: %v", err)
	}
	// Another requester has an allowance of its own.
	stranger := sampleOperation(`3`)
	stranger.RequesterID = "someone-else"
	if _, _, err := s.CreatePendingOperation(ctx, stranger, 2, now); err != nil {
		t.Fatalf("cap leaked across requesters: %v", err)
	}
	late := now.Add(PendingLifetime)
	if _, err := s.ClaimPendingOperation(ctx, first.ID, "user", "admin", late); !errors.Is(err, ErrPendingExpired) {
		t.Fatalf("late claim: %v", err)
	}
	if got, _ := s.GetPendingOperation(ctx, first.ID, late); got.State != PendingExpired {
		t.Fatalf("not expired: %+v", got)
	}
	// Room again once the old ones expired.
	if _, _, err := s.CreatePendingOperation(ctx, sampleOperation(`4`), 2, late); err != nil {
		t.Fatalf("expired requests still counted: %v", err)
	}
	// A request caught executing by a restart is never replayed.
	running, _, _ := s.CreatePendingOperation(ctx, sampleOperation(`5`), 5, late)
	if _, err := s.ClaimPendingOperation(ctx, running.ID, "user", "admin", late); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetPendingOperation(ctx, running.ID, late)
	if err != nil || got.State != PendingIndeterminate {
		t.Fatalf("after restart: %+v %v", got, err)
	}
	if _, err := s.ClaimPendingOperation(ctx, running.ID, "user", "admin", late); !errors.Is(err, ErrConflict) {
		t.Fatalf("an indeterminate request can be claimed again: %v", err)
	}
	// Old decided requests are forgotten, waiting ones are not.
	if _, err := s.GetPendingOperation(ctx, first.ID, late.Add(pendingKeep+time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an old expired request was kept: %v", err)
	}
}

func TestOnlyOneApproverClaimsAPendingOperation(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	now := time.Now().UTC()
	op, _, err := s.CreatePendingOperation(ctx, sampleOperation(`x`), 3, now)
	if err != nil {
		t.Fatal(err)
	}
	var wins, losses int
	var mutex sync.Mutex
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := s.ClaimPendingOperation(ctx, op.ID, "user", "admin", now)
			mutex.Lock()
			defer mutex.Unlock()
			if err == nil {
				wins++
			} else if errors.Is(err, ErrConflict) {
				losses++
			} else {
				t.Errorf("claim: %v", err)
			}
		}()
	}
	group.Wait()
	if wins != 1 || losses != 7 {
		t.Fatalf("wins=%d losses=%d", wins, losses)
	}
}

func TestPendingListFiltersByStateAndRequester(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	now := time.Now().UTC()
	mine, _, _ := s.CreatePendingOperation(ctx, sampleOperation(`1`), 5, now)
	other := sampleOperation(`2`)
	other.RequesterID = "someone-else"
	theirs, _, _ := s.CreatePendingOperation(ctx, other, 5, now.Add(time.Second))
	if _, err := s.RejectPendingOperation(ctx, theirs.ID, "user", "admin", "", now); err != nil {
		t.Fatal(err)
	}
	all, _ := s.ListPendingOperations(ctx, "", "", "", 10, now)
	waiting, _ := s.ListPendingOperations(ctx, PendingState, "", "", 10, now)
	own, _ := s.ListPendingOperations(ctx, "", "user", "op", 10, now)
	if len(all) != 2 || len(waiting) != 1 || waiting[0].ID != mine.ID || len(own) != 1 || own[0].ID != mine.ID {
		t.Fatalf("all=%d waiting=%d own=%d", len(all), len(waiting), len(own))
	}
}

func TestPendingOperationIntegrity(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	op, _, err := s.CreatePendingOperation(ctx, sampleOperation(`{"a":1}`), 3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetPendingOperation(ctx, op.ID, time.Now())
	if !got.IntegrityOK() {
		t.Fatal("a stored request failed its own check")
	}
	got.Body = []byte(`{"a":2}`)
	if got.IntegrityOK() {
		t.Fatal("a changed body passed the check")
	}
}

func TestAClaimRefusesARequestThatNoLongerMatchesItsDigest(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	now := time.Now().UTC()
	op, _, err := s.CreatePendingOperation(ctx, sampleOperation(`{"path":"a.txt"}`), 3, now)
	if err != nil {
		t.Fatal(err)
	}
	// Someone with the database changes what will be replayed.
	if _, err := s.db.ExecContext(ctx, `UPDATE pending_operations SET body=? WHERE id=?`, []byte(`{"path":"everything"}`), op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimPendingOperation(ctx, op.ID, "user", "admin", now); !errors.Is(err, ErrPendingCorrupt) {
		t.Fatalf("a tampered request was claimed: %v", err)
	}
	got, _ := s.GetPendingOperation(ctx, op.ID, now)
	if got.State != PendingState {
		t.Fatalf("a refused claim changed the state: %+v", got)
	}
}
