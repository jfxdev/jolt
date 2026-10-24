package state

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = make([]byte, 32)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func sampleJob(id string) entities.Job {
	return entities.Job{ID: id, Type: "copy_local", MountID: "files", State: "queued", Phase: "validation", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), MaxAttempts: 3}
}
func TestDurabilityBoundaries(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := openTest(t)
			ctx := context.Background()
			if _, _, err := s.CreateJob(ctx, sampleJob("first"), "first-request"); err != nil {
				t.Fatal(err)
			}
			s.fault = func(at string) error {
				if at == point {
					return errors.New("injected power loss")
				}
				return nil
			}
			_, _, err := s.CreateJobWithItemsHashed(ctx, sampleJob("second"), []entities.JobItem{{RelativePath: "one", Ordinal: 0}, {RelativePath: "two", Ordinal: 1}}, "second-request", "hash")
			if err == nil {
				t.Fatal("fault was not injected")
			}
			if _, _, err = s.CreateJob(ctx, sampleJob("third"), ""); !errors.Is(err, contracts.ErrStateUnavailable) {
				t.Fatal("poisoned store continued")
			}
			s.Close()
			s, err = Open(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.GetJob(ctx, "first"); err != nil {
				t.Fatal("acknowledged transaction lost")
			}
			_, err = s.GetJob(ctx, "second")
			want := point == "after_rename" || point == "after_directory_sync"
			if (err == nil) != want {
				t.Fatalf("unexpected transaction outcome at %s: %v", point, err)
			}
			if want {
				items, e := s.ListJobItems(ctx, "second")
				if e != nil || len(items) != 2 {
					t.Fatal("partial transaction")
				}
				_, hash, found, e := s.FindJobByIdempotency(ctx, "second-request")
				if e != nil || !found || hash != "hash" {
					t.Fatal("idempotency not atomic")
				}
			}
		})
	}
}
func TestEncryptionTamperingAndLock(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	if _, _, err := s.CreateJob(ctx, sampleJob("classified-name"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, testKey); err == nil {
		t.Fatal("second instance opened")
	}
	s.Close()
	wrong := make([]byte, 32)
	wrong[0] = 1
	if _, err := OpenExisting(dir, wrong); err == nil {
		t.Fatal("wrong key accepted")
	}
	path := filepath.Join(dir, "journal", "00000000000000000001.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "classified-name") {
		t.Fatal("plaintext leaked")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
	raw = []byte(strings.Replace(string(raw), "kind: transaction", "kind: snapshot", 1))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(dir, testKey); err == nil {
		t.Fatal("tampered state accepted")
	}
}
func TestCompactionPreservesHistoryAndIdempotency(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	job := sampleJob("job")
	if _, _, err := s.CreateJob(ctx, job, "request"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < compactTransactions+20; i++ {
		if _, err := s.RecordJobEvent(ctx, entities.JobEvent{JobID: job.ID, Type: "progress", BytesCompleted: int64(i), CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if s.journalCount >= compactTransactions || s.snapshotSequence == 0 {
		t.Fatal("journal was not bounded")
	}
	s.Close()
	s, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after := int64(0)
	count := 0
	for {
		events, e := s.ListJobEvents(ctx, after, "job", 97)
		if e != nil {
			t.Fatal(e)
		}
		if len(events) == 0 {
			break
		}
		count += len(events)
		after = events[len(events)-1].ID
	}
	if count != compactTransactions+20 {
		t.Fatalf("history lost: %d", count)
	}
	_, _, found, err := s.FindJobByIdempotency(ctx, "request")
	if err != nil || !found {
		t.Fatal("idempotency lost")
	}
	if s.cacheBytes > cacheLimit {
		t.Fatal("unbounded payload cache")
	}
}
func TestConcurrentClaimsIdempotencyAndUploads(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	ids := make(chan string, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, _, err := s.CreateJobWithItemsHashed(ctx, sampleJob("job"), nil, "key", "hash")
			if err != nil {
				t.Error(err)
			}
			ids <- j.ID
		}()
	}
	wg.Wait()
	close(ids)
	for id := range ids {
		if id != "job" {
			t.Fatal("duplicate request")
		}
	}
	if _, _, err := s.CreateJobWithItemsHashed(ctx, sampleJob("other"), nil, "key", "different"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("hash conflict accepted")
	}
	claims := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.ClaimNextJob(ctx, time.Now()); claims <- err }()
	}
	wg.Wait()
	close(claims)
	count := 0
	for err := range claims {
		if err == nil {
			count++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatalf("claimed %d times", count)
	}
	if err := s.CreateUploadSession(ctx, entities.UploadSession{ID: "one", MountID: "files", Destination: "same"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadSession(ctx, entities.UploadSession{ID: "two", MountID: "files", Destination: "same"}); !errors.Is(err, ErrUploadSessionExists) {
		t.Fatal("destination collision accepted")
	}
}
func TestConfigurationBindingsAndRevocationSurviveRepair(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	mount := entities.Mount{ID: "files", Name: "Files", LocalPath: t.TempDir(), Mode: "read_write", TargetType: "directory", Published: true, Enabled: true}
	mount.LocalPath, _ = filepath.EvalSymlinks(mount.LocalPath)
	grant := entities.TransferPathGrant{ID: "allow", PeerNodeID: "peer", MountID: mount.ID, Path: ".", Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true}
	if err := s.ApplyConfiguration(ctx, "v1", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetTransferGrant(ctx, "allow")
	if err != nil || g.Enabled || !g.ConfiguredEnabled {
		t.Fatalf("unpaired grant active: %+v %v", g, err)
	}
	trust := func(s *Store, id string) {
		t.Helper()
		now := time.Now()
		if err := s.CreatePairingInvite(ctx, entities.PairingInvite{ID: id, Status: "pending", ExpiresAt: now.Add(time.Hour)}, "hash"); err != nil {
			t.Fatal(err)
		}
		if err := s.ApprovePairingInvite(ctx, id, "hash", entities.Peer{NodeID: "peer", State: "trusted", TransferMode: "dual_channel"}, now); err != nil {
			t.Fatal(err)
		}
	}
	trust(s, "invite-one")
	g, err = s.GetTransferGrant(ctx, "allow")
	if err != nil || !g.Enabled {
		t.Fatalf("trusted grant unavailable: %+v %v", g, err)
	}
	if err := s.RevokePeer(ctx, "peer", "correlation", time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.ApplyConfiguration(ctx, "v1", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
		t.Fatal(err)
	}
	beforeTrust := grant
	beforeTrust.ID = "declared-before-renewed-trust"
	if err := s.ApplyConfiguration(ctx, "before-renewal", []entities.Mount{mount}, []entities.TransferPathGrant{grant, beforeTrust}); err != nil {
		t.Fatal(err)
	}
	trust(s, "invite-two")
	premature, err := s.GetTransferGrant(ctx, beforeTrust.ID)
	if err != nil || premature.Enabled || premature.InactiveReason != "revoked" {
		t.Fatal("reauthorization bypassed renewed trust")
	}
	g, err = s.GetTransferGrant(ctx, "allow")
	if err != nil || g.Enabled || g.InactiveReason != "revoked" {
		t.Fatalf("revoked grant resurrected: %+v %v", g, err)
	}
	changed := mount
	changed.LocalPath = t.TempDir()
	if err = s.ApplyConfiguration(ctx, "bad", []entities.Mount{changed}, []entities.TransferPathGrant{grant}); err == nil {
		t.Fatal("mount retargeted")
	}
	grant.ID = "new-authorization"
	if err = s.ApplyConfiguration(ctx, "v2", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
		t.Fatal(err)
	}
	g, err = s.GetTransferGrant(ctx, grant.ID)
	if err != nil || !g.Enabled {
		t.Fatal("explicit new authorization unavailable")
	}
	if err = s.UpsertMount(ctx, mount); !errors.Is(err, contracts.ErrManagedConfiguration) {
		t.Fatal("managed configuration mutated")
	}
}
func TestRejectLegacyAndMissingState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jolt.db-wal"), []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, testKey); err == nil {
		t.Fatal("legacy state ignored")
	}
	if _, err := OpenExisting(t.TempDir(), testKey); err == nil {
		t.Fatal("recovery created empty state")
	}
}

func TestInterruptedCompactionRetainsCommittedTransactions(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		for _, failureWrite := range []int{2, 3, 4} { // committed head, page and manifest publication
			t.Run(point, func(t *testing.T) {
				s, dir := openTest(t)
				ctx := context.Background()
				if _, _, err := s.CreateJob(ctx, sampleJob("job"), "key"); err != nil {
					t.Fatal(err)
				}
				// Force the next mutation to compact; inject only after its journal commit.
				s.journalCount = compactTransactions - 1
				calls := 0
				s.fault = func(at string) error {
					if at == point {
						calls++
						if calls == failureWrite {
							return errors.New("snapshot interrupted")
						}
					}
					return nil
				}
				if err := s.StageOperationalToken(ctx, "new-hash", "cor", time.Now()); err == nil {
					t.Fatal("expected compaction failure")
				}
				s.Close()
				s, err := OpenExisting(dir, testKey)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if _, _, found, err := s.FindJobByIdempotency(ctx, "key"); err != nil || !found {
					t.Fatal("acknowledged transaction lost")
				}
				token, err := s.GetOperationalTokenState(ctx)
				if err != nil || token.StagedHash != "new-hash" {
					t.Fatal("journal was discarded before snapshot publication")
				}
			})
		}
	}
}
func TestOperationalTokenRecoveryIsDurable(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.StageOperationalToken(ctx, "old", "stage", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverOperationalToken(ctx, "recovered", "recovery", now); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err := s.GetOperationalTokenState(ctx)
	if err != nil || v.StagedHash != "" || v.ActiveHash != "recovered" || !v.EnvTokenDisabled {
		t.Fatalf("token recovery failed: %+v %v", v, err)
	}
}

func TestConcurrentInviteConsumptionAndRemovedGrantRevocation(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	now := time.Now()
	mountPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mount := entities.Mount{ID: "files", Name: "Files", LocalPath: mountPath, Mode: "read_write", Enabled: true}
	grant := entities.TransferPathGrant{ID: "old", PeerNodeID: "peer", MountID: "files", Path: ".", Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true}
	if err := s.ApplyConfiguration(ctx, "one", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairingInvite(ctx, entities.PairingInvite{ID: "invite", Status: "pending", ExpiresAt: now.Add(time.Hour)}, "hash"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.ApprovePairingInvite(ctx, "invite", "hash", entities.Peer{NodeID: "peer", State: "trusted"}, now)
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("invite consumed %d times", successes)
	}
	if err := s.ApplyConfiguration(ctx, "removed", []entities.Mount{mount}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePeer(ctx, "peer", "revoke", now); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePairingInvite(ctx, entities.PairingInvite{ID: "repair", Status: "pending", ExpiresAt: now.Add(time.Hour)}, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePairingInvite(ctx, "repair", "hash", entities.Peer{NodeID: "peer", State: "trusted"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyConfiguration(ctx, "reintroduced", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetTransferGrant(ctx, "old")
	if err != nil || g.Enabled || g.InactiveReason != "revoked" {
		t.Fatalf("removed grant resurrected: %+v %v", g, err)
	}
}

func TestSequenceGapAndRuntimeCorruptionFailClosed(t *testing.T) {
	for _, runtimeCorruption := range []bool{false, true} {
		t.Run(fmt.Sprint(runtimeCorruption), func(t *testing.T) {
			s, dir := openTest(t)
			ctx := context.Background()
			for _, id := range []string{"one", "two", "three"} {
				if _, _, err := s.CreateJob(ctx, sampleJob(id), ""); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, "journal", "00000000000000000002.yaml")
			if runtimeCorruption {
				s.cache = map[string]cacheEntry{}
				s.cacheOrder = nil
				s.cacheBytes = 0
				if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.GetJob(ctx, "two"); err == nil {
					t.Fatal("corrupt read accepted")
				}
				select {
				case <-s.Failure():
				default:
					t.Fatal("corruption did not stop processing")
				}
			} else {
				s.Close()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if reopened, err := OpenExisting(dir, testKey); err == nil {
					reopened.Close()
					t.Fatal("sequence gap accepted")
				}
			}
		})
	}
}

func TestCommittedTailCannotBeSilentlyLost(t *testing.T) {
	s, dir := openTest(t)
	if _, _, err := s.CreateJob(context.Background(), sampleJob("confirmed"), "key"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.Remove(filepath.Join(dir, "journal", "00000000000000000001.yaml")); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenExisting(dir, testKey); err == nil {
		reopened.Close()
		t.Fatal("missing acknowledged state was silently rolled back")
	}
}

func TestUnpublishedTemporaryFilesAreIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".tmp-unpublished"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateJob(context.Background(), sampleJob("kept"), ""); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.WriteFile(filepath.Join(dir, "journal", ".tmp-unpublished"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetJob(context.Background(), "kept"); err != nil {
		t.Fatal(err)
	}
}
