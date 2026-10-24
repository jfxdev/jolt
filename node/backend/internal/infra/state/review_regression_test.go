package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

func TestInvalidRecordCannotPoisonCommittedState(t *testing.T) {
	for _, invalid := range []record{{Bucket: "jobs"}, {Key: "job"}, {Bucket: "jobs", Delete: true}} {
		t.Run(fmt.Sprintf("%+v", invalid), func(t *testing.T) {
			s, dir := openTest(t)
			ctx := context.Background()
			if _, _, err := s.CreateJob(ctx, sampleJob("before"), ""); err != nil {
				t.Fatal(err)
			}
			sequence := s.sequence
			head, err := os.ReadFile(filepath.Join(dir, "head.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			err = s.update(ctx, func(tx *transaction) error {
				if err := tx.put("jobs", "partial", "", "", sampleJob("partial")); err != nil {
					return err
				}
				tx.records = append(tx.records, invalid)
				return nil
			})
			if err == nil || err.Error() != "empty state record identity" {
				t.Fatalf("invalid identity: %v", err)
			}
			gotHead, err := os.ReadFile(filepath.Join(dir, "head.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if s.sequence != sequence || !bytes.Equal(head, gotHead) {
				t.Fatal("rejected transaction changed committed state")
			}
			if _, err := s.GetJob(ctx, "partial"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("partial transaction visible: %v", err)
			}
			if _, _, err := s.CreateJob(ctx, sampleJob("after"), ""); err != nil {
				t.Fatal(err)
			}
			s.Close()
			reopened, err := OpenExisting(dir, testKey)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			for _, id := range []string{"before", "after"} {
				if _, err := reopened.GetJob(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOpenExistingIsReadOnlyWithoutLockFileOrHeadRepair(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	// Simulate a crash after transaction publication and before updating the head.
	if _, err := s.write("journal/00000000000000000001.yaml", "transaction", 1,
		document{Records: []record{{Bucket: "jobs", Key: "recovered", Data: "id: recovered\nstate: queued\n"}}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.Remove(filepath.Join(dir, ".state.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "snapshots")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	before := stateTree(t, dir)
	reader, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetJob(ctx, "recovered"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.CreateJob(ctx, sampleJob("forbidden"), ""); err == nil {
		t.Fatal("read-only store accepted a mutation")
	}
	if other, err := OpenExisting(dir, testKey); err == nil {
		other.Close()
		t.Fatal("offline lock was not exclusive")
	}
	if other, err := Open(dir, testKey); err == nil {
		other.Close()
		t.Fatal("runtime ignored offline directory lock")
	}
	reader.Close()
	if after := stateTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("offline inspection changed files or permissions")
	}
	// Runtime open still repairs the committed head and allows mutations.
	runtime, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	var head struct{}
	if seq, err := runtime.read("head.yaml", "head", 1, &head); err != nil || seq != 1 {
		t.Fatalf("head not repaired: %d %v", seq, err)
	}
}

func stateTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if !info.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += string(raw)
		}
		out[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOrderedIndexesMatchRecordsAcrossUpdatesDeletesAndReopen(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	for i := 79; i >= 0; i-- {
		j := sampleJob(fmt.Sprintf("job-%03d", i))
		j.PeerNodeID = fmt.Sprintf("peer-%d", i%3)
		j.CreatedAt = time.Unix(int64(i%7), 0)
		if i%2 == 0 {
			j.State = "completed"
		}
		if _, _, err := s.CreateJob(ctx, j, ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("job-%03d", i)
		if i%3 == 0 {
			if err := s.update(ctx, func(tx *transaction) error { tx.remove("jobs", id); return nil }); err != nil {
				t.Fatal(err)
			}
			continue
		}
		j, err := s.GetJob(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		j.PeerNodeID = "moved"
		j.State = "queued"
		if err := s.UpdateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	assertIndexes(t, s)
	if err := s.compact(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertIndexes(t, reopened)
}

func assertIndexes(t *testing.T, s *Store) {
	t.Helper()
	expected := map[indexSelection][]string{}
	for bucket, records := range s.index {
		for key, r := range records {
			for _, selection := range selections(bucket, r) {
				expected[selection] = append(expected[selection], key)
			}
		}
	}
	for selection, ids := range expected {
		sort.Slice(ids, func(i, j int) bool {
			a, b := s.index[selection.bucket][ids[i]], s.index[selection.bucket][ids[j]]
			if a.Order == b.Order {
				return ids[i] < ids[j]
			}
			return a.Order < b.Order
		})
		expected[selection] = ids
	}
	if !reflect.DeepEqual(expected, s.ordered) {
		t.Fatal("ordered index differs from persisted record order/groups/states")
	}
}

func TestEventCursorAndQueuedClaimsUseOrderedGroups(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	for _, id := range []string{"one", "two"} {
		if _, _, err := s.CreateJob(ctx, sampleJob(id), ""); err != nil {
			t.Fatal(err)
		}
	}
	var events []entities.JobEvent
	for i := 0; i < 20; i++ {
		id := "one"
		if i%2 == 0 {
			id = "two"
		}
		event, err := s.RecordJobEvent(ctx, entities.JobEvent{JobID: id})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	for _, group := range []string{"", "one", "two"} {
		for _, after := range []int64{-1, 0, events[10].ID, events[19].ID} {
			got, err := s.ListJobEvents(ctx, after, group, 3)
			if err != nil {
				t.Fatal(err)
			}
			var want []entities.JobEvent
			for _, event := range events {
				if event.ID > after && (group == "" || event.JobID == group) {
					want = append(want, event)
					if len(want) == 3 {
						break
					}
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("cursor %d group %q: got %+v want %+v", after, group, got, want)
			}
		}
	}
	for _, id := range []string{"one", "two"} {
		j, err := s.ClaimNextJob(ctx, time.Now())
		if err != nil || j.ID != id {
			t.Fatalf("claim %+v %v", j, err)
		}
	}
	if _, err := s.ClaimNextJob(ctx, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claimed nonqueued job: %v", err)
	}
}

func TestCompactionReusesImmutableHistoryAndRetainsAudit(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	if _, _, err := s.CreateJob(ctx, sampleJob("job"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordJobEvent(ctx, entities.JobEvent{JobID: "job"}); err != nil {
		t.Fatal(err)
	}
	if err := s.update(ctx, func(tx *transaction) error { return tx.audit("test", "resource", "before") }); err != nil {
		t.Fatal(err)
	}
	if err := s.compact(); err != nil {
		t.Fatal(err)
	}
	old := map[string][]byte{}
	for _, name := range s.historyPages {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		old[name] = raw
	}
	if len(old) != 2 {
		t.Fatalf("history buckets not separated: %v", s.historyPages)
	}
	// A later compaction must neither read nor rewrite historical pages.
	for name := range old {
		if err := os.Chmod(filepath.Join(dir, name), 0000); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := s.RecordJobEvent(ctx, entities.JobEvent{JobID: "job"}); err != nil {
			t.Fatal(err)
		}
		if err := s.compact(); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range old {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0 {
			t.Fatal("historical segment rewritten")
		}
		if err := os.Chmod(filepath.Join(dir, name), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatal("historical ciphertext changed")
		}
	}
	s.Close()
	reader, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	events, err := reader.ListJobEvents(ctx, 0, "job", 100)
	if err != nil || len(events) != 3 {
		t.Fatalf("history lost: %d %v", len(events), err)
	}
	if len(reader.index["audit"]) != 1 {
		t.Fatal("audit lost")
	}
	assertIndexes(t, reader)
}

func TestEffectiveGrantReasonsAfterReleasingStoreLock(t *testing.T) {
	for _, reason := range []string{"", "disabled", "revoked", "peer_untrusted", "mount_unavailable", "mount_read_only", "peer_role_incompatible", "path_unavailable"} {
		t.Run(reason, func(t *testing.T) {
			s, _ := openTest(t)
			ctx := context.Background()
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			mount := entities.Mount{ID: "files", Name: "Files", LocalPath: root, Enabled: true, Mode: "read_write"}
			peer := entities.Peer{NodeID: "peer", State: "trusted", TransferMode: "dual_channel"}
			grant := entities.TransferPathGrant{ID: "grant", PeerNodeID: peer.NodeID, MountID: mount.ID, Path: ".", Direction: "send", Enabled: true, Permissions: entities.GrantPermissions{Read: true}}
			switch reason {
			case "disabled":
				grant.Enabled = false
			case "peer_untrusted":
				peer.State = "revoked"
			case "mount_unavailable":
				mount.LocalPath = filepath.Join(root, "missing")
			case "mount_read_only":
				mount.Mode = "read_only"
				grant.Direction = "receive"
				grant.Permissions.Write = true
			case "peer_role_incompatible":
				peer.TransferMode = "one_sided"
				peer.LocalRole = "receiver"
			case "path_unavailable":
				grant.Path = "missing"
			}
			if err := s.ApplyConfiguration(ctx, "revision", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
				t.Fatal(err)
			}
			if err := s.update(ctx, func(tx *transaction) error {
				if err := tx.put("peers", peer.NodeID, "", "", peer); err != nil {
					return err
				}
				if reason == "revoked" {
					return tx.put("revoked_grants", grant.ID, peer.NodeID, "", true)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			got, err := s.GetTransferGrant(ctx, grant.ID)
			if err != nil {
				t.Fatal(err)
			}
			listed, err := s.ListTransferGrants(ctx)
			if err != nil || len(listed) != 1 {
				t.Fatalf("list: %+v %v", listed, err)
			}
			if got.InactiveReason != reason || got.Enabled != (reason == "") || got.ConfiguredEnabled != grant.Enabled || !reflect.DeepEqual(got, listed[0]) {
				t.Fatalf("unexpected grant: %+v", got)
			}
			var check grantCheck
			if err := s.view(ctx, func() error { var err error; check, err = s.prepareGrant(grant); return err }); err != nil {
				t.Fatal(err)
			}
			// Filesystem validation operates entirely on a captured value: it cannot
			// reenter the global store lock, even when another operation holds it.
			s.mu.Lock()
			done := make(chan entities.TransferPathGrant, 1)
			go func() { done <- check.effective() }()
			select {
			case value := <-done:
				if value.InactiveReason != reason {
					t.Error(value.InactiveReason)
				}
			case <-time.After(time.Second):
				t.Error("filesystem validation reentered store lock")
			}
			s.mu.Unlock()
		})
	}
}

func TestExistingWritableRecoveryRequiresStateAndPersistsChanges(t *testing.T) {
	missing := t.TempDir()
	if s, err := OpenExistingForUpdate(missing, testKey); err == nil {
		s.Close()
		t.Fatal("offline recovery initialized missing state")
	}
	s, dir := openTest(t)
	s.Close()
	if err := os.Remove(filepath.Join(dir, ".state.lock")); err != nil {
		t.Fatal(err)
	}
	writer, err := OpenExistingForUpdate(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.RecoverOperationalToken(context.Background(), "recovered", "offline", time.Now()); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir, testKey); err == nil {
		other.Close()
		t.Fatal("writable recovery did not exclude another writer")
	}
	writer.Close()
	reader, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	token, err := reader.GetOperationalTokenState(context.Background())
	if err != nil || token.ActiveHash != "recovered" {
		t.Fatalf("recovery not durable: %+v %v", token, err)
	}
}

func TestHistorySegmentsSurviveInterruptedLaterCompaction(t *testing.T) {
	for _, point := range []string{"before_file_sync", "after_file_sync", "after_rename", "after_directory_sync"} {
		for _, failureWrite := range []int{3, 4, 5} {
			t.Run(fmt.Sprintf("%s/write-%d", point, failureWrite), func(t *testing.T) {
				s, dir := openTest(t)
				ctx := context.Background()
				if _, _, err := s.CreateJob(ctx, sampleJob("job"), ""); err != nil {
					t.Fatal(err)
				}
				if _, err := s.RecordJobEvent(ctx, entities.JobEvent{JobID: "job"}); err != nil {
					t.Fatal(err)
				}
				if err := s.update(ctx, func(tx *transaction) error { return tx.audit("test", "resource", "original") }); err != nil {
					t.Fatal(err)
				}
				if err := s.compact(); err != nil {
					t.Fatal(err)
				}
				s.journalCount = compactTransactions - 1
				writes := 0
				s.fault = func(at string) error {
					if at == point {
						writes++
						if writes == failureWrite {
							return errors.New("interrupted compaction")
						}
					}
					return nil
				}
				// Writes 3..5 publish the new event segment, current job page and manifest.
				if _, err := s.RecordJobEvent(ctx, entities.JobEvent{JobID: "job"}); err == nil {
					t.Fatal("expected compaction interruption")
				}
				s.Close()
				reader, err := OpenExisting(dir, testKey)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				events, err := reader.ListJobEvents(ctx, 0, "job", 100)
				if err != nil || len(events) != 2 {
					t.Fatalf("event history lost: %+v %v", events, err)
				}
				if len(reader.index["audit"]) != 1 {
					t.Fatal("audit segment lost")
				}
				assertIndexes(t, reader)
			})
		}
	}
}
