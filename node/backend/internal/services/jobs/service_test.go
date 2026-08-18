package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

type stalledRemoteExecutor struct{}

func (stalledRemoteExecutor) ExecutePull(ctx context.Context, _ entities.Job, _ func(int64, int64) error) (int64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (stalledRemoteExecutor) ExecuteDirectoryPull(ctx context.Context, _ entities.Job, _ func(int64, int64, int, int) error) (int64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (stalledRemoteExecutor) CleanupPull(context.Context, entities.Job) error { return nil }
func (stalledRemoteExecutor) CleanupDirectoryPull(context.Context, entities.Job) error {
	return nil
}

func testService(t *testing.T) (*Service, *filesystem.Service, string) {
	t.Helper()
	root := t.TempDir()
	store, err := db.Open(filepath.Join(root, "jolt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mountRoot := filepath.Join(root, "mount")
	if err := os.Mkdir(mountRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	files := filesystem.New(store)
	mount, err := files.SaveMount(context.Background(), entities.Mount{
		Name: "test", LocalPath: mountRoot, Mode: "read_write", Enabled: true, Published: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := New(store, files)
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(shutdownContext)
	})
	return service, files, mount.ID
}

func TestWorkerExecutesPersistentCopy(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("durable queue")
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, repeated, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "source.txt", Destination: "copy.txt",
	}, "copy-once")
	if err != nil || repeated {
		t.Fatalf("create: repeated=%v err=%v", repeated, err)
	}
	job = waitForState(t, service, job.ID, "completed")
	if job.BytesCompleted != int64(len(content)) || job.Attempt != 1 {
		t.Fatalf("unexpected progress: %+v", job)
	}
	copied, err := os.ReadFile(filepath.Join(mount.LocalPath, "copy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != string(content) {
		t.Fatalf("copied content = %q", copied)
	}
	events, err := service.ListEvents(context.Background(), 0, job.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"job.created", "job.started", "job.progress", "job.completed"} {
		if !containsEvent(events, expected) {
			t.Fatalf("missing %s in events: %+v", expected, events)
		}
	}
}

func TestLocalCopyPersistsAndEnforcesPerJobBandwidthLimit(t *testing.T) {
	service, files, mountID := testService(t)
	service.ConfigureChunkSize(64 << 10)
	service.ConfigureTimeouts(time.Second, 50*time.Millisecond, 50*time.Millisecond)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("x"), 4096)
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "limited.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "limited.bin",
		Destination: "limited-copy.bin", BandwidthLimit: 64 << 10,
	}, "limited-copy")
	if err != nil {
		t.Fatal(err)
	}
	job = waitForState(t, service, job.ID, "completed")
	if job.BandwidthLimit != 64<<10 {
		t.Fatalf("persisted bandwidth limit=%d", job.BandwidthLimit)
	}
	if elapsed := time.Since(started); elapsed < 45*time.Millisecond {
		t.Fatalf("copy completed too quickly for its bandwidth limit: %s", elapsed)
	}
}

func TestNodeBandwidthLimiterSharesCapacityAcrossConcurrentWaiters(t *testing.T) {
	limiter := newByteRateLimiter(100_000)
	started := time.Now()
	done := make(chan error, 2)
	for range 2 {
		go func() {
			done <- limiter.Wait(context.Background(), 5_000)
		}()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); elapsed < 85*time.Millisecond {
		t.Fatalf("shared limiter did not aggregate concurrent reservations: %s", elapsed)
	}
}

func TestRejectsInvalidPerJobBandwidthLimit(t *testing.T) {
	service, _, mountID := testService(t)
	if _, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "a",
		Destination: "b", BandwidthLimit: -1,
	}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected invalid bandwidth limit, got %v", err)
	}
}

func TestProgressCalculatesDurableETA(t *testing.T) {
	service, _, mountID := testService(t)
	started := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	current := started
	service.now = func() time.Time { return current }
	job, _, err := service.CreateInline(context.Background(), CreateRequest{
		Type: "upload", MountID: mountID, Destination: "estimate.bin",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	current = started.Add(5 * time.Second)
	service.updateProgress(job.ID, 500, 1000, current)
	job, err = service.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.BytesPerSecond != 100 {
		t.Fatalf("bytes_per_second = %v", job.BytesPerSecond)
	}
	if job.ETASeconds == nil || *job.ETASeconds != 5 || job.ETAConfidence != "medium" {
		t.Fatalf("unexpected ETA: %+v", job)
	}
	events, err := service.ListEvents(context.Background(), 0, job.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsEvent(events, "job.progress") {
		t.Fatalf("progress event not persisted: %+v", events)
	}
}

func TestWorkerFailsStalledJobWithoutGlobalJobTimeout(t *testing.T) {
	service, _, mountID := testService(t)
	service.ConfigureRemoteExecutor(stalledRemoteExecutor{})
	service.ConfigureTimeouts(time.Second, time.Second, 25*time.Millisecond)
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, repeated, err := service.Create(context.Background(), CreateRequest{
		Type: "transfer_pull", MountID: mountID, PeerNodeID: "peer-a",
		SourceGrantID: "source", DestinationGrantID: "destination", MaxAttempts: 1,
	}, "stalled-transfer")
	if err != nil || repeated {
		t.Fatalf("create: repeated=%v err=%v", repeated, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err = service.Get(context.Background(), job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.State == "failed" {
			if !strings.Contains(job.Error, ErrNoProgress.Error()) {
				t.Fatalf("unexpected stalled job error: %+v", job)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("stalled job was not failed: %+v", job)
}

func TestWorkerEnforcesChunkTimeoutSeparately(t *testing.T) {
	service, _, mountID := testService(t)
	service.ConfigureRemoteExecutor(stalledRemoteExecutor{})
	service.ConfigureTimeouts(time.Second, 25*time.Millisecond, time.Second)
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "transfer_pull", MountID: mountID, PeerNodeID: "peer-a",
		SourceGrantID: "source", DestinationGrantID: "destination", MaxAttempts: 1,
	}, "chunk-timeout")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err = service.Get(context.Background(), job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.State == "failed" {
			if !strings.Contains(job.Error, ErrChunkTimeout.Error()) {
				t.Fatalf("unexpected chunk timeout error: %+v", job)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("chunk timeout did not fail the job: %+v", job)
}

func TestCancelPeerCancelsAllActiveRelatedJobs(t *testing.T) {
	service, _, mountID := testService(t)
	now := time.Now().UTC()
	for _, job := range []entities.Job{
		{
			ID: "remote-queued", Type: "transfer_pull", State: "queued", Phase: "validation",
			MountID: mountID, PeerNodeID: "peer-a", SourceGrantID: "source",
			DestinationGrantID: "destination", MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "remote-decision", Type: "transfer_pull_directory", State: "waiting_user_decision",
			Phase: "waiting_user_decision", MountID: mountID, PeerNodeID: "peer-a",
			SourceGrantID: "source", DestinationGrantID: "destination",
			MaxAttempts: 3, CreatedAt: now.Add(time.Second), UpdatedAt: now,
		},
		{
			ID: "other-peer", Type: "transfer_pull", State: "queued", Phase: "validation",
			MountID: mountID, PeerNodeID: "peer-b", SourceGrantID: "source",
			DestinationGrantID: "destination", MaxAttempts: 3,
			CreatedAt: now.Add(2 * time.Second), UpdatedAt: now,
		},
	} {
		if _, _, err := service.store.CreateJob(context.Background(), job, ""); err != nil {
			t.Fatal(err)
		}
	}
	count, err := service.CancelPeer(context.Background(), "peer-a")
	if err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	for _, id := range []string{"remote-queued", "remote-decision"} {
		job, err := service.Get(context.Background(), id)
		if err != nil || job.State != "canceled" {
			t.Fatalf("job %s=%+v err=%v", id, job, err)
		}
	}
	other, err := service.Get(context.Background(), "other-peer")
	if err != nil || other.State != "queued" {
		t.Fatalf("other=%+v err=%v", other, err)
	}
}

func TestDirectoryPlanAppliesRenamePolicy(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"source", "destination"} {
		if err := os.Mkdir(filepath.Join(mount.LocalPath, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", "movie.mkv"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "destination", "movie.mkv"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := service.PlanCopy(context.Background(), mountID, "source", "destination", "rename")
	if err != nil {
		t.Fatal(err)
	}
	if plan.FilesTotal != 1 || plan.RenameCount != 1 || plan.ConflictCount != 0 {
		t.Fatalf("unexpected summary: %+v", plan)
	}
	var fileItem entities.JobItem
	for _, item := range plan.Items {
		if item.Type == "file" {
			fileItem = item
		}
	}
	if fileItem.Action != "rename" || fileItem.DestinationPath != "destination/movie (1).mkv" {
		t.Fatalf("unexpected file plan: %+v", fileItem)
	}
}

func TestDirectoryJobUsesPersistedFileParallelism(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mount.LocalPath, "parallel-source"), 0o755); err != nil {
		t.Fatal(err)
	}
	for index := range 4 {
		name := fmt.Sprintf("file-%d.bin", index)
		if err := os.WriteFile(filepath.Join(mount.LocalPath, "parallel-source", name),
			bytes.Repeat([]byte{byte(index)}, 1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "parallel-source",
		Destination: "parallel-destination", ConflictPolicy: "fail",
		MaxParallelFiles: 3, MaxParallelChunks: 2,
	}, "parallel-directory")
	if err != nil {
		t.Fatal(err)
	}
	job = waitForState(t, service, job.ID, "completed")
	if job.MaxParallelFiles != 3 || job.MaxParallelChunks != 2 || job.FilesCompleted != 4 {
		t.Fatalf("unexpected parallel job: %+v", job)
	}
	for index := range 4 {
		name := filepath.Join(mount.LocalPath, "parallel-destination", fmt.Sprintf("file-%d.bin", index))
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("parallel copy did not publish %s: %v", name, err)
		}
	}
}

func TestDirectoryJobPersistsItemsAndRetriesOnlyConflict(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"source", "destination"} {
		if err := os.Mkdir(filepath.Join(mount.LocalPath, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", "blocked.txt"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", "copied.txt"), []byte("copied"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "destination", "blocked.txt"), []byte("destination"), 0o644); err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "source",
		Destination: "destination", ConflictPolicy: "fail",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	job = waitForState(t, service, job.ID, "completed_with_warnings")
	if job.FilesTotal != 2 || job.FilesCompleted != 1 || job.FilesFailed != 1 {
		t.Fatalf("unexpected job counters: %+v", job)
	}
	items, err := service.ListItems(context.Background(), job.ID)
	if err != nil || len(items) != 3 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if err := os.Remove(filepath.Join(mount.LocalPath, "destination", "blocked.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Retry(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	job = waitForState(t, service, job.ID, "completed")
	if job.FilesCompleted != 2 || job.FilesFailed != 0 {
		t.Fatalf("unexpected retried counters: %+v", job)
	}
	content, err := os.ReadFile(filepath.Join(mount.LocalPath, "destination", "blocked.txt"))
	if err != nil || string(content) != "source" {
		t.Fatalf("content=%q err=%v", content, err)
	}
}

func TestDirectoryJobsApplySkipOverwriteAndRename(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mount.LocalPath, "source"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", "item.txt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"skip", "overwrite", "rename"} {
		if err := os.Mkdir(filepath.Join(mount.LocalPath, destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mount.LocalPath, destination, "item.txt"), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"skip", "overwrite", "rename"} {
		job, _, err := service.Create(context.Background(), CreateRequest{
			Type: "copy_local", MountID: mountID, SourcePath: "source",
			Destination: policy, ConflictPolicy: policy,
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		waitForState(t, service, job.ID, "completed")
	}
	assertFileContent(t, filepath.Join(mount.LocalPath, "skip", "item.txt"), "old")
	assertFileContent(t, filepath.Join(mount.LocalPath, "overwrite", "item.txt"), "new")
	assertFileContent(t, filepath.Join(mount.LocalPath, "rename", "item.txt"), "old")
	assertFileContent(t, filepath.Join(mount.LocalPath, "rename", "item (1).txt"), "new")
}

func TestChecksumPolicySkipsEqualContentAndOverwritesDifferentContent(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"source", "destination"} {
		if err := os.Mkdir(filepath.Join(mount.LocalPath, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", "same.txt"), []byte("same"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "destination", "same.txt"), []byte("same"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", "changed.txt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "destination", "changed.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := service.PlanCopy(context.Background(), mountID, "source", "destination", "checksum")
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, item := range plan.Items {
		if item.Type == "file" {
			actions[item.RelativePath] = item.Action
			if len(item.Checksum) != 64 {
				t.Fatalf("missing SHA-256 for %+v", item)
			}
		}
	}
	if actions["same.txt"] != "skip" || actions["changed.txt"] != "overwrite" {
		t.Fatalf("unexpected checksum actions: %+v", actions)
	}
}

func TestSourceChangePoliciesFailOrRetryWithFreshManifestData(t *testing.T) {
	for _, policy := range []string{"fail", "retry"} {
		t.Run(policy, func(t *testing.T) {
			service, files, mountID := testService(t)
			mount, err := files.GetMount(context.Background(), mountID)
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(mount.LocalPath, "source.txt")
			if err := os.WriteFile(source, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			job, _, err := service.Create(context.Background(), CreateRequest{
				Type: "copy_local", MountID: mountID, SourcePath: "source.txt",
				Destination: "destination.txt", ConflictPolicy: "fail",
				SourceChangePolicy: policy, MaxAttempts: 3,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := service.PlanCopy(context.Background(), mountID, "source.txt", "destination.txt", "fail")
			if err != nil {
				t.Fatal(err)
			}
			for index := range plan.Items {
				plan.Items[index].JobID = job.ID
			}
			if err := service.store.ReplaceJobItems(context.Background(), job.ID, plan.Items); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * time.Millisecond)
			if err := os.WriteFile(source, []byte("new content"), 0o644); err != nil {
				t.Fatal(err)
			}
			runContext, stop := context.WithCancel(context.Background())
			defer stop()
			if _, err := service.Start(runContext, 1); err != nil {
				t.Fatal(err)
			}
			expected := "completed_with_warnings"
			if policy == "retry" {
				expected = "completed"
			}
			job = waitForState(t, service, job.ID, expected)
			if policy == "fail" {
				if _, err := os.Stat(filepath.Join(mount.LocalPath, "destination.txt")); !os.IsNotExist(err) {
					t.Fatalf("destination should not exist, err=%v", err)
				}
			} else {
				if job.Attempt != 2 {
					t.Fatalf("attempt = %d, want 2", job.Attempt)
				}
				assertFileContent(t, filepath.Join(mount.LocalPath, "destination.txt"), "new content")
			}
		})
	}
}

func TestPausedCopyResumesFromPersistedChunk(t *testing.T) {
	service, files, mountID := testService(t)
	service.ConfigureChunkSize(64 << 10)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("jolt-resume-"), 2<<20)
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "large.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "large.bin",
		Destination: "resumed.bin", ConflictPolicy: "fail",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var checkpoint int64
	for time.Now().Before(deadline) {
		items, listErr := service.ListItems(context.Background(), job.ID)
		if listErr == nil && len(items) == 1 && items[0].BytesCompleted > 0 &&
			items[0].BytesCompleted < int64(len(content)) {
			checkpoint = items[0].BytesCompleted
			if _, err := service.Pause(context.Background(), job.ID); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	if checkpoint == 0 {
		t.Fatal("copy completed before a durable chunk checkpoint could be observed")
	}
	job = waitForState(t, service, job.ID, "paused")
	items, err := service.ListItems(context.Background(), job.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if items[0].BytesCompleted < checkpoint {
		t.Fatalf("checkpoint regressed: got=%d observed=%d", items[0].BytesCompleted, checkpoint)
	}
	if _, err := os.Stat(filepath.Join(mount.LocalPath, "resumed.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination published while paused, err=%v", err)
	}
	if _, err := service.Resume(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	job = waitForState(t, service, job.ID, "completed")
	if job.BytesCompleted != int64(len(content)) {
		t.Fatalf("bytes completed=%d want=%d", job.BytesCompleted, len(content))
	}
	copied, err := os.ReadFile(filepath.Join(mount.LocalPath, "resumed.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, content) {
		t.Fatal("resumed file differs from source")
	}
}

func TestCancelRemovesPersistedCopyPartials(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source.bin"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "source.bin",
		Destination: "destination.bin", ConflictPolicy: "fail",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PlanCopy(context.Background(), mountID, "source.bin", "destination.bin", "fail")
	if err != nil {
		t.Fatal(err)
	}
	for index := range plan.Items {
		plan.Items[index].JobID = job.ID
		plan.Items[index].BytesCompleted = 4
	}
	if err := service.store.ReplaceJobItems(context.Background(), job.ID, plan.Items); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(mount.LocalPath, ".jolt-"+job.ID+"-0.partial")
	if err := os.WriteFile(partial, []byte("sour"), 0o600); err != nil {
		t.Fatal(err)
	}
	job, err = service.Cancel(context.Background(), job.ID)
	if err != nil || job.State != "canceled" {
		t.Fatalf("job=%+v err=%v", job, err)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("partial remains after cancellation, err=%v", err)
	}
	items, err := service.ListItems(context.Background(), job.ID)
	if err != nil || len(items) != 1 || items[0].BytesCompleted != 0 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
}

func TestAskPolicyWaitsForOverrideAndAppliesItToFollowingConflicts(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"source", "destination"} {
		if err := os.Mkdir(filepath.Join(mount.LocalPath, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"one.txt", "two.txt"} {
		if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", name), []byte("new-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mount.LocalPath, "destination", name), []byte("old-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "source",
		Destination: "destination", ConflictPolicy: "ask",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	job = waitForState(t, service, job.ID, "waiting_user_decision")
	items, err := service.ListItems(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	conflictOrdinal := -1
	for _, item := range items {
		if item.Action == "conflict" {
			conflictOrdinal = item.Ordinal
			break
		}
	}
	if conflictOrdinal < 0 {
		t.Fatalf("no conflict found in %+v", items)
	}
	job, err = service.OverrideItem(context.Background(), job.ID, conflictOrdinal, "overwrite", true)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "queued" {
		t.Fatalf("job state=%s want queued", job.State)
	}
	job = waitForState(t, service, job.ID, "completed")
	if job.FilesCompleted != 2 || job.FilesFailed != 0 {
		t.Fatalf("unexpected counters: %+v", job)
	}
	assertFileContent(t, filepath.Join(mount.LocalPath, "destination", "one.txt"), "new-one.txt")
	assertFileContent(t, filepath.Join(mount.LocalPath, "destination", "two.txt"), "new-two.txt")
}

func TestPausedQueuedJobOnlyRunsAfterResume(t *testing.T) {
	service, _, mountID := testService(t)
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "mkdir", MountID: mountID, Destination: "later",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if job, err = service.Pause(context.Background(), job.ID); err != nil || job.State != "paused" {
		t.Fatalf("pause: state=%s err=%v", job.State, err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	if job, err = service.Resume(context.Background(), job.ID); err != nil || job.State != "queued" {
		t.Fatalf("resume: state=%s err=%v", job.State, err)
	}
	waitForState(t, service, job.ID, "completed")
}

func TestStartMarksPreviouslyRunningJobWaitingValidation(t *testing.T) {
	service, _, mountID := testService(t)
	job, _, err := service.CreateInline(context.Background(), CreateRequest{
		Type: "upload", MountID: mountID, Destination: "partial.bin",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	recovered, err := service.Start(runContext, 1)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d", recovered)
	}
	job, err = service.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "waiting_validation" || job.Phase != "waiting_validation" {
		t.Fatalf("unexpected recovered job: %+v", job)
	}
	if job, err = service.Resume(context.Background(), job.ID); err != nil || job.State != "queued" || job.Phase != "validation" {
		t.Fatalf("resume must explicitly return the restored job to validation: job=%+v err=%v", job, err)
	}
}

func TestWaitingMountWakesAutomaticallyWithoutConsumingAttempt(t *testing.T) {
	service, files, mountID := testService(t)
	service.ConfigureMountCheckInterval(10 * time.Millisecond)
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "mkdir", MountID: mountID, Destination: "after-recovery",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	mount.Enabled = false
	if _, err := files.SaveMount(context.Background(), mount); err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 1); err != nil {
		t.Fatal(err)
	}
	waiting := waitForState(t, service, job.ID, "waiting_mount")
	if waiting.Attempt != 0 || waiting.Phase != "waiting_mount" {
		t.Fatalf("waiting for a mount must preserve retry budget: %+v", waiting)
	}
	mount.Enabled = true
	if _, err := files.SaveMount(context.Background(), mount); err != nil {
		t.Fatal(err)
	}
	completed := waitForState(t, service, job.ID, "completed")
	if completed.Attempt != 1 {
		t.Fatalf("job should use its first real attempt after mount recovery: %+v", completed)
	}
	if _, err := files.Metadata(context.Background(), mountID, "after-recovery"); err != nil {
		t.Fatalf("operation was not completed after mount recovery: %v", err)
	}
}

func waitForState(t *testing.T, service *Service, id, expected string) entities.Job {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, err := service.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if job.State == expected {
			return job
		}
		if job.State == "failed" {
			t.Fatalf("job failed: %+v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, _ := service.Get(context.Background(), id)
	t.Fatalf("job did not reach %s: %+v", expected, job)
	return entities.Job{}
}

func containsEvent(events []entities.JobEvent, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s = %q, want %q", path, content, expected)
	}
}
