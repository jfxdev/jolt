package jobs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
)

type delayedCompletionStore struct {
	contracts.JobStore
	delayed atomic.Bool
	full    chan struct{}
	once    sync.Once
}

func (s *delayedCompletionStore) UpdateJobItem(ctx context.Context, item entities.JobItem) error {
	if err := s.JobStore.UpdateJobItem(ctx, item); err != nil {
		return err
	}
	if item.Type == "file" && item.State == "completed" && s.delayed.CompareAndSwap(false, true) {
		// Let a newer aggregate overtake this worker if publication is not
		// serialized. Ordered publication holds the other workers until release.
		select {
		case <-s.full:
		case <-time.After(time.Second):
		}
	}
	return nil
}

func (s *delayedCompletionStore) UpdateJob(ctx context.Context, job entities.Job) error {
	if err := s.JobStore.UpdateJob(ctx, job); err != nil {
		return err
	}
	if job.FilesTotal > 0 && job.FilesCompleted == job.FilesTotal {
		s.once.Do(func() { close(s.full) })
	}
	return nil
}

func TestParallelDirectoryProgressSurvivesDelayedCompletionCheckpoint(t *testing.T) {
	service, files, mountID := testService(t)
	service.store = &delayedCompletionStore{JobStore: service.store, full: make(chan struct{})}
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mount.LocalPath, "source"), 0700); err != nil {
		t.Fatal(err)
	}
	const count = 8
	for index := range count {
		if err := os.WriteFile(filepath.Join(mount.LocalPath, "source", fmt.Sprint(index)), []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := service.Start(ctx, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(ctx, CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "source", Destination: "copy",
		MaxParallelFiles: count, MaxParallelChunks: 2,
	}, "delayed-progress")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for job.State != "completed" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		job, err = service.Get(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if job.State != "completed" {
		t.Fatalf("parallel copy did not complete: %+v", job)
	}
	if job.FilesCompleted != count || job.BytesCompleted != count*int64(len("payload")) {
		t.Fatalf("parallel checkpoint regressed: files=%d bytes=%d", job.FilesCompleted, job.BytesCompleted)
	}
}
