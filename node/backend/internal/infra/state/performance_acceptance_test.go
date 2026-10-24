//go:build acceptance

package state

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// This deliberately retains only record locations at open. Historical payloads
// are larger than the cache so an accidental eager decode is observable.
func TestAcceptanceStateCheckpointAndHistoryMemory(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	const historyCount = 4096
	const messageBytes = 8192
	for start := 0; start < historyCount; start += 64 {
		err := s.update(ctx, func(tx *transaction) error {
			for i := start; i < start+64; i++ {
				key := fmt.Sprintf("%020d", i+1)
				if err := tx.put("events", key, "history", key, entities.JobEvent{ID: int64(i + 1), JobID: "history", Message: strings.Repeat("x", messageBytes)}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.compact(); err != nil {
		t.Fatal(err)
	}
	job := sampleJob("active")
	if _, _, err := s.CreateJobWithItems(ctx, job, []entities.JobItem{{RelativePath: "file", Size: 1 << 30}}, ""); err != nil {
		t.Fatal(err)
	}
	checkpointStart := time.Now()
	for i := 0; i < 100; i++ {
		if err := s.UpdateJobItem(ctx, entities.JobItem{JobID: job.ID, RelativePath: "file", Size: 1 << 30, BytesCompleted: int64(i) * 65536}); err != nil {
			t.Fatal(err)
		}
	}
	checkpointTime := time.Since(checkpointStart) / 100
	s.Close()
	s.index = nil
	s.cache = nil
	s.cacheOrder = nil
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	opened := time.Now()
	reopened, err := OpenExisting(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	openTime := time.Since(opened)
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if retained > historyCount*messageBytes/4 {
		t.Fatalf("history loaded eagerly: retained %d bytes", retained)
	}
	if reopened.cacheBytes != 0 {
		t.Fatal("open populated historical payload cache")
	}
	events, err := reopened.ListJobEvents(ctx, 0, "history", 17)
	if err != nil || len(events) != 17 {
		t.Fatalf("pagination: %d, %v", len(events), err)
	}
	if reopened.cacheBytes > cacheLimit {
		t.Fatal("cache exceeds its bound")
	}
	t.Logf("history=%d records/%d MiB; checkpoint_mean=%s; open=%s; retained_heap=%d bytes; page_cache=%d bytes; active_journal=%d transactions", historyCount, historyCount*messageBytes/(1<<20), checkpointTime, openTime, retained, reopened.cacheBytes, reopened.journalCount)
	runtime.KeepAlive(reopened)
}
