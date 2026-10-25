package state

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"sync"
	"testing"
	"time"
)

func TestJobSummaryIncludesOldActiveJobsAndItemsPageUsesIndex(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	items := make([]entities.JobItem, 1203)
	for i := range items {
		items[i] = entities.JobItem{RelativePath: fmt.Sprintf("file-%05d", i), Ordinal: i}
	}
	job := sampleJob("old-active")
	job.State = "waiting_validation"
	if _, _, err := s.CreateJobWithItems(ctx, job, items, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.update(ctx, func(tx *transaction) error {
		for i := 0; i < 550; i++ {
			j := sampleJob(fmt.Sprint(i))
			j.State = "completed"
			if err := tx.put("jobs", j.ID, "", order(j.CreatedAt), j); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := s.JobSummary(ctx)
	if err != nil || summary.Counts["waiting_validation"] != 1 || summary.Counts["completed"] != 550 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	seen := 0
	after := 0
	for {
		page, next, err := s.ListJobItemsPage(ctx, job.ID, after, 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page {
			if item.Ordinal != seen {
				t.Fatalf("ordinal=%d want=%d", item.Ordinal, seen)
			}
			seen++
		}
		if next == 0 {
			break
		}
		after = next
	}
	if seen != len(items) {
		t.Fatalf("items=%d", seen)
	}
}

func TestTokenPreparationIsExclusiveAndCommitIsIdempotent(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan struct {
		hash string
		err  error
	}, 2)
	for _, hash := range []string{"a", "b"} {
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			results <- struct {
				hash string
				err  error
			}{hash, s.StageOperationalToken(ctx, hash, "rotation", time.Now())}
		}(hash)
	}
	wg.Wait()
	close(results)
	winner := ""
	denied := 0
	for result := range results {
		if result.err == nil {
			winner = result.hash
		} else if errors.Is(result.err, contracts.ErrInUse) {
			denied++
		} else {
			t.Fatal(result.err)
		}
	}
	if winner == "" || denied != 1 {
		t.Fatal("competing preparation accepted")
	}
	for i := 0; i < 2; i++ {
		if err := s.CommitOperationalToken(ctx, winner, "rotation", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}
