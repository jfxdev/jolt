package sweep

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunnerRunsEveryTaskImmediatelyAndOnEachTick(t *testing.T) {
	var calls atomic.Int64
	runner := New(5*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), Task{
		Name: "counter",
		Run: func(ctx context.Context, now time.Time) (int64, error) {
			calls.Add(1)
			return 1, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	runner.Start(ctx)
	if calls.Load() < 2 {
		t.Fatalf("calls=%d, want at least 2 (immediate pass + at least one tick)", calls.Load())
	}
}

func TestRunnerContinuesAfterATaskFailsAndRunsRemainingTasks(t *testing.T) {
	var ranAfterFailure atomic.Bool
	runner := New(time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)),
		Task{
			Name: "failing",
			Run: func(ctx context.Context, now time.Time) (int64, error) {
				return 0, errors.New("boom")
			},
		},
		Task{
			Name: "healthy",
			Run: func(ctx context.Context, now time.Time) (int64, error) {
				ranAfterFailure.Store(true)
				return 0, nil
			},
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner.Start(ctx)
	if !ranAfterFailure.Load() {
		t.Fatal("healthy task did not run after failing task errored")
	}
}
