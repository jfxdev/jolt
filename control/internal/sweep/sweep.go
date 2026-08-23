// Package sweep runs periodic maintenance tasks against the Control Tower
// store — purging rows that would otherwise grow unbounded, such as expired
// login lockouts, sessions, pairing invites, or idempotency keys.
package sweep

import (
	"context"
	"log/slog"
	"time"
)

// Task is one periodic cleanup routine. Run should be idempotent and cheap;
// it is invoked on every tick regardless of how much (if anything) the
// previous tick deleted, and returns the number of rows it removed.
type Task struct {
	Name string
	Run  func(ctx context.Context, now time.Time) (int64, error)
}

// Runner ticks on a fixed interval and executes every registered Task in
// sequence, logging outcomes. To add a new cleanup routine, append a Task
// to the slice passed to New — the loop itself does not change.
type Runner struct {
	interval time.Duration
	tasks    []Task
	logger   *slog.Logger
}

func New(interval time.Duration, logger *slog.Logger, tasks ...Task) *Runner {
	return &Runner{interval: interval, tasks: tasks, logger: logger}
}

// Start runs an immediate pass over every task, then one more pass per tick,
// until ctx is canceled. It blocks, so callers run it in its own goroutine.
func (r *Runner) Start(ctx context.Context) {
	r.runOnce(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

func (r *Runner) runOnce(ctx context.Context) {
	now := time.Now().UTC()
	for _, task := range r.tasks {
		deleted, err := task.Run(ctx, now)
		if err != nil {
			r.logger.Error("sweep task failed", "task", task.Name, "error", err)
			continue
		}
		if deleted > 0 {
			r.logger.Info("sweep task purged rows", "task", task.Name, "count", deleted)
		}
	}
}
