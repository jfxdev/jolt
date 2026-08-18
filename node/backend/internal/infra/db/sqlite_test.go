package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

func TestMigrationUpgradesLegacyJobsAndAddsEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE jobs (
 id TEXT PRIMARY KEY, type TEXT NOT NULL, state TEXT NOT NULL, phase TEXT NOT NULL,
 mount_id TEXT NOT NULL, source_path TEXT, destination_path TEXT,
 bytes_total INTEGER NOT NULL DEFAULT 0, bytes_completed INTEGER NOT NULL DEFAULT 0,
 error TEXT, correlation_id TEXT NOT NULL, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, completed_at TEXT
);
CREATE TABLE job_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, type TEXT NOT NULL,
 state TEXT NOT NULL, phase TEXT NOT NULL, bytes_total INTEGER NOT NULL DEFAULT 0,
 bytes_completed INTEGER NOT NULL DEFAULT 0, bytes_per_second REAL NOT NULL DEFAULT 0,
 eta_seconds INTEGER, eta_confidence TEXT, message TEXT, correlation_id TEXT NOT NULL,
 created_at TEXT NOT NULL
)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	eta := int64(4)
	job := entities.Job{
		ID: "job_legacy", Type: "copy_local", State: "running", Phase: "transfer",
		MountID: "mount", BytesTotal: 100, BytesCompleted: 50, BytesPerSecond: 12.5,
		ETASeconds: &eta, ETAConfidence: "medium", MaxAttempts: 3,
		BandwidthLimit:    1 << 20,
		MaxParallelFiles:  4,
		MaxParallelChunks: 3,
		CorrelationID:     "cor_legacy", CreatedAt: now, UpdatedAt: now,
	}
	if _, _, err := store.CreateJob(context.Background(), job, ""); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetJob(context.Background(), job.ID)
	if err != nil || stored.BandwidthLimit != job.BandwidthLimit ||
		stored.MaxParallelFiles != 4 || stored.MaxParallelChunks != 3 {
		t.Fatalf("stored execution controls=%+v err=%v", stored, err)
	}
	event, err := store.RecordJobEvent(context.Background(), entities.JobEvent{
		JobID: job.ID, Type: "job.progress", State: job.State, Phase: job.Phase,
		BytesTotal: job.BytesTotal, BytesCompleted: job.BytesCompleted,
		BytesPerSecond: job.BytesPerSecond, ETASeconds: job.ETASeconds,
		ETAConfidence: job.ETAConfidence, CorrelationID: job.CorrelationID, CreatedAt: now,
	})
	if err != nil || event.ID == 0 {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	events, err := store.ListJobEvents(context.Background(), 0, job.ID, 10)
	if err != nil || len(events) != 1 || events[0].ETASeconds == nil || *events[0].ETASeconds != eta {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestRecoverOperationalTokenReplacesStagedAndEnvironmentCredentials(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "jolt.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.StageOperationalToken(ctx, "staged-old", "cor-stage", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverOperationalToken(ctx, "active-recovered", "cor-recovery", now); err != nil {
		t.Fatal(err)
	}
	state, err := store.GetOperationalTokenState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveHash != "active-recovered" || state.StagedHash != "" || !state.EnvTokenDisabled ||
		state.CorrelationID != "cor-recovery" {
		t.Fatalf("unexpected recovered state: %+v", state)
	}
}
