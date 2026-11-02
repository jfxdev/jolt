package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuditChainPersistsAcrossRetentionAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if err := s.appendAudit(ctx, auditRecord{actorID: "user", actorType: "user", action: "legacy", resource: "legacy", result: "allowed", correlationID: "one", createdAt: old}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.appendAudit(ctx, auditRecord{actorID: "user", actorType: "user", action: "old", resource: "one", result: "allowed", correlationID: "two", createdAt: old}); err != nil {
		t.Fatal(err)
	}
	if err := s.appendAudit(ctx, auditRecord{actorID: "user", actorType: "user", action: "new", resource: "two", result: "allowed", correlationID: "three"}); err != nil {
		t.Fatal(err)
	}
	events, _, err := s.ListAuditEvents(ctx, AuditQuery{Ascending: true, Limit: 100})
	if err != nil || len(events) != 3 || events[0].ChainHash != "" {
		t.Fatalf("events: %+v %v", events, err)
	}
	prev := strings.Repeat("0", 64)
	for _, event := range events[1:] {
		var fields []string
		digest := sha256.Sum256([]byte(event.ChainData))
		if json.Unmarshal([]byte(event.ChainData), &fields) != nil || len(fields) != 15 || fields[1] != prev || event.ChainHash != hex.EncodeToString(digest[:]) {
			t.Fatalf("invalid chain: %+v", event)
		}
		prev = event.ChainHash
	}
	removed, err := s.PurgeAuditBefore(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil || removed != 2 {
		t.Fatalf("purge: %d %v", removed, err)
	}
	checkpoint, err := s.AuditCheckpoint(ctx)
	if err != nil || checkpoint == nil || checkpoint.EventID != events[1].ID || checkpoint.EventHash != events[1].ChainHash || checkpoint.Reason != "retention" {
		t.Fatalf("checkpoint: %+v %v", checkpoint, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.appendAudit(ctx, auditRecord{actorID: "user", actorType: "user", action: "after_restart", resource: "three", result: "allowed", correlationID: "four"}); err != nil {
		t.Fatal(err)
	}
	events, _, err = s.ListAuditEvents(ctx, AuditQuery{Ascending: true, Limit: 100})
	if err != nil || len(events) != 2 {
		t.Fatalf("after restart: %+v %v", events, err)
	}
	var fields []string
	if json.Unmarshal([]byte(events[1].ChainData), &fields) != nil || fields[1] != events[0].ChainHash {
		t.Fatalf("chain did not persist: %+v", events)
	}
}

func TestAuditRetentionKeepsContiguousPrefixWhenClockMoves(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.EnableAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	for _, when := range []time.Time{time.Now().Add(-48 * time.Hour), time.Now(), time.Now().Add(-48 * time.Hour)} {
		if err := s.appendAudit(ctx, auditRecord{actorID: "u", actorType: "user", action: "event", resource: "r", result: "allowed", correlationID: "c", createdAt: when.UTC().Format(time.RFC3339Nano)}); err != nil {
			t.Fatal(err)
		}
	}
	count, err := s.PurgeAuditBefore(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || count != 1 {
		t.Fatalf("retention made a gap: %d %v", count, err)
	}
}

func TestAuditChainConcurrentAppends(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.EnableAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.appendAudit(ctx, auditRecord{actorID: "u", actorType: "user", action: "event", resource: "r", result: "allowed", correlationID: "c"})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	events, _, err := s.ListAuditEvents(ctx, AuditQuery{Ascending: true, Limit: 100})
	if err != nil || len(events) != 32 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	previous := strings.Repeat("0", 64)
	for _, event := range events {
		var fields []string
		if err := json.Unmarshal([]byte(event.ChainData), &fields); err != nil || len(fields) != 15 || fields[1] != previous {
			t.Fatalf("broken concurrent chain: %+v %v", event, err)
		}
		previous = event.ChainHash
	}
}
