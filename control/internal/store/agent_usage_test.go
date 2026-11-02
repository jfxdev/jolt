package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentReservationsAreAtomicAndPersistAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	account := ServiceAccount{ID: "agent", Name: "agent", Kind: "agent", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour)
	if err := s.CreateServiceAccountToken(ctx, ServiceAccountToken{ID: "key", ServiceAccountID: account.ID, Name: "key", TokenHash: "digest", ExpiresAt: &expires, CreatedAt: now}, false); err != nil {
		t.Fatal(err)
	}
	day := now.Format("2006-01-02")
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reserved, err := s.ReserveAgentBytes(ctx, "key", day, 1024, 4096)
			if err == nil && reserved == 1024 {
				accepted.Add(1)
			} else if !errors.Is(err, ErrAgentQuota) {
				t.Errorf("reservation=%d err=%v", reserved, err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 4 {
		t.Fatalf("accepted reservations: %d", accepted.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if used, err := s.AgentUsage(ctx, "key", day); err != nil || used != 4096 {
		t.Fatalf("after restart: %d %v", used, err)
	}
	if _, err := s.ReserveAgentBytes(ctx, "key", day, 1024, 4096); !errors.Is(err, ErrAgentQuota) {
		t.Fatalf("quota after restart: %v", err)
	}
	if err := s.RefundAgentBytes(ctx, "key", day, 1024); err != nil {
		t.Fatal(err)
	}
	if amount, err := s.ReserveAgentBytes(ctx, "key", day, 1024, 4096); err != nil || amount != 1024 {
		t.Fatalf("after refund: %d %v", amount, err)
	}
	if _, err := s.db.Exec(`UPDATE metadata SET value='3' WHERE key='minimum_security_version'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if newer, err := Open(path, testDatabaseKey); err == nil {
		newer.Close()
		t.Fatal("unsupported security version was accepted")
	}
}

func TestAuditRetentionAndAscendingCursor(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{"old", "new"} {
		if err := s.AuditAgentRequest(ctx, "agent", name, "allowed", "cor", "192.0.2.1", map[string]any{"bytes_out": 5}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE audit_events SET created_at=? WHERE resource='old'`, time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	first, more, err := s.ListAuditEvents(ctx, AuditQuery{Ascending: true, Limit: 1})
	if err != nil || !more || len(first) != 1 || first[0].Resource != "old" {
		t.Fatalf("first: %+v %v %v", first, more, err)
	}
	second, _, err := s.ListAuditEvents(ctx, AuditQuery{Ascending: true, AfterID: first[0].ID, Limit: 1})
	if err != nil || len(second) != 1 || second[0].Resource != "new" {
		t.Fatalf("second: %+v %v", second, err)
	}
	if removed, err := s.PurgeAuditBefore(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil || removed != 1 {
		t.Fatalf("purge: %d %v", removed, err)
	}
}
