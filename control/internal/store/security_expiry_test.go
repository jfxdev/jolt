package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticationExpiryUsesInstants(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, now := context.Background(), time.Now().UTC()
	user := User{ID: "u", Username: "user", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	account := ServiceAccount{ID: "a", Name: "service", Kind: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	expired := now.Truncate(time.Second)
	futureOffset := now.Add(time.Hour).In(time.FixedZone("west", -12*60*60))
	for _, tc := range []struct {
		name   string
		expiry time.Time
		valid  bool
	}{{"expired whole second", expired, false}, {"future in western offset", futureOffset, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.CreateSession(ctx, tc.name, user.ID, tc.expiry); err != nil {
				t.Fatal(err)
			}
			_, _, sessionErr := s.SessionUserAndExpiry(ctx, tc.name)
			if (sessionErr == nil) != tc.valid {
				t.Fatalf("session err=%v valid=%v", sessionErr, tc.valid)
			}
			token := ServiceAccountToken{ID: tc.name, ServiceAccountID: account.ID, Name: tc.name, TokenHash: tc.name, ExpiresAt: &tc.expiry, CreatedAt: now}
			if err := s.CreateServiceAccountToken(ctx, token, false); err != nil {
				t.Fatal(err)
			}
			_, _, tokenErr := s.AuthenticateServiceAccount(ctx, token.TokenHash)
			if (tokenErr == nil) != tc.valid {
				t.Fatalf("token err=%v valid=%v", tokenErr, tc.valid)
			}
		})
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at='invalid' WHERE token_hash=?`, "future in western offset"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionUserAndExpiry(ctx, "future in western offset"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid session expiry: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET expires_at='invalid' WHERE id=?`, "future in western offset"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateServiceAccount(ctx, "future in western offset"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid token expiry: %v", err)
	}
}

func TestShareExpiryAndAtomicReservationUseInstants(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		expiry time.Time
		now    time.Time
		valid  bool
	}{
		{"expired whole second", base, base.Add(100 * time.Millisecond), false},
		{"expired shorter fraction", base.Add(100 * time.Millisecond), base.Add(120 * time.Millisecond), false},
		{"future longer fraction", base.Add(120 * time.Millisecond), base.Add(100 * time.Millisecond), true},
		{"exact deadline", base, base, false},
		{"future western offset", base.Add(time.Hour).In(time.FixedZone("west", -12*60*60)), base, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			share := Share{ID: tc.name, TokenHash: tc.name, NodeID: "n", MountID: "m", Path: "a", Kind: "file", Name: "a", CreatedBy: "user", CreatedAt: base, ExpiresAt: &tc.expiry, MaxDownloads: 1}
			if err := s.CreateShare(ctx, share); err != nil {
				t.Fatal(err)
			}
			if share.Active(tc.now) != tc.valid {
				t.Fatalf("Active disagrees: %v", tc.valid)
			}
			err := s.RegisterShareDownload(ctx, share.ID, tc.now)
			if (err == nil) != tc.valid {
				t.Fatalf("reservation error=%v valid=%v", err, tc.valid)
			}
			if tc.valid && !errors.Is(s.RegisterShareDownload(ctx, share.ID, tc.now), ErrShareExhausted) {
				t.Fatal("download limit was exceeded")
			}
		})
	}
	malformed := Share{ID: "malformed", TokenHash: "malformed", NodeID: "n", MountID: "m", Path: "a", Kind: "file", Name: "a", CreatedBy: "user", CreatedAt: base}
	if err := s.CreateShare(ctx, malformed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE shares SET expires_at='invalid' WHERE id=?`, malformed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetShare(ctx, malformed.ID); err == nil {
		t.Fatal("malformed share expiration accepted")
	}
	if err := s.RegisterShareDownload(ctx, malformed.ID, base); !errors.Is(err, ErrShareExhausted) {
		t.Fatalf("malformed reservation: %v", err)
	}
	count, err := s.PurgeExpiredShares(ctx, base.Add(110*time.Millisecond))
	if err != nil || count != 3 {
		t.Fatalf("purge count=%d err=%v", count, err)
	}
	if _, err := s.GetShare(ctx, "future western offset"); err != nil {
		t.Fatalf("purged unexpired offset share: %v", err)
	}
}
