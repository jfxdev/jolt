package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrAgentQuota = errors.New("agent daily quota exhausted")

// ReserveAgentBytes charges before any response bytes are sent. A crash leaves
// the reservation charged, preventing a restart from replenishing a quota.
func (s *Store) ReserveAgentBytes(ctx context.Context, tokenID, day string, requested, daily int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_usage(token_id,day,charged_bytes) VALUES(?,?,0) ON CONFLICT(token_id,day) DO NOTHING`, tokenID, day); err != nil {
		return 0, err
	}
	var charged int64
	if err = tx.QueryRowContext(ctx, `SELECT charged_bytes FROM agent_usage WHERE token_id=? AND day=?`, tokenID, day).Scan(&charged); err != nil {
		return 0, err
	}
	remaining := daily - charged
	// Keep enough budget for a structured refusal; otherwise return the fixed
	// quota error without forwarding any protected content.
	if remaining < 1024 {
		return 0, ErrAgentQuota
	}
	if requested > remaining {
		requested = remaining
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_usage SET charged_bytes=charged_bytes+? WHERE token_id=? AND day=? AND charged_bytes+?<=?`, requested, tokenID, day, requested, daily)
	if err != nil {
		return 0, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		if err != nil {
			return 0, err
		}
		return 0, ErrAgentQuota
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return requested, nil
}

func (s *Store) RefundAgentBytes(ctx context.Context, tokenID, day string, amount int64) error {
	if amount <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE agent_usage SET charged_bytes=MAX(0,charged_bytes-?) WHERE token_id=? AND day=?`, amount, tokenID, day)
	return err
}

func (s *Store) DisableAgents(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE service_accounts SET enabled=0,updated_at=? WHERE kind='agent' AND enabled=1`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) UpdateAgentTokenLimits(ctx context.Context, accountID, tokenID string, limits AgentLimits) error {
	encoded, err := json.Marshal(limits)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET agent_limits=? WHERE id=? AND service_account_id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM service_accounts WHERE id=? AND kind='agent')`, string(encoded), tokenID, accountID, accountID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}

// AgentUsage is used by diagnostics and quota regression tests.
func (s *Store) AgentUsage(ctx context.Context, tokenID, day string) (int64, error) {
	var value int64
	err := s.db.QueryRowContext(ctx, `SELECT charged_bytes FROM agent_usage WHERE token_id=? AND day=?`, tokenID, day).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return value, err
}
