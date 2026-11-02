package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

func (s *Store) AuditAgentRequest(ctx context.Context, actorID, resource, result, correlationID, sourceIP string, detail map[string]any) error {
	encoded, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return s.appendAudit(ctx, auditRecord{actorID: actorID, actorType: "service_account", action: "agent_request", resource: resource, result: result, correlationID: correlationID, sourceIP: sourceIP, detail: string(encoded)})
}

func (s *Store) PurgeAuditBefore(ctx context.Context, before time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	cutoff := before.UTC().Format(time.RFC3339Nano)
	// Retain any later IDs after the first ineligible record, even if the clock
	// moved backwards, so retention never creates a hole in the chain.
	var boundary int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MIN(id),(SELECT COALESCE(MAX(id),0)+1 FROM audit_events)) FROM audit_events WHERE julianday(created_at) IS NULL OR julianday(created_at)>=julianday(?)`, cutoff).Scan(&boundary); err != nil {
		return 0, err
	}
	var lastID int64
	var lastHash string
	err = tx.QueryRowContext(ctx, `SELECT id,chain_hash FROM audit_events WHERE id<? AND chain_hash<>'' ORDER BY id DESC LIMIT 1`, boundary).Scan(&lastID, &lastHash)
	if err == nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_chain_checkpoints(event_id,event_hash,created_at,reason) VALUES(?,?,?,?)`, lastID, lastHash, time.Now().UTC().Format(time.RFC3339Nano), "retention"); err != nil {
			return 0, err
		}
	} else if err != sql.ErrNoRows {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id<?`, boundary)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}
