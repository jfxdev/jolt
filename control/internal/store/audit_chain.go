package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type auditRecord struct {
	actorID, actorType, action, resource, result, correlationID, createdAt string
	policyIDs, evaluatedPath, capability, sourceIP, detail                 string
}

// EnableAuditChain starts a persistent chain after the existing history. Once
// started, all new records are chained even if the configuration is later off.
func (s *Store) EnableAuditChain(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_chain_state WHERE singleton=1`).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return tx.Commit()
	}
	var lastID int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM audit_events`).Scan(&lastID); err != nil {
		return err
	}
	zero := strings.Repeat("0", 64)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_chain_state(singleton,last_id,last_hash) VALUES(1,?,?)`, lastID, zero); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_chain_checkpoints(event_id,event_hash,created_at,reason) VALUES(?,?,?,?)`, lastID, zero, time.Now().UTC().Format(time.RFC3339Nano), "activation"); err != nil {
		return err
	}
	return tx.Commit()
}

func appendAuditTx(ctx context.Context, tx *sql.Tx, record auditRecord) error {
	if record.createdAt == "" {
		record.createdAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if record.policyIDs == "" {
		record.policyIDs = "[]"
	}
	if record.detail == "" {
		record.detail = "{}"
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO audit_events(actor_id,actor_type,action,resource,result,correlation_id,created_at,policy_ids,evaluated_path,capability,source_ip,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		record.actorID, record.actorType, record.action, record.resource, record.result, record.correlationID, record.createdAt, record.policyIDs, record.evaluatedPath, record.capability, record.sourceIP, record.detail)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT last_hash FROM audit_chain_state WHERE singleton=1`).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	fields := []string{"jolt-audit-v1", previous, strconv.FormatInt(id, 10), record.actorID, record.actorType, record.action, record.resource, record.result, record.correlationID, record.createdAt, record.policyIDs, record.evaluatedPath, record.capability, record.sourceIP, record.detail}
	payload, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	hash := hex.EncodeToString(digest[:])
	if _, err := tx.ExecContext(ctx, `UPDATE audit_events SET chain_data=?,chain_hash=? WHERE id=?`, string(payload), hash, id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE audit_chain_state SET last_id=?,last_hash=? WHERE singleton=1`, id, hash)
	return err
}

func (s *Store) appendAudit(ctx context.Context, record auditRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := appendAuditTx(ctx, tx, record); err != nil {
		return err
	}
	return tx.Commit()
}

type AuditCheckpoint struct {
	EventID   int64  `json:"event_id"`
	EventHash string `json:"event_hash"`
	CreatedAt string `json:"created_at"`
	Reason    string `json:"reason"`
}

func (s *Store) AuditCheckpoint(ctx context.Context) (*AuditCheckpoint, error) {
	var checkpoint AuditCheckpoint
	err := s.db.QueryRowContext(ctx, `SELECT event_id,event_hash,created_at,reason FROM audit_chain_checkpoints ORDER BY id DESC LIMIT 1`).Scan(&checkpoint.EventID, &checkpoint.EventHash, &checkpoint.CreatedAt, &checkpoint.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &checkpoint, nil
}
