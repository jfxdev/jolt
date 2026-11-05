package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// A pending operation is a small request that a policy lets someone make only
// once a person approves it. The request is kept exactly as it was made; the
// Control Tower replays it when an approver accepts, with the approver's
// permissions.
const (
	PendingState         = "pending"
	PendingExecuting     = "executing"
	PendingExecuted      = "executed"
	PendingFailed        = "failed"
	PendingRejected      = "rejected"
	PendingExpired       = "expired"
	PendingIndeterminate = "indeterminate"

	// PendingLifetime is how long a request waits for a decision.
	PendingLifetime = 5 * time.Minute
	// pendingKeep is how long a decided request stays for audit and replies.
	pendingKeep = 30 * 24 * time.Hour
)

var (
	ErrPendingExpired = errors.New("pending operation expired")
	ErrPendingTooMany = errors.New("too many pending operations")
)

type PendingRequirement struct {
	Path       string `json:"path"`
	Capability string `json:"capability"`
}

type PendingOperation struct {
	ID            string               `json:"pending_operation_id"`
	RequesterType string               `json:"requester_type"`
	RequesterID   string               `json:"requester_id"`
	Method        string               `json:"method"`
	NodeID        string               `json:"node_id"`
	Resource      string               `json:"resource"`
	RawQuery      string               `json:"-"`
	Body          []byte               `json:"-"`
	BodySHA256    string               `json:"body_sha256"`
	Summary       json.RawMessage      `json:"summary"`
	Requirements  []PendingRequirement `json:"requirements"`
	State         string               `json:"state"`
	CreatedAt     time.Time            `json:"created_at"`
	ExpiresAt     time.Time            `json:"expires_at"`
	DecidedByType string               `json:"decided_by_type,omitempty"`
	DecidedByID   string               `json:"decided_by_id,omitempty"`
	DecidedAt     *time.Time           `json:"decided_at,omitempty"`
	Note          string               `json:"note,omitempty"`
	ResultStatus  int                  `json:"result_status,omitempty"`
	ResultBody    string               `json:"result_body,omitempty"`
}

const pendingColumns = `id,requester_type,requester_id,method,node_id,resource,raw_query,body,body_sha256,summary,requirements,state,created_at,expires_at_ns,decided_by_type,decided_by_id,decided_at,note,result_status,result_body`

// IntegrityOK reports whether the stored body is the one the request was made
// with. A replay refuses anything else.
func (op PendingOperation) IntegrityOK() bool {
	digest := sha256.Sum256(op.Body)
	return op.BodySHA256 == hex.EncodeToString(digest[:])
}

func scanPending(row interface{ Scan(...any) error }) (PendingOperation, error) {
	var op PendingOperation
	var summary, requirements, created, decidedAt string
	var expires int64
	if err := row.Scan(&op.ID, &op.RequesterType, &op.RequesterID, &op.Method, &op.NodeID, &op.Resource, &op.RawQuery, &op.Body, &op.BodySHA256, &summary, &requirements, &op.State, &created, &expires, &op.DecidedByType, &op.DecidedByID, &decidedAt, &op.Note, &op.ResultStatus, &op.ResultBody); err != nil {
		return PendingOperation{}, err
	}
	op.Summary = json.RawMessage(summary)
	if err := json.Unmarshal([]byte(requirements), &op.Requirements); err != nil {
		return PendingOperation{}, err
	}
	op.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	op.ExpiresAt = time.Unix(0, expires).UTC()
	if decidedAt != "" {
		moment, _ := time.Parse(time.RFC3339Nano, decidedAt)
		op.DecidedAt = &moment
	}
	return op, nil
}

// expirePending closes requests nobody decided in time and forgets old ones.
func expirePending(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE pending_operations SET state=? WHERE state=? AND expires_at_ns<=?`, PendingExpired, PendingState, now.UnixNano()); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM pending_operations WHERE state NOT IN (?,?) AND expires_at_ns<?`, PendingState, PendingExecuting, now.Add(-pendingKeep).UnixNano())
	return err
}

// CreatePendingOperation stores a request, or returns the identical one still
// waiting so that a retry does not queue a second approval. The second result
// reports that an existing request was returned.
func (s *Store) CreatePendingOperation(ctx context.Context, op PendingOperation, maxPerRequester int, now time.Time) (PendingOperation, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingOperation{}, false, err
	}
	defer tx.Rollback()
	if err := expirePending(ctx, tx, now); err != nil {
		return PendingOperation{}, false, err
	}
	if op.Body == nil {
		op.Body = []byte{}
	}
	digest := sha256.Sum256(op.Body)
	op.BodySHA256 = hex.EncodeToString(digest[:])
	existing, err := scanPending(tx.QueryRowContext(ctx, `SELECT `+pendingColumns+` FROM pending_operations WHERE requester_type=? AND requester_id=? AND state=? AND method=? AND node_id=? AND resource=? AND raw_query=? AND body_sha256=?`,
		op.RequesterType, op.RequesterID, PendingState, op.Method, op.NodeID, op.Resource, op.RawQuery, op.BodySHA256))
	if err == nil {
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PendingOperation{}, false, err
	}
	var open int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_operations WHERE requester_type=? AND requester_id=? AND state=?`, op.RequesterType, op.RequesterID, PendingState).Scan(&open); err != nil {
		return PendingOperation{}, false, err
	}
	if open >= maxPerRequester {
		return PendingOperation{}, false, ErrPendingTooMany
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return PendingOperation{}, false, err
	}
	op.ID = "pop_" + hex.EncodeToString(random)
	op.State, op.CreatedAt, op.ExpiresAt = PendingState, now.UTC(), now.UTC().Add(PendingLifetime)
	if len(op.Summary) == 0 {
		op.Summary = json.RawMessage("{}")
	}
	requirements, err := json.Marshal(op.Requirements)
	if err != nil {
		return PendingOperation{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pending_operations(`+pendingColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		op.ID, op.RequesterType, op.RequesterID, op.Method, op.NodeID, op.Resource, op.RawQuery, op.Body, op.BodySHA256, string(op.Summary), string(requirements), op.State,
		op.CreatedAt.Format(time.RFC3339Nano), op.ExpiresAt.UnixNano(), "", "", "", "", 0, ""); err != nil {
		return PendingOperation{}, false, err
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: op.RequesterID, actorType: op.RequesterType, action: "pending_operation_create", resource: "nodes/" + op.NodeID + "/" + op.Resource, result: "allowed", createdAt: op.CreatedAt.Format(time.RFC3339Nano), detail: `{"pending_operation_id":"` + op.ID + `"}`}); err != nil {
		return PendingOperation{}, false, err
	}
	return op, false, tx.Commit()
}

func (s *Store) GetPendingOperation(ctx context.Context, id string, now time.Time) (PendingOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingOperation{}, err
	}
	defer tx.Rollback()
	if err := expirePending(ctx, tx, now); err != nil {
		return PendingOperation{}, err
	}
	op, err := scanPending(tx.QueryRowContext(ctx, `SELECT `+pendingColumns+` FROM pending_operations WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PendingOperation{}, ErrNotFound
	}
	if err != nil {
		return PendingOperation{}, err
	}
	return op, tx.Commit()
}

// ListPendingOperations returns the newest requests first. An empty state lists
// every state; requesterID limits the list to one requester.
func (s *Store) ListPendingOperations(ctx context.Context, state, requesterType, requesterID string, limit int, now time.Time) ([]PendingOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := expirePending(ctx, tx, now); err != nil {
		return nil, err
	}
	query, args := `SELECT `+pendingColumns+` FROM pending_operations WHERE 1=1`, []any{}
	if state != "" {
		query += ` AND state=?`
		args = append(args, state)
	}
	if requesterID != "" {
		query += ` AND requester_type=? AND requester_id=?`
		args = append(args, requesterType, requesterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []PendingOperation
	for rows.Next() {
		op, err := scanPending(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, op)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, tx.Commit()
}

// ClaimPendingOperation moves a waiting request to executing for exactly one
// caller. A second caller, or a late one, gets ErrConflict or ErrPendingExpired.
func (s *Store) ClaimPendingOperation(ctx context.Context, id, byType, byID string, now time.Time) (PendingOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingOperation{}, err
	}
	defer tx.Rollback()
	op, err := scanPending(tx.QueryRowContext(ctx, `SELECT `+pendingColumns+` FROM pending_operations WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PendingOperation{}, ErrNotFound
	}
	if err != nil {
		return PendingOperation{}, err
	}
	if op.State == PendingState && !now.Before(op.ExpiresAt) {
		if _, err := tx.ExecContext(ctx, `UPDATE pending_operations SET state=? WHERE id=? AND state=?`, PendingExpired, id, PendingState); err != nil {
			return PendingOperation{}, err
		}
		if err := tx.Commit(); err != nil {
			return PendingOperation{}, err
		}
		return PendingOperation{}, ErrPendingExpired
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE pending_operations SET state=?,decided_by_type=?,decided_by_id=?,decided_at=? WHERE id=? AND state=?`, PendingExecuting, byType, byID, stamp, id, PendingState)
	if err != nil {
		return PendingOperation{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return op, ErrConflict
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: byID, actorType: byType, action: "pending_operation_approve", resource: "nodes/" + op.NodeID + "/" + op.Resource, result: "allowed", createdAt: stamp, detail: `{"pending_operation_id":"` + op.ID + `"}`}); err != nil {
		return PendingOperation{}, err
	}
	op.State, op.DecidedByType, op.DecidedByID = PendingExecuting, byType, byID
	moment := now.UTC()
	op.DecidedAt = &moment
	return op, tx.Commit()
}

// FinishPendingOperation records what the replay answered. Only an executing
// request can finish, so a late or repeated finish changes nothing.
func (s *Store) FinishPendingOperation(ctx context.Context, id string, status int, body string, now time.Time) error {
	state := PendingExecuted
	if status >= 400 {
		state = PendingFailed
	}
	if len(body) > 8192 {
		body = body[:8192]
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE pending_operations SET state=?,result_status=?,result_body=? WHERE id=? AND state=?`, state, status, body, id, PendingExecuting)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

// RejectPendingOperation closes a waiting request without running it.
func (s *Store) RejectPendingOperation(ctx context.Context, id, byType, byID, note string, now time.Time) (PendingOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingOperation{}, err
	}
	defer tx.Rollback()
	if err := expirePending(ctx, tx, now); err != nil {
		return PendingOperation{}, err
	}
	op, err := scanPending(tx.QueryRowContext(ctx, `SELECT `+pendingColumns+` FROM pending_operations WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PendingOperation{}, ErrNotFound
	}
	if err != nil {
		return PendingOperation{}, err
	}
	if op.State != PendingState {
		return op, ErrConflict
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE pending_operations SET state=?,decided_by_type=?,decided_by_id=?,decided_at=?,note=? WHERE id=? AND state=?`, PendingRejected, byType, byID, stamp, note, id, PendingState); err != nil {
		return PendingOperation{}, err
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: byID, actorType: byType, action: "pending_operation_reject", resource: "nodes/" + op.NodeID + "/" + op.Resource, result: "allowed", createdAt: stamp, detail: `{"pending_operation_id":"` + op.ID + `"}`}); err != nil {
		return PendingOperation{}, err
	}
	op.State, op.Note = PendingRejected, note
	return op, tx.Commit()
}

// recoverPendingOperations runs when the database opens, when nothing can be
// executing: a request left in that state may or may not have reached the node,
// so it is never replayed.
func recoverPendingOperations(db *sql.DB) error {
	_, err := db.Exec(`UPDATE pending_operations SET state=? WHERE state=?`, PendingIndeterminate, PendingExecuting)
	return err
}
