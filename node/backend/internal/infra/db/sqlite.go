package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrInUse    = errors.New("resource is in use")
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		database.Close()
		return nil, err
	}
	s := &Store{db: database}
	if err := s.migrate(); err != nil {
		database.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS mounts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, local_path TEXT NOT NULL UNIQUE,
 target_type TEXT NOT NULL, mode TEXT NOT NULL, published INTEGER NOT NULL,
 enabled INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, type TEXT NOT NULL, state TEXT NOT NULL, phase TEXT NOT NULL,
 mount_id TEXT NOT NULL, peer_node_id TEXT, source_grant_id TEXT, destination_grant_id TEXT,
 source_etag TEXT, source_path TEXT, destination_path TEXT,
 bytes_total INTEGER NOT NULL DEFAULT 0, bytes_completed INTEGER NOT NULL DEFAULT 0,
 bytes_per_second REAL NOT NULL DEFAULT 0, eta_seconds INTEGER, eta_confidence TEXT,
 files_total INTEGER NOT NULL DEFAULT 0, files_completed INTEGER NOT NULL DEFAULT 0,
 files_failed INTEGER NOT NULL DEFAULT 0, conflict_policy TEXT,
	source_change_policy TEXT NOT NULL DEFAULT 'fail',
	verify_checksum INTEGER NOT NULL DEFAULT 0,
	bandwidth_limit INTEGER NOT NULL DEFAULT 0,
	max_parallel_files INTEGER NOT NULL DEFAULT 1,
	max_parallel_chunks INTEGER NOT NULL DEFAULT 1,
	overwrite INTEGER NOT NULL DEFAULT 0, recursive INTEGER NOT NULL DEFAULT 0,
 attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
 error TEXT, correlation_id TEXT NOT NULL, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, started_at TEXT, next_attempt_at TEXT, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS job_items (
 job_id TEXT NOT NULL, ordinal INTEGER NOT NULL, relative_path TEXT NOT NULL,
 source_path TEXT NOT NULL, destination_path TEXT NOT NULL, type TEXT NOT NULL,
 size INTEGER NOT NULL DEFAULT 0, modified_at TEXT NOT NULL, checksum TEXT,
 action TEXT NOT NULL,
 state TEXT NOT NULL, bytes_completed INTEGER NOT NULL DEFAULT 0,
 attempt INTEGER NOT NULL DEFAULT 0, error TEXT, updated_at TEXT NOT NULL,
 PRIMARY KEY(job_id, relative_path), FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS job_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, type TEXT NOT NULL,
 state TEXT NOT NULL, phase TEXT NOT NULL, bytes_total INTEGER NOT NULL DEFAULT 0,
 bytes_completed INTEGER NOT NULL DEFAULT 0, bytes_per_second REAL NOT NULL DEFAULT 0,
 eta_seconds INTEGER, eta_confidence TEXT, message TEXT, correlation_id TEXT NOT NULL,
 files_total INTEGER NOT NULL DEFAULT 0, files_completed INTEGER NOT NULL DEFAULT 0,
 files_failed INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, FOREIGN KEY(job_id) REFERENCES jobs(id)
);
CREATE TABLE IF NOT EXISTS idempotency (
 key TEXT PRIMARY KEY, job_id TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(job_id) REFERENCES jobs(id)
);
CREATE TABLE IF NOT EXISTS pairing_invites (
 id TEXT PRIMARY KEY, target_node_id TEXT, transfer_mode TEXT NOT NULL,
 issuer_role TEXT NOT NULL, invitee_role TEXT NOT NULL, purpose TEXT,
 cluster_id TEXT, one_time INTEGER NOT NULL, status TEXT NOT NULL,
 secret_hash TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
 revoked_at TEXT, correlation_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pairing_requests (
 id TEXT PRIMARY KEY, invite_id TEXT NOT NULL UNIQUE, issuer_node_id TEXT NOT NULL,
 issuer_name TEXT NOT NULL, issuer_fingerprint TEXT NOT NULL,
 issuer_identity_epoch INTEGER NOT NULL DEFAULT 1,
 issuer_endpoint TEXT NOT NULL, issuer_mtls_endpoint TEXT NOT NULL DEFAULT '', transfer_mode TEXT NOT NULL,
 issuer_role TEXT NOT NULL, invitee_role TEXT NOT NULL, purpose TEXT,
 cluster_id TEXT, status TEXT NOT NULL, invite_secret_hash TEXT NOT NULL,
 expires_at TEXT NOT NULL, created_at TEXT NOT NULL, correlation_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
 node_id TEXT PRIMARY KEY, name TEXT NOT NULL, fingerprint TEXT NOT NULL,
 previous_fingerprint TEXT NOT NULL DEFAULT '',
 identity_epoch INTEGER NOT NULL DEFAULT 1,
 endpoint TEXT NOT NULL, mtls_endpoint TEXT NOT NULL DEFAULT '', transfer_mode TEXT NOT NULL, local_role TEXT NOT NULL,
 remote_role TEXT NOT NULL, cluster_id TEXT, state TEXT NOT NULL, trusted_at TEXT NOT NULL,
 last_seen_at TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0, correlation_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operational_token_state (
 id INTEGER PRIMARY KEY CHECK(id=1), staged_hash TEXT NOT NULL DEFAULT '',
 active_hash TEXT NOT NULL DEFAULT '', env_token_disabled INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL, correlation_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS transfer_grants (
 id TEXT PRIMARY KEY, peer_node_id TEXT NOT NULL, mount_id TEXT NOT NULL,
 path TEXT NOT NULL, direction TEXT NOT NULL, can_read INTEGER NOT NULL,
 can_write INTEGER NOT NULL, can_delete INTEGER NOT NULL, can_rename INTEGER NOT NULL,
 conflict_policies TEXT NOT NULL, visible_to_peer INTEGER NOT NULL,
 enabled INTEGER NOT NULL, correlation_id TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(peer_node_id,mount_id,path,direction),
 FOREIGN KEY(peer_node_id) REFERENCES peers(node_id) ON DELETE RESTRICT,
 FOREIGN KEY(mount_id) REFERENCES mounts(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS transfer_grant_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL, action TEXT NOT NULL,
 snapshot TEXT NOT NULL, correlation_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_job_events_job_id ON job_events(job_id, id);
CREATE INDEX IF NOT EXISTS idx_job_items_job_state ON job_items(job_id, state, ordinal);
CREATE INDEX IF NOT EXISTS idx_pairing_invites_created ON pairing_invites(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pairing_requests_created ON pairing_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfer_grants_peer ON transfer_grants(peer_node_id,mount_id);
`)
	if err != nil {
		return err
	}
	// Keep databases created by earlier development builds forward-compatible.
	columns := []struct {
		name        string
		declaration string
	}{
		{"overwrite", "INTEGER NOT NULL DEFAULT 0"},
		{"recursive", "INTEGER NOT NULL DEFAULT 0"},
		{"bytes_per_second", "REAL NOT NULL DEFAULT 0"},
		{"eta_seconds", "INTEGER"},
		{"eta_confidence", "TEXT"},
		{"files_total", "INTEGER NOT NULL DEFAULT 0"},
		{"files_completed", "INTEGER NOT NULL DEFAULT 0"},
		{"files_failed", "INTEGER NOT NULL DEFAULT 0"},
		{"conflict_policy", "TEXT"},
		{"source_change_policy", "TEXT NOT NULL DEFAULT 'fail'"},
		{"verify_checksum", "INTEGER NOT NULL DEFAULT 0"},
		{"bandwidth_limit", "INTEGER NOT NULL DEFAULT 0"},
		{"max_parallel_files", "INTEGER NOT NULL DEFAULT 1"},
		{"max_parallel_chunks", "INTEGER NOT NULL DEFAULT 1"},
		{"attempt", "INTEGER NOT NULL DEFAULT 0"},
		{"max_attempts", "INTEGER NOT NULL DEFAULT 3"},
		{"started_at", "TEXT"},
		{"next_attempt_at", "TEXT"},
		{"peer_node_id", "TEXT"},
		{"source_grant_id", "TEXT"},
		{"destination_grant_id", "TEXT"},
		{"source_etag", "TEXT"},
	}
	for _, column := range columns {
		exists, err := s.columnExists("jobs", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec("ALTER TABLE jobs ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	_, err = s.db.Exec(`
CREATE TABLE IF NOT EXISTS job_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, type TEXT NOT NULL,
 state TEXT NOT NULL, phase TEXT NOT NULL, bytes_total INTEGER NOT NULL DEFAULT 0,
 bytes_completed INTEGER NOT NULL DEFAULT 0, bytes_per_second REAL NOT NULL DEFAULT 0,
 eta_seconds INTEGER, eta_confidence TEXT, message TEXT, correlation_id TEXT NOT NULL,
 files_total INTEGER NOT NULL DEFAULT 0, files_completed INTEGER NOT NULL DEFAULT 0,
 files_failed INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, FOREIGN KEY(job_id) REFERENCES jobs(id)
);
CREATE TABLE IF NOT EXISTS job_items (
 job_id TEXT NOT NULL, ordinal INTEGER NOT NULL, relative_path TEXT NOT NULL,
 source_path TEXT NOT NULL, destination_path TEXT NOT NULL, type TEXT NOT NULL,
 size INTEGER NOT NULL DEFAULT 0, modified_at TEXT NOT NULL, checksum TEXT,
 action TEXT NOT NULL,
 state TEXT NOT NULL, bytes_completed INTEGER NOT NULL DEFAULT 0,
 attempt INTEGER NOT NULL DEFAULT 0, error TEXT, updated_at TEXT NOT NULL,
 PRIMARY KEY(job_id, relative_path), FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_jobs_queue ON jobs(state, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS idx_job_events_job_id ON job_events(job_id, id);
CREATE INDEX IF NOT EXISTS idx_job_items_job_state ON job_items(job_id, state, ordinal);
`)
	if err != nil {
		return err
	}
	itemColumns := []struct {
		name        string
		declaration string
	}{
		{"checksum", "TEXT"},
	}
	for _, column := range itemColumns {
		exists, err := s.columnExists("job_items", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec("ALTER TABLE job_items ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	eventColumns := []struct {
		name        string
		declaration string
	}{
		{"files_total", "INTEGER NOT NULL DEFAULT 0"},
		{"files_completed", "INTEGER NOT NULL DEFAULT 0"},
		{"files_failed", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, column := range eventColumns {
		exists, err := s.columnExists("job_events", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec("ALTER TABLE job_events ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	peerColumns := []struct {
		name        string
		declaration string
	}{
		{"cluster_id", "TEXT"},
		{"mtls_endpoint", "TEXT NOT NULL DEFAULT ''"},
		{"last_seen_at", "TEXT"},
		{"consecutive_failures", "INTEGER NOT NULL DEFAULT 0"},
		{"identity_epoch", "INTEGER NOT NULL DEFAULT 1"},
		{"previous_fingerprint", "TEXT NOT NULL DEFAULT ''"},
	}
	pairingRequestColumns := []struct {
		name        string
		declaration string
	}{
		{"issuer_mtls_endpoint", "TEXT NOT NULL DEFAULT ''"},
		{"issuer_identity_epoch", "INTEGER NOT NULL DEFAULT 1"},
	}
	for _, column := range pairingRequestColumns {
		exists, err := s.columnExists("pairing_requests", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec("ALTER TABLE pairing_requests ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	for _, column := range peerColumns {
		exists, err := s.columnExists("peers", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec("ALTER TABLE peers ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	_, err = s.db.Exec(`
CREATE TABLE IF NOT EXISTS transfer_grants (
 id TEXT PRIMARY KEY, peer_node_id TEXT NOT NULL, mount_id TEXT NOT NULL,
 path TEXT NOT NULL, direction TEXT NOT NULL, can_read INTEGER NOT NULL,
 can_write INTEGER NOT NULL, can_delete INTEGER NOT NULL, can_rename INTEGER NOT NULL,
 conflict_policies TEXT NOT NULL, visible_to_peer INTEGER NOT NULL,
 enabled INTEGER NOT NULL, correlation_id TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(peer_node_id,mount_id,path,direction),
 FOREIGN KEY(peer_node_id) REFERENCES peers(node_id) ON DELETE RESTRICT,
 FOREIGN KEY(mount_id) REFERENCES mounts(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS transfer_grant_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL, action TEXT NOT NULL,
 snapshot TEXT NOT NULL, correlation_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfer_grants_peer ON transfer_grants(peer_node_id,mount_id);
`)
	return err
}

func (s *Store) GetOperationalTokenState(ctx context.Context) (entities.OperationalTokenState, error) {
	var state entities.OperationalTokenState
	var disabled int
	var updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT staged_hash,active_hash,env_token_disabled,updated_at,correlation_id
FROM operational_token_state WHERE id=1`).
		Scan(&state.StagedHash, &state.ActiveHash, &disabled, &updatedAt, &state.CorrelationID)
	if errors.Is(err, sql.ErrNoRows) {
		return state, ErrNotFound
	}
	if err != nil {
		return state, err
	}
	state.EnvTokenDisabled = disabled != 0
	state.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return state, err
}

func (s *Store) StageOperationalToken(ctx context.Context, tokenHash, correlationID string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO operational_token_state(
id,staged_hash,active_hash,env_token_disabled,updated_at,correlation_id)
VALUES(1,?,'',0,?,?)
ON CONFLICT(id) DO UPDATE SET staged_hash=excluded.staged_hash,
updated_at=excluded.updated_at,correlation_id=excluded.correlation_id`,
		tokenHash, now.Format(time.RFC3339Nano), correlationID)
	return err
}

func (s *Store) CommitOperationalToken(ctx context.Context, tokenHash, correlationID string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE operational_token_state
SET active_hash=staged_hash,staged_hash='',env_token_disabled=1,updated_at=?,correlation_id=?
WHERE id=1 AND staged_hash=?`,
		now.Format(time.RFC3339Nano), correlationID, tokenHash)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

// RecoverOperationalToken atomically replaces every accepted HTTP operational
// credential. It is intended only for the offline emergency-recovery command.
func (s *Store) RecoverOperationalToken(ctx context.Context, tokenHash, correlationID string, now time.Time) error {
	if tokenHash == "" || correlationID == "" {
		return errors.New("token hash and correlation ID are required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO operational_token_state(
id,staged_hash,active_hash,env_token_disabled,updated_at,correlation_id)
VALUES(1,'',?,1,?,?)
ON CONFLICT(id) DO UPDATE SET staged_hash='',active_hash=excluded.active_hash,
env_token_disabled=1,updated_at=excluded.updated_at,correlation_id=excluded.correlation_id`,
		tokenHash, now.UTC().Format(time.RFC3339Nano), correlationID)
	return err
}

func (s *Store) columnExists(table, column string) (bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) ListMounts(ctx context.Context) ([]entities.Mount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,local_path,target_type,mode,published,enabled,created_at,updated_at FROM mounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []entities.Mount
	for rows.Next() {
		m, err := scanMount(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

func (s *Store) GetMount(ctx context.Context, id string) (entities.Mount, error) {
	m, err := scanMount(s.db.QueryRowContext(ctx, `SELECT id,name,local_path,target_type,mode,published,enabled,created_at,updated_at FROM mounts WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return entities.Mount{}, ErrNotFound
	}
	return m, err
}

type scanner interface{ Scan(...any) error }

func scanMount(row scanner) (entities.Mount, error) {
	var m entities.Mount
	var published, enabled int
	var created, updated string
	err := row.Scan(&m.ID, &m.Name, &m.LocalPath, &m.TargetType, &m.Mode, &published, &enabled, &created, &updated)
	if err != nil {
		return m, err
	}
	m.Published, m.Enabled = published != 0, enabled != 0
	m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	m.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return m, nil
}

func (s *Store) UpsertMount(ctx context.Context, m entities.Mount) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO mounts(id,name,local_path,target_type,mode,published,enabled,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,local_path=excluded.local_path,target_type=excluded.target_type,
mode=excluded.mode,published=excluded.published,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		m.ID, m.Name, m.LocalPath, m.TargetType, m.Mode, m.Published, m.Enabled, m.CreatedAt.Format(time.RFC3339Nano), m.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) DeleteMount(ctx context.Context, id string) error {
	var grants int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM transfer_grants WHERE mount_id=?`, id).Scan(&grants); err != nil {
		return err
	}
	if grants > 0 {
		return ErrInUse
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM mounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateJob(ctx context.Context, j entities.Job, key string) (entities.Job, bool, error) {
	return s.createJob(ctx, j, nil, key)
}

func (s *Store) CreateJobWithItems(ctx context.Context, j entities.Job, items []entities.JobItem, key string) (entities.Job, bool, error) {
	return s.createJob(ctx, j, items, key)
}

func (s *Store) createJob(ctx context.Context, j entities.Job, items []entities.JobItem, key string) (entities.Job, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return j, false, err
	}
	defer tx.Rollback()
	if key != "" {
		var existing string
		err := tx.QueryRowContext(ctx, `SELECT job_id FROM idempotency WHERE key=?`, key).Scan(&existing)
		if err == nil {
			if err := tx.Commit(); err != nil {
				return j, false, err
			}
			found, err := s.GetJob(ctx, existing)
			return found, true, err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return j, false, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,type,state,phase,mount_id,peer_node_id,source_grant_id,destination_grant_id,source_etag,source_path,destination_path,bytes_total,bytes_completed,bytes_per_second,eta_seconds,eta_confidence,files_total,files_completed,files_failed,conflict_policy,source_change_policy,verify_checksum,bandwidth_limit,max_parallel_files,max_parallel_chunks,overwrite,recursive,attempt,max_attempts,error,correlation_id,created_at,updated_at,started_at,next_attempt_at,completed_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, jobArgs(j)...)
	if err != nil {
		return j, false, err
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_items(
job_id,ordinal,relative_path,source_path,destination_path,type,size,modified_at,checksum,
action,state,bytes_completed,attempt,error,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			j.ID, item.Ordinal, item.RelativePath, item.SourcePath, item.DestinationPath,
			item.Type, item.Size, item.ModifiedAt.Format(time.RFC3339Nano), item.Checksum, item.Action,
			item.State, item.BytesCompleted, item.Attempt, item.Error,
			item.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
			return j, false, err
		}
	}
	if key != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency(key,job_id,created_at) VALUES(?,?,?)`, key, j.ID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return j, false, err
		}
	}
	return j, false, tx.Commit()
}

func (s *Store) UpdateJob(ctx context.Context, j entities.Job) error {
	result, err := s.db.ExecContext(ctx, `UPDATE jobs SET state=?,phase=?,source_etag=?,bytes_total=?,bytes_completed=?,bytes_per_second=?,eta_seconds=?,eta_confidence=?,files_total=?,files_completed=?,files_failed=?,conflict_policy=?,source_change_policy=?,verify_checksum=?,bandwidth_limit=?,max_parallel_files=?,max_parallel_chunks=?,overwrite=?,recursive=?,attempt=?,max_attempts=?,error=?,updated_at=?,started_at=?,next_attempt_at=?,completed_at=? WHERE id=?`,
		j.State, j.Phase, j.SourceETag, j.BytesTotal, j.BytesCompleted, j.BytesPerSecond, nullableInt64(j.ETASeconds), j.ETAConfidence,
		j.FilesTotal, j.FilesCompleted, j.FilesFailed, j.ConflictPolicy,
		j.SourceChangePolicy, j.VerifyChecksum, j.BandwidthLimit, j.MaxParallelFiles, j.MaxParallelChunks,
		j.Overwrite, j.Recursive, j.Attempt, j.MaxAttempts,
		j.Error, j.UpdatedAt.Format(time.RFC3339Nano), nullableTime(j.StartedAt), nullableTime(j.NextAttemptAt), nullableTime(j.CompletedAt), j.ID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListJobs(ctx context.Context, limit int) ([]entities.Job, error) {
	rows, err := s.db.QueryContext(ctx, jobSelect+` ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []entities.Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, j)
	}
	return result, rows.Err()
}

func (s *Store) ListJobsByPeer(ctx context.Context, peerNodeID string) ([]entities.Job, error) {
	rows, err := s.db.QueryContext(ctx, jobSelect+` WHERE peer_node_id=? ORDER BY created_at DESC`, peerNodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []entities.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Store) GetJob(ctx context.Context, id string) (entities.Job, error) {
	j, err := scanJob(s.db.QueryRowContext(ctx, jobSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return j, ErrNotFound
	}
	return j, err
}

func jobArgs(j entities.Job) []any {
	return []any{j.ID, j.Type, j.State, j.Phase, j.MountID, j.PeerNodeID, j.SourceGrantID,
		j.DestinationGrantID, j.SourceETag, j.SourcePath, j.Destination,
		j.BytesTotal, j.BytesCompleted, j.BytesPerSecond, nullableInt64(j.ETASeconds), j.ETAConfidence,
		j.FilesTotal, j.FilesCompleted, j.FilesFailed, j.ConflictPolicy,
		j.SourceChangePolicy, j.VerifyChecksum, j.BandwidthLimit, j.MaxParallelFiles, j.MaxParallelChunks,
		j.Overwrite, j.Recursive, j.Attempt, j.MaxAttempts,
		j.Error, j.CorrelationID, j.CreatedAt.Format(time.RFC3339Nano), j.UpdatedAt.Format(time.RFC3339Nano),
		nullableTime(j.StartedAt), nullableTime(j.NextAttemptAt), nullableTime(j.CompletedAt)}
}

const jobSelect = `SELECT id,type,state,phase,mount_id,peer_node_id,source_grant_id,
destination_grant_id,source_etag,source_path,destination_path,
bytes_total,bytes_completed,bytes_per_second,eta_seconds,eta_confidence,
files_total,files_completed,files_failed,conflict_policy,source_change_policy,verify_checksum,bandwidth_limit,max_parallel_files,max_parallel_chunks,
overwrite,recursive,attempt,max_attempts,error,correlation_id,
created_at,updated_at,started_at,next_attempt_at,completed_at FROM jobs`

func scanJob(row scanner) (entities.Job, error) {
	var j entities.Job
	var created, updated string
	var overwrite, recursive, verifyChecksum int
	var eta sql.NullInt64
	var started, nextAttempt, completed sql.NullString
	err := row.Scan(&j.ID, &j.Type, &j.State, &j.Phase, &j.MountID, &j.PeerNodeID,
		&j.SourceGrantID, &j.DestinationGrantID, &j.SourceETag, &j.SourcePath,
		&j.Destination, &j.BytesTotal, &j.BytesCompleted, &j.BytesPerSecond, &eta, &j.ETAConfidence,
		&j.FilesTotal, &j.FilesCompleted, &j.FilesFailed, &j.ConflictPolicy,
		&j.SourceChangePolicy, &verifyChecksum, &j.BandwidthLimit, &j.MaxParallelFiles, &j.MaxParallelChunks,
		&overwrite, &recursive,
		&j.Attempt, &j.MaxAttempts, &j.Error, &j.CorrelationID, &created, &updated,
		&started, &nextAttempt, &completed)
	if err != nil {
		return j, err
	}
	j.Overwrite, j.Recursive, j.VerifyChecksum = overwrite != 0, recursive != 0, verifyChecksum != 0
	if eta.Valid {
		j.ETASeconds = &eta.Int64
	}
	j.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	j.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	var parseErr error
	if j.StartedAt, parseErr = parseNullableTime(started); parseErr != nil {
		return j, parseErr
	}
	if j.NextAttemptAt, parseErr = parseNullableTime(nextAttempt); parseErr != nil {
		return j, parseErr
	}
	if j.CompletedAt, parseErr = parseNullableTime(completed); parseErr != nil {
		return j, parseErr
	}
	return j, nil
}

func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil, fmt.Errorf("parse job timestamp: %w", err)
	}
	return &parsed, nil
}

func (s *Store) ClaimNextJob(ctx context.Context, now time.Time) (entities.Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return entities.Job{}, err
	}
	defer tx.Rollback()
	j, err := scanJob(tx.QueryRowContext(ctx, jobSelect+
		` WHERE state='queued' AND (next_attempt_at IS NULL OR next_attempt_at<=?) ORDER BY created_at LIMIT 1`,
		now.Format(time.RFC3339Nano)))
	if errors.Is(err, sql.ErrNoRows) {
		return entities.Job{}, ErrNotFound
	}
	if err != nil {
		return entities.Job{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET state='running',phase='validation',
attempt=attempt+1,started_at=COALESCE(started_at,?),updated_at=?,next_attempt_at=NULL
WHERE id=? AND state='queued'`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), j.ID)
	if err != nil {
		return entities.Job{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return entities.Job{}, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return entities.Job{}, err
	}
	j.State, j.Phase, j.Attempt, j.NextAttemptAt = "running", "validation", j.Attempt+1, nil
	j.UpdatedAt = now
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
	return j, nil
}

func (s *Store) RecoverRunningJobs(ctx context.Context, now time.Time) ([]entities.Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, jobSelect+` WHERE state IN ('running','pause_requested','cancel_requested')`)
	if err != nil {
		return nil, err
	}
	var recovered []entities.Job
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		recovered = append(recovered, job)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs
SET state='waiting_validation',phase='waiting_validation',error='node stopped before the operation completed; explicit validation is required',updated_at=?
WHERE state IN ('running','pause_requested','cancel_requested')`, now.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	for i := range recovered {
		recovered[i].State, recovered[i].Phase = "waiting_validation", "waiting_validation"
		recovered[i].Error, recovered[i].UpdatedAt = "node stopped before the operation completed; explicit validation is required", now
		recovered[i].ETASeconds, recovered[i].ETAConfidence = nil, ""
	}
	return recovered, nil
}

func (s *Store) WakeWaitingPeerJobs(ctx context.Context, peerNodeID string, now time.Time) ([]entities.Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, jobSelect+` WHERE state='waiting_peer' AND peer_node_id=? ORDER BY created_at`, peerNodeID)
	if err != nil {
		return nil, err
	}
	var found []entities.Job
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		found = append(found, job)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state='queued',phase='validation',error='',next_attempt_at=NULL,updated_at=?
WHERE state='waiting_peer' AND peer_node_id=?`, now.Format(time.RFC3339Nano), peerNodeID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	for index := range found {
		found[index].State, found[index].Phase, found[index].Error = "queued", "validation", ""
		found[index].NextAttemptAt, found[index].UpdatedAt = nil, now
	}
	return found, nil
}

func (s *Store) WakeWaitingMountJobs(ctx context.Context, mountID string, now time.Time) ([]entities.Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, jobSelect+` WHERE state='waiting_mount' AND mount_id=? ORDER BY created_at`, mountID)
	if err != nil {
		return nil, err
	}
	var found []entities.Job
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		found = append(found, job)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state='queued',phase='validation',error='',next_attempt_at=NULL,updated_at=?
WHERE state='waiting_mount' AND mount_id=?`, now.Format(time.RFC3339Nano), mountID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	for index := range found {
		found[index].State, found[index].Phase, found[index].Error = "queued", "validation", ""
		found[index].NextAttemptAt, found[index].UpdatedAt = nil, now
	}
	return found, nil
}

func (s *Store) RecordJobEvent(ctx context.Context, event entities.JobEvent) (entities.JobEvent, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO job_events(
job_id,type,state,phase,bytes_total,bytes_completed,bytes_per_second,eta_seconds,
eta_confidence,message,correlation_id,files_total,files_completed,files_failed,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		event.JobID, event.Type, event.State, event.Phase, event.BytesTotal,
		event.BytesCompleted, event.BytesPerSecond, nullableInt64(event.ETASeconds),
		event.ETAConfidence, event.Message, event.CorrelationID,
		event.FilesTotal, event.FilesCompleted, event.FilesFailed,
		event.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return event, err
	}
	event.ID, err = result.LastInsertId()
	return event, err
}

func (s *Store) ListJobEvents(ctx context.Context, after int64, jobID string, limit int) ([]entities.JobEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id,job_id,type,state,phase,bytes_total,bytes_completed,bytes_per_second,
eta_seconds,eta_confidence,message,correlation_id,files_total,files_completed,files_failed,
created_at FROM job_events WHERE id>?`
	args := []any{after}
	if jobID != "" {
		query += ` AND job_id=?`
		args = append(args, jobID)
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []entities.JobEvent
	for rows.Next() {
		var event entities.JobEvent
		var eta sql.NullInt64
		var created string
		if err := rows.Scan(&event.ID, &event.JobID, &event.Type, &event.State,
			&event.Phase, &event.BytesTotal, &event.BytesCompleted, &event.BytesPerSecond,
			&eta, &event.ETAConfidence, &event.Message, &event.CorrelationID,
			&event.FilesTotal, &event.FilesCompleted, &event.FilesFailed, &created); err != nil {
			return nil, err
		}
		if eta.Valid {
			event.ETASeconds = &eta.Int64
		}
		event.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) ReplaceJobItems(ctx context.Context, jobID string, items []entities.JobItem) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM job_items WHERE job_id=?`, jobID); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_items(
job_id,ordinal,relative_path,source_path,destination_path,type,size,modified_at,checksum,
action,state,bytes_completed,attempt,error,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			jobID, item.Ordinal, item.RelativePath, item.SourcePath, item.DestinationPath,
			item.Type, item.Size, item.ModifiedAt.Format(time.RFC3339Nano), item.Checksum, item.Action,
			item.State, item.BytesCompleted, item.Attempt, item.Error,
			item.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListJobItems(ctx context.Context, jobID string) ([]entities.JobItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT job_id,ordinal,relative_path,source_path,
destination_path,type,size,modified_at,COALESCE(checksum,''),action,state,bytes_completed,attempt,error,updated_at
FROM job_items WHERE job_id=? ORDER BY ordinal`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []entities.JobItem
	for rows.Next() {
		item, err := scanJobItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateJobItem(ctx context.Context, item entities.JobItem) error {
	result, err := s.db.ExecContext(ctx, `UPDATE job_items SET destination_path=?,size=?,modified_at=?,checksum=?,action=?,
state=?,bytes_completed=?,attempt=?,error=?,updated_at=? WHERE job_id=? AND relative_path=?`,
		item.DestinationPath, item.Size, item.ModifiedAt.Format(time.RFC3339Nano), item.Checksum, item.Action, item.State, item.BytesCompleted, item.Attempt,
		item.Error, item.UpdatedAt.Format(time.RFC3339Nano), item.JobID, item.RelativePath)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func scanJobItem(row scanner) (entities.JobItem, error) {
	var item entities.JobItem
	var modified, updated string
	err := row.Scan(&item.JobID, &item.Ordinal, &item.RelativePath, &item.SourcePath,
		&item.DestinationPath, &item.Type, &item.Size, &modified, &item.Checksum, &item.Action,
		&item.State, &item.BytesCompleted, &item.Attempt, &item.Error, &updated)
	if err != nil {
		return item, err
	}
	item.ModifiedAt, _ = time.Parse(time.RFC3339Nano, modified)
	item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return item, nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339Nano)
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func (s *Store) CreatePairingInvite(ctx context.Context, invite entities.PairingInvite, secretHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pairing_invites(
id,target_node_id,transfer_mode,issuer_role,invitee_role,purpose,cluster_id,one_time,status,
secret_hash,expires_at,created_at,revoked_at,correlation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		invite.ID, invite.TargetNodeID, invite.TransferMode, invite.IssuerRole, invite.InviteeRole,
		invite.Purpose, invite.ClusterID, invite.OneTime, invite.Status, secretHash,
		invite.ExpiresAt.Format(time.RFC3339Nano), invite.CreatedAt.Format(time.RFC3339Nano),
		nullableTime(invite.RevokedAt), invite.CorrelationID)
	return err
}

func (s *Store) ListPairingInvites(ctx context.Context) ([]entities.PairingInvite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,target_node_id,transfer_mode,issuer_role,invitee_role,purpose,cluster_id,one_time,status,expires_at,created_at,revoked_at,correlation_id FROM pairing_invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []entities.PairingInvite
	for rows.Next() {
		invite, err := scanPairingInvite(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, invite)
	}
	return result, rows.Err()
}

func (s *Store) GetPairingInvite(ctx context.Context, id string) (entities.PairingInvite, error) {
	invite, err := scanPairingInvite(s.db.QueryRowContext(ctx, `SELECT id,target_node_id,transfer_mode,issuer_role,invitee_role,purpose,cluster_id,one_time,status,expires_at,created_at,revoked_at,correlation_id FROM pairing_invites WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return invite, ErrNotFound
	}
	return invite, err
}

func (s *Store) RevokePairingInvite(ctx context.Context, id string, revokedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE pairing_invites SET status='revoked',revoked_at=? WHERE id=? AND status='pending'`, revokedAt.Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreatePairingRequest(ctx context.Context, request entities.PairingRequest, secretHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pairing_requests(
id,invite_id,issuer_node_id,issuer_name,issuer_fingerprint,issuer_identity_epoch,issuer_endpoint,issuer_mtls_endpoint,transfer_mode,
issuer_role,invitee_role,purpose,cluster_id,status,invite_secret_hash,expires_at,created_at,correlation_id)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		request.ID, request.InviteID, request.IssuerNodeID, request.IssuerName,
		request.IssuerFingerprint, max(request.IssuerIdentityEpoch, 1),
		request.IssuerEndpoint, request.IssuerMTLSEndpoint, request.TransferMode,
		request.IssuerRole, request.InviteeRole, request.Purpose, request.ClusterID,
		request.Status, secretHash, request.ExpiresAt.Format(time.RFC3339Nano),
		request.CreatedAt.Format(time.RFC3339Nano), request.CorrelationID)
	return err
}

func (s *Store) ListPairingRequests(ctx context.Context) ([]entities.PairingRequest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,invite_id,issuer_node_id,issuer_name,issuer_fingerprint,issuer_identity_epoch,issuer_endpoint,issuer_mtls_endpoint,transfer_mode,issuer_role,invitee_role,purpose,cluster_id,status,expires_at,created_at,correlation_id FROM pairing_requests ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []entities.PairingRequest
	for rows.Next() {
		request, err := scanPairingRequest(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, request)
	}
	return result, rows.Err()
}

func (s *Store) GetPairingRequest(ctx context.Context, id string) (entities.PairingRequest, error) {
	request, err := scanPairingRequest(s.db.QueryRowContext(ctx, `SELECT id,invite_id,issuer_node_id,issuer_name,issuer_fingerprint,issuer_identity_epoch,issuer_endpoint,issuer_mtls_endpoint,transfer_mode,issuer_role,invitee_role,purpose,cluster_id,status,expires_at,created_at,correlation_id FROM pairing_requests WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return request, ErrNotFound
	}
	return request, err
}

func scanPairingInvite(row scanner) (entities.PairingInvite, error) {
	var invite entities.PairingInvite
	var oneTime int
	var expires, created string
	var revoked sql.NullString
	err := row.Scan(&invite.ID, &invite.TargetNodeID, &invite.TransferMode, &invite.IssuerRole,
		&invite.InviteeRole, &invite.Purpose, &invite.ClusterID, &oneTime, &invite.Status,
		&expires, &created, &revoked, &invite.CorrelationID)
	if err != nil {
		return invite, err
	}
	invite.OneTime = oneTime != 0
	invite.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	invite.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if revoked.Valid {
		value, _ := time.Parse(time.RFC3339Nano, revoked.String)
		invite.RevokedAt = &value
	}
	return invite, nil
}

func scanPairingRequest(row scanner) (entities.PairingRequest, error) {
	var request entities.PairingRequest
	var expires, created string
	err := row.Scan(&request.ID, &request.InviteID, &request.IssuerNodeID, &request.IssuerName,
		&request.IssuerFingerprint, &request.IssuerIdentityEpoch,
		&request.IssuerEndpoint, &request.IssuerMTLSEndpoint, &request.TransferMode,
		&request.IssuerRole, &request.InviteeRole, &request.Purpose, &request.ClusterID,
		&request.Status, &expires, &created, &request.CorrelationID)
	if err != nil {
		return request, err
	}
	request.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	request.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return request, nil
}

func (s *Store) ApprovePairingInvite(ctx context.Context, id, secretHash string, peer entities.Peer, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expectedHash, status, targetNodeID, expires string
	if err := tx.QueryRowContext(ctx, `SELECT secret_hash,status,target_node_id,expires_at FROM pairing_invites WHERE id=?`, id).
		Scan(&expectedHash, &status, &targetNodeID, &expires); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
	if status != "pending" || expectedHash != secretHash || now.After(expiresAt) || (targetNodeID != "" && targetNodeID != peer.NodeID) {
		return errors.New("invite cannot be approved")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO peers(node_id,name,fingerprint,previous_fingerprint,identity_epoch,endpoint,mtls_endpoint,transfer_mode,local_role,remote_role,cluster_id,state,trusted_at,correlation_id)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET name=excluded.name,fingerprint=excluded.fingerprint,previous_fingerprint='',identity_epoch=excluded.identity_epoch,
endpoint=excluded.endpoint,mtls_endpoint=excluded.mtls_endpoint,transfer_mode=excluded.transfer_mode,local_role=excluded.local_role,
remote_role=excluded.remote_role,cluster_id=excluded.cluster_id,state=excluded.state,trusted_at=excluded.trusted_at,correlation_id=excluded.correlation_id`,
		peer.NodeID, peer.Name, peer.Fingerprint, "", max(peer.IdentityEpoch, 1), peer.Endpoint, peer.MTLSEndpoint, peer.TransferMode, peer.LocalRole,
		peer.RemoteRole, peer.ClusterID, peer.State, peer.TrustedAt.Format(time.RFC3339Nano), peer.CorrelationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pairing_invites SET status='consumed' WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ResolvePairingRequest(ctx context.Context, id, status string, peer *entities.Peer, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current, expires string
	if err := tx.QueryRowContext(ctx, `SELECT status,expires_at FROM pairing_requests WHERE id=?`, id).Scan(&current, &expires); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
	if current != "pending_review" || now.After(expiresAt) {
		return errors.New("pairing request cannot be resolved")
	}
	if peer != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO peers(node_id,name,fingerprint,previous_fingerprint,identity_epoch,endpoint,mtls_endpoint,transfer_mode,local_role,remote_role,cluster_id,state,trusted_at,correlation_id)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET name=excluded.name,fingerprint=excluded.fingerprint,previous_fingerprint='',identity_epoch=excluded.identity_epoch,
endpoint=excluded.endpoint,mtls_endpoint=excluded.mtls_endpoint,transfer_mode=excluded.transfer_mode,local_role=excluded.local_role,
remote_role=excluded.remote_role,cluster_id=excluded.cluster_id,state=excluded.state,trusted_at=excluded.trusted_at,correlation_id=excluded.correlation_id`,
			peer.NodeID, peer.Name, peer.Fingerprint, "", max(peer.IdentityEpoch, 1), peer.Endpoint, peer.MTLSEndpoint, peer.TransferMode, peer.LocalRole,
			peer.RemoteRole, peer.ClusterID, peer.State, peer.TrustedAt.Format(time.RFC3339Nano), peer.CorrelationID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pairing_requests SET status=? WHERE id=?`, status, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListPeers(ctx context.Context) ([]entities.Peer, error) {
	rows, err := s.db.QueryContext(ctx, peerSelect+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var peers []entities.Peer
	for rows.Next() {
		var peer entities.Peer
		var trustedAt string
		var lastSeen sql.NullString
		if err := rows.Scan(&peer.NodeID, &peer.Name, &peer.Fingerprint, &peer.PreviousFingerprint,
			&peer.IdentityEpoch, &peer.Endpoint, &peer.MTLSEndpoint, &peer.TransferMode,
			&peer.LocalRole, &peer.RemoteRole, &peer.ClusterID, &peer.State, &trustedAt, &lastSeen,
			&peer.ConsecutiveFailures, &peer.CorrelationID); err != nil {
			return nil, err
		}
		peer.TrustedAt, _ = time.Parse(time.RFC3339Nano, trustedAt)
		if lastSeen.Valid {
			value, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
			peer.LastSeenAt = &value
		}
		peers = append(peers, peer)
	}
	return peers, rows.Err()
}

func (s *Store) GetPeer(ctx context.Context, nodeID string) (entities.Peer, error) {
	var peer entities.Peer
	var trustedAt string
	var lastSeen sql.NullString
	err := s.db.QueryRowContext(ctx, peerSelect+` WHERE node_id=?`, nodeID).
		Scan(&peer.NodeID, &peer.Name, &peer.Fingerprint, &peer.PreviousFingerprint,
			&peer.IdentityEpoch, &peer.Endpoint, &peer.MTLSEndpoint, &peer.TransferMode,
			&peer.LocalRole, &peer.RemoteRole, &peer.ClusterID, &peer.State, &trustedAt, &lastSeen,
			&peer.ConsecutiveFailures, &peer.CorrelationID)
	if errors.Is(err, sql.ErrNoRows) {
		return peer, ErrNotFound
	}
	peer.TrustedAt, _ = time.Parse(time.RFC3339Nano, trustedAt)
	if lastSeen.Valid {
		value, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
		peer.LastSeenAt = &value
	}
	return peer, err
}

const peerSelect = `SELECT node_id,name,fingerprint,previous_fingerprint,identity_epoch,endpoint,mtls_endpoint,transfer_mode,
local_role,remote_role,COALESCE(cluster_id,''),state,trusted_at,last_seen_at,
consecutive_failures,correlation_id FROM peers`

func (s *Store) UpdatePeerHealth(ctx context.Context, nodeID, state string, lastSeenAt *time.Time, failures int) error {
	result, err := s.db.ExecContext(ctx, `UPDATE peers SET state=?,last_seen_at=?,consecutive_failures=?
WHERE node_id=? AND state!='revoked'`,
		state, nullableTime(lastSeenAt), failures, nodeID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdatePeerEndpoints(ctx context.Context, nodeID, endpoint, mtlsEndpoint, correlationID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE peers
SET endpoint=?,mtls_endpoint=?,state='unknown',last_seen_at=NULL,
consecutive_failures=0,correlation_id=?
WHERE node_id=? AND state!='revoked'`,
		endpoint, mtlsEndpoint, correlationID, nodeID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RecoverPeerIdentity(ctx context.Context, nodeID, fingerprint, correlationID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE peers
SET fingerprint=?,previous_fingerprint='',identity_epoch=identity_epoch+1,state='unknown',last_seen_at=NULL,consecutive_failures=0,correlation_id=?
WHERE node_id=? AND state='identity_changed'`,
		fingerprint, correlationID, nodeID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ApplyPeerIdentityHandover(ctx context.Context, nodeID string, previousEpoch int,
	previousFingerprint string, nextEpoch int, nextFingerprint, correlationID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE peers
SET previous_fingerprint=fingerprint,fingerprint=?,identity_epoch=?,state='unknown',last_seen_at=NULL,
consecutive_failures=0,correlation_id=?
WHERE node_id=? AND identity_epoch=? AND fingerprint=? AND state!='revoked'`,
		nextFingerprint, nextEpoch, correlationID, nodeID, previousEpoch, previousFingerprint)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ConfirmPeerIdentityHandover(ctx context.Context, nodeID string, epoch int,
	fingerprint string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE peers SET previous_fingerprint=''
WHERE node_id=? AND identity_epoch=? AND fingerprint=? AND previous_fingerprint!='' AND state!='revoked'`,
		nodeID, epoch, fingerprint)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokePeer(ctx context.Context, nodeID, correlationID string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE peers
SET state='revoked',consecutive_failures=0,correlation_id=? WHERE node_id=?`,
		correlationID, nodeID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	rows, err := tx.QueryContext(ctx, grantSelect+` WHERE peer_node_id=? AND enabled=1`, nodeID)
	if err != nil {
		return err
	}
	var grants []entities.TransferPathGrant
	for rows.Next() {
		grant, scanErr := scanTransferGrant(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		grants = append(grants, grant)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, grant := range grants {
		grant.Enabled, grant.CorrelationID, grant.UpdatedAt = false, correlationID, now
		if _, err := tx.ExecContext(ctx, `UPDATE transfer_grants
SET enabled=0,correlation_id=?,updated_at=? WHERE id=?`,
			correlationID, now.Format(time.RFC3339Nano), grant.ID); err != nil {
			return err
		}
		if err := recordGrantEvent(ctx, tx, grant, "peer_revoked"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CreateTransferGrant(ctx context.Context, grant entities.TransferPathGrant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	policies, _ := json.Marshal(grant.ConflictPolicies)
	_, err = tx.ExecContext(ctx, `INSERT INTO transfer_grants(
id,peer_node_id,mount_id,path,direction,can_read,can_write,can_delete,can_rename,
conflict_policies,visible_to_peer,enabled,correlation_id,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		grant.ID, grant.PeerNodeID, grant.MountID, grant.Path, grant.Direction,
		grant.Permissions.Read, grant.Permissions.Write, grant.Permissions.Delete,
		grant.Permissions.Rename, string(policies), grant.VisibleToPeer, grant.Enabled,
		grant.CorrelationID, grant.CreatedAt.Format(time.RFC3339Nano), grant.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if err := recordGrantEvent(ctx, tx, grant, "created"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateTransferGrant(ctx context.Context, grant entities.TransferPathGrant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	policies, _ := json.Marshal(grant.ConflictPolicies)
	result, err := tx.ExecContext(ctx, `UPDATE transfer_grants SET peer_node_id=?,mount_id=?,
path=?,direction=?,can_read=?,can_write=?,can_delete=?,can_rename=?,conflict_policies=?,
visible_to_peer=?,enabled=?,correlation_id=?,updated_at=? WHERE id=?`,
		grant.PeerNodeID, grant.MountID, grant.Path, grant.Direction,
		grant.Permissions.Read, grant.Permissions.Write, grant.Permissions.Delete,
		grant.Permissions.Rename, string(policies), grant.VisibleToPeer, grant.Enabled,
		grant.CorrelationID, grant.UpdatedAt.Format(time.RFC3339Nano), grant.ID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	if err := recordGrantEvent(ctx, tx, grant, "updated"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListTransferGrants(ctx context.Context) ([]entities.TransferPathGrant, error) {
	rows, err := s.db.QueryContext(ctx, grantSelect+` ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []entities.TransferPathGrant
	for rows.Next() {
		grant, err := scanTransferGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (s *Store) GetTransferGrant(ctx context.Context, id string) (entities.TransferPathGrant, error) {
	grant, err := scanTransferGrant(s.db.QueryRowContext(ctx, grantSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return grant, ErrNotFound
	}
	return grant, err
}

func (s *Store) DeleteTransferGrant(ctx context.Context, id, correlationID string, now time.Time) error {
	grant, err := s.GetTransferGrant(ctx, id)
	if err != nil {
		return err
	}
	grant.CorrelationID, grant.UpdatedAt = correlationID, now
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM transfer_grants WHERE id=?`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	if err := recordGrantEvent(ctx, tx, grant, "deleted"); err != nil {
		return err
	}
	return tx.Commit()
}

const grantSelect = `SELECT id,peer_node_id,mount_id,path,direction,can_read,can_write,
can_delete,can_rename,conflict_policies,visible_to_peer,enabled,correlation_id,
created_at,updated_at FROM transfer_grants`

func scanTransferGrant(row scanner) (entities.TransferPathGrant, error) {
	var grant entities.TransferPathGrant
	var read, write, deletePermission, rename, visible, enabled int
	var policies, created, updated string
	err := row.Scan(&grant.ID, &grant.PeerNodeID, &grant.MountID, &grant.Path,
		&grant.Direction, &read, &write, &deletePermission, &rename, &policies,
		&visible, &enabled, &grant.CorrelationID, &created, &updated)
	if err != nil {
		return grant, err
	}
	grant.Permissions = entities.GrantPermissions{
		Read: read != 0, Write: write != 0, Delete: deletePermission != 0, Rename: rename != 0,
	}
	grant.VisibleToPeer, grant.Enabled = visible != 0, enabled != 0
	_ = json.Unmarshal([]byte(policies), &grant.ConflictPolicies)
	grant.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	grant.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return grant, nil
}

func recordGrantEvent(ctx context.Context, tx *sql.Tx, grant entities.TransferPathGrant, action string) error {
	snapshot, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO transfer_grant_events(
grant_id,action,snapshot,correlation_id,created_at) VALUES(?,?,?,?,?)`,
		grant.ID, action, string(snapshot), grant.CorrelationID, grant.UpdatedAt.Format(time.RFC3339Nano))
	return err
}
