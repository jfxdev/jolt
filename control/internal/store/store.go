package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/database"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrLastAdmin = errors.New("at least one enabled administrator is required")
)

const supportedSecurityVersion = 10

type User struct {
	ID           string    `json:"user_id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ServiceAccount struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"service_account_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AccessGroup defines the nodes and policies that can be shared by API keys.
// A group is intentionally evaluated in addition to the key's own policies so
// existing service accounts remain backwards compatible while groups provide a
// safe, reusable boundary for file and transfer automation.
type AccessGroup struct {
	ID          string    `json:"group_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	NodeIDs     []string  `json:"node_ids"`
	PolicyIDs   []string  `json:"policy_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ServiceAccountToken struct {
	AgentLimits      *AgentLimits `json:"agent_limits,omitempty"`
	ID               string       `json:"token_id"`
	ServiceAccountID string       `json:"service_account_id"`
	Name             string       `json:"name"`
	TokenHash        string       `json:"-"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time   `json:"last_used_at,omitempty"`
	RevokedAt        *time.Time   `json:"revoked_at,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
}

// AgentLimits are per-credential server-enforced ceilings.
type AgentLimits struct {
	RequestsPerMinute int       `json:"requests_per_minute"`
	Burst             int       `json:"burst"`
	MaxConcurrent     int       `json:"max_concurrent"`
	MaxResponseBytes  int64     `json:"max_response_bytes"`
	DailyBytes        int64     `json:"daily_bytes"`
	AllowedCIDRs      []string  `json:"allowed_cidrs,omitempty"`
	ReadMediaTypes    []string  `json:"read_media_types,omitempty"`
	Capabilities      *[]string `json:"capabilities,omitempty"`
	// RequestDeletes lets the credential ask a person to delete a file. It
	// still cannot delete: only a rule that needs approval can be asked, and a
	// person decides.
	RequestDeletes bool `json:"request_deletes,omitempty"`
}

func DefaultAgentLimits() AgentLimits {
	return AgentLimits{RequestsPerMinute: 60, Burst: 10, MaxConcurrent: 2, MaxResponseBytes: 16 << 20, DailyBytes: 1 << 30}
}

type Policy struct {
	ID          string      `json:"policy_id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rules       []rbac.Rule `json:"rules"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type Role struct {
	ID          string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	PolicyIDs   []string  `json:"policy_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type NodeConfiguration struct {
	Source        string `json:"source"`
	ApplyMode     string `json:"apply_mode"`
	MountsMutable bool   `json:"mounts_mutable"`
	GrantsMutable bool   `json:"grants_mutable"`
}
type Node struct {
	Configuration  *NodeConfiguration `json:"configuration,omitempty"`
	ID             string             `json:"node_id"`
	Name           string             `json:"name"`
	Endpoint       string             `json:"endpoint"`
	TokenEncrypted string             `json:"-"`
	State          string             `json:"state"`
	LastSeenAt     *time.Time         `json:"last_seen_at,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

type Connection struct {
	RequestID            string    `json:"request_id"`
	InviteID             string    `json:"invite_id"`
	IssuerNodeID         string    `json:"issuer_node_id"`
	TargetNodeID         string    `json:"target_node_id"`
	InviteTokenEncrypted string    `json:"-"`
	IssuerFingerprint    string    `json:"issuer_fingerprint"`
	Status               string    `json:"status"`
	ExpiresAt            time.Time `json:"expires_at"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type AuditEvent struct {
	ChainData     string         `json:"chain_data,omitempty"`
	ChainHash     string         `json:"chain_hash,omitempty"`
	SourceIP      string         `json:"source_ip,omitempty"`
	Detail        map[string]any `json:"detail,omitempty"`
	ID            int64          `json:"event_id"`
	ActorID       string         `json:"actor_id"`
	ActorType     string         `json:"actor_type"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Result        string         `json:"result"`
	CorrelationID string         `json:"correlation_id"`
	PolicyIDs     []string       `json:"policy_ids"`
	EvaluatedPath string         `json:"evaluated_path,omitempty"`
	Capability    string         `json:"capability,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

type AuditQuery struct {
	AfterID       int64
	Ascending     bool
	BeforeID      int64
	Limit         int
	ActorType     string
	Action        string
	Result        string
	CorrelationID string
}

type AdminRecoveryResult struct {
	User            User `json:"user"`
	Created         bool `json:"created"`
	RevokedSessions int  `json:"revoked_sessions"`
}

type Store struct{ db *sql.DB }

func Open(path string, encryptionKey []byte) (*Store, error) {
	database, err := database.Open(path, encryptionKey, false)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		database.Close()
		return nil, err
	}
	s := &Store{db: database}
	if err := s.checkSecurityVersion(); err != nil {
		database.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		database.Close()
		return nil, err
	}
	if err := recoverPendingOperations(database); err != nil {
		database.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ready(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS service_accounts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
	 enabled INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_groups (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
 enabled INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_group_nodes (
 group_id TEXT NOT NULL, node_id TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(group_id,node_id),
 FOREIGN KEY(group_id) REFERENCES access_groups(id) ON DELETE CASCADE,
 FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS access_group_policies (
 group_id TEXT NOT NULL, policy_id TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(group_id,policy_id),
 FOREIGN KEY(group_id) REFERENCES access_groups(id) ON DELETE CASCADE,
 FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS service_account_groups (
 service_account_id TEXT NOT NULL, group_id TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(service_account_id,group_id),
 FOREIGN KEY(service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(group_id) REFERENCES access_groups(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS service_account_tokens (
 id TEXT PRIMARY KEY, service_account_id TEXT NOT NULL, name TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE, expires_at TEXT, last_used_at TEXT, revoked_at TEXT,
 created_at TEXT NOT NULL,
 FOREIGN KEY(service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS agent_usage (
 token_id TEXT NOT NULL, day TEXT NOT NULL, charged_bytes INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(token_id,day), FOREIGN KEY(token_id) REFERENCES service_account_tokens(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS workload_identities (
 credential_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, issuer TEXT NOT NULL,
 subject TEXT NOT NULL, audience TEXT NOT NULL, enabled INTEGER NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(provider_id,issuer,subject,audience),
 FOREIGN KEY(credential_id) REFERENCES service_account_tokens(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS job_authorization_links (
 node_id TEXT NOT NULL, job_id TEXT NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT NOT NULL,
 credential_id TEXT NOT NULL, credential_digest TEXT NOT NULL, binding TEXT NOT NULL,
 confirmed_revision INTEGER NOT NULL DEFAULT 0, confirmed_digest TEXT NOT NULL DEFAULT '', confirmed_expiry_ns INTEGER NOT NULL DEFAULT 0,
 pending_revision INTEGER NOT NULL DEFAULT 0,
 pending_envelope TEXT NOT NULL DEFAULT '', pending_expiry_ns INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(node_id,job_id), FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS job_authorization_scopes (
 node_id TEXT NOT NULL, job_id TEXT NOT NULL, scope TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(node_id,job_id), FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS job_authorization_finished (
 node_id TEXT NOT NULL, job_id TEXT NOT NULL, finished_at TEXT NOT NULL,
 PRIMARY KEY(node_id,job_id), FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS pending_operations (
 id TEXT PRIMARY KEY, requester_type TEXT NOT NULL, requester_id TEXT NOT NULL,
 method TEXT NOT NULL, node_id TEXT NOT NULL, resource TEXT NOT NULL, raw_query TEXT NOT NULL,
 body BLOB NOT NULL, body_sha256 TEXT NOT NULL, summary TEXT NOT NULL, requirements TEXT NOT NULL,
 state TEXT NOT NULL, created_at TEXT NOT NULL, expires_at_ns INTEGER NOT NULL,
 decided_by_type TEXT NOT NULL DEFAULT '', decided_by_id TEXT NOT NULL DEFAULT '', decided_at TEXT NOT NULL DEFAULT '',
 note TEXT NOT NULL DEFAULT '', result_status INTEGER NOT NULL DEFAULT 0, result_body TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS pending_operations_state ON pending_operations(state, expires_at_ns);
CREATE TABLE IF NOT EXISTS join_tokens (
 id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL UNIQUE, node_name TEXT NOT NULL, approval TEXT NOT NULL,
 created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 used_at TEXT NOT NULL DEFAULT '', enrollment_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS enrollments (
 id TEXT PRIMARY KEY, token_id TEXT NOT NULL, state TEXT NOT NULL, node_name TEXT NOT NULL, node_id TEXT NOT NULL,
 node_fingerprint TEXT NOT NULL, api_endpoint TEXT NOT NULL, remote_addr TEXT NOT NULL, csr_pem TEXT NOT NULL, csr_hash TEXT NOT NULL,
 operational_encrypted TEXT NOT NULL, poll_hash TEXT NOT NULL, decided_by TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
 response TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS enrollments_state ON enrollments(state, expires_at);
CREATE TABLE IF NOT EXISTS managed_nodes (
 node_id TEXT PRIMARY KEY, enrolled_at TEXT NOT NULL, bundle_version INTEGER NOT NULL DEFAULT 0, cert_serial TEXT NOT NULL DEFAULT '',
 cert_not_before TEXT NOT NULL DEFAULT '', cert_not_after TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '', last_error_at TEXT NOT NULL DEFAULT '',
 FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS pki_objects (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL, serial TEXT NOT NULL DEFAULT '',
 fingerprint TEXT NOT NULL DEFAULT '', public TEXT NOT NULL, secret TEXT NOT NULL DEFAULT '',
 not_before TEXT NOT NULL, not_after TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_copy_intents (
 node_id TEXT NOT NULL, job_id TEXT NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT NOT NULL,
 credential_id TEXT NOT NULL, credential_digest TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 binding TEXT NOT NULL, request_body TEXT NOT NULL, options TEXT NOT NULL,
 envelope TEXT NOT NULL, expiry_ns INTEGER NOT NULL, accepted INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(node_id,job_id), UNIQUE(node_id,actor_type,actor_id,idempotency_key),
 FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS policies (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id TEXT NOT NULL, path TEXT NOT NULL,
 capabilities TEXT NOT NULL, position INTEGER NOT NULL,
 FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS policy_assignments (
 policy_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
 created_at TEXT NOT NULL, PRIMARY KEY(policy_id,subject_type,subject_id),
 FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS temporary_policy_assignments (
 policy_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL, expires_at_ns INTEGER NOT NULL,
 PRIMARY KEY(policy_id,subject_type,subject_id),
 FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_temporary_policy_subject ON temporary_policy_assignments(subject_type,subject_id,expires_at_ns);
CREATE TABLE IF NOT EXISTS roles (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_policies (
 role_id TEXT NOT NULL, policy_id TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(role_id,policy_id),
 FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
 FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS user_roles (
 user_id TEXT NOT NULL, role_id TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(user_id,role_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS nodes (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, endpoint TEXT NOT NULL UNIQUE,
 token_encrypted TEXT NOT NULL, state TEXT NOT NULL, last_seen_at TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_token_rotations (
 node_id TEXT PRIMARY KEY, candidate_encrypted TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT, action TEXT NOT NULL,
 resource TEXT NOT NULL, result TEXT NOT NULL, correlation_id TEXT NOT NULL,
 created_at TEXT NOT NULL, actor_type TEXT NOT NULL DEFAULT 'user',
 policy_ids TEXT NOT NULL DEFAULT '[]', evaluated_path TEXT NOT NULL DEFAULT '',
 capability TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_chain_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_id INTEGER NOT NULL, last_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, event_hash TEXT NOT NULL, created_at TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metadata (
 key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, node_id TEXT NOT NULL,
 mount_id TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL,
 password_hash TEXT NOT NULL DEFAULT '', allow_archive INTEGER NOT NULL DEFAULT 1,
 max_downloads INTEGER NOT NULL DEFAULT 0, download_count INTEGER NOT NULL DEFAULT 0,
 created_by TEXT NOT NULL, created_by_type TEXT NOT NULL DEFAULT 'user', created_credential_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 expires_at TEXT, revoked_at TEXT, last_access_at TEXT
);
CREATE INDEX IF NOT EXISTS shares_created_by ON shares(created_by);
CREATE INDEX IF NOT EXISTS shares_expires_at ON shares(expires_at);
CREATE TABLE IF NOT EXISTS login_attempts (
 key TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
 locked_until TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connections (
 request_id TEXT PRIMARY KEY, invite_id TEXT NOT NULL UNIQUE,
 issuer_node_id TEXT NOT NULL, target_node_id TEXT NOT NULL,
 invite_token_encrypted TEXT NOT NULL, issuer_fingerprint TEXT NOT NULL,
 status TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(issuer_node_id) REFERENCES nodes(id),
 FOREIGN KEY(target_node_id) REFERENCES nodes(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_type_id ON audit_events(actor_type, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_id ON audit_events(action, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_result_id ON audit_events(result, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_events(correlation_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_service_account_tokens_account ON service_account_tokens(service_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_account_groups_group ON service_account_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_access_group_nodes_node ON access_group_nodes(node_id);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_subject ON policy_assignments(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_role_policies_policy ON role_policies(policy_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
`)
	if err != nil {
		return err
	}
	for _, migration := range []struct {
		table, oldName, newName string
	}{
		{"connections", "issuer_worker_id", "issuer_node_id"},
		{"connections", "target_worker_id", "target_node_id"},
	} {
		if err := s.renameColumnIfNeeded(migration.table, migration.oldName, migration.newName); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`UPDATE policy_rules
SET path='nodes/' || substr(path, length('workers/') + 1)
WHERE path LIKE 'workers/%'`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return err
	}
	if _, err = s.db.Exec(`UPDATE users SET updated_at=created_at WHERE updated_at=''`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`ALTER TABLE audit_events ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'user'`); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return err
	}
	for _, statement := range []string{
		`ALTER TABLE policy_rules ADD COLUMN file_types TEXT NOT NULL DEFAULT 'null'`,
		`ALTER TABLE policy_rules ADD COLUMN visibility TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE policy_rules ADD COLUMN needs_approval TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE pending_operations ADD COLUMN kind TEXT NOT NULL DEFAULT 'replay'`,
		`ALTER TABLE pending_operations ADD COLUMN credential_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE shares ADD COLUMN created_by_type TEXT NOT NULL DEFAULT 'user'`,
		`ALTER TABLE shares ADD COLUMN created_credential_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE service_accounts ADD COLUMN kind TEXT NOT NULL DEFAULT 'automation'`,
		`ALTER TABLE service_account_tokens ADD COLUMN agent_limits TEXT NOT NULL DEFAULT 'null'`,
		`ALTER TABLE audit_events ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN detail TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE audit_events ADD COLUMN chain_data TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN chain_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN policy_ids TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE audit_events ADD COLUMN evaluated_path TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN capability TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE managed_nodes ADD COLUMN cert_fingerprint TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE managed_nodes ADD COLUMN cert_issuer TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE managed_nodes ADD COLUMN auth_mode TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(statement); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

func (s *Store) renameColumnIfNeeded(table, oldName, newName string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	hasOld, hasNew := false, false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		hasOld = hasOld || name == oldName
		hasNew = hasNew || name == newName
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if hasOld && !hasNew {
		_, err = s.db.Exec(`ALTER TABLE ` + table + ` RENAME COLUMN ` + oldName + ` TO ` + newName)
	}
	return err
}

const serviceAccountSelect = `SELECT id,name,description,enabled,created_at,updated_at,kind FROM service_accounts`

func searchPattern(query string) string {
	escaped := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	).Replace(strings.TrimSpace(query))
	return "%" + escaped + "%"
}

func scanServiceAccount(scanner interface{ Scan(...any) error }) (ServiceAccount, error) {
	var account ServiceAccount
	var enabled int
	var createdAt, updatedAt string
	err := scanner.Scan(&account.ID, &account.Name, &account.Description, &enabled, &createdAt, &updatedAt, &account.Kind)
	account.Enabled = enabled != 0
	account.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	account.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return account, err
}

func (s *Store) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	return s.SearchServiceAccounts(ctx, "")
}

func (s *Store) SearchServiceAccounts(ctx context.Context, query string) ([]ServiceAccount, error) {
	statement := serviceAccountSelect
	var args []any
	if strings.TrimSpace(query) != "" {
		statement += ` WHERE LOWER(name) LIKE LOWER(?) ESCAPE '\' OR LOWER(description) LIKE LOWER(?) ESCAPE '\'`
		pattern := searchPattern(query)
		args = []any{pattern, pattern}
	}
	rows, err := s.db.QueryContext(ctx, statement+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []ServiceAccount
	for rows.Next() {
		account, scanErr := scanServiceAccount(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (s *Store) GetServiceAccount(ctx context.Context, id string) (ServiceAccount, error) {
	account, err := scanServiceAccount(s.db.QueryRowContext(ctx, serviceAccountSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return account, ErrNotFound
	}
	return account, err
}

func (s *Store) CreateServiceAccount(ctx context.Context, account ServiceAccount) error {
	if account.Kind == "" {
		account.Kind = "automation"
	}
	if account.Kind != "automation" && account.Kind != "agent" {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO service_accounts(id,name,description,enabled,created_at,updated_at,kind)
VALUES(?,?,?,?,?,?,?)`, account.ID, account.Name, account.Description, boolInt(account.Enabled),
		account.CreatedAt.Format(time.RFC3339Nano), account.UpdatedAt.Format(time.RFC3339Nano), account.Kind)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if account.Kind == "agent" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','1') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<1 THEN '1' ELSE value END`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Older releases did not check this marker; operators must still use a
// pre-feature backup when rolling back to one of those releases.
func (s *Store) checkSecurityVersion() error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='metadata'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	var raw string
	err := s.db.QueryRow(`SELECT value FROM metadata WHERE key='minimum_security_version'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	version, err := strconv.Atoi(raw)
	if err != nil || version < 1 || version > supportedSecurityVersion {
		return errors.New("database requires an unsupported security version")
	}
	return nil
}

func (s *Store) UpdateServiceAccount(ctx context.Context, account ServiceAccount) error {
	result, err := s.db.ExecContext(ctx, `UPDATE service_accounts SET name=?,description=?,enabled=?,updated_at=? WHERE id=?`,
		account.Name, account.Description, boolInt(account.Enabled), account.UpdatedAt.Format(time.RFC3339Nano), account.ID)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteServiceAccount(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_assignments WHERE subject_type='service_account' AND subject_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM temporary_policy_assignments WHERE subject_type='service_account' AND subject_id=?`, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM service_accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Store) CreateServiceAccountToken(ctx context.Context, token ServiceAccountToken, revokeExisting bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM service_accounts WHERE id=?`, token.ServiceAccountID).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if revokeExisting {
		now := token.CreatedAt.Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `UPDATE service_account_tokens SET revoked_at=? WHERE service_account_id=? AND revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM workload_identities w WHERE w.credential_id=service_account_tokens.id)`,
			now, token.ServiceAccountID); err != nil {
			return err
		}
	}
	limits, err := json.Marshal(token.AgentLimits)
	if err != nil {
		return err
	}
	if token.AgentLimits != nil && token.AgentLimits.RequestDeletes {
		// An older binary would read the credential as read-only without
		// noticing the field, which is the safe way to misread it; the marker
		// still keeps it from opening a database that asks for approvals.
		if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','8') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<8 THEN '8' ELSE value END`); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO service_account_tokens(
id,service_account_id,name,token_hash,expires_at,last_used_at,revoked_at,created_at,agent_limits
) VALUES(?,?,?,?,?,?,?,?,?)`, token.ID, token.ServiceAccountID, token.Name, token.TokenHash,
		nullableTime(token.ExpiresAt), nullableTime(token.LastUsedAt), nullableTime(token.RevokedAt),
		token.CreatedAt.Format(time.RFC3339Nano), string(limits))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListServiceAccountTokens(ctx context.Context, accountID string) ([]ServiceAccountToken, error) {
	if _, err := s.GetServiceAccount(ctx, accountID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,service_account_id,name,token_hash,expires_at,last_used_at,revoked_at,created_at,agent_limits
FROM service_account_tokens t WHERE service_account_id=? AND NOT EXISTS (SELECT 1 FROM workload_identities w WHERE w.credential_id=t.id) ORDER BY created_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []ServiceAccountToken
	for rows.Next() {
		token, scanErr := scanServiceAccountToken(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// GetActiveServiceAccountToken rechecks a persisted credential without
// exposing or needing its secret. Callers must separately validate the account.
func (s *Store) GetActiveServiceAccountToken(ctx context.Context, accountID, tokenID string, now time.Time) (ServiceAccountToken, error) {
	var expiry, revoked sql.NullString
	var limits string
	err := s.db.QueryRowContext(ctx, `SELECT expires_at,revoked_at,agent_limits FROM service_account_tokens WHERE id=? AND service_account_id=?`, tokenID, accountID).Scan(&expiry, &revoked, &limits)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceAccountToken{}, ErrNotFound
	}
	if err != nil {
		return ServiceAccountToken{}, err
	}
	if revoked.Valid {
		return ServiceAccountToken{}, ErrNotFound
	}
	token := ServiceAccountToken{ID: tokenID, ServiceAccountID: accountID}
	if err := json.Unmarshal([]byte(limits), &token.AgentLimits); err != nil {
		return ServiceAccountToken{}, err
	}
	if expiry.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, expiry.String)
		if err != nil || !parsed.After(now) {
			return ServiceAccountToken{}, ErrNotFound
		}
		token.ExpiresAt = &parsed
	}
	return token, nil
}

func scanServiceAccountToken(scanner interface{ Scan(...any) error }) (ServiceAccountToken, error) {
	var token ServiceAccountToken
	var expiresAt, lastUsedAt, revokedAt sql.NullString
	var createdAt string
	var limits string
	err := scanner.Scan(&token.ID, &token.ServiceAccountID, &token.Name, &token.TokenHash,
		&expiresAt, &lastUsedAt, &revokedAt, &createdAt, &limits)
	if err == nil {
		err = json.Unmarshal([]byte(limits), &token.AgentLimits)
	}
	token.ExpiresAt = parseNullableTime(expiresAt)
	token.LastUsedAt = parseNullableTime(lastUsedAt)
	token.RevokedAt = parseNullableTime(revokedAt)
	token.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return token, err
}

func (s *Store) AuthenticateServiceAccount(ctx context.Context, tokenHash string) (ServiceAccount, ServiceAccountToken, error) {
	query := `SELECT a.id,a.name,a.description,a.enabled,a.created_at,a.updated_at,a.kind,
t.id,t.service_account_id,t.name,t.token_hash,t.expires_at,t.last_used_at,t.revoked_at,t.created_at,t.agent_limits
FROM service_account_tokens t JOIN service_accounts a ON a.id=t.service_account_id
WHERE t.token_hash=? AND a.enabled=1 AND t.revoked_at IS NULL`
	row := s.db.QueryRowContext(ctx, query, tokenHash)
	var account ServiceAccount
	var enabled int
	var accountCreated, accountUpdated string
	var token ServiceAccountToken
	var expiresAt, lastUsedAt, revokedAt sql.NullString
	var tokenCreated string
	var limits string
	err := row.Scan(&account.ID, &account.Name, &account.Description, &enabled, &accountCreated, &accountUpdated, &account.Kind,
		&token.ID, &token.ServiceAccountID, &token.Name, &token.TokenHash, &expiresAt, &lastUsedAt, &revokedAt, &tokenCreated, &limits)
	if errors.Is(err, sql.ErrNoRows) {
		return account, token, ErrNotFound
	}
	if err != nil {
		return account, token, err
	}
	if err := json.Unmarshal([]byte(limits), &token.AgentLimits); err != nil {
		return account, token, err
	}
	account.Enabled = enabled != 0
	account.CreatedAt, _ = time.Parse(time.RFC3339Nano, accountCreated)
	account.UpdatedAt, _ = time.Parse(time.RFC3339Nano, accountUpdated)
	if expiresAt.Valid {
		expiry, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil || !expiry.After(time.Now().UTC()) {
			return ServiceAccount{}, ServiceAccountToken{}, ErrNotFound
		}
		token.ExpiresAt = &expiry
	}
	token.LastUsedAt = parseNullableTime(lastUsedAt)
	token.RevokedAt = parseNullableTime(revokedAt)
	token.CreatedAt, _ = time.Parse(time.RFC3339Nano, tokenCreated)
	now := time.Now().UTC()
	_, _ = s.db.ExecContext(ctx, `UPDATE service_account_tokens SET last_used_at=? WHERE id=?`,
		now.Format(time.RFC3339Nano), token.ID)
	token.LastUsedAt = &now
	return account, token, nil
}

func (s *Store) RevokeServiceAccountToken(ctx context.Context, accountID, tokenID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET revoked_at=?
WHERE id=? AND service_account_id=? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), tokenID, accountID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ServiceAccountGroupIDs(ctx context.Context, accountID string, activeOnly bool) ([]string, error) {
	query := `SELECT sg.group_id FROM service_account_groups sg`
	if activeOnly {
		query += ` JOIN access_groups g ON g.id=sg.group_id AND g.enabled=1`
	}
	query += ` WHERE sg.service_account_id=? ORDER BY sg.group_id`
	rows, err := s.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) SetServiceAccountGroups(ctx context.Context, accountID string, groupIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_accounts WHERE id=?`, accountID).Scan(&count); err != nil || count == 0 {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	for _, groupID := range uniqueStrings(groupIDs) {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_groups WHERE id=?`, groupID).Scan(&count); err != nil || count == 0 {
			if err != nil {
				return err
			}
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_account_groups WHERE service_account_id=?`, accountID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, groupID := range uniqueStrings(groupIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO service_account_groups(service_account_id,group_id,created_at) VALUES(?,?,?)`, accountID, groupID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const accessGroupSelect = `SELECT id,name,description,enabled,created_at,updated_at FROM access_groups`

func scanAccessGroup(scanner interface{ Scan(...any) error }) (AccessGroup, error) {
	var group AccessGroup
	var enabled int
	var createdAt, updatedAt string
	err := scanner.Scan(&group.ID, &group.Name, &group.Description, &enabled, &createdAt, &updatedAt)
	group.Enabled = enabled != 0
	group.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	group.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return group, err
}

func (s *Store) ListAccessGroups(ctx context.Context) ([]AccessGroup, error) {
	return s.SearchAccessGroups(ctx, "")
}

func (s *Store) SearchAccessGroups(ctx context.Context, query string) ([]AccessGroup, error) {
	statement := accessGroupSelect
	var args []any
	if strings.TrimSpace(query) != "" {
		statement += ` WHERE LOWER(name) LIKE LOWER(?) ESCAPE '\' OR LOWER(description) LIKE LOWER(?) ESCAPE '\'`
		pattern := searchPattern(query)
		args = []any{pattern, pattern}
	}
	rows, err := s.db.QueryContext(ctx, statement+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []AccessGroup{}
	for rows.Next() {
		group, scanErr := scanAccessGroup(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for index := range groups {
		if err := s.populateAccessGroup(ctx, &groups[index]); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func (s *Store) GetAccessGroup(ctx context.Context, id string) (AccessGroup, error) {
	group, err := scanAccessGroup(s.db.QueryRowContext(ctx, accessGroupSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return group, ErrNotFound
	}
	if err != nil {
		return group, err
	}
	return group, s.populateAccessGroup(ctx, &group)
}

func (s *Store) populateAccessGroup(ctx context.Context, group *AccessGroup) error {
	nodes, err := s.AccessGroupNodeIDs(ctx, group.ID)
	if err != nil {
		return err
	}
	policies, err := s.AccessGroupPolicyIDs(ctx, group.ID)
	if err != nil {
		return err
	}
	group.NodeIDs, group.PolicyIDs = nodes, policies
	return nil
}

func (s *Store) CreateAccessGroup(ctx context.Context, group AccessGroup) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO access_groups(id,name,description,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		group.ID, group.Name, group.Description, boolInt(group.Enabled), group.CreatedAt.Format(time.RFC3339Nano), group.UpdatedAt.Format(time.RFC3339Nano))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) UpdateAccessGroup(ctx context.Context, group AccessGroup) error {
	result, err := s.db.ExecContext(ctx, `UPDATE access_groups SET name=?,description=?,enabled=?,updated_at=? WHERE id=?`,
		group.Name, group.Description, boolInt(group.Enabled), group.UpdatedAt.Format(time.RFC3339Nano), group.ID)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAccessGroup(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_account_groups WHERE group_id=?`, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM access_groups WHERE id=?`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Store) AccessGroupNodeIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM access_group_nodes WHERE group_id=? ORDER BY node_id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) SetAccessGroupNodes(ctx context.Context, groupID string, nodeIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_groups WHERE id=?`, groupID).Scan(&count); err != nil || count == 0 {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	for _, nodeID := range uniqueStrings(nodeIDs) {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id=?`, nodeID).Scan(&count); err != nil || count == 0 {
			if err != nil {
				return err
			}
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_group_nodes WHERE group_id=?`, groupID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, nodeID := range uniqueStrings(nodeIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_group_nodes(group_id,node_id,created_at) VALUES(?,?,?)`, groupID, nodeID, now); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE access_groups SET updated_at=? WHERE id=?`, now, groupID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AccessGroupPolicyIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT policy_id FROM access_group_policies WHERE group_id=? ORDER BY policy_id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) SetAccessGroupPolicies(ctx context.Context, groupID string, policyIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_groups WHERE id=?`, groupID).Scan(&count); err != nil || count == 0 {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	for _, policyID := range uniqueStrings(policyIDs) {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE id=?`, policyID).Scan(&count); err != nil || count == 0 {
			if err != nil {
				return err
			}
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_group_policies WHERE group_id=?`, groupID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, policyID := range uniqueStrings(policyIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_group_policies(group_id,policy_id,created_at) VALUES(?,?,?)`, groupID, policyID, now); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE access_groups SET updated_at=? WHERE id=?`, now, groupID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) NodeInAccessGroup(ctx context.Context, groupID, nodeID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_group_nodes WHERE group_id=? AND node_id=?`, groupID, nodeID).Scan(&count)
	return count > 0, err
}

func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	return s.SearchPolicies(ctx, "")
}

func (s *Store) SearchPolicies(ctx context.Context, query string) ([]Policy, error) {
	statement := `SELECT id,name,description,created_at,updated_at FROM policies`
	var args []any
	if strings.TrimSpace(query) != "" {
		statement += ` WHERE LOWER(name) LIKE LOWER(?) ESCAPE '\' OR LOWER(description) LIKE LOWER(?) ESCAPE '\'`
		pattern := searchPattern(query)
		args = []any{pattern, pattern}
	}
	rows, err := s.db.QueryContext(ctx, statement+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	var policies []Policy
	for rows.Next() {
		var policy Policy
		var createdAt, updatedAt string
		if err := rows.Scan(&policy.ID, &policy.Name, &policy.Description, &createdAt, &updatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		policy.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		policy.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range policies {
		rules, err := s.policyRules(ctx, policies[index].ID)
		if err != nil {
			return nil, err
		}
		policies[index].Rules = rules
	}
	return policies, nil
}

func (s *Store) GetPolicy(ctx context.Context, id string) (Policy, error) {
	return s.getPolicy(ctx, `id`, id)
}

// GetPolicyByName finds the policy with exactly this name; names are unique.
func (s *Store) GetPolicyByName(ctx context.Context, name string) (Policy, error) {
	return s.getPolicy(ctx, `name`, name)
}

func (s *Store) getPolicy(ctx context.Context, column, value string) (Policy, error) {
	var policy Policy
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT id,name,description,created_at,updated_at FROM policies WHERE `+column+`=?`, value).
		Scan(&policy.ID, &policy.Name, &policy.Description, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, ErrNotFound
	}
	if err != nil {
		return policy, err
	}
	policy.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	policy.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	policy.Rules, err = s.policyRules(ctx, policy.ID)
	return policy, err
}

func (s *Store) policyRules(ctx context.Context, policyID string) ([]rbac.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT path,capabilities,file_types,visibility,needs_approval FROM policy_rules WHERE policy_id=? ORDER BY position,id`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []rbac.Rule
	for rows.Next() {
		var rule rbac.Rule
		var encoded, selector, approval string
		if err := rows.Scan(&rule.Path, &encoded, &selector, &rule.Visibility, &approval); err != nil {
			return nil, err
		}
		if approval != "" && approval != "[]" {
			if err := json.Unmarshal([]byte(approval), &rule.NeedsApproval); err != nil {
				return nil, err
			}
		}
		if err := json.Unmarshal([]byte(encoded), &rule.Capabilities); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(strings.NewReader(selector))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&rule.FileTypes); err != nil {
			return nil, err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, errors.New("invalid trailing file type selector data")
		}
		if err := validatePolicyTypeRule(rule); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *Store) CreatePolicy(ctx context.Context, policy Policy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO policies(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)`,
		policy.ID, policy.Name, policy.Description, policy.CreatedAt.Format(time.RFC3339Nano), policy.UpdatedAt.Format(time.RFC3339Nano))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if err := insertPolicyRules(ctx, tx, policy.ID, policy.Rules); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdatePolicy(ctx context.Context, policy Policy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE policies SET name=?,description=?,updated_at=? WHERE id=?`,
		policy.Name, policy.Description, policy.UpdatedAt.Format(time.RFC3339Nano), policy.ID)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_rules WHERE policy_id=?`, policy.ID); err != nil {
		return err
	}
	if err := insertPolicyRules(ctx, tx, policy.ID, policy.Rules); err != nil {
		return err
	}
	return tx.Commit()
}

func insertPolicyRules(ctx context.Context, tx *sql.Tx, policyID string, rules []rbac.Rule) error {
	for position, rule := range rules {
		if err := validatePolicyTypeRule(rule); err != nil {
			return err
		}
		encoded, err := json.Marshal(rule.Capabilities)
		if err != nil {
			return err
		}
		selector, err := json.Marshal(rule.FileTypes)
		if err != nil {
			return err
		}
		if rule.FileTypes != nil {
			if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','2') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<2 THEN '2' ELSE value END`); err != nil {
				return err
			}
		}
		approval := []byte("[]")
		if len(rule.NeedsApproval) > 0 {
			if approval, err = json.Marshal(rule.NeedsApproval); err != nil {
				return err
			}
			// An older binary would read the rule as a plain grant and skip the
			// approval, so keep it from opening a database that holds one.
			if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','8') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<8 THEN '8' ELSE value END`); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rules(policy_id,path,capabilities,position,file_types,visibility,needs_approval) VALUES(?,?,?,?,?,?,?)`,
			policyID, rule.Path, string(encoded), position, string(selector), rule.Visibility, string(approval)); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyTypeRule(rule rbac.Rule) error {
	if !rbac.ValidNeedsApproval(rule) {
		return errors.New("invalid approval marks")
	}
	if rule.FileTypes == nil {
		if rule.Visibility != "" {
			return errors.New("visibility requires file types")
		}
		return nil
	}
	if rule.Visibility != "" && rule.Visibility != "hidden" && rule.Visibility != "visible" {
		return errors.New("invalid file type visibility")
	}
	parts := strings.Split(rbac.NormalizePath(rule.Path), "/")
	if !rbac.ValidPath(rule.Path) || len(parts) < 5 || parts[0] != "nodes" || parts[2] != "files" || parts[3] != "mounts" || parts[1] == "**" || parts[4] == "**" {
		return errors.New("file types require a mount file path")
	}
	return rule.FileTypes.Validate()
}

func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	return s.SearchRoles(ctx, "")
}

func (s *Store) SearchRoles(ctx context.Context, query string) ([]Role, error) {
	statement := `SELECT id,name,description,created_at,updated_at FROM roles`
	var args []any
	if strings.TrimSpace(query) != "" {
		statement += ` WHERE LOWER(name) LIKE LOWER(?) ESCAPE '\' OR LOWER(description) LIKE LOWER(?) ESCAPE '\'`
		pattern := searchPattern(query)
		args = []any{pattern, pattern}
	}
	rows, err := s.db.QueryContext(ctx, statement+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	var roles []Role
	for rows.Next() {
		role, scanErr := scanRole(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range roles {
		roles[index].PolicyIDs, err = s.RolePolicyIDs(ctx, roles[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return roles, nil
}

func (s *Store) GetRole(ctx context.Context, id string) (Role, error) {
	role, err := scanRole(s.db.QueryRowContext(ctx,
		`SELECT id,name,description,created_at,updated_at FROM roles WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return role, ErrNotFound
	}
	if err != nil {
		return role, err
	}
	role.PolicyIDs, err = s.RolePolicyIDs(ctx, role.ID)
	return role, err
}

func scanRole(scanner interface{ Scan(...any) error }) (Role, error) {
	var role Role
	var createdAt, updatedAt string
	err := scanner.Scan(&role.ID, &role.Name, &role.Description, &createdAt, &updatedAt)
	role.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	role.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return role, err
}

func (s *Store) CreateRole(ctx context.Context, role Role) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO roles(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)`,
		role.ID, role.Name, role.Description, role.CreatedAt.Format(time.RFC3339Nano), role.UpdatedAt.Format(time.RFC3339Nano))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if err := setRolePolicies(ctx, tx, role.ID, role.PolicyIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateRole(ctx context.Context, role Role) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE roles SET name=?,description=?,updated_at=? WHERE id=?`,
		role.Name, role.Description, role.UpdatedAt.Format(time.RFC3339Nano), role.ID)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	if err := setRolePolicies(ctx, tx, role.ID, role.PolicyIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id=?`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func setRolePolicies(ctx context.Context, tx *sql.Tx, roleID string, policyIDs []string) error {
	var count int
	for _, policyID := range uniqueStrings(policyIDs) {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE id=?`, policyID).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_policies WHERE role_id=?`, roleID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, policyID := range uniqueStrings(policyIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_policies(role_id,policy_id,created_at) VALUES(?,?,?)`,
			roleID, policyID, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RolePolicyIDs(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT policy_id FROM role_policies WHERE role_id=? ORDER BY policy_id`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) SetUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=?`, userID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	for _, roleID := range uniqueStrings(roleIDs) {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE id=?`, roleID).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id=?`, userID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, roleID := range uniqueStrings(roleIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id,created_at) VALUES(?,?,?)`,
			userID, roleID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UserRoleIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role_id FROM user_roles WHERE user_id=? ORDER BY role_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) SetSubjectPolicies(ctx context.Context, subjectType, subjectID string, policyIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	var subjectQuery string
	switch subjectType {
	case "user":
		subjectQuery = `SELECT COUNT(*) FROM users WHERE id=?`
	case "service_account":
		subjectQuery = `SELECT COUNT(*) FROM service_accounts WHERE id=?`
	default:
		return ErrNotFound
	}
	if err := tx.QueryRowContext(ctx, subjectQuery, subjectID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	for _, policyID := range policyIDs {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE id=?`, policyID).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_assignments WHERE subject_type=? AND subject_id=?`, subjectType, subjectID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, policyID := range uniqueStrings(policyIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_assignments(policy_id,subject_type,subject_id,created_at) VALUES(?,?,?,?)`,
			policyID, subjectType, subjectID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SubjectPolicyIDs(ctx context.Context, subjectType, subjectID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT policy_id FROM policy_assignments
WHERE subject_type=? AND subject_id=? ORDER BY policy_id`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) RBACPoliciesForSubject(ctx context.Context, subjectType, subjectID string) ([]rbac.Policy, error) {
	query := `SELECT DISTINCT p.id,p.name FROM policies p
JOIN policy_assignments a ON a.policy_id=p.id
WHERE a.subject_type=? AND a.subject_id=?`
	args := []any{subjectType, subjectID}
	if subjectType == "user" {
		query = `SELECT DISTINCT p.id,p.name FROM policies p
LEFT JOIN policy_assignments a ON a.policy_id=p.id AND a.subject_type='user' AND a.subject_id=?
LEFT JOIN temporary_policy_assignments t ON t.policy_id=p.id AND t.subject_type='user' AND t.subject_id=? AND t.expires_at_ns>?
LEFT JOIN role_policies rp ON rp.policy_id=p.id
LEFT JOIN user_roles ur ON ur.role_id=rp.role_id AND ur.user_id=?
WHERE a.policy_id IS NOT NULL OR t.policy_id IS NOT NULL OR ur.user_id IS NOT NULL`
		args = []any{subjectID, subjectID, time.Now().UTC().UnixNano(), subjectID}
	} else if subjectType == "service_account" {
		query = `SELECT DISTINCT p.id,p.name FROM policies p
LEFT JOIN policy_assignments a ON a.policy_id=p.id AND a.subject_type='service_account' AND a.subject_id=?
LEFT JOIN temporary_policy_assignments t ON t.policy_id=p.id AND t.subject_type='service_account' AND t.subject_id=? AND t.expires_at_ns>?
LEFT JOIN service_account_groups sg ON sg.service_account_id=?
LEFT JOIN access_groups g ON g.id=sg.group_id AND g.enabled=1
LEFT JOIN access_group_policies gp ON gp.policy_id=p.id AND gp.group_id=g.id
WHERE a.policy_id IS NOT NULL OR t.policy_id IS NOT NULL OR gp.policy_id IS NOT NULL`
		args = []any{subjectID, subjectID, time.Now().UTC().UnixNano(), subjectID}
	}
	query += ` ORDER BY p.id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var policies []rbac.Policy
	for rows.Next() {
		var policy rbac.Policy
		if err := rows.Scan(&policy.ID, &policy.Name); err != nil {
			rows.Close()
			return nil, err
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range policies {
		policies[index].Rules, err = s.policyRules(ctx, policies[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return policies, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (s *Store) Metadata(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

func (s *Store) SetMetadata(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// EmergencyRecoverAdmin resets or creates one enabled administrator and
// revokes every browser session. Callers must enforce offline execution and
// validate the external database encryption key before invoking it.
func (s *Store) EmergencyRecoverAdmin(ctx context.Context, newUserID, username, passwordHash, correlationID string) (AdminRecoveryResult, error) {
	if strings.TrimSpace(username) == "" || passwordHash == "" || correlationID == "" {
		return AdminRecoveryResult{}, errors.New("username, password hash, and correlation ID are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AdminRecoveryResult{}, err
	}
	defer tx.Rollback()
	user, err := scanUser(tx.QueryRowContext(ctx, userSelect+` WHERE username=?`, username))
	created := false
	now := time.Now().UTC()
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if newUserID == "" {
			return AdminRecoveryResult{}, errors.New("new user ID is required")
		}
		user = User{
			ID: newUserID, Username: username, PasswordHash: passwordHash,
			Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now,
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO users(
id,username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)`,
			user.ID, user.Username, user.PasswordHash, user.Role,
			user.CreatedAt.Format(time.RFC3339Nano), user.UpdatedAt.Format(time.RFC3339Nano))
		created = true
	case err != nil:
		return AdminRecoveryResult{}, err
	default:
		user.PasswordHash, user.Role, user.Enabled, user.UpdatedAt = passwordHash, "admin", true, now
		_, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=?,role='admin',enabled=1,updated_at=? WHERE id=?`,
			passwordHash, now.Format(time.RFC3339Nano), user.ID)
	}
	if err != nil {
		return AdminRecoveryResult{}, err
	}
	sessionResult, err := tx.ExecContext(ctx, `DELETE FROM sessions`)
	if err != nil {
		return AdminRecoveryResult{}, err
	}
	revoked, _ := sessionResult.RowsAffected()
	err = appendAuditTx(ctx, tx, auditRecord{actorID: user.ID, actorType: "recovery", action: "recover_admin", resource: "control-tower/users/" + user.ID, result: "allowed", correlationID: correlationID, createdAt: now.Format(time.RFC3339Nano), evaluatedPath: "control-tower/users", capability: "sudo"})
	if err != nil {
		return AdminRecoveryResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminRecoveryResult{}, err
	}
	user.PasswordHash = ""
	return AdminRecoveryResult{User: user, Created: created, RevokedSessions: int(revoked)}, nil
}

// EmergencyReplaceNodeToken updates the encrypted Control Tower copy after an
// offline node token recovery. The plaintext token never reaches this layer.
func (s *Store) EmergencyReplaceNodeToken(ctx context.Context, nodeID, encryptedToken, correlationID string) (Node, error) {
	if strings.TrimSpace(nodeID) == "" || encryptedToken == "" || correlationID == "" {
		return Node{}, errors.New("node ID, encrypted token, and correlation ID are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Node{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET token_encrypted=?,state='unknown',
last_seen_at=NULL,updated_at=? WHERE id=?`, encryptedToken, now.Format(time.RFC3339Nano), nodeID)
	if err != nil {
		return Node{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return Node{}, ErrNotFound
	}
	err = appendAuditTx(ctx, tx, auditRecord{actorID: nodeID, actorType: "recovery", action: "recover_node_token", resource: "control-tower/nodes/" + nodeID + "/token", result: "allowed", correlationID: correlationID, createdAt: now.Format(time.RFC3339Nano), evaluatedPath: "control-tower/nodes/" + nodeID + "/token", capability: "sudo"})
	if err != nil {
		return Node{}, err
	}
	node, err := scanNode(tx.QueryRowContext(ctx, `SELECT id,name,endpoint,token_encrypted,state,last_seen_at,
created_at,updated_at FROM nodes WHERE id=?`, nodeID))
	if err != nil {
		return Node{}, err
	}
	if err := tx.Commit(); err != nil {
		return Node{}, err
	}
	node.TokenEncrypted = ""
	return node, nil
}

func (s *Store) EnsureAdmin(ctx context.Context, id, username, passwordHash string) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)`,
		id, username, passwordHash, "admin", now, now)
	return err
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE username=?`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return user, ErrNotFound
	}
	return user, err
}

const userSelect = `SELECT id,username,password_hash,role,enabled,created_at,updated_at FROM users`

func scanUser(scanner interface{ Scan(...any) error }) (User, error) {
	var user User
	var enabled int
	var createdAt, updatedAt string
	err := scanner.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &enabled, &createdAt, &updatedAt)
	user.Enabled = enabled != 0
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return user, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	return s.SearchUsers(ctx, "")
}

func (s *Store) SearchUsers(ctx context.Context, query string) ([]User, error) {
	statement := userSelect
	var args []any
	if strings.TrimSpace(query) != "" {
		statement += ` WHERE LOWER(username) LIKE LOWER(?) ESCAPE '\' OR LOWER(role) LIKE LOWER(?) ESCAPE '\'`
		pattern := searchPattern(query)
		args = []any{pattern, pattern}
	}
	rows, err := s.db.QueryContext(ctx, statement+` ORDER BY username`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return user, ErrNotFound
	}
	return user, err
}

func (s *Store) CreateUser(ctx context.Context, user User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,enabled,created_at,updated_at)
VALUES(?,?,?,?,?,?,?)`, user.ID, user.Username, user.PasswordHash, user.Role, boolInt(user.Enabled),
		user.CreatedAt.Format(time.RFC3339Nano), user.UpdatedAt.Format(time.RFC3339Nano))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) UpdateUser(ctx context.Context, user User, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := scanUser(tx.QueryRowContext(ctx, userSelect+` WHERE id=?`, user.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current.Role == "admin" && current.Enabled && (user.Role != "admin" || !user.Enabled) {
		var others int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1 AND id<>?`, user.ID).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrLastAdmin
		}
	}
	if passwordHash == "" {
		_, err = tx.ExecContext(ctx, `UPDATE users SET username=?,role=?,enabled=?,updated_at=? WHERE id=?`,
			user.Username, user.Role, boolInt(user.Enabled), user.UpdatedAt.Format(time.RFC3339Nano), user.ID)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE users SET username=?,password_hash=?,role=?,enabled=?,updated_at=? WHERE id=?`,
			user.Username, passwordHash, user.Role, boolInt(user.Enabled), user.UpdatedAt.Format(time.RFC3339Nano), user.ID)
	}
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if passwordHash != "" || !user.Enabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, user.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := scanUser(tx.QueryRowContext(ctx, userSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current.Role == "admin" && current.Enabled {
		var others int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1 AND id<>?`, id).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_assignments WHERE subject_type='user' AND subject_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM temporary_policy_assignments WHERE subject_type='user' AND subject_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateSession(ctx context.Context, hash, userID string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)`,
		hash, userID, expires.Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SessionUser(ctx context.Context, hash string) (User, error) {
	user, _, err := s.SessionUserAndExpiry(ctx, hash)
	return user, err
}

// SessionUserAndExpiry revalidates the session and returns its current user and
// expiry together so short-lived authorizations cannot outlive the session.
func (s *Store) SessionUserAndExpiry(ctx context.Context, hash string) (User, time.Time, error) {
	var user User
	var enabled int
	var createdAt, updatedAt, expiresAt string
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.password_hash,u.role,u.enabled,u.created_at,u.updated_at,s.expires_at
FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, hash).
		Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &enabled, &createdAt, &updatedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return user, time.Time{}, ErrNotFound
	}
	if err != nil {
		return user, time.Time{}, err
	}
	user.Enabled = enabled != 0
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || !expiry.After(time.Now().UTC()) {
		return User{}, time.Time{}, ErrNotFound
	}
	return user, expiry, nil
}

func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hash)
	return err
}

func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,endpoint,token_encrypted,state,last_seen_at,created_at,updated_at FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id string) (Node, error) {
	node, err := scanNode(s.db.QueryRowContext(ctx, `SELECT id,name,endpoint,token_encrypted,state,last_seen_at,created_at,updated_at FROM nodes WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return node, ErrNotFound
	}
	return node, err
}

func (s *Store) SaveNode(ctx context.Context, node Node) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO nodes(id,name,endpoint,token_encrypted,state,last_seen_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,endpoint=excluded.endpoint,
token_encrypted=excluded.token_encrypted,state=excluded.state,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`,
		node.ID, node.Name, node.Endpoint, node.TokenEncrypted, node.State, nullableTime(node.LastSeenAt),
		node.CreatedAt.Format(time.RFC3339Nano), node.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) UpdateNodeToken(ctx context.Context, nodeID, encryptedToken string, updatedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET token_encrypted=?,updated_at=? WHERE id=?`,
		encryptedToken, updatedAt.Format(time.RFC3339Nano), nodeID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateNodeState(ctx context.Context, id, state string, seen *time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET state=?,last_seen_at=?,updated_at=? WHERE id=?`,
		state, nullableTime(seen), time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) DeleteNode(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id=?`, id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	// Connections contain Control Tower orchestration material (including an
	// encrypted invite secret) and cannot outlive either registered node.
	if _, err := tx.ExecContext(ctx, `DELETE FROM connections WHERE issuer_node_id=? OR target_node_id=?`, id, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id=?`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// LoginLockedUntil returns the instant a login key is locked until, or the
// zero time if the key is not currently locked.
func (s *Store) LoginLockedUntil(ctx context.Context, key string, now time.Time) (time.Time, error) {
	var lockedUntil sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT locked_until FROM login_attempts WHERE key=?`, key).Scan(&lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil || !lockedUntil.Valid {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, lockedUntil.String)
	if err != nil {
		return time.Time{}, err
	}
	if t.After(now) {
		return t, nil
	}
	return time.Time{}, nil
}

// RegisterLoginFailure increments the failure counter for key and applies an
// exponential lockout once the failure count reaches the threshold.
func (s *Store) RegisterLoginFailure(ctx context.Context, key string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var failures int
	_ = tx.QueryRowContext(ctx, `SELECT failures FROM login_attempts WHERE key=?`, key).Scan(&failures)
	failures++
	var lockedUntil sql.NullString
	if failures >= 5 {
		const maxShiftExponent = 5 // 30<<5 = 960s already exceeds the 900s cap.
		exponent := failures - 5
		if exponent > maxShiftExponent {
			exponent = maxShiftExponent
		}
		shifted := 30 << uint(exponent)
		backoff := time.Duration(math.Min(float64(shifted), 900)) * time.Second
		lockedUntil = sql.NullString{String: now.Add(backoff).Format(time.RFC3339Nano), Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO login_attempts(key,failures,locked_until,updated_at) VALUES(?,?,?,?)
ON CONFLICT(key) DO UPDATE SET failures=excluded.failures,
	locked_until=excluded.locked_until, updated_at=excluded.updated_at`,
		key, failures, lockedUntil, now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearLoginFailures resets the failure counter and lockout for key.
func (s *Store) ClearLoginFailures(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE key=?`, key)
	return err
}

// PurgeStaleLoginAttempts deletes login_attempts rows that have not been
// touched since before the given cutoff, so the table does not grow
// unbounded. Safe to call with any cutoff: the exponential backoff in
// RegisterLoginFailure caps well under an hour, so any reasonable retention
// window outlives an active lockout.
func (s *Store) PurgeStaleLoginAttempts(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM login_attempts WHERE updated_at < ?`, before.Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) Audit(ctx context.Context, actorID, action, resource, result, correlationID string) {
	s.AuditActor(ctx, actorID, "user", action, resource, result, correlationID)
}

func (s *Store) AuditActor(ctx context.Context, actorID, actorType, action, resource, result, correlationID string) {
	_ = s.appendAudit(ctx, auditRecord{actorID: actorID, actorType: actorType, action: action, resource: resource, result: result, correlationID: correlationID})
}

func (s *Store) AuditDecision(ctx context.Context, actorID, actorType, action, resource, result, correlationID string,
	policyIDs []string, evaluatedPath, capability string) {
	encodedPolicies, _ := json.Marshal(policyIDs)
	_ = s.appendAudit(ctx, auditRecord{actorID: actorID, actorType: actorType, action: action, resource: resource, result: result, correlationID: correlationID, policyIDs: string(encodedPolicies), evaluatedPath: evaluatedPath, capability: capability})
}

func (s *Store) ListAuditEvents(ctx context.Context, query AuditQuery) ([]AuditEvent, bool, error) {
	if query.Limit <= 0 {
		query.Limit = 100
	}
	if query.Limit > 500 {
		query.Limit = 500
	}
	clauses := []string{"1=1"}
	arguments := make([]any, 0, 6)
	if query.Ascending {
		clauses = append(clauses, "id > ?")
		arguments = append(arguments, query.AfterID)
	}
	if query.BeforeID > 0 {
		clauses = append(clauses, "id < ?")
		arguments = append(arguments, query.BeforeID)
	}
	if query.ActorType != "" {
		clauses = append(clauses, "actor_type = ?")
		arguments = append(arguments, query.ActorType)
	}
	if query.Action != "" {
		clauses = append(clauses, "action = ?")
		arguments = append(arguments, query.Action)
	}
	if query.Result != "" {
		clauses = append(clauses, "result = ?")
		arguments = append(arguments, query.Result)
	}
	if query.CorrelationID != "" {
		clauses = append(clauses, "correlation_id = ?")
		arguments = append(arguments, query.CorrelationID)
	}
	arguments = append(arguments, query.Limit+1)
	order := "DESC"
	if query.Ascending {
		order = "ASC"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,COALESCE(actor_id,''),actor_type,action,resource,result,
correlation_id,created_at,policy_ids,evaluated_path,capability,source_ip,detail,chain_data,chain_hash
FROM audit_events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY id `+order+` LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	events := make([]AuditEvent, 0, query.Limit)
	for rows.Next() {
		var event AuditEvent
		var createdAt, policyIDs, detail string
		if err := rows.Scan(&event.ID, &event.ActorID, &event.ActorType, &event.Action, &event.Resource,
			&event.Result, &event.CorrelationID, &createdAt, &policyIDs, &event.EvaluatedPath,
			&event.Capability, &event.SourceIP, &detail, &event.ChainData, &event.ChainHash); err != nil {
			return nil, false, err
		}
		event.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		if err := json.Unmarshal([]byte(policyIDs), &event.PolicyIDs); err != nil {
			event.PolicyIDs = []string{}
		}
		if err := json.Unmarshal([]byte(detail), &event.Detail); err != nil {
			return nil, false, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(events) > query.Limit
	if hasMore {
		events = events[:query.Limit]
	}
	return events, hasMore, nil
}

func (s *Store) SaveConnection(ctx context.Context, connection Connection) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO connections(request_id,invite_id,issuer_node_id,target_node_id,
invite_token_encrypted,issuer_fingerprint,status,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		connection.RequestID, connection.InviteID, connection.IssuerNodeID, connection.TargetNodeID,
		connection.InviteTokenEncrypted, connection.IssuerFingerprint, connection.Status,
		connection.ExpiresAt.Format(time.RFC3339Nano), connection.CreatedAt.Format(time.RFC3339Nano),
		connection.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

const connectionSelect = `SELECT request_id,invite_id,issuer_node_id,target_node_id,
invite_token_encrypted,issuer_fingerprint,status,expires_at,created_at,updated_at FROM connections`

func scanConnection(row scanner) (Connection, error) {
	var connection Connection
	var expires, created, updated string
	err := row.Scan(&connection.RequestID, &connection.InviteID, &connection.IssuerNodeID,
		&connection.TargetNodeID, &connection.InviteTokenEncrypted, &connection.IssuerFingerprint,
		&connection.Status, &expires, &created, &updated)
	if err != nil {
		return connection, err
	}
	connection.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	connection.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	connection.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return connection, nil
}

func (s *Store) GetConnection(ctx context.Context, requestID string) (Connection, error) {
	connection, err := scanConnection(s.db.QueryRowContext(ctx,
		connectionSelect+` WHERE request_id=?`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return connection, ErrNotFound
	}
	return connection, err
}

// ListConnections returns every orchestrated connection, newest first. The
// encrypted invite secret stays in the struct for reconciliation but is never
// serialized (Connection.InviteTokenEncrypted is `json:"-"`).
func (s *Store) ListConnections(ctx context.Context) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, connectionSelect+` ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	connections := []Connection{}
	for rows.Next() {
		connection, scanErr := scanConnection(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		connections = append(connections, connection)
	}
	return connections, rows.Err()
}

// ConnectionsForNode returns the connections where the node is either the
// issuer or the target, newest first.
func (s *Store) ConnectionsForNode(ctx context.Context, nodeID string) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx,
		connectionSelect+` WHERE issuer_node_id=? OR target_node_id=? ORDER BY created_at DESC`,
		nodeID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	connections := []Connection{}
	for rows.Next() {
		connection, scanErr := scanConnection(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		connections = append(connections, connection)
	}
	return connections, rows.Err()
}

func (s *Store) UpdateConnectionStatus(ctx context.Context, requestID, status string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE connections SET status=?,updated_at=? WHERE request_id=?`,
		status, time.Now().UTC().Format(time.RFC3339Nano), requestID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scanNode(row scanner) (Node, error) {
	var node Node
	var lastSeen sql.NullString
	var created, updated string
	err := row.Scan(&node.ID, &node.Name, &node.Endpoint, &node.TokenEncrypted, &node.State, &lastSeen, &created, &updated)
	if err != nil {
		return node, err
	}
	node.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	node.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if lastSeen.Valid {
		value, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
		node.LastSeenAt = &value
	}
	return node, nil
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.Format(time.RFC3339Nano)
}

func parseNullableTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil
	}
	return &parsed
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

// A retry always receives the same durable candidate, even after process loss.
func (s *Store) BeginNodeTokenRotation(ctx context.Context, id, candidate string) (string, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO node_token_rotations(node_id,candidate_encrypted,created_at) VALUES(?,?,?) ON CONFLICT(node_id) DO NOTHING`, id, candidate, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return "", false, err
	}
	inserted, _ := result.RowsAffected()
	if err = tx.QueryRowContext(ctx, `SELECT candidate_encrypted FROM node_token_rotations WHERE node_id=?`, id).Scan(&candidate); err != nil {
		return "", false, err
	}
	return candidate, inserted == 0, tx.Commit()
}

func (s *Store) FinishNodeTokenRotation(ctx context.Context, id, candidate string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored string
	if err = tx.QueryRowContext(ctx, `SELECT candidate_encrypted FROM node_token_rotations WHERE node_id=?`, id).Scan(&stored); err != nil {
		return err
	}
	if stored != candidate {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE nodes SET token_encrypted=?,updated_at=? WHERE id=?`, candidate, time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM node_token_rotations WHERE node_id=? AND candidate_encrypted=?`, id, candidate); err != nil {
		return err
	}
	return tx.Commit()
}
