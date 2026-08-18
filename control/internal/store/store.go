package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	ID               string     `json:"token_id"`
	ServiceAccountID string     `json:"service_account_id"`
	Name             string     `json:"name"`
	TokenHash        string     `json:"-"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
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

type Node struct {
	ID             string     `json:"node_id"`
	Name           string     `json:"name"`
	Endpoint       string     `json:"endpoint"`
	TokenEncrypted string     `json:"-"`
	State          string     `json:"state"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
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
	ID            int64     `json:"event_id"`
	ActorID       string    `json:"actor_id"`
	ActorType     string    `json:"actor_type"`
	Action        string    `json:"action"`
	Resource      string    `json:"resource"`
	Result        string    `json:"result"`
	CorrelationID string    `json:"correlation_id"`
	PolicyIDs     []string  `json:"policy_ids"`
	EvaluatedPath string    `json:"evaluated_path,omitempty"`
	Capability    string    `json:"capability,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type AuditQuery struct {
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
	if err := s.migrate(); err != nil {
		database.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

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
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT, action TEXT NOT NULL,
 resource TEXT NOT NULL, result TEXT NOT NULL, correlation_id TEXT NOT NULL,
 created_at TEXT NOT NULL, actor_type TEXT NOT NULL DEFAULT 'user',
 policy_ids TEXT NOT NULL DEFAULT '[]', evaluated_path TEXT NOT NULL DEFAULT '',
 capability TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS metadata (
 key TEXT PRIMARY KEY, value TEXT NOT NULL
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
		`ALTER TABLE audit_events ADD COLUMN policy_ids TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE audit_events ADD COLUMN evaluated_path TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_events ADD COLUMN capability TEXT NOT NULL DEFAULT ''`,
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

const serviceAccountSelect = `SELECT id,name,description,enabled,created_at,updated_at FROM service_accounts`

func scanServiceAccount(scanner interface{ Scan(...any) error }) (ServiceAccount, error) {
	var account ServiceAccount
	var enabled int
	var createdAt, updatedAt string
	err := scanner.Scan(&account.ID, &account.Name, &account.Description, &enabled, &createdAt, &updatedAt)
	account.Enabled = enabled != 0
	account.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	account.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return account, err
}

func (s *Store) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	rows, err := s.db.QueryContext(ctx, serviceAccountSelect+` ORDER BY name`)
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_accounts(id,name,description,enabled,created_at,updated_at)
VALUES(?,?,?,?,?,?)`, account.ID, account.Name, account.Description, boolInt(account.Enabled),
		account.CreatedAt.Format(time.RFC3339Nano), account.UpdatedAt.Format(time.RFC3339Nano))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	return err
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
		if _, err := tx.ExecContext(ctx, `UPDATE service_account_tokens SET revoked_at=? WHERE service_account_id=? AND revoked_at IS NULL`,
			now, token.ServiceAccountID); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO service_account_tokens(
id,service_account_id,name,token_hash,expires_at,last_used_at,revoked_at,created_at
) VALUES(?,?,?,?,?,?,?,?)`, token.ID, token.ServiceAccountID, token.Name, token.TokenHash,
		nullableTime(token.ExpiresAt), nullableTime(token.LastUsedAt), nullableTime(token.RevokedAt),
		token.CreatedAt.Format(time.RFC3339Nano))
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
	rows, err := s.db.QueryContext(ctx, `SELECT id,service_account_id,name,token_hash,expires_at,last_used_at,revoked_at,created_at
FROM service_account_tokens WHERE service_account_id=? ORDER BY created_at DESC`, accountID)
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

func scanServiceAccountToken(scanner interface{ Scan(...any) error }) (ServiceAccountToken, error) {
	var token ServiceAccountToken
	var expiresAt, lastUsedAt, revokedAt sql.NullString
	var createdAt string
	err := scanner.Scan(&token.ID, &token.ServiceAccountID, &token.Name, &token.TokenHash,
		&expiresAt, &lastUsedAt, &revokedAt, &createdAt)
	token.ExpiresAt = parseNullableTime(expiresAt)
	token.LastUsedAt = parseNullableTime(lastUsedAt)
	token.RevokedAt = parseNullableTime(revokedAt)
	token.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return token, err
}

func (s *Store) AuthenticateServiceAccount(ctx context.Context, tokenHash string) (ServiceAccount, ServiceAccountToken, error) {
	query := `SELECT a.id,a.name,a.description,a.enabled,a.created_at,a.updated_at,
t.id,t.service_account_id,t.name,t.token_hash,t.expires_at,t.last_used_at,t.revoked_at,t.created_at
FROM service_account_tokens t JOIN service_accounts a ON a.id=t.service_account_id
WHERE t.token_hash=? AND a.enabled=1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>?)`
	row := s.db.QueryRowContext(ctx, query, tokenHash, time.Now().UTC().Format(time.RFC3339Nano))
	var account ServiceAccount
	var enabled int
	var accountCreated, accountUpdated string
	var token ServiceAccountToken
	var expiresAt, lastUsedAt, revokedAt sql.NullString
	var tokenCreated string
	err := row.Scan(&account.ID, &account.Name, &account.Description, &enabled, &accountCreated, &accountUpdated,
		&token.ID, &token.ServiceAccountID, &token.Name, &token.TokenHash, &expiresAt, &lastUsedAt, &revokedAt, &tokenCreated)
	if errors.Is(err, sql.ErrNoRows) {
		return account, token, ErrNotFound
	}
	if err != nil {
		return account, token, err
	}
	account.Enabled = enabled != 0
	account.CreatedAt, _ = time.Parse(time.RFC3339Nano, accountCreated)
	account.UpdatedAt, _ = time.Parse(time.RFC3339Nano, accountUpdated)
	token.ExpiresAt = parseNullableTime(expiresAt)
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
	rows, err := s.db.QueryContext(ctx, accessGroupSelect+` ORDER BY name`)
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
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,description,created_at,updated_at FROM policies ORDER BY name`)
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
	var policy Policy
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT id,name,description,created_at,updated_at FROM policies WHERE id=?`, id).
		Scan(&policy.ID, &policy.Name, &policy.Description, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, ErrNotFound
	}
	if err != nil {
		return policy, err
	}
	policy.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	policy.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	policy.Rules, err = s.policyRules(ctx, id)
	return policy, err
}

func (s *Store) policyRules(ctx context.Context, policyID string) ([]rbac.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT path,capabilities FROM policy_rules WHERE policy_id=? ORDER BY position,id`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []rbac.Rule
	for rows.Next() {
		var rule rbac.Rule
		var encoded string
		if err := rows.Scan(&rule.Path, &encoded); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(encoded), &rule.Capabilities); err != nil {
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
		encoded, err := json.Marshal(rule.Capabilities)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rules(policy_id,path,capabilities,position) VALUES(?,?,?,?)`,
			policyID, rule.Path, string(encoded), position); err != nil {
			return err
		}
	}
	return nil
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
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,description,created_at,updated_at FROM roles ORDER BY name`)
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
LEFT JOIN role_policies rp ON rp.policy_id=p.id
LEFT JOIN user_roles ur ON ur.role_id=rp.role_id AND ur.user_id=?
WHERE a.policy_id IS NOT NULL OR ur.user_id IS NOT NULL`
		args = []any{subjectID, subjectID}
	} else if subjectType == "service_account" {
		query = `SELECT DISTINCT p.id,p.name FROM policies p
LEFT JOIN policy_assignments a ON a.policy_id=p.id AND a.subject_type='service_account' AND a.subject_id=?
LEFT JOIN service_account_groups sg ON sg.service_account_id=?
LEFT JOIN access_groups g ON g.id=sg.group_id AND g.enabled=1
LEFT JOIN access_group_policies gp ON gp.policy_id=p.id AND gp.group_id=sg.group_id
WHERE a.policy_id IS NOT NULL OR gp.policy_id IS NOT NULL`
		args = []any{subjectID, subjectID}
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
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(
actor_id,actor_type,action,resource,result,correlation_id,created_at,policy_ids,evaluated_path,capability
) VALUES(?,?,?,?,?,?,?,?,?,?)`, user.ID, "recovery", "recover_admin",
		"control-tower/users/"+user.ID, "allowed", correlationID, now.Format(time.RFC3339Nano),
		"[]", "control-tower/users", "sudo")
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
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(
actor_id,actor_type,action,resource,result,correlation_id,created_at,policy_ids,evaluated_path,capability
) VALUES(?,?,?,?,?,?,?,?,?,?)`, nodeID, "recovery", "recover_node_token",
		"control-tower/nodes/"+nodeID+"/token", "allowed", correlationID,
		now.Format(time.RFC3339Nano), "[]", "control-tower/nodes/"+nodeID+"/token", "sudo")
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
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY username`)
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
	var user User
	var enabled int
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.password_hash,u.role,u.enabled,u.created_at,u.updated_at
FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`,
		hash, time.Now().UTC().Format(time.RFC3339Nano)).
		Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &enabled, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return user, ErrNotFound
	}
	user.Enabled = enabled != 0
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return user, err
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

func (s *Store) Audit(ctx context.Context, actorID, action, resource, result, correlationID string) {
	s.AuditActor(ctx, actorID, "user", action, resource, result, correlationID)
}

func (s *Store) AuditActor(ctx context.Context, actorID, actorType, action, resource, result, correlationID string) {
	_, _ = s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_id,actor_type,action,resource,result,correlation_id,created_at) VALUES(?,?,?,?,?,?,?)`,
		actorID, actorType, action, resource, result, correlationID, time.Now().UTC().Format(time.RFC3339Nano))
}

func (s *Store) AuditDecision(ctx context.Context, actorID, actorType, action, resource, result, correlationID string,
	policyIDs []string, evaluatedPath, capability string) {
	encodedPolicies, _ := json.Marshal(policyIDs)
	_, _ = s.db.ExecContext(ctx, `INSERT INTO audit_events(
actor_id,actor_type,action,resource,result,correlation_id,created_at,policy_ids,evaluated_path,capability
) VALUES(?,?,?,?,?,?,?,?,?,?)`, actorID, actorType, action, resource, result, correlationID,
		time.Now().UTC().Format(time.RFC3339Nano), string(encodedPolicies), evaluatedPath, capability)
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
	rows, err := s.db.QueryContext(ctx, `SELECT id,COALESCE(actor_id,''),actor_type,action,resource,result,
correlation_id,created_at,policy_ids,evaluated_path,capability
FROM audit_events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY id DESC LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	events := make([]AuditEvent, 0, query.Limit)
	for rows.Next() {
		var event AuditEvent
		var createdAt, policyIDs string
		if err := rows.Scan(&event.ID, &event.ActorID, &event.ActorType, &event.Action, &event.Resource,
			&event.Result, &event.CorrelationID, &createdAt, &policyIDs, &event.EvaluatedPath,
			&event.Capability); err != nil {
			return nil, false, err
		}
		event.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		if err := json.Unmarshal([]byte(policyIDs), &event.PolicyIDs); err != nil {
			event.PolicyIDs = []string{}
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

func (s *Store) GetConnection(ctx context.Context, requestID string) (Connection, error) {
	var connection Connection
	var expires, created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT request_id,invite_id,issuer_node_id,target_node_id,
invite_token_encrypted,issuer_fingerprint,status,expires_at,created_at,updated_at FROM connections WHERE request_id=?`, requestID).
		Scan(&connection.RequestID, &connection.InviteID, &connection.IssuerNodeID, &connection.TargetNodeID,
			&connection.InviteTokenEncrypted, &connection.IssuerFingerprint, &connection.Status,
			&expires, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return connection, ErrNotFound
	}
	connection.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	connection.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	connection.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return connection, err
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
