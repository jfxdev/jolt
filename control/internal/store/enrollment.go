package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Enrollment states.
const (
	EnrollmentPending  = "pending"
	EnrollmentIssued   = "issued"
	EnrollmentRejected = "rejected"
	EnrollmentExpired  = "expired"

	// EnrollmentLifetime is how long a pending enrollment waits for a person.
	EnrollmentLifetime = 15 * time.Minute
	maxPendingEnroll   = 20
)

var (
	// ErrTokenUsed means a join token was already spent; the enrollment it
	// started is in the returned token.
	ErrTokenUsed = errors.New("join token already used")
	// ErrTooManyEnrollments means too many enrollments already wait.
	ErrTooManyEnrollments = errors.New("too many pending enrollments")
)

// JoinToken lets one node enroll once. Only a hash of the secret is kept.
type JoinToken struct {
	ID           string     `json:"token_id"`
	SecretHash   string     `json:"-"`
	NodeName     string     `json:"node_name"`
	Approval     string     `json:"approval"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	EnrollmentID string     `json:"enrollment_id,omitempty"`
}

// Enrollment is one node's request to join.
type Enrollment struct {
	ID                   string     `json:"enrollment_id"`
	TokenID              string     `json:"token_id"`
	State                string     `json:"state"`
	NodeName             string     `json:"node_name"`
	NodeID               string     `json:"node_id"`
	NodeFingerprint      string     `json:"node_fingerprint"`
	APIEndpoint          string     `json:"api_endpoint"`
	RemoteAddr           string     `json:"remote_addr"`
	CSRPEM               string     `json:"-"`
	CSRHash              string     `json:"-"`
	OperationalEncrypted string     `json:"-"`
	PollHash             string     `json:"-"`
	DecidedBy            string     `json:"decided_by,omitempty"`
	Note                 string     `json:"note,omitempty"`
	Response             string     `json:"-"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	DecidedAt            *time.Time `json:"decided_at,omitempty"`
}

// ManagedNode is what the Control Tower knows about a node it enrolled.
type ManagedNode struct {
	NodeID        string    `json:"node_id"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	BundleVersion int64     `json:"bundle_version"`
	CertSerial    string    `json:"cert_serial"`
	CertNotBefore time.Time `json:"cert_not_before"`
	CertNotAfter  time.Time `json:"cert_not_after"`
	// CertFingerprint is the SHA-256 of the API certificate the Control Tower
	// issued, and CertIssuer the serial of the intermediate that signed it.
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	CertIssuer      string `json:"cert_issuer,omitempty"`
	// AuthMode is what the node reports it authenticates the Control Tower by:
	// "token" or "certificate". Empty until the first sync.
	AuthMode    string     `json:"auth_mode,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func parseTimePtr(value string) *time.Time {
	if value == "" {
		return nil
	}
	parsed := parseTime(value)
	return &parsed
}

const raiseVersion = `INSERT INTO metadata(key,value) VALUES('minimum_security_version','10') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<10 THEN '10' ELSE value END`

// CreateJoinToken stores a new token. The first one raises the database's
// minimum security version: an older binary would not know to enroll or renew.
func (s *Store) CreateJoinToken(ctx context.Context, token JoinToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, raiseVersion); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO join_tokens(id,secret_hash,node_name,approval,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		token.ID, token.SecretHash, token.NodeName, token.Approval, token.CreatedBy, formatTime(token.CreatedAt), formatTime(token.ExpiresAt))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ListJoinTokens returns the newest tokens first.
func (s *Store) ListJoinTokens(ctx context.Context, limit int) ([]JoinToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,secret_hash,node_name,approval,created_by,created_at,expires_at,used_at,enrollment_id FROM join_tokens ORDER BY created_at DESC, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JoinToken
	for rows.Next() {
		var token JoinToken
		var created, expires, used string
		if err := rows.Scan(&token.ID, &token.SecretHash, &token.NodeName, &token.Approval, &token.CreatedBy, &created, &expires, &used, &token.EnrollmentID); err != nil {
			return nil, err
		}
		token.CreatedAt, token.ExpiresAt, token.UsedAt = parseTime(created), parseTime(expires), parseTimePtr(used)
		out = append(out, token)
	}
	return out, rows.Err()
}

// RevokeJoinToken removes a token that has not been used. A spent token stays,
// because the audit trail needs to say which enrollment it started.
func (s *Store) RevokeJoinToken(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM join_tokens WHERE id=? AND used_at=''`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

// StartEnrollment spends a token and records the enrollment it starts, in one
// step. Every way a token can be wrong (unknown, expired, for another name)
// answers ErrNotFound, so a guess learns nothing; a token already spent answers
// ErrTokenUsed with the enrollment it started, which lets a retry of the same
// request be recognised.
func (s *Store) StartEnrollment(ctx context.Context, secretHash string, enrollment Enrollment, now time.Time) (JoinToken, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JoinToken{}, err
	}
	defer tx.Rollback()
	var token JoinToken
	var created, expires, used string
	err = tx.QueryRowContext(ctx, `SELECT id,secret_hash,node_name,approval,created_by,created_at,expires_at,used_at,enrollment_id FROM join_tokens WHERE secret_hash=?`, secretHash).
		Scan(&token.ID, &token.SecretHash, &token.NodeName, &token.Approval, &token.CreatedBy, &created, &expires, &used, &token.EnrollmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return JoinToken{}, ErrNotFound
	}
	if err != nil {
		return JoinToken{}, err
	}
	token.CreatedAt, token.ExpiresAt, token.UsedAt = parseTime(created), parseTime(expires), parseTimePtr(used)
	if token.NodeName != enrollment.NodeName {
		return JoinToken{}, ErrNotFound
	}
	if used != "" {
		return token, ErrTokenUsed
	}
	if !now.Before(token.ExpiresAt) {
		return JoinToken{}, ErrNotFound
	}
	if enrollment.State == EnrollmentPending {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrollments WHERE state='pending' AND expires_at>?`, formatTime(now)).Scan(&pending); err != nil {
			return JoinToken{}, err
		}
		if pending >= maxPendingEnroll {
			return JoinToken{}, ErrTooManyEnrollments
		}
	}
	if _, err := tx.ExecContext(ctx, raiseVersion); err != nil {
		return JoinToken{}, err
	}
	enrollment.TokenID = token.ID
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollments(id,token_id,state,node_name,node_id,node_fingerprint,api_endpoint,remote_addr,csr_pem,csr_hash,operational_encrypted,poll_hash,decided_by,note,response,created_at,expires_at,decided_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		enrollment.ID, enrollment.TokenID, enrollment.State, enrollment.NodeName, enrollment.NodeID, enrollment.NodeFingerprint, enrollment.APIEndpoint, enrollment.RemoteAddr,
		enrollment.CSRPEM, enrollment.CSRHash, enrollment.OperationalEncrypted, enrollment.PollHash, enrollment.DecidedBy, enrollment.Note, enrollment.Response,
		formatTime(enrollment.CreatedAt), formatTime(enrollment.ExpiresAt), ""); err != nil {
		return JoinToken{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE join_tokens SET used_at=?, enrollment_id=? WHERE id=?`, formatTime(now), enrollment.ID, token.ID); err != nil {
		return JoinToken{}, err
	}
	used2 := now
	token.UsedAt, token.EnrollmentID = &used2, enrollment.ID
	return token, tx.Commit()
}

const enrollmentColumns = `id,token_id,state,node_name,node_id,node_fingerprint,api_endpoint,remote_addr,csr_pem,csr_hash,operational_encrypted,poll_hash,decided_by,note,response,created_at,expires_at,decided_at`

func scanEnrollment(row interface{ Scan(...any) error }) (Enrollment, error) {
	var e Enrollment
	var created, expires, decided string
	err := row.Scan(&e.ID, &e.TokenID, &e.State, &e.NodeName, &e.NodeID, &e.NodeFingerprint, &e.APIEndpoint, &e.RemoteAddr, &e.CSRPEM, &e.CSRHash, &e.OperationalEncrypted,
		&e.PollHash, &e.DecidedBy, &e.Note, &e.Response, &created, &expires, &decided)
	e.CreatedAt, e.ExpiresAt, e.DecidedAt = parseTime(created), parseTime(expires), parseTimePtr(decided)
	return e, err
}

// GetEnrollment returns one enrollment. A pending one past its time reads as
// expired, without waiting for the sweep.
func (s *Store) GetEnrollment(ctx context.Context, id string, now time.Time) (Enrollment, error) {
	e, err := scanEnrollment(s.db.QueryRowContext(ctx, `SELECT `+enrollmentColumns+` FROM enrollments WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, ErrNotFound
	}
	if err == nil && e.State == EnrollmentPending && !now.Before(e.ExpiresAt) {
		e.State = EnrollmentExpired
	}
	return e, err
}

// ListEnrollments returns enrollments in a state ("" for all), newest first.
func (s *Store) ListEnrollments(ctx context.Context, state string, limit int, now time.Time) ([]Enrollment, error) {
	query := `SELECT ` + enrollmentColumns + ` FROM enrollments`
	var args []any
	if state != "" {
		query += ` WHERE state=?`
		args = append(args, state)
	}
	query += ` ORDER BY created_at DESC, id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		if e.State == EnrollmentPending && !now.Before(e.ExpiresAt) {
			e.State = EnrollmentExpired
		}
		if state == "" || e.State == state {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// DecideEnrollment moves a pending enrollment to its outcome, once. A second
// decision, or one after the time ran out, answers ErrConflict.
func (s *Store) DecideEnrollment(ctx context.Context, id, state, by, note, response string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE enrollments SET state=?, decided_by=?, note=?, response=?, decided_at=?, csr_pem=CASE WHEN ?='issued' THEN '' ELSE csr_pem END
WHERE id=? AND state='pending' AND expires_at>?`, state, by, note, response, formatTime(now), state, id, formatTime(now))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrConflict
	}
	return nil
}

// ReplacePollSecret gives a pending enrollment a new poll secret, for a retry
// of the request that started it.
func (s *Store) ReplacePollSecret(ctx context.Context, id, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enrollments SET poll_hash=? WHERE id=? AND state='pending'`, hash, id)
	return err
}

// ExpireEnrollments marks pending enrollments past their time as expired and
// drops what they held for approval.
func (s *Store) ExpireEnrollments(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE enrollments SET state='expired', csr_pem='', operational_encrypted='', decided_at=? WHERE state='pending' AND expires_at<=?`, formatTime(now), formatTime(now))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// SaveManagedNode records or updates a node the Control Tower enrolled.
func (s *Store) SaveManagedNode(ctx context.Context, node ManagedNode) error {
	last := ""
	if node.LastErrorAt != nil {
		last = formatTime(*node.LastErrorAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO managed_nodes(node_id,enrolled_at,bundle_version,cert_serial,cert_not_before,cert_not_after,last_error,last_error_at,cert_fingerprint,cert_issuer,auth_mode)
VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET bundle_version=excluded.bundle_version, cert_serial=excluded.cert_serial,
cert_not_before=excluded.cert_not_before, cert_not_after=excluded.cert_not_after, last_error=excluded.last_error, last_error_at=excluded.last_error_at,
cert_fingerprint=excluded.cert_fingerprint, cert_issuer=excluded.cert_issuer, auth_mode=excluded.auth_mode`,
		node.NodeID, formatTime(node.EnrolledAt), node.BundleVersion, node.CertSerial, formatTime(node.CertNotBefore), formatTime(node.CertNotAfter), node.LastError, last,
		node.CertFingerprint, node.CertIssuer, node.AuthMode)
	return err
}

// ListManagedNodes returns every enrolled node.
func (s *Store) ListManagedNodes(ctx context.Context) ([]ManagedNode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,enrolled_at,bundle_version,cert_serial,cert_not_before,cert_not_after,last_error,last_error_at,cert_fingerprint,cert_issuer,auth_mode FROM managed_nodes ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagedNode
	for rows.Next() {
		var node ManagedNode
		var enrolled, before, after, last string
		if err := rows.Scan(&node.NodeID, &enrolled, &node.BundleVersion, &node.CertSerial, &before, &after, &node.LastError, &last, &node.CertFingerprint, &node.CertIssuer, &node.AuthMode); err != nil {
			return nil, err
		}
		node.EnrolledAt, node.CertNotBefore, node.CertNotAfter, node.LastErrorAt = parseTime(enrolled), parseTime(before), parseTime(after), parseTimePtr(last)
		out = append(out, node)
	}
	return out, rows.Err()
}
