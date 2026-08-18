package recovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	controldb "github.com/jfxdev/jolt/control/internal/database"
	"github.com/jfxdev/jolt/control/internal/security"
)

type DiagnosticIssue struct {
	Severity     string `json:"severity"`
	Code         string `json:"code"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	Message      string `json:"message"`
}

type RestoreDiagnosticReport struct {
	Version                int               `json:"version"`
	Kind                   string            `json:"kind"`
	CheckedAt              time.Time         `json:"checked_at"`
	Status                 string            `json:"status"`
	DatabaseIntegrity      string            `json:"database_integrity"`
	ForeignKeyViolations   int               `json:"foreign_key_violations"`
	EncryptionKeyValid     bool              `json:"encryption_key_valid"`
	EnabledAdminCount      int               `json:"enabled_admin_count"`
	UserCount              int               `json:"user_count"`
	ServiceAccountCount    int               `json:"service_account_count"`
	NodeCount              int               `json:"node_count"`
	NodeCredentialsValid   int               `json:"node_credentials_valid"`
	ConnectionSecretsValid int               `json:"connection_secrets_valid"`
	Issues                 []DiagnosticIssue `json:"issues"`
}

func DiagnoseRestore(ctx context.Context, dataDir string, encryptionKey []byte) (RestoreDiagnosticReport, error) {
	report := RestoreDiagnosticReport{
		Version: 1, Kind: "jolt_control_tower_restore", CheckedAt: time.Now().UTC(),
		Status: "ok", Issues: []DiagnosticIssue{},
	}
	lock, err := AcquireLock(dataDir)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	database, err := openDiagnosticDatabase(filepath.Join(dataDir, "control.db"), encryptionKey)
	if err != nil {
		if errors.Is(err, controldb.ErrCannotUnlock) {
			report.add("error", "encryption_key_invalid", "encryption_key", "",
				"provided encryption key cannot unlock the restored database")
		} else {
			report.add("error", "database_unavailable", "database", "control.db", err.Error())
		}
		report.finalize()
		return report, nil
	}
	defer database.Close()
	report.DatabaseIntegrity, err = databaseIntegrity(ctx, database)
	if err != nil {
		report.add("error", "database_integrity_failed", "database", "control.db", err.Error())
	}
	report.ForeignKeyViolations, err = foreignKeyViolations(ctx, database)
	if err != nil {
		report.add("error", "foreign_key_check_failed", "database", "control.db", err.Error())
	} else if report.ForeignKeyViolations > 0 {
		report.add("error", "foreign_key_violations", "database", "control.db",
			fmt.Sprintf("%d foreign key violation(s) found", report.ForeignKeyViolations))
	}
	var encryptedCheck string
	if err := database.QueryRowContext(ctx,
		`SELECT value FROM metadata WHERE key='encryption_key_check'`).Scan(&encryptedCheck); err != nil {
		report.add("error", "encryption_key_check_missing", "database", "metadata",
			"database does not contain the encryption-key validation record")
	} else if decrypted, err := security.Decrypt(encryptionKey, encryptedCheck); err != nil || decrypted != security.EncryptionKeyCheck {
		report.add("error", "encryption_key_invalid", "encryption_key", "",
			"provided encryption key cannot unlock the restored database")
	} else {
		report.EncryptionKeyValid = true
	}
	report.UserCount = countQuery(ctx, database, `SELECT COUNT(*) FROM users`, &report, "users")
	report.ServiceAccountCount = countQuery(ctx, database,
		`SELECT COUNT(*) FROM service_accounts`, &report, "service_accounts")
	report.NodeCount = countQuery(ctx, database, `SELECT COUNT(*) FROM nodes`, &report, "nodes")
	report.EnabledAdminCount = countQuery(ctx, database,
		`SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1`, &report, "enabled_admins")
	if report.EnabledAdminCount == 0 {
		report.add("error", "enabled_admin_missing", "user", "",
			"restored Control Tower has no enabled administrator")
	}
	validateAdminHashes(ctx, database, &report)
	validateEncryptedColumn(ctx, database,
		`SELECT id,token_encrypted FROM nodes ORDER BY id`, "node", encryptionKey,
		&report.NodeCredentialsValid, &report)
	validateEncryptedColumn(ctx, database,
		`SELECT request_id,invite_token_encrypted FROM connections
WHERE status NOT IN ('rejected','expired') ORDER BY request_id`,
		"connection", encryptionKey, &report.ConnectionSecretsValid, &report)
	report.finalize()
	return report, nil
}

func validateAdminHashes(ctx context.Context, database *sql.DB, report *RestoreDiagnosticReport) {
	rows, err := database.QueryContext(ctx,
		`SELECT id,password_hash FROM users WHERE role='admin' AND enabled=1`)
	if err != nil {
		report.add("error", "admin_credentials_unreadable", "database", "users", err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, passwordHash string
		if err := rows.Scan(&id, &passwordHash); err != nil {
			report.add("error", "admin_credential_unreadable", "user", id, err.Error())
			continue
		}
		if !strings.HasPrefix(passwordHash, "$argon2id$") {
			report.add("error", "admin_password_hash_invalid", "user", id,
				"enabled administrator does not have a valid Argon2id password hash")
		}
	}
	if err := rows.Err(); err != nil {
		report.add("error", "admin_credentials_unreadable", "database", "users", err.Error())
	}
}

func openDiagnosticDatabase(path string, encryptionKey []byte) (*sql.DB, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("database is not a regular file")
	}
	return controldb.Open(path, encryptionKey, true)
}

func databaseIntegrity(ctx context.Context, database *sql.DB) (string, error) {
	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return "", err
	}
	if result != "ok" {
		return result, fmt.Errorf("integrity check returned %s", result)
	}
	return result, nil
}

func foreignKeyViolations(ctx context.Context, database *sql.DB) (int, error) {
	rows, err := database.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

func countQuery(ctx context.Context, database *sql.DB, query string,
	report *RestoreDiagnosticReport, resource string) int {
	var count int
	if err := database.QueryRowContext(ctx, query).Scan(&count); err != nil {
		report.add("error", "resource_count_failed", "database", resource, err.Error())
	}
	return count
}

func validateEncryptedColumn(ctx context.Context, database *sql.DB, query, resourceType string,
	key []byte, validCount *int, report *RestoreDiagnosticReport) {
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		report.add("error", "encrypted_resources_unreadable", "database", resourceType, err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, encrypted string
		if err := rows.Scan(&id, &encrypted); err != nil {
			report.add("error", "encrypted_resource_unreadable", resourceType, id, err.Error())
			continue
		}
		plaintext, err := security.Decrypt(key, encrypted)
		if err != nil || plaintext == "" {
			report.add("error", "encrypted_resource_invalid", resourceType, id,
				"encrypted credential cannot be recovered with the provided key")
			continue
		}
		*validCount++
	}
	if err := rows.Err(); err != nil {
		report.add("error", "encrypted_resources_unreadable", "database", resourceType, err.Error())
	}
}

func (r *RestoreDiagnosticReport) add(severity, code, resourceType, resourceID, message string) {
	r.Issues = append(r.Issues, DiagnosticIssue{
		Severity: severity, Code: code, ResourceType: resourceType,
		ResourceID: resourceID, Message: message,
	})
}

func (r *RestoreDiagnosticReport) finalize() {
	r.Status = "ok"
	for _, issue := range r.Issues {
		if issue.Severity == "error" {
			r.Status = "error"
			return
		}
		if issue.Severity == "warning" {
			r.Status = "warning"
		}
	}
}
