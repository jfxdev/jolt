package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

var (
	ErrInvalidKey        = errors.New("database encryption key must contain exactly 32 bytes")
	ErrPlaintextDatabase = errors.New("plaintext SQLite database requires offline encryption migration")
	ErrNotSQLCipher      = errors.New("SQLite driver does not provide SQLCipher")
	ErrCannotUnlock      = errors.New("cannot unlock SQLCipher database")
)

const sqliteHeader = "SQLite format 3\x00"

func Open(path string, key []byte, readOnly bool) (*sql.DB, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	plaintext, err := IsPlaintext(path)
	if err != nil {
		return nil, err
	}
	if plaintext {
		return nil, ErrPlaintextDatabase
	}
	database, err := sql.Open("sqlite3", encryptedDSN(path, key, readOnly))
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	if err := verifyCipher(database); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func IsPlaintext(path string) (bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	header := make([]byte, len(sqliteHeader))
	count, err := file.Read(header)
	if err != nil && count == 0 {
		return false, err
	}
	return count == len(header) && bytes.Equal(header, []byte(sqliteHeader)), nil
}

func MigratePlaintext(ctx context.Context, path string, key []byte) error {
	if len(key) != 32 {
		return ErrInvalidKey
	}
	plaintext, err := IsPlaintext(path)
	if err != nil {
		return err
	}
	if !plaintext {
		return errors.New("database is not a plaintext SQLite database")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".control.db.encrypted-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryPath)
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)

	source, err := sql.Open("sqlite3", plaintextDSN(path))
	if err != nil {
		return err
	}
	source.SetMaxOpenConns(1)
	defer source.Close()
	if err := ensureCipherAvailable(source); err != nil {
		return err
	}
	escapedPath := strings.ReplaceAll(temporaryPath, "'", "''")
	rawKey := hex.EncodeToString(key)
	if _, err := source.ExecContext(ctx, "ATTACH DATABASE '"+escapedPath+"' AS encrypted KEY \"x'"+rawKey+"'\""); err != nil {
		return fmt.Errorf("attach encrypted migration target: %w", err)
	}
	attached := true
	defer func() {
		if attached {
			_, _ = source.Exec("DETACH DATABASE encrypted")
		}
	}()
	if _, err := source.ExecContext(ctx, "SELECT sqlcipher_export('encrypted')"); err != nil {
		return fmt.Errorf("export plaintext database: %w", err)
	}
	if _, err := source.ExecContext(ctx, "DETACH DATABASE encrypted"); err != nil {
		return fmt.Errorf("detach encrypted migration target: %w", err)
	}
	attached = false
	if err := source.Close(); err != nil {
		return err
	}

	encrypted, err := Open(temporaryPath, key, false)
	if err != nil {
		return fmt.Errorf("validate encrypted migration target: %w", err)
	}
	var integrity string
	if err := encrypted.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		encrypted.Close()
		return fmt.Errorf("validate encrypted database integrity: %w", err)
	}
	if integrity != "ok" {
		encrypted.Close()
		return fmt.Errorf("encrypted database integrity check returned %s", integrity)
	}
	if err := encrypted.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	if err := syncFile(temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func encryptedDSN(path string, key []byte, readOnly bool) string {
	values := url.Values{
		"_pragma_key":              {fmt.Sprintf("x'%s'", hex.EncodeToString(key))},
		"_pragma_cipher_page_size": {"4096"},
	}
	if readOnly {
		values.Set("mode", "ro")
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: values.Encode()}).String()
}

func plaintextDSN(path string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
}

func verifyCipher(database *sql.DB) error {
	if err := ensureCipherAvailable(database); err != nil {
		if !errors.Is(err, ErrNotSQLCipher) {
			return fmt.Errorf("%w: %v", ErrCannotUnlock, err)
		}
		return err
	}
	if _, err := database.Exec("PRAGMA cipher_memory_security=ON"); err != nil {
		return err
	}
	var tables int
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master").Scan(&tables); err != nil {
		return fmt.Errorf("%w: %v", ErrCannotUnlock, err)
	}
	return nil
}

func ensureCipherAvailable(database *sql.DB) error {
	var version string
	if err := database.QueryRow("PRAGMA cipher_version").Scan(&version); err != nil {
		return fmt.Errorf("query SQLCipher version: %w", err)
	}
	if strings.TrimSpace(version) == "" {
		return ErrNotSQLCipher
	}
	return nil
}

func syncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
