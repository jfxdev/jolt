package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestOpenCreatesEncryptedDatabaseAndRejectsWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	database, err := Open(path, testKey, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE secret(value TEXT); INSERT INTO secret(value) VALUES('classified')`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	plaintext, err := IsPlaintext(path)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext {
		t.Fatal("new SQLCipher database has a plaintext SQLite header")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if stringContains(contents, []byte("classified")) {
		t.Fatal("database file contains the inserted plaintext value")
	}
	wrongKey := []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if unlocked, err := Open(path, wrongKey, false); err == nil {
		unlocked.Close()
		t.Fatal("encrypted database opened with the wrong key")
	}
}

func TestMigratePlaintextDatabaseAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	plaintext, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plaintext.Exec(`CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT);
INSERT INTO records(value) VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	if err := plaintext.Close(); err != nil {
		t.Fatal(err)
	}
	if encrypted, err := Open(path, testKey, false); !errors.Is(err, ErrPlaintextDatabase) {
		if encrypted != nil {
			encrypted.Close()
		}
		t.Fatalf("plaintext open error=%v, want ErrPlaintextDatabase", err)
	}
	if err := MigratePlaintext(context.Background(), path, testKey); err != nil {
		t.Fatal(err)
	}
	database, err := Open(path, testKey, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value string
	if err := database.QueryRow(`SELECT value FROM records WHERE id=1`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "preserved" {
		t.Fatalf("migrated value=%q", value)
	}
	if _, err := os.Stat(path + ".plaintext-migration"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext migration source still exists: %v", err)
	}
}

func stringContains(value, fragment []byte) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		match := true
		for offset := range fragment {
			if value[index+offset] != fragment[offset] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
