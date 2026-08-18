package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/database"
	"github.com/jfxdev/jolt/control/internal/httpapi"
	"github.com/jfxdev/jolt/control/internal/recovery"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "snapshot" {
		if err := runSnapshot(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "snapshot failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "restore-diagnostics" {
		if err := runRestoreDiagnostics(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "restore diagnostics failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "recover-admin" {
		if err := runRecoverAdmin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "administrator recovery failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "recover-node-token" {
		if err := runRecoverNodeToken(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "node token recovery failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "encrypt-database" {
		if err := runEncryptDatabase(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "database encryption migration failed:", err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		logger.Error("create data directory", "error", err)
		os.Exit(1)
	}
	instanceLock, err := recovery.AcquireLock(cfg.DataDir)
	if err != nil {
		logger.Error("acquire instance lock", "error", err)
		os.Exit(1)
	}
	defer instanceLock.Close()
	storage, err := store.Open(filepath.Join(cfg.DataDir, "control.db"), cfg.EncryptionKey)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer storage.Close()
	storedCheck, checkErr := storage.Metadata(context.Background(), "encryption_key_check")
	if errors.Is(checkErr, store.ErrNotFound) {
		encryptedCheck, encryptErr := security.Encrypt(cfg.EncryptionKey, security.EncryptionKeyCheck)
		if encryptErr != nil || storage.SetMetadata(context.Background(), "encryption_key_check", encryptedCheck) != nil {
			logger.Error("initialize encryption key check")
			os.Exit(1)
		}
	} else if checkErr != nil {
		logger.Error("read encryption key check", "error", checkErr)
		os.Exit(1)
	} else {
		decryptedCheck, decryptErr := security.Decrypt(cfg.EncryptionKey, storedCheck)
		if decryptErr != nil || decryptedCheck != security.EncryptionKeyCheck {
			logger.Error("CONTROL_TOWER_DB_ENCRYPTION_KEY cannot unlock the existing database")
			os.Exit(1)
		}
	}
	passwordHash, err := security.HashPassword(cfg.AdminPassword)
	if err != nil {
		logger.Error("hash bootstrap password", "error", err)
		os.Exit(1)
	}
	if err := storage.EnsureAdmin(context.Background(), "usr_admin", cfg.AdminUsername, passwordHash); err != nil {
		logger.Error("bootstrap admin", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           httpapi.New(cfg, storage, logger),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		logger.Info("jolt control tower started", "address", cfg.Address)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

func runSnapshot(arguments []string) error {
	flags := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	dataDir := flags.String("data-dir",
		environmentOrDefault("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		"Control Tower data directory")
	output := flags.String("output", "", "destination .tar.gz file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if strings.TrimSpace(*output) == "" {
		return errors.New("--output is required")
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	encryptionKey, err := config.ParseEncryptionKey(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	manifest, err := recovery.CreateSnapshot(context.Background(), absoluteData, absoluteOutput, encryptionKey)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}

func runRestoreDiagnostics(arguments []string) error {
	flags := flag.NewFlagSet("restore-diagnostics", flag.ContinueOnError)
	dataDir := flags.String("data-dir",
		environmentOrDefault("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		"restored Control Tower data directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	encryptionKey, err := config.ParseEncryptionKey(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	report, err := recovery.DiagnoseRestore(context.Background(), absoluteData, encryptionKey)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	if report.Status == "error" {
		return errors.New("blocking inconsistencies were found")
	}
	return nil
}

func runRecoverAdmin(arguments []string) error {
	flags := flag.NewFlagSet("recover-admin", flag.ContinueOnError)
	dataDir := flags.String("data-dir",
		environmentOrDefault("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		"offline Control Tower data directory")
	username := flags.String("username", "", "administrator username to recover or create")
	confirmation := flags.String("confirm-username", "", "must exactly match --username")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	*username = strings.TrimSpace(*username)
	if *username == "" || *confirmation != *username {
		return errors.New("--username and an exact matching --confirm-username are required")
	}
	if !validRecoveryUsername(*username) {
		return errors.New("username must be 3-64 characters using letters, numbers, dot, underscore, or hyphen")
	}
	password := os.Getenv("CONTROL_TOWER_RECOVERY_ADMIN_PASSWORD")
	if len(password) < 12 {
		return errors.New("CONTROL_TOWER_RECOVERY_ADMIN_PASSWORD must contain at least 12 characters")
	}
	encryptionKey, err := config.ParseEncryptionKey(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	databasePath := filepath.Join(absoluteData, "control.db")
	if info, err := os.Stat(databasePath); err != nil {
		return fmt.Errorf("open existing Control Tower database: %w", err)
	} else if !info.Mode().IsRegular() {
		return errors.New("Control Tower database is not a regular file")
	}
	instanceLock, err := recovery.AcquireLock(absoluteData)
	if err != nil {
		return err
	}
	defer instanceLock.Close()
	storage, err := store.Open(databasePath, encryptionKey)
	if err != nil {
		return err
	}
	defer storage.Close()
	keyCheck, err := storage.Metadata(context.Background(), "encryption_key_check")
	if err != nil {
		return errors.New("database has no encryption-key verification record")
	}
	plainCheck, err := security.Decrypt(encryptionKey, keyCheck)
	if err != nil || plainCheck != security.EncryptionKeyCheck {
		return errors.New("CONTROL_TOWER_DB_ENCRYPTION_KEY cannot unlock the existing database")
	}
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	correlationID, err := recoveryCorrelationID()
	if err != nil {
		return err
	}
	userID, err := recoveryUserID()
	if err != nil {
		return err
	}
	result, err := storage.EmergencyRecoverAdmin(context.Background(), userID, *username,
		passwordHash, correlationID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "recovered", "username": result.User.Username, "user_id": result.User.ID,
		"created": result.Created, "revoked_sessions": result.RevokedSessions,
		"correlation_id": correlationID,
	})
}

func runRecoverNodeToken(arguments []string) error {
	flags := flag.NewFlagSet("recover-node-token", flag.ContinueOnError)
	dataDir := flags.String("data-dir",
		environmentOrDefault("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		"offline Control Tower data directory")
	nodeID := flags.String("node-id", "", "registered node_id whose token must be replaced")
	confirmation := flags.String("confirm-node-id", "", "must exactly match --node-id")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	*nodeID = strings.TrimSpace(*nodeID)
	if *nodeID == "" || *confirmation != *nodeID {
		return errors.New("--node-id and an exact matching --confirm-node-id are required")
	}
	token := strings.TrimSpace(os.Getenv("CONTROL_TOWER_RECOVERY_NODE_TOKEN"))
	if len(token) < 32 {
		return errors.New("CONTROL_TOWER_RECOVERY_NODE_TOKEN must contain at least 32 characters")
	}
	encryptionKey, err := config.ParseEncryptionKey(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	databasePath := filepath.Join(absoluteData, "control.db")
	if info, err := os.Stat(databasePath); err != nil {
		return fmt.Errorf("open existing Control Tower database: %w", err)
	} else if !info.Mode().IsRegular() {
		return errors.New("Control Tower database is not a regular file")
	}
	instanceLock, err := recovery.AcquireLock(absoluteData)
	if err != nil {
		return err
	}
	defer instanceLock.Close()
	storage, err := store.Open(databasePath, encryptionKey)
	if err != nil {
		return err
	}
	defer storage.Close()
	keyCheck, err := storage.Metadata(context.Background(), "encryption_key_check")
	if err != nil {
		return errors.New("database has no encryption-key verification record")
	}
	plainCheck, err := security.Decrypt(encryptionKey, keyCheck)
	if err != nil || plainCheck != security.EncryptionKeyCheck {
		return errors.New("CONTROL_TOWER_DB_ENCRYPTION_KEY cannot unlock the existing database")
	}
	encryptedToken, err := security.Encrypt(encryptionKey, token)
	if err != nil {
		return err
	}
	correlationID, err := recoveryCorrelationID()
	if err != nil {
		return err
	}
	node, err := storage.EmergencyReplaceNodeToken(context.Background(), *nodeID, encryptedToken, correlationID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "recovered", "node_id": node.ID, "node_state": node.State,
		"correlation_id": correlationID,
	})
}

func runEncryptDatabase(arguments []string) error {
	flags := flag.NewFlagSet("encrypt-database", flag.ContinueOnError)
	dataDir := flags.String("data-dir",
		environmentOrDefault("CONTROL_TOWER_DATA_DIR", "./.jolt-control"),
		"offline Control Tower data directory")
	confirmation := flags.String("confirm", "",
		`required acknowledgement: "encrypt-control-database"`)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *confirmation != "encrypt-control-database" {
		return errors.New(`--confirm encrypt-control-database is required`)
	}
	encryptionKey, err := config.ParseEncryptionKey(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	databasePath := filepath.Join(absoluteData, "control.db")
	if info, err := os.Stat(databasePath); err != nil {
		return fmt.Errorf("open existing Control Tower database: %w", err)
	} else if !info.Mode().IsRegular() {
		return errors.New("Control Tower database is not a regular file")
	}
	instanceLock, err := recovery.AcquireLock(absoluteData)
	if err != nil {
		return err
	}
	defer instanceLock.Close()
	if err := database.MigratePlaintext(context.Background(), databasePath, encryptionKey); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "encrypted", "database": "control.db", "cipher": "SQLCipher",
		"plaintext_source_removed": true,
	})
}

func validRecoveryUsername(username string) bool {
	if len(username) < 3 || len(username) > 64 {
		return false
	}
	for _, character := range username {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func recoveryCorrelationID() (string, error) {
	value, err := recoveryRandomHex(12)
	if err != nil {
		return "", err
	}
	return "cor_recovery_" + value, nil
}

func recoveryUserID() (string, error) {
	value, err := recoveryRandomHex(12)
	if err != nil {
		return "", err
	}
	return "usr_recovery_" + value, nil
}

func recoveryRandomHex(size int) (string, error) {
	random := make([]byte, size)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

func environmentOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
