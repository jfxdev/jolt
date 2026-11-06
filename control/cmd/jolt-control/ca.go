package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/recovery"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const rootPasswordVariable = "JOLT_ROOT_KEY_PASSWORD"

const caUsage = `usage: jolt-control ca <command> [flags]

commands:
  status              show the roots, intermediates and whether the root key is in the database
  export-root         write the root key to a password-protected file and remove it from the database
  import-root         put the root key back in the database from that file
  renew-intermediate  issue the next intermediate using the file, without storing the root key

These work on the database directly, so stop the Control Tower first. The file's
password is read from ` + rootPasswordVariable + ` or ` + rootPasswordVariable + `_FILE.`

// runCA is the offline side of the certificate authority: the few operations a
// person does with the Control Tower stopped, around the root key.
func runCA(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New(caUsage)
	}
	switch arguments[0] {
	case "status":
		return caStatus(arguments[1:])
	case "export-root":
		return caExportRoot(arguments[1:])
	case "import-root":
		return caImportRoot(arguments[1:])
	case "renew-intermediate":
		return caRenewIntermediate(arguments[1:])
	default:
		return fmt.Errorf("unknown ca command %q\n%s", arguments[0], caUsage)
	}
}

// offlineAuthority opens the database of a stopped Control Tower and builds the
// authority over it. The returned function releases the lock and the database.
func offlineAuthority(dataDir string) (*pki.Manager, func(), error) {
	encryptionKey, err := config.LoadEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	absolute, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, nil, err
	}
	databasePath := filepath.Join(absolute, "control.db")
	if info, err := os.Stat(databasePath); err != nil {
		return nil, nil, fmt.Errorf("open existing Control Tower database: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, nil, errors.New("Control Tower database is not a regular file")
	}
	lock, err := recovery.AcquireLock(absolute)
	if err != nil {
		return nil, nil, fmt.Errorf("%w (stop the Control Tower first)", err)
	}
	storage, err := store.Open(databasePath, encryptionKey)
	if err != nil {
		_ = lock.Close()
		return nil, nil, err
	}
	release := func() {
		_ = storage.Close()
		_ = lock.Close()
	}
	check, err := storage.Metadata(context.Background(), "encryption_key_check")
	if err != nil {
		release()
		return nil, nil, errors.New("database has no encryption-key verification record")
	}
	if plain, err := security.Decrypt(encryptionKey, check); err != nil || plain != security.EncryptionKeyCheck {
		release()
		return nil, nil, errors.New("CONTROL_TOWER_DB_ENCRYPTION_KEY cannot unlock the existing database")
	}
	manager, err := pki.NewManager(storage, pki.Options{Key: encryptionKey})
	if err != nil {
		release()
		return nil, nil, err
	}
	return manager, release, nil
}

func caFlags(name string, arguments []string, set func(*flag.FlagSet)) (dataDir string, err error) {
	flags := flag.NewFlagSet("ca "+name, flag.ContinueOnError)
	dir := flags.String("data-dir", environmentOrDefault("CONTROL_TOWER_DATA_DIR", "./.jolt-control"), "offline Control Tower data directory")
	if set != nil {
		set(flags)
	}
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return *dir, nil
}

func rootPassword() (string, error) {
	password, err := config.SecretValue(rootPasswordVariable)
	if err != nil {
		return "", err
	}
	if len(password) < pki.MinRootPasswordLength {
		return "", fmt.Errorf("%s must contain at least %d characters", rootPasswordVariable, pki.MinRootPasswordLength)
	}
	return password, nil
}

func caStatus(arguments []string) error {
	dataDir, err := caFlags("status", arguments, nil)
	if err != nil {
		return err
	}
	manager, release, err := offlineAuthority(dataDir)
	if err != nil {
		return err
	}
	defer release()
	if err := manager.Ensure(context.Background()); err != nil && !errors.Is(err, pki.ErrRootUnavailable) {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"root_sha256": manager.RootFingerprint(), "root_key_in_database": manager.RootKeyInDatabase(),
		"rotation": manager.Rotation(), "bundle_version": manager.Bundle().Version, "items": manager.Inventory(),
	})
}

func caExportRoot(arguments []string) error {
	var out *string
	var confirm *bool
	dataDir, err := caFlags("export-root", arguments, func(flags *flag.FlagSet) {
		out = flags.String("out", "", "file to write; it must not exist")
		confirm = flags.Bool("confirm-remove-from-database", false, "acknowledge that the database will no longer hold the root key")
	})
	if err != nil {
		return err
	}
	if *out == "" || !*confirm {
		return errors.New("--out and --confirm-remove-from-database are required: after this the root key exists only in that file, and without it and its password the intermediate cannot be renewed")
	}
	password, err := rootPassword()
	if err != nil {
		return err
	}
	manager, release, err := offlineAuthority(dataDir)
	if err != nil {
		return err
	}
	defer release()
	ctx := context.Background()
	data, err := manager.ExportRoot(ctx, password)
	if err != nil {
		return err
	}
	if err := writeNewFile(*out, data); err != nil {
		return err
	}
	// The key leaves the database only after the file on disk, read back,
	// opens with the password.
	onDisk, err := os.ReadFile(*out)
	if err != nil {
		return err
	}
	if err := manager.RemoveRootKey(ctx, onDisk, password); err != nil {
		return fmt.Errorf("the file was written but the key was not removed: %w", err)
	}
	fmt.Fprintln(os.Stderr, "The root key is no longer in the database. Move "+*out+" off this host and keep the password apart from it.")
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "exported", "file": *out, "root_sha256": manager.RootFingerprint(), "root_key_in_database": false})
}

// writeNewFile never replaces a file: an earlier export is the only copy of a
// key.
func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readRootFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, errors.New("not a root key file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others; chmod 600 it first", path)
	}
	return os.ReadFile(path)
}

func caImportRoot(arguments []string) error {
	var in *string
	dataDir, err := caFlags("import-root", arguments, func(flags *flag.FlagSet) {
		in = flags.String("in", "", "root key file written by export-root")
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(*in) == "" {
		return errors.New("--in is required")
	}
	password, err := rootPassword()
	if err != nil {
		return err
	}
	file, err := readRootFile(*in)
	if err != nil {
		return err
	}
	manager, release, err := offlineAuthority(dataDir)
	if err != nil {
		return err
	}
	defer release()
	if err := manager.ImportRoot(context.Background(), file, password); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "imported", "root_sha256": manager.RootFingerprint(), "root_key_in_database": true})
}

func caRenewIntermediate(arguments []string) error {
	var in, reason *string
	var revoke *bool
	dataDir, err := caFlags("renew-intermediate", arguments, func(flags *flag.FlagSet) {
		in = flags.String("root-file", "", "root key file written by export-root")
		revoke = flags.Bool("revoke-previous", false, "also revoke every earlier intermediate, for a leaked issuing key")
		reason = flags.String("reason", "", "why, recorded with the revocation")
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(*in) == "" {
		return errors.New("--root-file is required")
	}
	password, err := rootPassword()
	if err != nil {
		return err
	}
	file, err := readRootFile(*in)
	if err != nil {
		return err
	}
	manager, release, err := offlineAuthority(dataDir)
	if err != nil {
		return err
	}
	defer release()
	if err := manager.RenewIntermediateFromFile(context.Background(), file, password, *revoke, *reason); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "renewed", "revoked_previous": *revoke, "bundle_version": manager.Bundle().Version, "root_key_in_database": manager.RootKeyInDatabase()})
}
