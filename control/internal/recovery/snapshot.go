package recovery

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/database"
	"golang.org/x/sys/unix"
)

var ErrInstanceActive = errors.New("jolt Control Tower is running")

const lockName = ".jolt-control.lock"

type Lock struct {
	file *os.File
}

type FileManifest struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version             int            `json:"version"`
	Kind                string         `json:"kind"`
	CreatedAt           time.Time      `json:"created_at"`
	DatabaseIntegrity   string         `json:"database_integrity"`
	ExternalKeyIncluded bool           `json:"external_encryption_key_included"`
	Files               []FileManifest `json:"files"`
}

func AcquireLock(dataDir string) (*Lock, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dataDir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrInstanceActive
		}
		return nil, err
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func CreateSnapshot(ctx context.Context, dataDir, output string, encryptionKey []byte) (Manifest, error) {
	dataDir, output = filepath.Clean(dataDir), filepath.Clean(output)
	if output == "." || output == "" {
		return Manifest{}, errors.New("snapshot output is required")
	}
	if inside(output, dataDir) {
		return Manifest{}, errors.New("snapshot output must be outside the Control Tower data directory")
	}
	if _, err := os.Lstat(output); err == nil {
		return Manifest{}, errors.New("snapshot output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	lock, err := AcquireLock(dataDir)
	if err != nil {
		return Manifest{}, err
	}
	defer lock.Close()

	stage, err := os.MkdirTemp("", "jolt-control-snapshot-*")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return Manifest{}, err
	}
	stageData := filepath.Join(stage, "data")
	if err := os.MkdirAll(stageData, 0o700); err != nil {
		return Manifest{}, err
	}
	integrity, err := snapshotSQLite(ctx, filepath.Join(dataDir, "control.db"),
		filepath.Join(stageData, "control.db"), encryptionKey)
	if err != nil {
		return Manifest{}, err
	}
	if err := copyTree(dataDir, stageData, map[string]bool{
		"control.db": true, "control.db-wal": true, "control.db-shm": true, lockName: true,
	}); err != nil {
		return Manifest{}, fmt.Errorf("stage Control Tower data: %w", err)
	}
	files, err := manifestFiles(stage)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		Version: 1, Kind: "jolt_control_tower", CreatedAt: time.Now().UTC(),
		DatabaseIntegrity: integrity, ExternalKeyIncluded: false, Files: files,
	}
	if err := writeArchiveAtomic(stage, output, manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func snapshotSQLite(ctx context.Context, source, destination string, encryptionKey []byte) (string, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return "", fmt.Errorf("open database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("database is not a regular file")
	}
	database, err := database.Open(source, encryptionKey, false)
	if err != nil {
		return "", err
	}
	defer database.Close()
	var integrity string
	if err := database.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return "", fmt.Errorf("check database integrity: %w", err)
	}
	if integrity != "ok" {
		return "", fmt.Errorf("database integrity check failed: %s", integrity)
	}
	escaped := strings.ReplaceAll(destination, "'", "''")
	if _, err := database.ExecContext(ctx, "VACUUM INTO '"+escaped+"'"); err != nil {
		return "", fmt.Errorf("create consistent database copy: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return "", err
	}
	return integrity, nil
}

func copyTree(source, destination string, excluded map[string]bool) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !sourceInfo.IsDir() {
		return errors.New("snapshot source is not a directory")
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		relative = filepath.ToSlash(relative)
		if excluded[relative] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(relative))
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported snapshot entry %s", relative)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		syncErr := output.Sync()
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		for _, candidate := range []error{copyErr, syncErr, closeOutputErr, closeInputErr} {
			if candidate != nil {
				return candidate
			}
		}
		return nil
	})
}

func manifestFiles(root string) ([]FileManifest, error) {
	files := []FileManifest{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported staged entry %s", path)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, hashErr := io.Copy(hash, input)
		closeErr := input.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, FileManifest{
			Path: filepath.ToSlash(relative), Size: info.Size(), Mode: uint32(info.Mode().Perm()),
			SHA256: strings.ToUpper(hex.EncodeToString(hash.Sum(nil))),
		})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

func writeArchiveAtomic(stage, output string, manifest Manifest) error {
	parent := filepath.Dir(output)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(parent, ".jolt-control-snapshot-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	gzipWriter := gzip.NewWriter(temp)
	tarWriter := tar.NewWriter(gzipWriter)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err == nil {
		err = tarWriter.WriteHeader(&tar.Header{
			Name: "manifest.json", Mode: 0o600, Size: int64(len(manifestBytes)),
			ModTime: manifest.CreatedAt,
		})
	}
	if err == nil {
		_, err = tarWriter.Write(manifestBytes)
	}
	if err == nil {
		err = addTreeToArchive(tarWriter, stage, manifest.CreatedAt)
	}
	for _, closeErr := range []error{tarWriter.Close(), gzipWriter.Close()} {
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tempName, output); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.New("snapshot output already exists")
		}
		return fmt.Errorf("publish snapshot: %w", err)
	}
	return nil
}

func addTreeToArchive(writer *tar.Writer, root string, modTime time.Time) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || path == root {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name, header.ModTime = filepath.ToSlash(relative), modTime
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(writer, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
		return nil
	})
}

func inside(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && (relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}
