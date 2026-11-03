package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"path/filepath"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"golang.org/x/sys/unix"
)

// TreeSnapshot is an internal building block for destructive operation plans.
// It neither authorizes nor confirms an operation. A future plan must bind the
// snapshot to the subject, operation, destination and a one-use token.
type TreeSnapshot struct {
	Version     int    `json:"version"`
	Digest      string `json:"digest"`
	Files       int64  `json:"files"`
	Directories int64  `json:"directories"`
	Bytes       int64  `json:"bytes"`
}

type treeEntryIdentity struct {
	Path           string
	Device, Inode  uint64
	Mode, UID, GID uint32
	Links          uint64
	Size           int64
	ModifiedSec    int64
	ModifiedNsec   int64
	ChangedSec     int64
	ChangedNsec    int64
}

func treeEntryFromInfo(relative string, info fs.FileInfo) (treeEntryIdentity, error) {
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || stat == nil {
		return treeEntryIdentity{}, ErrInvalid
	}
	return treeEntryIdentity{Path: base64.RawStdEncoding.EncodeToString([]byte(relative)), Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Mode: uint32(stat.Mode), UID: stat.Uid, GID: stat.Gid, Links: uint64(stat.Nlink), Size: stat.Size, ModifiedSec: stat.Mtim.Sec, ModifiedNsec: stat.Mtim.Nsec, ChangedSec: stat.Ctim.Sec, ChangedNsec: stat.Ctim.Nsec}, nil
}

// SnapshotDestructiveTree reads a directory without following symlinks and
// rejects hidden entries. It fails if a visited entry changes while scanning.
// External processes can still mutate the tree after this function returns;
// callers must revalidate before mutation and handle subsequent changes.
func (s *Service) SnapshotDestructiveTree(ctx context.Context, mountID, relative string) (TreeSnapshot, error) {
	if relative == "" || strings.TrimSpace(relative) != relative || strings.ContainsAny(relative, "\\\x00") || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return TreeSnapshot{}, fmt.Errorf("%w: tree path must be canonical and inside the mount", ErrInvalid)
	}
	mount, root, err := s.resolvePath(ctx, mountID, relative, false, true)
	if err != nil {
		return TreeSnapshot{}, err
	}
	if err := writable(mount); err != nil {
		return TreeSnapshot{}, err
	}
	info, err := safeLstat(root)
	if err != nil {
		return TreeSnapshot{}, err
	}
	if !info.IsDir() {
		return TreeSnapshot{}, ErrInvalid
	}
	state := treeSnapshotWalker{ctx: ctx, mount: mount, digest: sha256.New(), result: TreeSnapshot{Version: 1}}
	_, _ = state.digest.Write([]byte("jolt-destructive-tree-v1\x00"))
	if err := state.walk(root, "."); err != nil {
		return TreeSnapshot{}, err
	}
	state.result.Digest = hex.EncodeToString(state.digest.Sum(nil))
	return state.result, nil
}

type treeSnapshotWalker struct {
	ctx    context.Context
	mount  entities.Mount
	digest hash.Hash
	result TreeSnapshot
}

func (w *treeSnapshotWalker) walk(path, relative string) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if relative != "." && hiddenName(w.mount, filepath.Base(path)) {
		return ErrProtectedTree
	}
	info, err := safeLstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return ErrProtectedTree
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return ErrInvalid
	}
	identity, err := treeEntryFromInfo(relative, info)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	_, _ = w.digest.Write(encoded)
	_, _ = w.digest.Write([]byte{'\n'})
	if info.IsDir() {
		w.result.Directories++
		children, err := safeReadDir(path)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := w.walk(filepath.Join(path, child.Name()), filepath.Join(relative, child.Name())); err != nil {
				return err
			}
		}
	} else {
		if info.Size() < 0 || w.result.Bytes > math.MaxInt64-info.Size() {
			return ErrInvalid
		}
		file, err := safeOpen(path)
		if err != nil {
			return err
		}
		var opened unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
			file.Close()
			return err
		}
		openedIdentity, err := treeEntryFromInfo(relative, pathInfo{filepath.Base(path), opened})
		if err != nil || identity != openedIdentity {
			file.Close()
			return fmt.Errorf("%w: file changed during inspection", ErrConflict)
		}
		content := sha256.New()
		read, readErr := io.Copy(content, &contextReader{ctx: w.ctx, reader: file})
		statErr := unix.Fstat(int(file.Fd()), &opened)
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return closeErr
		}
		finalIdentity, err := treeEntryFromInfo(relative, pathInfo{filepath.Base(path), opened})
		if err != nil || read != info.Size() || identity != finalIdentity {
			return fmt.Errorf("%w: file changed during inspection", ErrConflict)
		}
		_, _ = w.digest.Write(content.Sum(nil))
		w.result.Files++
		w.result.Bytes += info.Size()
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	current, err := safeLstat(path)
	if err != nil {
		return err
	}
	after, err := treeEntryFromInfo(relative, current)
	if err != nil {
		return err
	}
	if identity != after {
		return fmt.Errorf("%w: tree changed during inspection", ErrConflict)
	}
	return nil
}
