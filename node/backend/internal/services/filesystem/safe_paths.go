package filesystem

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Open every directory relative to its already-open parent. O_NOFOLLOW on
// every component prevents a concurrent symlink swap from changing the scope
// between validation and use. Mount paths are canonicalized at registration.
func pathParent(name string) (*os.File, string, error) {
	if !filepath.IsAbs(name) {
		return nil, "", ErrTraversal
	}
	name = filepath.Clean(name)
	fd, err := unix.Open("/", directorySearchFlags, 0)
	if err != nil {
		return nil, "", err
	}
	for _, part := range strings.Split(strings.Trim(filepath.Dir(name), "/"), "/") {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, directorySearchFlags|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, "", pathError("open", name, openErr)
		}
		fd = next
	}
	base := filepath.Base(name)
	if name == "/" {
		base = "."
	}
	return os.NewFile(uintptr(fd), filepath.Dir(name)), base, nil
}

func pathError(op, name string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		err = ErrTraversal
	}
	return &os.PathError{Op: op, Path: name, Err: err}
}

func safeOpenFile(name string, flags int, mode fs.FileMode) (*os.File, error) {
	parent, base, err := pathParent(name)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), base, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(mode.Perm()))
	if err != nil {
		return nil, pathError("open", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func safeOpen(name string) (*os.File, error) { return safeOpenFile(name, os.O_RDONLY, 0) }

type pathInfo struct {
	name string
	stat unix.Stat_t
}

func (i pathInfo) Name() string       { return i.name }
func (i pathInfo) Size() int64        { return i.stat.Size }
func (i pathInfo) ModTime() time.Time { return statTime(i.stat) }
func (i pathInfo) Sys() any           { return &i.stat }
func (i pathInfo) IsDir() bool        { return i.Mode().IsDir() }
func (i pathInfo) Mode() fs.FileMode {
	m := fs.FileMode(i.stat.Mode & 0777)
	switch i.stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		m |= fs.ModeDir
	case unix.S_IFLNK:
		m |= fs.ModeSymlink
	case unix.S_IFIFO:
		m |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		m |= fs.ModeSocket
	case unix.S_IFBLK:
		m |= fs.ModeDevice
	case unix.S_IFCHR:
		m |= fs.ModeDevice | fs.ModeCharDevice
	}
	if i.stat.Mode&unix.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if i.stat.Mode&unix.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if i.stat.Mode&unix.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	return m
}

func safeLstat(name string) (os.FileInfo, error) {
	parent, base, err := pathParent(name)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, pathError("lstat", name, err)
	}
	return pathInfo{filepath.Base(name), st}, nil
}

func safeStat(name string) (os.FileInfo, error) {
	info, err := safeLstat(name)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return nil, ErrTraversal
	}
	return info, err
}

func safeReadDir(name string) ([]os.DirEntry, error) {
	file, err := safeOpen(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	names, err := file.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	entries := make([]os.DirEntry, 0, len(names))
	for _, child := range names {
		info, err := safeLstat(filepath.Join(name, child))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, fs.FileInfoToDirEntry(info))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func safeWalkDir(name string, visit fs.WalkDirFunc) error {
	info, err := safeLstat(name)
	if err != nil {
		return visit(name, nil, err)
	}
	var walk func(string, fs.DirEntry) error
	walk = func(current string, entry fs.DirEntry) error {
		if err := visit(current, entry, nil); err != nil {
			if err == fs.SkipDir && entry.IsDir() {
				return nil
			}
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		entries, err := safeReadDir(current)
		if err != nil {
			return visit(current, entry, err)
		}
		for _, child := range entries {
			if err := walk(filepath.Join(current, child.Name()), child); err != nil {
				if err == fs.SkipDir {
					break
				}
				return err
			}
		}
		return nil
	}
	err = walk(name, fs.FileInfoToDirEntry(info))
	if err == fs.SkipAll || err == fs.SkipDir {
		return nil
	}
	return err
}

func safeCreateTemp(dir, pattern string) (*os.File, error) {
	for range 10 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, strings.Replace(pattern, "*", hex.EncodeToString(random[:]), 1))
		file, err := safeOpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if !errors.Is(err, fs.ErrExist) {
			return file, err
		}
	}
	return nil, ErrConflict
}

func safeMkdir(name string, mode fs.FileMode) error {
	p, b, err := pathParent(name)
	if err != nil {
		return err
	}
	defer p.Close()
	return unix.Mkdirat(int(p.Fd()), b, uint32(mode.Perm()))
}

func safeMkdirAll(name string, mode fs.FileMode) error {
	if info, err := safeStat(name); err == nil {
		if !info.IsDir() {
			return &os.PathError{Op: "mkdir", Path: name, Err: unix.ENOTDIR}
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := safeMkdirAll(filepath.Dir(name), mode); err != nil {
		return err
	}
	err := safeMkdir(name, mode)
	if errors.Is(err, fs.ErrExist) {
		var info os.FileInfo
		info, err = safeStat(name)
		if err == nil && !info.IsDir() {
			err = &os.PathError{Op: "mkdir", Path: name, Err: unix.ENOTDIR}
		}
	}
	return err
}

func safeRemove(name string) error    { return safeRemovePath(name, false) }
func safeRemoveAll(name string) error { return safeRemovePath(name, true) }
func safeRemovePath(name string, recursive bool) error {
	p, b, err := pathParent(name)
	if recursive && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer p.Close()
	err = removeAt(int(p.Fd()), b, recursive)
	if recursive && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
func removeAt(parent int, base string, recursive bool) error {
	var st unix.Stat_t
	if err := unix.Fstatat(parent, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parent, base, 0)
	}
	if recursive {
		fd, err := unix.Openat(parent, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(fd), base)
		defer dir.Close()
		names, err := dir.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, child := range names {
			if err := removeAt(fd, child, true); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return unix.Unlinkat(parent, base, unix.AT_REMOVEDIR)
}

// publishPath performs a single filesystem operation, with both directories
// pinned and with no-replace enforced by the kernel rather than a prior stat.
func publishPath(source, destination string, overwrite bool) error {
	from, src, err := pathParent(source)
	if err != nil {
		return err
	}
	defer from.Close()
	to, dst, err := pathParent(destination)
	if err != nil {
		return err
	}
	defer to.Close()
	if overwrite {
		err = unix.Renameat(int(from.Fd()), src, int(to.Fd()), dst)
	} else {
		err = renameNoReplace(int(from.Fd()), src, int(to.Fd()), dst)
	}
	if errors.Is(err, fs.ErrExist) {
		return ErrConflict
	}
	return err
}
