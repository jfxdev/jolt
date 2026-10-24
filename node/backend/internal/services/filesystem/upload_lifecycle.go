package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

type uploadGate struct {
	gate chan struct{}
	refs int
}

var lifecycle = struct {
	sync.Mutex
	gates map[string]*uploadGate
}{gates: map[string]*uploadGate{}}

// LockUploadSession spans state and filesystem changes, including expiry.
// Reference counting prevents waiters from splitting onto a new lock.
func LockUploadSession(ctx context.Context, id string) (func(), error) {
	lifecycle.Lock()
	g := lifecycle.gates[id]
	if g == nil {
		g = &uploadGate{gate: make(chan struct{}, 1)}
		lifecycle.gates[id] = g
	}
	g.refs++
	lifecycle.Unlock()
	release := func() {
		lifecycle.Lock()
		g.refs--
		if g.refs == 0 {
			delete(lifecycle.gates, id)
		}
		lifecycle.Unlock()
	}
	select {
	case g.gate <- struct{}{}:
		return func() { <-g.gate; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

func (s *Service) PrepareUpload(ctx context.Context, v entities.UploadSession) (string, error) {
	_, dst, err := s.resolve(ctx, v.MountID, v.Destination, true)
	if err != nil {
		return "", err
	}
	partial := resumablePartialPath(dst, v.ID)
	if v.Size == 0 {
		f, e := safeOpenFile(partial, os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return "", e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return "", e
		}
	}
	return uploadDigest(ctx, partial, v.Size)
}

func uploadDigest(ctx context.Context, path string, size int64) (string, error) {
	f, err := safeOpen(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return "", ErrInvalid
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, &contextReader{ctx: ctx, reader: f}); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// A missing partial can be recognized as a publication only after a durable
// intent with a verified full checksum exists. Size alone is never sufficient.
func (s *Service) PublishedUpload(ctx context.Context, v entities.UploadSession) (bool, error) {
	_, dst, err := s.resolve(ctx, v.MountID, v.Destination, true)
	if err != nil {
		return false, err
	}
	if _, err := safeLstat(resumablePartialPath(dst, v.ID)); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if v.State != "publishing" || v.PublishChecksum == "" {
		return false, ErrNotFound
	}
	digest, err := uploadDigest(ctx, dst, v.Size)
	if err != nil {
		return false, err
	}
	if digest != v.PublishChecksum {
		return false, ErrSourceChanged
	}
	return true, syncUploadDirectory(dst)
}

func syncUploadDirectory(dst string) error {
	dir, err := safeOpen(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Service) UploadBlocks(ctx context.Context, v entities.UploadSession, after int64, limit int) (entities.UploadVerification, error) {
	result := entities.UploadVerification{Blocks: []entities.UploadBlock{}}
	_, dst, err := s.resolve(ctx, v.MountID, v.Destination, true)
	if err != nil {
		return result, err
	}
	source := resumablePartialPath(dst, v.ID)
	f, err := safeOpen(source)
	if errors.Is(err, os.ErrNotExist) && v.State == "publishing" {
		published, e := s.PublishedUpload(ctx, v)
		if e != nil {
			return result, e
		}
		if published {
			f, err = safeOpen(dst)
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return result, err
	}
	result.Offset = info.Size()
	if after < 0 || after > result.Offset {
		return result, ErrInvalid
	}
	if limit <= 0 || limit > 16 {
		limit = 16
	}
	// Fixed blocks bound both browser memory and verification work per request.
	const blockSize int64 = 8 << 20
	if after%blockSize != 0 {
		return result, ErrInvalid
	}
	for offset := after; offset < result.Offset && len(result.Blocks) < limit; {
		size := min(blockSize, result.Offset-offset)
		hash := sha256.New()
		if _, err := io.Copy(hash, &contextReader{ctx: ctx, reader: io.NewSectionReader(f, offset, size)}); err != nil {
			return result, err
		}
		result.Blocks = append(result.Blocks, entities.UploadBlock{Offset: offset, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))})
		offset += size
		if offset < result.Offset {
			result.NextAfter = offset
		} else {
			result.NextAfter = 0
		}
	}
	return result, nil
}
