// Package state stores versioned YAML transactions encrypted with AES-256-GCM.
// There is no database driver: committed files and an authenticated snapshot
// manifest are the source of truth. Only record locations are indexed in RAM.
package state

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/yamlutil"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

const compactTransactions = 1024
const compactBytes = 64 << 20
const cacheLimit = 16 << 20

// Error aliases are provided for callers of the concrete storage adapter.
var (
	ErrNotFound            = contracts.ErrNotFound
	ErrInUse               = contracts.ErrInUse
	ErrIdempotencyConflict = contracts.ErrIdempotencyConflict
	ErrUploadSessionExists = contracts.ErrUploadSessionExists
)

type envelope struct {
	Version    int    `yaml:"version"`
	StorageID  string `yaml:"storage_id"`
	Kind       string `yaml:"kind"`
	Sequence   uint64 `yaml:"sequence"`
	Nonce      string `yaml:"nonce"`
	Ciphertext string `yaml:"ciphertext"`
}
type record struct {
	Bucket string `yaml:"bucket"`
	Key    string `yaml:"key"`
	Group  string `yaml:"group,omitempty"`
	Order  string `yaml:"order,omitempty"`
	State  string `yaml:"state,omitempty"`
	Delete bool   `yaml:"delete,omitempty"`
	Data   string `yaml:"data,omitempty"`
}
type document struct {
	Records []record `yaml:"records"`
}
type manifest struct {
	Pages []string `yaml:"pages"`
}
type reference struct {
	File         string
	Slot         int
	Group, Order string
	State        string
}
type cacheEntry struct {
	Doc   document
	Bytes int
}
type transaction struct {
	store   *Store
	records []record
}

type Store struct {
	failure                   chan struct{}
	mu                        sync.Mutex
	dir, id                   string
	aead                      cipher.AEAD
	lock                      *os.File
	sequence                  uint64
	snapshotSequence          uint64
	journalCount              int
	journalBytes              int64
	index                     map[string]map[string]reference
	cache                     map[string]cacheEntry
	cacheOrder                []string
	cacheBytes                int
	closed, poisoned, managed bool
	// fault is used by durability tests at filesystem commit boundaries.
	fault func(string) error
}

func RejectLegacy(dir string) error {
	for _, name := range []string{"jolt.db", "jolt.db-wal", "jolt.db-shm", "jolt.db-journal"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return errors.New("legacy SQLite data found; use a new installation and a new data directory")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func Open(dir string, key []byte) (*Store, error) { return open(dir, key, false) }

// OpenExisting never initializes missing state. It is used by offline recovery.
func OpenExisting(dir string, key []byte) (*Store, error) { return open(dir, key, true) }
func open(dir string, key []byte, existing bool) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("state encryption key must contain exactly 32 bytes")
	}
	if err := RejectLegacy(dir); err != nil {
		return nil, err
	}
	if existing {
		if _, err := os.Stat(filepath.Join(dir, "store.yaml")); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("state directory must not be a symlink")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".state.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("node state is already open")
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	s := &Store{failure: make(chan struct{}), dir: dir, aead: aead, lock: lock, index: map[string]map[string]reference{}, cache: map[string]cacheEntry{}}
	success := false
	defer func() {
		if !success {
			s.Close()
		}
	}()
	header := filepath.Join(dir, "store.yaml")
	if _, err := os.Lstat(header); errors.Is(err, os.ErrNotExist) {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if entry.Name() != ".state.lock" && entry.Name() != ".jolt-node.lock" && !strings.HasPrefix(entry.Name(), ".tmp-") {
				return nil, errors.New("refusing to initialize nonempty state directory")
			}
		}
		id := make([]byte, 16)
		if _, e := rand.Read(id); e != nil {
			return nil, e
		}
		s.id = hex.EncodeToString(id)
		if _, e := s.write("store.yaml", "header", 0, struct {
			Format string `yaml:"format"`
		}{"jolt-yaml-state"}); e != nil {
			return nil, e
		}
		if _, e := s.write("head.yaml", "head", 0, struct{}{}); e != nil {
			return nil, e
		}
	} else if err != nil {
		return nil, err
	} else {
		var h struct {
			Format string `yaml:"format"`
		}
		if _, err := s.read("store.yaml", "header", 0, &h); err != nil {
			return nil, err
		}
		if h.Format != "jolt-yaml-state" {
			return nil, errors.New("unsupported state format")
		}
	}
	var head struct{}
	committed, err := s.read("head.yaml", "head", ^uint64(0), &head)
	if err != nil {
		return nil, fmt.Errorf("read committed state head: %w", err)
	}
	for _, name := range []string{"journal", "snapshots"} {
		if info, err := os.Lstat(filepath.Join(dir, name)); err == nil && (!info.IsDir() || info.Mode().Perm()&0077 != 0) {
			return nil, errors.New("unsafe state subdirectory")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(dir, name), 0700); err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "manifest.yaml")); err == nil {
		var m manifest
		seq, err := s.read("manifest.yaml", "manifest", ^uint64(0), &m)
		if err != nil {
			return nil, err
		}
		s.sequence, s.snapshotSequence = seq, seq
		for i, name := range m.Pages {
			expected := fmt.Sprintf("snapshots/%020d-%06d.yaml", seq, i)
			if name != expected {
				return nil, errors.New("invalid snapshot page reference")
			}
			var doc document
			if _, err := s.read(name, "snapshot", seq, &doc); err != nil {
				return nil, err
			}
			if err := s.apply(doc, name, true); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "journal"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".yaml"), 10, 64)
		if err != nil || entry.Name() != fmt.Sprintf("%020d.yaml", seq) {
			return nil, errors.New("unexpected journal entry")
		}
		if seq <= s.snapshotSequence {
			continue
		}
		if seq != s.sequence+1 {
			return nil, errors.New("journal sequence gap")
		}
		name := "journal/" + entry.Name()
		var doc document
		if _, err := s.read(name, "transaction", seq, &doc); err != nil {
			return nil, err
		}
		if err := s.apply(doc, name, false); err != nil {
			return nil, err
		}
		s.sequence = seq
		s.journalCount++
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		s.journalBytes += info.Size()
	}
	if s.sequence < committed {
		return nil, errors.New("committed journal tail is missing")
	}
	// A transaction published immediately before a crash can precede its head
	// update. Accept it atomically and durably protect it before exposing reads.
	if s.sequence > committed {
		if _, err := s.write("head.yaml", "head", s.sequence, struct{}{}); err != nil {
			return nil, err
		}
	}
	s.managed = len(s.index["configuration"]) > 0
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	success = true
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		return s.lock.Close()
	}
	return nil
}
func (s *Store) available(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed || s.poisoned {
		return contracts.ErrStateUnavailable
	}
	return nil
}
func (s *Store) view(ctx context.Context, fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(ctx); err != nil {
		return err
	}
	return fn()
}
func (s *Store) update(ctx context.Context, fn func(*transaction) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(ctx); err != nil {
		return err
	}
	tx := &transaction{store: s}
	if err := fn(tx); err != nil {
		return err
	}
	if len(tx.records) == 0 {
		return nil
	}
	seq := s.sequence + 1
	name := fmt.Sprintf("journal/%020d.yaml", seq)
	doc := document{Records: tx.records}
	n, err := s.write(name, "transaction", seq, doc)
	if err != nil {
		s.poison()
		return fmt.Errorf("%w: %v", contracts.ErrStateUnavailable, err)
	}
	if _, err := s.write("head.yaml", "head", seq, struct{}{}); err != nil {
		s.poison()
		return fmt.Errorf("%w: %v", contracts.ErrStateUnavailable, err)
	}
	if err = s.apply(doc, name, false); err != nil {
		s.poison()
		return err
	}
	s.remember(name, doc, n)
	s.sequence = seq
	s.journalCount++
	s.journalBytes += int64(n)
	if s.journalCount >= compactTransactions || s.journalBytes >= compactBytes {
		if err := s.compact(); err != nil {
			s.poison()
			return fmt.Errorf("%w: snapshot: %v", contracts.ErrStateUnavailable, err)
		}
	}
	return nil
}
func (tx *transaction) put(bucket, key, group, order string, value any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	r := record{Bucket: bucket, Key: key, Group: group, Order: order, Data: string(data)}
	if job, ok := value.(entities.Job); ok {
		r.State = job.State
	}
	tx.records = append(tx.records, r)
	return nil
}
func (tx *transaction) remove(bucket, key string) {
	tx.records = append(tx.records, record{Bucket: bucket, Key: key, Delete: true})
}
func get[T any](s *Store, bucket, key string) (T, error) {
	var value T
	r, ok := s.index[bucket][key]
	if !ok {
		return value, ErrNotFound
	}
	doc, err := s.load(r.File)
	if err != nil {
		return value, err
	}
	if r.Slot >= len(doc.Records) {
		s.poison()
		return value, errors.New("invalid state record location")
	}
	err = yaml.Unmarshal([]byte(doc.Records[r.Slot].Data), &value)
	if err != nil {
		s.poison()
	}
	return value, err
}
func keys(s *Store, bucket, group string) []string {
	out := []string{}
	for key, r := range s.index[bucket] {
		if group == "" || r.Group == group {
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := s.index[bucket][out[i]], s.index[bucket][out[j]]
		if a.Order == b.Order {
			return out[i] < out[j]
		}
		return a.Order < b.Order
	})
	return out
}
func (s *Store) load(name string) (document, error) {
	if cached, ok := s.cache[name]; ok {
		return cached.Doc, nil
	}
	var doc document
	kind := "transaction"
	if strings.HasPrefix(name, "snapshots/") {
		kind = "snapshot"
	}
	seqText := strings.Split(strings.TrimSuffix(filepath.Base(name), ".yaml"), "-")[0]
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil {
		return doc, err
	}
	if _, err = s.read(name, kind, seq, &doc); err != nil {
		s.poison()
		return doc, err
	}
	n := 0
	for _, r := range doc.Records {
		n += len(r.Data) + len(r.Key) + len(r.Group) + 128
	}
	s.remember(name, doc, n)
	return doc, nil
}
func (s *Store) remember(name string, doc document, n int) {
	if n > cacheLimit/2 {
		return
	}
	if _, ok := s.cache[name]; ok {
		return
	}
	for s.cacheBytes+n > cacheLimit && len(s.cacheOrder) > 0 {
		old := s.cacheOrder[0]
		s.cacheOrder = s.cacheOrder[1:]
		s.cacheBytes -= s.cache[old].Bytes
		delete(s.cache, old)
	}
	s.cache[name] = cacheEntry{doc, n}
	s.cacheOrder = append(s.cacheOrder, name)
	s.cacheBytes += n
}
func (s *Store) apply(doc document, name string, snapshot bool) error {
	for i, r := range doc.Records {
		if r.Bucket == "" || r.Key == "" {
			return errors.New("empty state record identity")
		}
		if s.index[r.Bucket] == nil {
			s.index[r.Bucket] = map[string]reference{}
		}
		if snapshot {
			if _, ok := s.index[r.Bucket][r.Key]; ok {
				return errors.New("duplicate snapshot record")
			}
		}
		if r.Delete {
			delete(s.index[r.Bucket], r.Key)
		} else {
			s.index[r.Bucket][r.Key] = reference{name, i, r.Group, r.Order, r.State}
		}
	}
	return nil
}
func (s *Store) compact() error {
	names := []string{}
	for bucket := range s.index {
		names = append(names, bucket)
	}
	sort.Strings(names)
	var pages []string
	doc := document{}
	size := 0
	flush := func() error {
		if len(doc.Records) == 0 {
			return nil
		}
		name := fmt.Sprintf("snapshots/%020d-%06d.yaml", s.sequence, len(pages))
		if _, err := s.write(name, "snapshot", s.sequence, doc); err != nil {
			return err
		}
		pages = append(pages, name)
		doc = document{}
		size = 0
		return nil
	}
	for _, bucket := range names {
		for _, key := range keys(s, bucket, "") {
			ref := s.index[bucket][key]
			source, err := s.load(ref.File)
			if err != nil {
				return err
			}
			r := source.Records[ref.Slot]
			doc.Records = append(doc.Records, r)
			size += len(r.Data)
			if len(doc.Records) >= 256 || size >= 1<<20 {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if _, err := s.write("manifest.yaml", "manifest", s.sequence, manifest{Pages: pages}); err != nil {
		return err
	}
	s.index = map[string]map[string]reference{}
	s.cache = map[string]cacheEntry{}
	s.cacheOrder = nil
	s.cacheBytes = 0
	for _, name := range pages {
		var doc document
		if _, err := s.read(name, "snapshot", s.sequence, &doc); err != nil {
			return err
		}
		if err := s.apply(doc, name, true); err != nil {
			return err
		}
	}
	// Only files superseded by the durable manifest can now be removed.
	for _, subdir := range []string{"journal", "snapshots"} {
		entries, err := os.ReadDir(filepath.Join(s.dir, subdir))
		if err != nil {
			return err
		}
		live := map[string]bool{}
		for _, name := range pages {
			live[filepath.Base(name)] = true
		}
		for _, entry := range entries {
			if subdir == "snapshots" && live[entry.Name()] {
				continue
			}
			if err := os.Remove(filepath.Join(s.dir, subdir, entry.Name())); err != nil {
				return err
			}
		}
		if err := syncDir(filepath.Join(s.dir, subdir)); err != nil {
			return err
		}
	}
	s.snapshotSequence = s.sequence
	s.journalCount = 0
	s.journalBytes = 0
	return nil
}
func (s *Store) read(name, kind string, seq uint64, value any) (uint64, error) {
	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return 0, fmt.Errorf("unsafe state file %s: expected regular file with mode 0600", name)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var e envelope
	if err := yamlutil.Decode(raw, &e); err != nil {
		return 0, err
	}
	if e.Version != 1 || e.Kind != kind || (seq != ^uint64(0) && e.Sequence != seq) || e.StorageID == "" || (s.id != "" && s.id != e.StorageID) {
		return 0, errors.New("state envelope identity mismatch")
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != s.aead.NonceSize() {
		return 0, errors.New("invalid state nonce")
	}
	data, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return 0, err
	}
	aad := fmt.Sprintf("jolt-state:1:%s:%s:%d:%s", e.StorageID, e.Kind, e.Sequence, name)
	plain, err := s.aead.Open(nil, nonce, data, []byte(aad))
	if err != nil {
		return 0, errors.New("cannot authenticate state: wrong key or corrupted file")
	}
	if err := yamlutil.Decode(plain, value); err != nil {
		return 0, err
	}
	s.id = e.StorageID
	return e.Sequence, nil
}
func (s *Store) write(name, kind string, seq uint64, value any) (int, error) {
	plain, err := yaml.Marshal(value)
	if err != nil {
		return 0, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	aad := fmt.Sprintf("jolt-state:1:%s:%s:%d:%s", s.id, kind, seq, name)
	e := envelope{1, s.id, kind, seq, base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(s.aead.Seal(nil, nonce, plain, []byte(aad)))}
	raw, err := yaml.Marshal(e)
	if err != nil {
		return 0, err
	}
	path := filepath.Join(s.dir, name)
	temp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return 0, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	step := func(label string) error {
		if s.fault != nil {
			return s.fault(label)
		}
		return nil
	}
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(raw)
	}
	if err != nil {
		return 0, err
	}
	if err = step("before_file_sync"); err != nil {
		return 0, err
	}
	if err = temp.Sync(); err != nil {
		return 0, err
	}
	if err = step("after_file_sync"); err != nil {
		return 0, err
	}
	if err = temp.Close(); err != nil {
		return 0, err
	}
	if err = os.Rename(temp.Name(), path); err != nil {
		return 0, err
	}
	if err = step("after_rename"); err != nil {
		return 0, err
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		return 0, err
	}
	if err = step("after_directory_sync"); err != nil {
		return 0, err
	}
	return len(raw), nil
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Store) poison() {
	if !s.poisoned {
		s.poisoned = true
		close(s.failure)
	}
}
func (s *Store) Failure() <-chan struct{} { return s.failure }
