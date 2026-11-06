package store

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestPKIObjectsRoundTripAndRaiseTheSecurityVersionOnFirstWrite(t *testing.T) {
	ctx := context.Background()
	s, path := openPendingStore(t)
	if _, err := s.Metadata(ctx, "minimum_security_version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version set before any write: %v", err)
	}
	if objects, err := s.ListPKIObjects(ctx); err != nil || len(objects) != 0 {
		t.Fatalf("fresh store: %v %v", objects, err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	root := PKIObject{ID: "root-1", Kind: PKIRoot, State: "active", Serial: "0a", Fingerprint: "ff", Public: "PEM", Secret: "sealed", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now}
	key := PKIObject{ID: "key-1", Kind: PKISigningKey, State: "active", Public: "pub", Secret: "sealed-2", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now.Add(time.Second)}
	if err := s.SavePKIObjects(ctx, []PKIObject{root, key}, nil); err != nil {
		t.Fatal(err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err != nil || version != "9" {
		t.Fatalf("security version %q %v", version, err)
	}
	objects, err := s.ListPKIObjects(ctx)
	if err != nil || len(objects) != 2 || objects[0].ID != "root-1" || objects[1].ID != "key-1" {
		t.Fatalf("list: %+v %v", objects, err)
	}
	if got := objects[0]; got.Kind != PKIRoot || got.Serial != "0a" || got.Secret != "sealed" || !got.NotAfter.Equal(root.NotAfter) || !got.CreatedAt.Equal(now) {
		t.Fatalf("round trip: %+v", got)
	}

	// An update changes the state and the validity, not the identity.
	key.State, key.NotAfter, key.Kind = "retired", now.Add(2*time.Hour), PKIRoot
	if err := s.SavePKIObjects(ctx, []PKIObject{key}, []string{"root-1"}); err != nil {
		t.Fatal(err)
	}
	objects, _ = s.ListPKIObjects(ctx)
	if len(objects) != 1 || objects[0].ID != "key-1" || objects[0].State != "retired" || objects[0].Kind != PKISigningKey || !objects[0].NotAfter.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("update: %+v", objects)
	}

	// A binary that does not know these objects must not open the database.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if objects, _ := reopened.ListPKIObjects(ctx); len(objects) != 1 {
		t.Fatalf("lost across restart: %+v", objects)
	}
	if _, err := reopened.db.Exec(`UPDATE metadata SET value=? WHERE key='minimum_security_version'`, strconv.Itoa(supportedSecurityVersion+1)); err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if newer, err := Open(path, testDatabaseKey); err == nil {
		newer.Close()
		t.Fatal("a database from a newer version was opened")
	}
}
