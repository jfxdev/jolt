package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

func testTrashItem(id string, now time.Time) entities.TrashItem {
	return entities.TrashItem{ID: id, MountID: "mount", Path: "docs/a.txt", Type: "file", Size: 3, State: "stored", DeletedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func TestTrashRecordsPersistAcrossRestartAndRaiseTheVersion(t *testing.T) {
	s, dir := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	if err := s.PutTrashItem(ctx, testTrashItem("tr_1_a", now)); err != nil {
		t.Fatal(err)
	}
	if s.envelopeVersion != 7 {
		t.Fatalf("security version=%d", s.envelopeVersion)
	}
	later := testTrashItem("tr_2_b", now.Add(time.Minute))
	if err := s.PutTrashItem(ctx, later); err != nil {
		t.Fatal(err)
	}
	other := testTrashItem("tr_3_c", now)
	other.MountID = "elsewhere"
	if err := s.PutTrashItem(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	if reopened.envelopeVersion != 7 {
		t.Fatalf("the version was not kept across a restart: %d", reopened.envelopeVersion)
	}
	items, err := reopened.ListTrashItems(ctx, "mount")
	if err != nil || len(items) != 2 || items[0].ID != "tr_2_b" || items[1].ID != "tr_1_a" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	all, _ := reopened.AllTrashItems(ctx)
	if len(all) != 3 {
		t.Fatalf("all=%+v", all)
	}
	moving := testTrashItem("tr_1_a", now)
	moving.State = "purging"
	if err := reopened.PutTrashItem(ctx, moving); err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.GetTrashItem(ctx, "tr_1_a"); err != nil || got.State != "purging" {
		t.Fatalf("replace: %+v %v", got, err)
	}
	if err := reopened.DeleteTrashItem(ctx, "tr_1_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetTrashItem(ctx, "tr_1_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted record: %v", err)
	}
	if err := reopened.DeleteTrashItem(ctx, "tr_1_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting twice: %v", err)
	}
}

func TestTrashRecordsAreValidatedBeforeAnythingIsWritten(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := context.Background(), time.Now().UTC()
	for name, mutate := range map[string]func(*entities.TrashItem){
		"id with a slash":      func(i *entities.TrashItem) { i.ID = "a/b" },
		"path escaping":        func(i *entities.TrashItem) { i.Path = "../outside" },
		"absolute path":        func(i *entities.TrashItem) { i.Path = "/etc/passwd" },
		"the trash folder":     func(i *entities.TrashItem) { i.Path = ".jolt-trash/tr_1_a/x" },
		"unknown type":         func(i *entities.TrashItem) { i.Type = "socket" },
		"unknown state":        func(i *entities.TrashItem) { i.State = "lost" },
		"expires before start": func(i *entities.TrashItem) { i.ExpiresAt = i.DeletedAt },
		"negative size":        func(i *entities.TrashItem) { i.Size = -1 },
	} {
		item := testTrashItem("tr_9_z", now)
		mutate(&item)
		if err := s.PutTrashItem(ctx, item); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if s.envelopeVersion != 1 {
		t.Fatalf("an invalid record raised the version: %d", s.envelopeVersion)
	}
}
