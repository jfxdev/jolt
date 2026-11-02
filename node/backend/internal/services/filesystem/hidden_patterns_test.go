package filesystem

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHiddenPatternsAcrossFilesystemOperations(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	ctx := context.Background()
	mount, err := service.GetMount(ctx, mountID)
	if err != nil {
		t.Fatal(err)
	}
	mount.HiddenPatterns = []string{".env", "*.pem", "secret-dir"}
	if _, err := service.SaveMount(ctx, mount); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"tree/readme.txt": "readable", "tree/.ENV": "hidden", "tree/keys/CERT.PEM": "hidden",
		"tree/secret-dir/inside.txt": "hidden", "destination/.env": "keep",
	} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tree/.ENV", "tree/keys/CERT.PEM", "tree/secret-dir/inside.txt"} {
		if _, err := service.Metadata(ctx, mountID, name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("metadata %s: %v", name, err)
		}
	}
	if _, _, _, _, err := service.BrowsePath(ctx, filepath.Join(root, "tree", "secret-dir"), 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("raw filesystem browse entered protected directory: %v", err)
	}
	_, _, _, rawEntries, err := service.BrowsePath(ctx, filepath.Join(root, "tree", "keys"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawEntries) != 0 {
		t.Fatalf("raw filesystem browse exposed protected entries: %+v", rawEntries)
	}
	if _, err := service.Upload(ctx, mountID, "tree/new.PEM", strings.NewReader("x"), false); !errors.Is(err, ErrHiddenName) {
		t.Fatalf("hidden upload: %v", err)
	}
	if err := service.CreateDirectory(ctx, mountID, "tree/SECRET-DIR"); !errors.Is(err, ErrHiddenName) {
		t.Fatalf("hidden mkdir: %v", err)
	}
	page, err := service.ListPage(ctx, mountID, "tree", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if strings.EqualFold(item.Name, ".env") || strings.EqualFold(item.Name, "secret-dir") {
			t.Fatalf("hidden listing item: %+v", item)
		}
	}
	for _, paged := range []bool{false, true} {
		var entries []string
		if paged {
			items, total, err := service.ManifestPage(ctx, mountID, "tree", 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if total != len(items) {
				t.Fatalf("hidden items affected total: %d / %d", total, len(items))
			}
			for _, item := range items {
				entries = append(entries, item.Path)
			}
		} else {
			items, err := service.Manifest(ctx, mountID, "tree")
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range items {
				entries = append(entries, item.Path)
			}
		}
		joined := strings.ToLower(strings.Join(entries, ","))
		if strings.Contains(joined, ".env") || strings.Contains(joined, ".pem") || strings.Contains(joined, "secret-dir") {
			t.Fatalf("hidden manifest item: %s", joined)
		}
	}
	search, err := service.Search(ctx, mountID, "tree", SearchOptions{Query: "."})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range search.Entries {
		if item.Name != "readme.txt" {
			t.Fatalf("unexpected search result: %+v", item)
		}
	}
	usage, err := service.DiskUsage(ctx, mountID, "tree", DiskUsageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range usage.Entries {
		if strings.EqualFold(item.Name, ".env") || strings.EqualFold(item.Name, "secret-dir") {
			t.Fatalf("hidden disk usage entry: %+v", item)
		}
	}
	var archive bytes.Buffer
	if _, err := service.Archive(ctx, mountID, "tree", ArchiveOptions{}, &archive); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range zr.File {
		name := strings.ToLower(item.Name)
		if strings.Contains(name, ".env") || strings.Contains(name, ".pem") || strings.Contains(name, "secret-dir") {
			t.Fatalf("hidden archive item: %s", item.Name)
		}
	}
	if _, err := service.Copy(ctx, mountID, "tree", "copy", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "copy", "readme.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "copy", ".ENV")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hidden file copied: %v", err)
	}
	if err := service.Move(ctx, mountID, "tree", "moved", false); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("move protected tree: %v", err)
	}
	if err := service.Delete(ctx, mountID, "tree", true); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("delete protected tree: %v", err)
	}
	if _, err := service.Copy(ctx, mountID, "tree/readme.txt", "destination", true); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("overwrite protected tree: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "destination", ".env")); err != nil || string(data) != "keep" {
		t.Fatalf("protected destination changed: %q %v", data, err)
	}
}
