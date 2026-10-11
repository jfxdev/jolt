package filesystem

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func archiveEntries(t *testing.T, data []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	entries := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, "/") {
			entries[file.Name] = ""
			continue
		}
		opened, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", file.Name, err)
		}
		content, err := io.ReadAll(opened)
		opened.Close()
		if err != nil {
			t.Fatalf("read %s: %v", file.Name, err)
		}
		entries[file.Name] = string(content)
	}
	return entries
}

func TestArchiveStreamsWholeDirectory(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "docs", "a.txt"), "alpha")
	writeFile(t, filepath.Join(root, "docs", "nested", "b.txt"), "beta")

	var buffer bytes.Buffer
	result, err := service.Archive(context.Background(), mountID, "docs", ArchiveOptions{}, &buffer)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if result.Entries != 2 || result.Bytes != 9 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := archiveEntries(t, buffer.Bytes())
	if entries["a.txt"] != "alpha" || entries["nested/b.txt"] != "beta" {
		t.Fatalf("unexpected archive contents: %v", entries)
	}
}

func TestArchiveSelectionKeepsRootNames(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "photos", "one.jpg"), "1")
	writeFile(t, filepath.Join(root, "album", "two.jpg"), "2")
	writeFile(t, filepath.Join(root, "ignored.txt"), "x")

	var buffer bytes.Buffer
	if _, err := service.Archive(context.Background(), mountID, "",
		ArchiveOptions{Names: []string{"photos", "album"}}, &buffer); err != nil {
		t.Fatalf("archive: %v", err)
	}
	entries := archiveEntries(t, buffer.Bytes())
	// Each selected root keeps its own directory so extracting does not mix
	// files from different folders together.
	if entries["photos/one.jpg"] != "1" || entries["album/two.jpg"] != "2" {
		t.Fatalf("unexpected archive contents: %v", entries)
	}
	if _, present := entries["ignored.txt"]; present {
		t.Fatal("archive included an unselected file")
	}
}

func TestArchiveRejectsSelectionOutsideTheMount(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "inside.txt"), "ok")
	for _, name := range []string{"..", "../etc", "sub/child", `sub\child`, ".", ""} {
		var buffer bytes.Buffer
		_, err := service.Archive(context.Background(), mountID, "",
			ArchiveOptions{Names: []string{name}}, &buffer)
		if err == nil {
			t.Fatalf("selection %q was accepted", name)
		}
	}
}

func TestArchiveSkipsSymlinksInsteadOfFollowingThem(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	outside := filepath.Join(t.TempDir(), "secret.txt")
	writeFile(t, outside, "secret")
	writeFile(t, filepath.Join(root, "docs", "a.txt"), "alpha")
	if err := os.Symlink(outside, filepath.Join(root, "docs", "leak.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	var buffer bytes.Buffer
	result, err := service.Archive(context.Background(), mountID, "docs", ArchiveOptions{}, &buffer)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if result.SkippedSymlink != 1 {
		t.Fatalf("expected one skipped symlink, got %+v", result)
	}
	entries := archiveEntries(t, buffer.Bytes())
	if _, present := entries["leak.txt"]; present {
		t.Fatal("archive followed a symlink out of the mount")
	}
	if entries["a.txt"] != "alpha" {
		t.Fatalf("archive dropped a regular file: %v", entries)
	}
}

func TestArchiveRefusesOversizedSelection(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	for index := 0; index < 5; index++ {
		writeFile(t, filepath.Join(root, "docs", fmt.Sprintf("file-%d.txt", index)), "content")
	}
	options := ArchiveOptions{MaxEntries: 3}
	if _, err := service.PlanArchive(context.Background(), mountID, "docs", options); err == nil {
		t.Fatal("plan accepted a selection over the entry limit")
	}
	byteLimited := ArchiveOptions{MaxBytes: 10}
	if _, err := service.PlanArchive(context.Background(), mountID, "docs", byteLimited); err == nil {
		t.Fatal("plan accepted a selection over the byte limit")
	}
	// Within the limits the same plan succeeds.
	plan, err := service.PlanArchive(context.Background(), mountID, "docs",
		ArchiveOptions{MaxEntries: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Entries != 5 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestArchiveSingleFileSelection(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "report.pdf"), "pdf-bytes")
	var buffer bytes.Buffer
	if _, err := service.Archive(context.Background(), mountID, "",
		ArchiveOptions{Names: []string{"report.pdf"}}, &buffer); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if entries := archiveEntries(t, buffer.Bytes()); entries["report.pdf"] != "pdf-bytes" {
		t.Fatalf("unexpected archive contents: %v", entries)
	}
}

func TestArchiveRequiresDirectoryWithoutSelection(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "report.pdf"), "pdf")
	var buffer bytes.Buffer
	if _, err := service.Archive(context.Background(), mountID, "report.pdf", ArchiveOptions{}, &buffer); err == nil {
		t.Fatal("archived a file without a selection")
	}
}

func TestArchiveNameFallsBackForTheMountRoot(t *testing.T) {
	cases := map[string]string{
		"":            "arquivos.zip",
		"/":           "arquivos.zip",
		".":           "arquivos.zip",
		"docs":        "docs.zip",
		"/a/b/photos": "photos.zip",
		"Férias 2024": "Férias 2024.zip",
	}
	for input, expected := range cases {
		if got := ArchiveName(input); got != expected {
			t.Fatalf("ArchiveName(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestSearchMatchesNameCaseInsensitively(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "Relatório Final.pdf"), "a")
	writeFile(t, filepath.Join(root, "notes", "relatorio.txt"), "b")
	writeFile(t, filepath.Join(root, "notes", "other.txt"), "c")

	result, err := service.Search(context.Background(), mountID, "", SearchOptions{Query: "RELATÓRIO"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Path != "Relatório Final.pdf" {
		t.Fatalf("unexpected results: %+v", result.Entries)
	}
	if result.Truncated {
		t.Fatal("a complete search reported truncation")
	}
}

func TestSearchFiltersByTypeExtensionSizeAndTime(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "media", "clip.mp4"), strings.Repeat("x", 100))
	writeFile(t, filepath.Join(root, "media", "note.txt"), "small")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, "media", "note.txt"), old, old); err != nil {
		t.Fatal(err)
	}

	byType, err := service.Search(context.Background(), mountID, "", SearchOptions{Type: "directory"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(byType.Entries) != 1 || byType.Entries[0].Path != "media" {
		t.Fatalf("type filter returned %+v", byType.Entries)
	}

	byExtension, err := service.Search(context.Background(), mountID, "",
		SearchOptions{Extensions: []string{".MP4"}})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(byExtension.Entries) != 1 || byExtension.Entries[0].Name != "clip.mp4" {
		t.Fatalf("extension filter returned %+v", byExtension.Entries)
	}

	bySize, err := service.Search(context.Background(), mountID, "", SearchOptions{MinSize: 50})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(bySize.Entries) != 1 || bySize.Entries[0].Name != "clip.mp4" {
		t.Fatalf("size filter returned %+v", bySize.Entries)
	}

	byTime, err := service.Search(context.Background(), mountID, "",
		SearchOptions{Type: "file", ModifiedBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(byTime.Entries) != 1 || byTime.Entries[0].Name != "note.txt" {
		t.Fatalf("time filter returned %+v", byTime.Entries)
	}
}

func TestSearchTruncatesAtTheResultLimit(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	for index := 0; index < 10; index++ {
		writeFile(t, filepath.Join(root, fmt.Sprintf("match-%02d.txt", index)), "x")
	}
	result, err := service.Search(context.Background(), mountID, "",
		SearchOptions{Query: "match", MaxResults: 4})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(result.Entries) != 4 {
		t.Fatalf("expected 4 results, got %d", len(result.Entries))
	}
	if !result.Truncated || result.TruncatedReason != "results" {
		t.Fatalf("truncation not reported: %+v", result)
	}
}

func TestSearchStopsAtTheScanLimit(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	for index := 0; index < 20; index++ {
		writeFile(t, filepath.Join(root, fmt.Sprintf("file-%02d.txt", index)), "x")
	}
	result, err := service.Search(context.Background(), mountID, "",
		SearchOptions{Query: "nothing-matches", MaxEntries: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if !result.Truncated || result.TruncatedReason != "entries" {
		t.Fatalf("scan limit not reported: %+v", result)
	}
}

func TestSearchNeverFollowsSymlinks(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret-match.txt"), "secret")
	writeFile(t, filepath.Join(root, "inside-match.txt"), "ok")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// A link back to the mount root would make a following walk loop forever.
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	result, err := service.Search(context.Background(), mountID, "", SearchOptions{Query: "match"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Path != "inside-match.txt" {
		t.Fatalf("search leaked across a symlink: %+v", result.Entries)
	}
}

func TestSearchRequiresAQueryOrFilter(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	if _, err := service.Search(context.Background(), mountID, "", SearchOptions{}); err == nil {
		t.Fatal("an unfiltered search was accepted")
	}
}

func TestSearchRejectsTraversalAndFiles(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "a.txt"), "x")
	if _, err := service.Search(context.Background(), mountID, "../..", SearchOptions{Query: "a"}); err == nil {
		t.Fatal("search escaped the mount")
	}
	if _, err := service.Search(context.Background(), mountID, "a.txt", SearchOptions{Query: "a"}); err == nil {
		t.Fatal("search accepted a file as its root")
	}
}

func TestSearchFailsFastOnACancelledContext(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "file.txt"), "x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The caller is already gone, so the search must not start walking.
	if _, err := service.Search(ctx, mountID, "", SearchOptions{Query: "file"}); err == nil {
		t.Fatal("a cancelled search was executed")
	}
}

func TestSearchExcludesInFlightPartials(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	if _, err := service.AppendUpload(ctx, mountID, "movie.mkv", "upl_search", 0, 10,
		strings.NewReader("12345")); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	// The partial exists on disk but is not content, so it must not be a hit.
	result, err := service.Search(ctx, mountID, "", SearchOptions{Query: "movie"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("search surfaced an in-flight upload: %+v", result.Entries)
	}
}

func TestArchiveExcludesInFlightPartials(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	ctx := context.Background()
	writeFile(t, filepath.Join(root, "docs", "a.txt"), "alpha")
	if _, err := service.AppendUpload(ctx, mountID, "docs/b.txt", "upl_archive", 0, 10,
		strings.NewReader("12345")); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	var buffer bytes.Buffer
	result, err := service.Archive(ctx, mountID, "docs", ArchiveOptions{}, &buffer)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if result.Entries != 1 {
		t.Fatalf("archive included an in-flight upload: %+v", result)
	}
	if entries := archiveEntries(t, buffer.Bytes()); len(entries) != 1 || entries["a.txt"] != "alpha" {
		t.Fatalf("unexpected archive contents: %v", entries)
	}
}

func TestResumableUploadAppendsAndPublishes(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	ctx := context.Background()
	content := []byte("resumable upload content")
	const uploadID = "upl_test"

	if err := os.MkdirAll(filepath.Join(root, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	offset, err := service.UploadOffset(ctx, mountID, "dir/file.bin", uploadID)
	if err != nil {
		t.Fatalf("offset: %v", err)
	}
	if offset != 0 {
		t.Fatalf("a fresh upload reported offset %d", offset)
	}

	// Two chunks, as a client resuming after a dropped connection would send.
	written, err := service.AppendUpload(ctx, mountID, "dir/file.bin", uploadID, 0,
		int64(len(content)), bytes.NewReader(content[:10]))
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if written != 10 {
		t.Fatalf("first chunk reported %d", written)
	}
	written, err = service.AppendUpload(ctx, mountID, "dir/file.bin", uploadID, 10,
		int64(len(content)), bytes.NewReader(content[10:]))
	if err != nil {
		t.Fatalf("second chunk: %v", err)
	}
	if written != int64(len(content)) {
		t.Fatalf("second chunk reported %d", written)
	}

	// The destination must not exist until the upload is completed.
	if _, err := os.Stat(filepath.Join(root, "dir", "file.bin")); !os.IsNotExist(err) {
		t.Fatal("destination appeared before completion")
	}

	size, checksum, err := service.CompleteUpload(ctx, mountID, "dir/file.bin", uploadID,
		int64(len(content)), "", false)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if size != int64(len(content)) || checksum != "" {
		t.Fatalf("unexpected completion: size=%d checksum=%q", size, checksum)
	}
	stored, err := os.ReadFile(filepath.Join(root, "dir", "file.bin"))
	if err != nil {
		t.Fatalf("read published file: %v", err)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("published content mismatch: %q", stored)
	}
}

func TestResumableUploadRejectsWrongOffset(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	const uploadID = "upl_offset"
	if _, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 0, 10,
		bytes.NewReader([]byte("12345"))); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	// Appending at the wrong offset would leave a hole, so it must be refused
	// and report where the upload actually stands.
	stored, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 9, 10,
		bytes.NewReader([]byte("x")))
	if !errors.Is(err, ErrOffsetMismatch) {
		t.Fatalf("expected an offset mismatch, got %v", err)
	}
	if stored != 5 {
		t.Fatalf("mismatch reported offset %d, want 5", stored)
	}
}

func TestResumableUploadCapsAtDeclaredSize(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	const uploadID = "upl_cap"
	// The client declares 4 bytes but sends 10; only the declared size lands.
	written, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 0, 4,
		bytes.NewReader([]byte("0123456789")))
	if err == nil {
		t.Fatal("an oversized chunk was accepted")
	}
	if written != 4 {
		t.Fatalf("wrote %d bytes past the declared size", written)
	}
}

func TestCompleteUploadRejectsShortAndCorruptedContent(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	const uploadID = "upl_verify"
	content := []byte("verified content")
	if _, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 0,
		int64(len(content)), bytes.NewReader(content[:5])); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	// Completing before every byte arrived must fail rather than publish a
	// truncated file.
	if _, _, err := service.CompleteUpload(ctx, mountID, "file.bin", uploadID,
		int64(len(content)), "", false); err == nil {
		t.Fatal("an incomplete upload was published")
	}
	if _, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 5,
		int64(len(content)), bytes.NewReader(content[5:])); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	// A declared checksum that does not match must also block publication.
	wrong := strings.Repeat("a", 64)
	if _, _, err := service.CompleteUpload(ctx, mountID, "file.bin", uploadID,
		int64(len(content)), wrong, false); err == nil {
		t.Fatal("a checksum mismatch was published")
	}
	if _, _, err := service.CompleteUpload(ctx, mountID, "file.bin", uploadID,
		int64(len(content)), sha256Hex(content), false); err != nil {
		t.Fatalf("complete with a matching checksum: %v", err)
	}
}

func TestCompleteUploadHonoursOverwrite(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	ctx := context.Background()
	writeFile(t, filepath.Join(root, "file.bin"), "existing")
	content := []byte("replacement")
	const uploadID = "upl_overwrite"
	if _, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 0,
		int64(len(content)), bytes.NewReader(content)); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if _, _, err := service.CompleteUpload(ctx, mountID, "file.bin", uploadID,
		int64(len(content)), "", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected a conflict without overwrite, got %v", err)
	}
	if _, _, err := service.CompleteUpload(ctx, mountID, "file.bin", uploadID,
		int64(len(content)), "", true); err != nil {
		t.Fatalf("complete with overwrite: %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(root, "file.bin"))
	if err != nil || string(stored) != "replacement" {
		t.Fatalf("overwrite did not publish: %q %v", stored, err)
	}
}

func TestAbortUploadRemovesThePartialAndIsIdempotent(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	ctx := context.Background()
	const uploadID = "upl_abort"
	if _, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 0, 10,
		bytes.NewReader([]byte("12345"))); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if err := service.AbortUpload(ctx, mountID, "file.bin", uploadID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	// Aborting twice, or aborting an upload that never started, must succeed.
	if err := service.AbortUpload(ctx, mountID, "file.bin", uploadID); err != nil {
		t.Fatalf("second abort: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("abort left files behind: %v", entries)
	}
}

func TestResumableUploadRefusesReadOnlyMount(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_only")
	if _, err := service.AppendUpload(context.Background(), mountID, "file.bin", "upl_ro", 0, 4,
		bytes.NewReader([]byte("data"))); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("expected a read-only error, got %v", err)
	}
}

func TestResumableUploadRejectsTraversal(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	if _, err := service.AppendUpload(context.Background(), mountID, "../escape.bin", "upl_esc", 0, 4,
		bytes.NewReader([]byte("data"))); err == nil {
		t.Fatal("an upload escaped the mount")
	}
}

func TestUploadPartialIsHiddenFromListings(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	const uploadID = "upl_hidden"
	if _, err := service.AppendUpload(ctx, mountID, "file.bin", uploadID, 0, 10,
		bytes.NewReader([]byte("12345"))); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	entries, err := service.List(ctx, mountID, "", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// An in-flight upload must not appear as a file operators can act on.
	for _, entry := range entries {
		if strings.Contains(entry.Name, uploadID) {
			t.Fatalf("partial upload is visible in listings: %+v", entries)
		}
	}
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestEmptyResumableUploadCompletes(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	// A zero-byte file sends no chunk, so the partial never exists. Completing
	// it must still publish an empty file rather than report "not found".
	size, _, err := service.CompleteUpload(context.Background(), mountID, "empty.bin",
		"upl_empty", 0, "", false)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if size != 0 {
		t.Fatalf("published %d bytes", size)
	}
	info, err := os.Stat(filepath.Join(root, "empty.bin"))
	if err != nil || info.Size() != 0 {
		t.Fatalf("empty file was not published: %v %+v", err, info)
	}
}

func TestEmptyResumableUploadVerifiesItsChecksum(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	// The empty file still goes through verification, so a declared checksum
	// that does not match the empty digest must refuse to publish.
	if _, _, err := service.CompleteUpload(context.Background(), mountID, "empty.bin",
		"upl_empty_bad", 0, strings.Repeat("a", 64), false); err == nil {
		t.Fatal("a mismatched checksum published an empty file")
	}
	if _, _, err := service.CompleteUpload(context.Background(), mountID, "empty2.bin",
		"upl_empty_ok", 0, sha256Hex(nil), false); err != nil {
		t.Fatalf("the empty digest was rejected: %v", err)
	}
}

func TestConcurrentAppendsToOneSessionStaySerialized(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	const uploadID = "upl_concurrent"
	const total = 2000
	// Two writers race at the same offset. Exactly one may win; the other must
	// see an offset mismatch rather than interleaving its bytes into the
	// partial file.
	type result struct {
		written int64
		err     error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for writer := 0; writer < 2; writer++ {
		payload := strings.Repeat(string(rune('a'+writer)), 1000)
		go func() {
			start.Wait()
			written, err := service.AppendUpload(ctx, mountID, "race.bin", uploadID, 0, total,
				strings.NewReader(payload))
			results <- result{written, err}
		}()
	}
	start.Done()
	first, second := <-results, <-results
	succeeded := 0
	for _, outcome := range []result{first, second} {
		if outcome.err == nil {
			succeeded++
		} else if !errors.Is(outcome.err, ErrOffsetMismatch) {
			t.Fatalf("unexpected error: %v", outcome.err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d writers succeeded at the same offset, want 1", succeeded)
	}
	offset, err := service.UploadOffset(ctx, mountID, "race.bin", uploadID)
	if err != nil {
		t.Fatal(err)
	}
	// One winner means exactly one payload landed: no interleaving.
	if offset != 1000 {
		t.Fatalf("partial holds %d bytes, want 1000", offset)
	}
}
