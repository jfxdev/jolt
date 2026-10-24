package filesystem

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryPagesCoverLargeDirectoryWithStableCaseTies(t *testing.T) {
	if !(entryKey(false, "A") < entryKey(false, "a")) {
		t.Fatal("case ties lack exact-name ordering")
	}
	s, id, root := newTestService(t, "read_write")
	for i := 0; i < 1007; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"A-dir", "B-dir", "Z-dir"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	after := ""
	pages := 0
	for {
		page, err := s.ListPage(context.Background(), id, "", 173, after)
		if err != nil {
			t.Fatal(err)
		}
		if pages == 0 && (page.Items[0].Name != "A-dir" || page.Items[1].Name != "B-dir") {
			t.Fatalf("case ordering: %+v", page.Items[:2])
		}
		for _, item := range page.Items {
			if seen[item.Name] {
				t.Fatalf("duplicate %s", item.Name)
			}
			seen[item.Name] = true
		}
		pages++
		if !page.HasMore {
			break
		}
		if page.NextAfter == "" || page.NextAfter == after {
			t.Fatal("cursor did not advance")
		}
		after = page.NextAfter
	}
	if len(seen) != 1010 || pages < 6 {
		t.Fatalf("entries=%d pages=%d", len(seen), pages)
	}
	if _, err := s.ListPage(context.Background(), id, "", 200, "invalid!"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid cursor: %v", err)
	}
}

func TestPublicationRecoveryRefusesChangedDestination(t *testing.T) {
	s, id, root := newTestService(t, "read_write")
	ctx := context.Background()
	session := entities.UploadSession{ID: "recover-test", MountID: id, Destination: "result.txt", Size: 7, State: "publishing"}
	if _, err := s.AppendUpload(ctx, id, session.Destination, session.ID, 0, 7, strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	digest, err := s.PrepareUpload(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	session.PublishChecksum = digest
	if _, _, err := s.CompleteUpload(ctx, id, session.Destination, session.ID, 7, digest, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "result.txt"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if published, err := s.PublishedUpload(ctx, session); published || !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("accepted external replacement: published=%v err=%v", published, err)
	}
}
