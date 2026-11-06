package filesystem

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/filetypes"
)

func TestResumableFilteredCopyCancellationAndRevalidation(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		for _, mode := range []string{"cancel and resume", "destination changed", "destination appeared", "source replaced"} {
			t.Run(fmt.Sprintf("parallel_%t/%s", parallel, mode), func(t *testing.T) {
				service, mountID, root := newTestService(t, "read_write")
				content := strings.Repeat("data", 8192)
				writeFile(t, filepath.Join(root, "source.txt"), content)
				base := "nodes/n/files/mounts/m"
				compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}}).Compile()
				if err != nil {
					t.Fatal(err)
				}
				filter, err := NewAccessFilter(compiled, base)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var once sync.Once
				progress := func(done, total int64) error {
					if done != total {
						return nil
					}
					once.Do(func() {
						switch mode {
						case "cancel and resume":
							cancel()
						case "destination changed":
							if err := os.Mkdir(filepath.Join(root, "destination"), 0o700); err != nil {
								t.Error(err)
								return
							}
							if err := os.WriteFile(filepath.Join(root, "destination", "keep"), []byte("keep"), 0o600); err != nil {
								t.Error(err)
							}
						case "destination appeared":
							if err := os.WriteFile(filepath.Join(root, "destination"), []byte("concurrent"), 0o600); err != nil {
								t.Error(err)
							}
						case "source replaced":
							if err := os.Rename(filepath.Join(root, "source.txt"), filepath.Join(root, "old-source")); err != nil {
								t.Error(err)
								return
							}
							if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte(content), 0o600); err != nil {
								t.Error(err)
							}
						}
					})
					return nil
				}
				copyFile := func(ctx context.Context, checkpoint int64, progress func(int64, int64) error) (int64, string, error) {
					overwrite := mode != "destination appeared"
					if parallel {
						return service.CopyFileResumableParallelFiltered(ctx, mountID, "source.txt", "destination", "job", overwrite, checkpoint, 4096, 2, "", false, progress, filter, nil)
					}
					return service.CopyFileResumableFiltered(ctx, mountID, "source.txt", "destination", "job", overwrite, checkpoint, 4096, "", false, progress, filter)
				}
				written, _, err := copyFile(ctx, 0, progress)
				switch mode {
				case "cancel and resume":
					if !errors.Is(err, context.Canceled) || written != int64(len(content)) {
						t.Fatalf("canceled copy=%d err=%v", written, err)
					}
					if _, err := os.Stat(filepath.Join(root, "destination")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("canceled destination exists: %v", err)
					}
					if _, err := os.Stat(resumablePartialPath(filepath.Join(root, "destination"), "job")); err != nil {
						t.Fatalf("partial missing: %v", err)
					}
					if _, _, err := copyFile(context.Background(), written, nil); err != nil {
						t.Fatalf("resume: %v", err)
					}
					if got, err := os.ReadFile(filepath.Join(root, "destination")); err != nil || string(got) != content {
						t.Fatalf("resumed content=%q err=%v", got, err)
					}
				case "destination changed":
					if !errors.Is(err, ErrProtectedTree) {
						t.Fatalf("changed destination: %v", err)
					}
					if got, err := os.ReadFile(filepath.Join(root, "destination", "keep")); err != nil || string(got) != "keep" {
						t.Fatalf("destination damaged: %q %v", got, err)
					}
				case "destination appeared":
					if !errors.Is(err, ErrConflict) {
						t.Fatalf("concurrent destination: %v", err)
					}
					if got, err := os.ReadFile(filepath.Join(root, "destination")); err != nil || string(got) != "concurrent" {
						t.Fatalf("concurrent destination changed: %q %v", got, err)
					}
				case "source replaced":
					if !errors.Is(err, ErrSourceChanged) {
						t.Fatalf("replaced source: %v", err)
					}
					if _, err := os.Stat(filepath.Join(root, "destination")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("destination published: %v", err)
					}
				}
			})
		}
	}
}

func TestResumableFilteredCopyRefusesDeniedPaths(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel_%t", parallel), func(t *testing.T) {
			service, mountID, root := newTestService(t, "read_write")
			writeFile(t, filepath.Join(root, "source.pem"), "secret")
			writeFile(t, filepath.Join(root, "source.txt"), "source")
			writeFile(t, filepath.Join(root, "existing.txt"), "existing")
			base := "nodes/n/files/mounts/m"
			compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
				{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}},
				{PolicyID: "secret", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
				{PolicyID: "no-update", Path: base + "/existing.txt", Capabilities: []string{"deny", "update"}},
			}}).Compile()
			if err != nil {
				t.Fatal(err)
			}
			filter, err := NewAccessFilter(compiled, base)
			if err != nil {
				t.Fatal(err)
			}
			copyFile := func(source, destination string) error {
				if parallel {
					_, _, err := service.CopyFileResumableParallelFiltered(context.Background(), mountID, source, destination, "job", true, 0, 4096, 2, "", false, nil, filter, nil)
					return err
				}
				_, _, err := service.CopyFileResumableFiltered(context.Background(), mountID, source, destination, "job", true, 0, 4096, "", false, nil, filter)
				return err
			}
			if err := copyFile("source.pem", "new.txt"); !errors.Is(err, ErrFilteredHidden) {
				t.Fatalf("hidden source: %v", err)
			}
			if err := copyFile("source.txt", "existing.txt"); !errors.Is(err, ErrFilteredBlocked) {
				t.Fatalf("denied update: %v", err)
			}
			if got, err := os.ReadFile(filepath.Join(root, "existing.txt")); err != nil || string(got) != "existing" {
				t.Fatalf("destination changed: %q %v", got, err)
			}
			if _, err := os.Stat(resumablePartialPath(filepath.Join(root, "new.txt"), "job")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial created before authorization: %v", err)
			}
		})
	}
}

func TestCopyAtomicDoesNotPublishAfterCancellationDuringFinalCheck(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mount, destination, err := service.resolve(ctx, mountID, "destination", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = copyAtomicWithCheck(ctx, mount, strings.NewReader("content"), destination, false, 7, 0, nil, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("copy=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "destination")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled copy published: %v", err)
	}
}

func TestResumableCopyDoesNotPublishAfterCancellation(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel_%t", parallel), func(t *testing.T) {
			service, mountID, root := newTestService(t, "read_write")
			content := strings.Repeat("data", 4096)
			writeFile(t, filepath.Join(root, "source"), content)
			writeFile(t, filepath.Join(root, "destination"), "original")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			progress := func(done, total int64) error {
				if done == total {
					cancel()
				}
				return nil
			}
			var err error
			if parallel {
				_, _, err = service.CopyFileResumableParallel(ctx, mountID, "source", "destination", "job", true, 0, 4096, 2, "", false, progress, nil)
			} else {
				_, _, err = service.CopyFileResumable(ctx, mountID, "source", "destination", "job", true, 0, 4096, "", false, progress)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("copy error=%v", err)
			}
			if got, err := os.ReadFile(filepath.Join(root, "destination")); err != nil || string(got) != "original" {
				t.Fatalf("existing destination changed: %q %v", got, err)
			}
			if _, err := os.Stat(resumablePartialPath(filepath.Join(root, "destination"), "job")); err != nil {
				t.Fatalf("partial missing: %v", err)
			}
		})
	}
}
