package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

func copyPlanFilter(t *testing.T, extra ...filetypes.Rule) *filesystem.AccessFilter {
	t.Helper()
	base := "nodes/node/files/mounts/mount"
	rules := append([]filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}, extra...)
	compiled, err := (filetypes.Context{Version: 1, Rules: rules}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := filesystem.NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func TestPlanCopyFilteredOmitsHiddenSourcesAndCountsVisibleFiles(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		target := filepath.Join(mount.LocalPath, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("source/public.txt", "public")
	write("source/secret.pem", "secret")
	write("source/blocked.lock", "blocked")
	write("source/private/nested.txt", "hidden")
	write("source/folder.pem/inside.txt", "inside")
	write("source/.jolt-job.partial", "partial")
	base := "nodes/node/files/mounts/mount"
	filter := copyPlanFilter(t,
		filetypes.Rule{PolicyID: "pem", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		filetypes.Rule{PolicyID: "lock", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"lock"}}, Visibility: "visible"},
		filetypes.Rule{PolicyID: "private", Path: base + "/source/private/**", Capabilities: []string{"deny"}},
	)
	plan, omitted, err := service.PlanCopyFiltered(context.Background(), mountID, "source", "destination", "fail", filter, true)
	if err != nil || omitted != 4 || plan.FilesTotal != 2 || plan.CopyCount != 2 || plan.BytesTotal != int64(len("public")+len("inside")) {
		t.Fatalf("plan=%+v omitted=%d err=%v", plan, omitted, err)
	}
	text := fmt.Sprintf("%+v", plan)
	for _, forbidden := range []string{"secret.pem", "blocked.lock", "private", ".jolt"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("hidden name exposed in plan: %s", text)
		}
	}
	if !strings.Contains(text, "folder.pem/inside.txt") {
		t.Fatalf("directory with extension was hidden: %s", text)
	}
	if _, err := os.Stat(filepath.Join(mount.LocalPath, "destination")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("planning mutated destination: %v", err)
	}
	if _, _, err := service.PlanCopyFiltered(context.Background(), mountID, "source", "source/child", "fail", filter, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("destination inside source: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if plan, omitted, err := service.PlanCopyFiltered(canceled, mountID, "source", "destination", "fail", filter, false); !errors.Is(err, context.Canceled) || len(plan.Items) != 0 || omitted != 0 {
		t.Fatalf("canceled plan=%+v omitted=%d err=%v", plan, omitted, err)
	}
}

func TestPlanCopyFilteredChecksFinalDestinations(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "source.txt"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount.LocalPath, "existing.txt"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "nodes/node/files/mounts/mount"
	denyType := copyPlanFilter(t, filetypes.Rule{PolicyID: "deny-pem", Path: base + "/**", Capabilities: []string{"deny", "create"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}})
	if _, _, err := service.PlanCopyFiltered(context.Background(), mountID, "source.txt", "new.pem", "fail", denyType, false); !errors.Is(err, filesystem.ErrFilteredBlocked) {
		t.Fatalf("renamed type was not denied: %v", err)
	}
	denyUpdate := copyPlanFilter(t, filetypes.Rule{PolicyID: "deny-update", Path: base + "/existing.txt", Capabilities: []string{"deny", "update"}})
	if _, _, err := service.PlanCopyFiltered(context.Background(), mountID, "source.txt", "existing.txt", "overwrite", denyUpdate, false); !errors.Is(err, filesystem.ErrFilteredBlocked) {
		t.Fatalf("overwrite was not denied: %v", err)
	}
	denyRename := copyPlanFilter(t, filetypes.Rule{PolicyID: "deny-rename", Path: base + "/existing (1).txt", Capabilities: []string{"deny", "create"}})
	if _, _, err := service.PlanCopyFiltered(context.Background(), mountID, "source.txt", "existing.txt", "rename", denyRename, false); !errors.Is(err, filesystem.ErrFilteredBlocked) {
		t.Fatalf("renamed final destination was not denied: %v", err)
	}
	plan, omitted, err := service.PlanCopyFiltered(context.Background(), mountID, "source.txt", "existing.txt", "rename", copyPlanFilter(t), false)
	if err != nil || omitted != 0 || len(plan.Items) != 1 || plan.Items[0].Action != "rename" || plan.Items[0].DestinationPath != "existing (1).txt" {
		t.Fatalf("rename plan=%+v omitted=%d err=%v", plan, omitted, err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(mount.LocalPath, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.PlanCopyFiltered(context.Background(), mountID, "source.txt", "link/new.txt", "fail", copyPlanFilter(t), false); err == nil {
		t.Fatal("symlink destination accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside file changed: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(mount.LocalPath, "existing.txt")); err != nil || string(got) != "existing" {
		t.Fatalf("planning changed destination: %q %v", got, err)
	}
}

func TestPlanCopyFilteredReportsTypeMismatchAsConflict(t *testing.T) {
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		target := filepath.Join(mount.LocalPath, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("source/dir/inner.txt", "inner")
	write("source/file.txt", "file")
	// Destination has a file where a directory is planned, and a directory
	// where a file is planned.
	write("destination/dir", "not a directory")
	write("destination/file.txt/keep.txt", "keep")
	plan, omitted, err := service.PlanCopyFiltered(context.Background(), mountID, "source", "destination", "overwrite", copyPlanFilter(t), false)
	if err != nil || omitted != 0 {
		t.Fatalf("plan=%+v omitted=%d err=%v", plan, omitted, err)
	}
	actions := map[string]string{}
	for _, item := range plan.Items {
		actions[item.RelativePath] = item.Action
	}
	if actions["dir"] != "conflict" || actions["file.txt"] != "conflict" || actions["dir/inner.txt"] != "conflict" || plan.ConflictCount != 2 || plan.CopyCount != 0 {
		t.Fatalf("actions=%v plan=%+v", actions, plan)
	}
	if got, err := os.ReadFile(filepath.Join(mount.LocalPath, "destination/dir")); err != nil || string(got) != "not a directory" {
		t.Fatalf("planning changed destination: %q %v", got, err)
	}
}
