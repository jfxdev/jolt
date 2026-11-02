package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

func TestPolicyTypeRulesPersistAndSetSecurityVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	want := Policy{ID: "typed", Name: "typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/n/files/mounts/m", Capabilities: []string{"read"}, FileTypes: &filetypes.Selector{Classes: []string{"video"}, Extensions: []string{"txt"}, Names: []string{"README"}}, Visibility: "visible"},
		{Path: "nodes/n/files/mounts/m/**", Capabilities: []string{"list"}},
	}}
	if err := s.CreatePolicy(ctx, want); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := s.db.QueryRow(`SELECT value FROM metadata WHERE key='minimum_security_version'`).Scan(&version); err != nil || version != "2" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetPolicy(ctx, want.ID)
	if err != nil || !reflect.DeepEqual(got.Rules, want.Rules) {
		t.Fatalf("rules=%+v err=%v", got.Rules, err)
	}
	want.Rules[0].FileTypes.Extensions = []string{"pdf"}
	if err := s.UpdatePolicy(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetPolicy(ctx, want.ID)
	if err != nil || !reflect.DeepEqual(got.Rules, want.Rules) {
		t.Fatalf("updated rules=%+v err=%v", got.Rules, err)
	}
	if _, err := s.db.Exec(`UPDATE policy_rules SET file_types='{"unknown":true}' WHERE policy_id='typed' AND position=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPolicy(ctx, want.ID); err == nil {
		t.Fatal("corrupt selector was accepted")
	}
}

func TestInvalidPolicyTypeRuleRollsBack(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	p := Policy{ID: "bad", Name: "bad", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n/files/mounts/m", Capabilities: []string{"read"}, FileTypes: &filetypes.Selector{Classes: []string{"unknown"}}}}}
	if err := s.CreatePolicy(context.Background(), p); err == nil {
		t.Fatal("invalid selector was accepted")
	}
	if _, err := s.GetPolicy(context.Background(), p.ID); err != ErrNotFound {
		t.Fatalf("policy persisted: %v", err)
	}
	p.Rules[0].FileTypes = &filetypes.Selector{Extensions: []string{"txt"}}
	p.Rules[0].Path = "nodes/n/**"
	if err := s.CreatePolicy(context.Background(), p); err == nil {
		t.Fatal("type selector outside a mount was accepted")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM metadata WHERE key='minimum_security_version'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("version marker persisted: %d %v", count, err)
	}
}
