package tfprovider

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/httpapi"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const testToken = "jolt-terraform-test-token"

// newControl starts a Control Tower with typed policies and approvals on, and
// a service account whose token has sudo on control-tower/policies only.
func newControl(t *testing.T) (string, *store.Store) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	key := make([]byte, 32)
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	steps := []error{
		storage.CreatePolicy(ctx, store.Policy{ID: "terraform", Name: "terraform", Rules: []rbac.Rule{{Path: "control-tower/policies", Capabilities: []string{"sudo"}}}, CreatedAt: now, UpdatedAt: now}),
		storage.CreateAccessGroup(ctx, store.AccessGroup{ID: "iac", Name: "iac", Enabled: true, CreatedAt: now, UpdatedAt: now}),
		storage.SetAccessGroupPolicies(ctx, "iac", []string{"terraform"}),
		storage.CreateServiceAccount(ctx, store.ServiceAccount{ID: "svc-terraform", Name: "terraform", Enabled: true, CreatedAt: now, UpdatedAt: now}),
		storage.SetServiceAccountGroups(ctx, "svc-terraform", []string{"iac"}),
		storage.CreateServiceAccountToken(ctx, store.ServiceAccountToken{ID: "tok-terraform", ServiceAccountID: "svc-terraform", Name: "ci", TokenHash: security.Digest(testToken), CreatedAt: now}, false),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{
		EncryptionKey: key, StaticDir: t.TempDir(), TypedPolicies: true, Approvals: true,
		SignedLocalReads: true, SignedUploads: true, SignedLocalJobs: true,
		AuthorizationSigningKeyID: "key", AuthorizationSigningKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
	}
	handler, err := httpapi.New(cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL, storage
}
