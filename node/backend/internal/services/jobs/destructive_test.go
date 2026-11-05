package jobs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func (e *signedEnv) destructiveRules(capabilities ...string) []filetypes.Rule {
	return []filetypes.Rule{{PolicyID: "allow", Path: "nodes/node/files/mounts/" + e.mountID + "/**", Capabilities: capabilities}}
}

func (e *signedEnv) plan(t *testing.T, request DestructivePlanRequest) DestructivePlanSummary {
	t.Helper()
	request.SubjectType, request.SubjectID, request.MountID = "user", "actor", e.mountID
	summary, err := e.service.CreateDestructivePlan(context.Background(), request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return summary
}

func (e *signedEnv) accept(t *testing.T, plan DestructivePlanSummary, key string) (entities.Job, bool, error) {
	t.Helper()
	return e.service.AcceptDestructivePlan(context.Background(), "user", "actor", plan.ID, plan.Token, key, "")
}

// authorize registers the first lease for an accepted destructive job.
func (e *signedEnv) authorize(t *testing.T, job entities.Job, plan DestructivePlanSummary, ttl time.Duration, rules []filetypes.Rule) {
	t.Helper()
	binding := signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: job.Type, SourceNodeID: "node", SourceMountID: e.mountID, SourceRoot: plan.Source, PlanID: job.ID}
	if job.Type == "move_local" {
		binding.DestinationNodeID, binding.DestinationMountID, binding.DestinationRoot = "node", e.mountID, plan.Destination
	}
	envelope := e.lease(t, binding, 1, ttl, rules)
	if _, err := e.store.RenewJobAuthorization(context.Background(), job.ID, "node", envelope, binding, e.keys, time.Now().UTC()); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	e.service.notify()
}

func (e *signedEnv) finished(t *testing.T, id string) entities.Job {
	t.Helper()
	return e.wait(t, id, 20*time.Second, func(j entities.Job) bool {
		return j.State == "completed" || j.State == "failed" || j.State == "canceled"
	})
}

func TestDestructiveDeleteRemovesTheConfirmedTree(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "tree/a.txt", []byte("alpha"))
	env.write(t, "tree/sub/b.txt", []byte("beta"))
	plan := env.plan(t, DestructivePlanRequest{Operation: "delete", Source: "tree"})
	if plan.Files != 2 || plan.Directories != 2 || plan.Bytes != 9 || plan.Token == "" || plan.ID == "" {
		t.Fatalf("plan=%+v", plan)
	}
	job, repeated, err := env.accept(t, plan, "key-1")
	if err != nil || repeated || job.State != "waiting_validation" || job.Phase != "waiting_authorization" || job.DestructivePlanID != plan.ID {
		t.Fatalf("accepted job=%+v repeated=%v err=%v", job, repeated, err)
	}
	// Confirming again with the same key returns the same job; another key fails.
	again, repeated, err := env.accept(t, plan, "key-1")
	if err != nil || !repeated || again.ID != job.ID {
		t.Fatalf("repeat=%+v repeated=%v err=%v", again, repeated, err)
	}
	if _, _, err := env.accept(t, plan, "key-2"); err == nil {
		t.Fatal("a consumed plan was accepted with a new key")
	}
	// Nothing happens until a lease is registered.
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(env.mountPath, "tree")); err != nil {
		t.Fatalf("tree removed without authorization: %v", err)
	}
	env.authorize(t, job, plan, 25*time.Second, env.destructiveRules("list", "read", "delete"))
	done := env.finished(t, job.ID)
	if done.State != "completed" || done.BytesCompleted != 9 {
		t.Fatalf("job=%+v", done)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "tree")); !os.IsNotExist(err) {
		t.Fatalf("tree still present: %v", err)
	}
}

func TestDestructivePlanRejectsWrongTokenSubjectAndChangedTree(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "tree/a.txt", []byte("alpha"))
	plan := env.plan(t, DestructivePlanRequest{Operation: "delete", Source: "tree"})
	ctx := context.Background()
	if _, _, err := env.service.AcceptDestructivePlan(ctx, "user", "actor", plan.ID, plan.Token+"x", "key", ""); !errors.Is(err, ErrPlanRejected) {
		t.Fatalf("wrong token: %v", err)
	}
	if _, _, err := env.service.AcceptDestructivePlan(ctx, "user", "someone-else", plan.ID, plan.Token, "key", ""); !errors.Is(err, ErrPlanRejected) {
		t.Fatalf("another subject: %v", err)
	}
	env.write(t, "tree/new.txt", []byte("added after the plan"))
	if _, _, err := env.accept(t, plan, "key"); !errors.Is(err, ErrTreeChanged) {
		t.Fatalf("changed tree accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "tree/a.txt")); err != nil {
		t.Fatalf("tree changed by a rejected plan: %v", err)
	}
	// A rejected confirmation does not consume the plan. Restoring the files is
	// not enough to reuse it: the identity includes timestamps, so a changed
	// tree needs a new plan.
	stored, err := env.store.GetDestructivePlan(ctx, plan.ID, "user", "actor", hashPlanToken(plan.Token), time.Now().UTC())
	if err != nil || stored.ConsumedJobID != "" {
		t.Fatalf("rejected confirmation consumed the plan: %+v %v", stored, err)
	}
}

func TestDestructiveJobRevalidatesTheTreeBeforeRemoving(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "tree/a.txt", []byte("alpha"))
	plan := env.plan(t, DestructivePlanRequest{Operation: "delete", Source: "tree"})
	job, _, err := env.accept(t, plan, "key")
	if err != nil {
		t.Fatal(err)
	}
	// Someone edits a file between the confirmation and the authorization.
	env.write(t, "tree/a.txt", []byte("ALPHA"))
	env.authorize(t, job, plan, 25*time.Second, env.destructiveRules("list", "read", "delete"))
	done := env.finished(t, job.ID)
	if done.State != "failed" || !strings.Contains(done.Error, "tree changed") {
		t.Fatalf("job=%+v", done)
	}
	if got, err := os.ReadFile(filepath.Join(env.mountPath, "tree/a.txt")); err != nil || string(got) != "ALPHA" {
		t.Fatalf("tree touched: %q %v", got, err)
	}
}

func TestDestructiveDeleteHonorsThePolicyContext(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "tree/a.txt", []byte("alpha"))
	plan := env.plan(t, DestructivePlanRequest{Operation: "delete", Source: "tree"})
	job, _, err := env.accept(t, plan, "key")
	if err != nil {
		t.Fatal(err)
	}
	// The lease grants no delete capability.
	env.authorize(t, job, plan, 25*time.Second, env.destructiveRules("list", "read"))
	done := env.finished(t, job.ID)
	if done.State != "failed" {
		t.Fatalf("job=%+v", done)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "tree/a.txt")); err != nil {
		t.Fatalf("tree removed without the delete capability: %v", err)
	}
}

func TestDestructiveMoveAndOverwriteRevalidateTheDestination(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "from/a.txt", []byte("alpha"))
	plan := env.plan(t, DestructivePlanRequest{Operation: "move", Source: "from", Destination: "to"})
	job, _, err := env.accept(t, plan, "key")
	if err != nil {
		t.Fatal(err)
	}
	env.authorize(t, job, plan, 25*time.Second, env.destructiveRules("list", "read", "create", "update"))
	if done := env.finished(t, job.ID); done.State != "completed" {
		t.Fatalf("move job=%+v", done)
	}
	if got, err := os.ReadFile(filepath.Join(env.mountPath, "to/a.txt")); err != nil || string(got) != "alpha" {
		t.Fatalf("moved content=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "from")); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}

	// Replacing an existing directory needs overwrite and pins its contents.
	env.write(t, "next/c.txt", []byte("gamma"))
	if _, err := env.service.CreateDestructivePlan(context.Background(), DestructivePlanRequest{SubjectType: "user", SubjectID: "actor", Operation: "move", MountID: env.mountID, Source: "next", Destination: "to"}); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatalf("existing destination without overwrite: %v", err)
	}
	replace := env.plan(t, DestructivePlanRequest{Operation: "move", Source: "next", Destination: "to", Overwrite: true})
	if !replace.DestinationExists || replace.DestinationFiles != 1 {
		t.Fatalf("plan=%+v", replace)
	}
	env.write(t, "to/extra.txt", []byte("appeared after the plan"))
	if _, _, err := env.accept(t, replace, "key-2"); !errors.Is(err, ErrTreeChanged) {
		t.Fatalf("changed destination accepted: %v", err)
	}
}

func TestDestructivePlansNeedAFileTreeAndAValidDestination(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "file.txt", []byte("not a tree"))
	env.write(t, "tree/a.txt", []byte("alpha"))
	ctx := context.Background()
	base := DestructivePlanRequest{SubjectType: "user", SubjectID: "actor", MountID: env.mountID}
	for name, request := range map[string]DestructivePlanRequest{
		"file":                {Operation: "delete", Source: "file.txt"},
		"mount root":          {Operation: "delete", Source: "."},
		"missing":             {Operation: "delete", Source: "missing"},
		"escaping":            {Operation: "delete", Source: "../outside"},
		"delete destination":  {Operation: "delete", Source: "tree", Destination: "x"},
		"move into itself":    {Operation: "move", Source: "tree", Destination: "tree/inside"},
		"move onto a file":    {Operation: "move", Source: "tree", Destination: "file.txt", Overwrite: true},
		"unknown operation":   {Operation: "copy", Source: "tree"},
		"move without target": {Operation: "move", Source: "tree"},
	} {
		request.SubjectType, request.SubjectID, request.MountID = base.SubjectType, base.SubjectID, base.MountID
		if _, err := env.service.CreateDestructivePlan(ctx, request); err == nil {
			t.Fatalf("%s: plan created", name)
		}
	}
}
