package transfers_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/infra/mtlsapi"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/transfers"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedPull struct {
	source, destination             *testNode
	key                             ed25519.PrivateKey
	keys                            map[string]ed25519.PublicKey
	sourceGrantID, destinationGrant string
}

func newSignedPull(t *testing.T) *signedPull {
	t.Helper()
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	destination.transfers.ConfigureDialContext(pipeTLSDialer(mtlsapi.New(source.identity, "source", source.transfers), source.certificates.TLSConfig()))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".", Direction: "send",
		Permissions: entities.GrantPermissions{Read: true, Delete: true}, VisibleToPeer: true, Enabled: true, CorrelationID: "cor-source-grant",
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".", Direction: "receive",
		Permissions: entities.GrantPermissions{Write: true}, ConflictPolicies: []string{"fail", "overwrite", "checksum", "rename", "skip"},
		VisibleToPeer: true, Enabled: true, CorrelationID: "cor-destination-grant",
	})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	p := &signedPull{source: source, destination: destination, key: key, keys: map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, sourceGrantID: sourceGrant.ID, destinationGrant: destinationGrant.ID}
	destination.jobs.ConfigureSignedExecution(destination.store, destination.identity.NodeID, p.keys)
	workerContext, stop := context.WithCancel(context.Background())
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdown)
	})
	return p
}

func (p *signedPull) base(node *testNode) string {
	return "nodes/" + node.identity.NodeID + "/files/mounts/" + node.mountID
}

// rules grants read on the source and write on the destination, plus extras.
func (p *signedPull) rules(extra ...filetypes.Rule) []filetypes.Rule {
	return append([]filetypes.Rule{
		{PolicyID: "read", Path: p.base(p.source) + "/**", Capabilities: []string{"list", "read"}},
		{PolicyID: "write", Path: p.base(p.destination) + "/**", Capabilities: []string{"list", "read", "create", "update"}},
	}, extra...)
}

func (p *signedPull) lease(t *testing.T, binding signedauth.Binding, revision uint64, ttl time.Duration, rules []filetypes.Rule) string {
	t.Helper()
	bound, err := signedauth.JobLeaseBinding(binding, revision)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(filetypes.Context{Version: 1, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := signedauth.Sign(signedauth.Claims{Version: signedauth.Version, KeyID: "key", Binding: bound, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), Context: policy}, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (p *signedPull) request(destinationPath string, bandwidth int64, paths ...string) transfers.BatchPullRequest {
	return transfers.BatchPullRequest{
		PullRequest: transfers.PullRequest{
			PeerNodeID: p.source.identity.NodeID, SourceGrantID: p.sourceGrantID, DestinationGrantID: p.destinationGrant,
			DestinationPath: destinationPath, ConflictPolicy: "fail", BandwidthLimit: bandwidth, CorrelationID: "cor-signed",
		},
		SourcePaths: paths,
	}
}

func (p *signedPull) moveRequest(destinationPath string, bandwidth int64, paths ...string) transfers.BatchPullRequest {
	request := p.request(destinationPath, bandwidth, paths...)
	request.Operation, request.SubjectType = "move", "user"
	return request
}

// moveRules also lets the actor update and delete what is moved from the source.
func (p *signedPull) moveRules(extra ...filetypes.Rule) []filetypes.Rule {
	return append([]filetypes.Rule{
		{PolicyID: "move-source", Path: p.base(p.source) + "/**", Capabilities: []string{"list", "read", "update", "delete"}},
		{PolicyID: "write", Path: p.base(p.destination) + "/**", Capabilities: []string{"list", "read", "create", "update"}},
	}, extra...)
}

func (p *signedPull) binding(t *testing.T, request transfers.BatchPullRequest, destinationRoot string) signedauth.Binding {
	t.Helper()
	_, digest, err := p.destination.transfers.PrepareSignedBatchPull(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	operation := "transfer_pull_batch"
	if request.Operation == "move" {
		operation = "transfer_move_batch"
	}
	return signedauth.Binding{
		ActorID: "actor", CredentialID: "credential", Operation: operation,
		SourceNodeID: p.source.identity.NodeID, SourceGrantID: p.sourceGrantID, SourceMountID: p.source.mountID, SourceRoot: ".",
		DestinationNodeID: p.destination.identity.NodeID, DestinationGrantID: p.destinationGrant, DestinationMountID: p.destination.mountID, DestinationRoot: destinationRoot,
		PlanID: "xfer", JobOptionsDigest: digest,
	}
}

// create plans and persists the copy, then registers its first lease as the
// Control Tower would.
func (p *signedPull) create(t *testing.T, request transfers.BatchPullRequest, ttl time.Duration, rules []filetypes.Rule) (entities.Job, signedauth.Binding, error) {
	t.Helper()
	binding := p.binding(t, request, ".")
	envelope := p.lease(t, binding, 1, ttl, rules)
	job, _, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, envelope, "request", p.keys)
	if err != nil {
		return entities.Job{}, binding, err
	}
	if _, err := p.destination.store.RenewJobAuthorization(context.Background(), job.ID, p.destination.identity.NodeID, envelope, binding, p.keys, time.Now().UTC()); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	return job, binding, nil
}

func (p *signedPull) wait(t *testing.T, id string, timeout time.Duration, done func(entities.Job) bool) entities.Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		job, err := p.destination.jobs.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if done(job) {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for job: %+v", job)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (p *signedPull) write(t *testing.T, node *testNode, name, content string) {
	t.Helper()
	target := filepath.Join(node.root, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSignedPullCopiesOnlyWhatThePolicyAllows(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/public.txt", "public")
	p.write(t, p.source, "tree/secret.pem", "private key")
	p.write(t, p.source, "tree/deep/inner.txt", "inner")
	hidden := filetypes.Rule{PolicyID: "pem", Path: p.base(p.source) + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}
	job, _, err := p.create(t, p.request(".", 0, "tree"), 25*time.Second, p.rules(hidden))
	if err != nil {
		t.Fatal(err)
	}
	done := p.wait(t, job.ID, 20*time.Second, func(j entities.Job) bool {
		return j.State == "completed" || j.State == "completed_with_warnings" || j.State == "failed"
	})
	if done.State != "completed_with_warnings" || !strings.HasSuffix(done.Error, "1 source entries were not accessible") {
		t.Fatalf("job=%+v", done)
	}
	for name, want := range map[string]string{"tree/public.txt": "public", "tree/deep/inner.txt": "inner"} {
		if got, err := os.ReadFile(filepath.Join(p.destination.root, name)); err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(p.destination.root, "tree/secret.pem")); !os.IsNotExist(err) {
		t.Fatalf("a hidden source file was copied: %v", err)
	}
	events, err := p.destination.jobs.ListEvents(context.Background(), 0, job.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "secret") || strings.Contains(event.Message, ".pem") {
			t.Fatalf("a hidden name leaked: %+v", event)
		}
	}
}

func TestSignedPullRefusesDestinationsThePolicyDoesNotAllow(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/a.txt", "alpha")
	readOnlyDestination := []filetypes.Rule{
		{PolicyID: "read", Path: p.base(p.source) + "/**", Capabilities: []string{"list", "read"}},
		{PolicyID: "write", Path: p.base(p.destination) + "/allowed/**", Capabilities: []string{"list", "read", "create", "update"}},
	}
	if _, _, err := p.create(t, p.request("elsewhere", 0, "tree"), 25*time.Second, readOnlyDestination); err == nil {
		t.Fatal("a destination outside the policy was planned")
	}
	if _, err := os.Stat(filepath.Join(p.destination.root, "elsewhere")); !os.IsNotExist(err) {
		t.Fatalf("destination touched: %v", err)
	}
	// A source the policy does not let the actor read is refused up front.
	noSource := []filetypes.Rule{{PolicyID: "write", Path: p.base(p.destination) + "/**", Capabilities: []string{"list", "read", "create", "update"}}}
	if _, _, err := p.create(t, p.request(".", 0, "tree"), 25*time.Second, noSource); err == nil {
		t.Fatal("an unreadable source was planned")
	}
}

func TestSignedPullRejectsMovesAndMismatchedLeases(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/a.txt", "alpha")
	// A move is prepared like a copy, but it cannot be created without a plan.
	move := p.moveRequest(".", 0, "tree")
	moveBinding := p.binding(t, move, ".")
	if moveBinding.Operation != "transfer_move_batch" {
		t.Fatalf("binding=%+v", moveBinding)
	}
	if _, _, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), move, p.destination.identity.NodeID, p.lease(t, moveBinding, 1, 25*time.Second, p.moveRules()), "request", p.keys); !errors.Is(err, jobs.ErrPlanRejected) {
		t.Fatalf("a move was created without a plan: %v", err)
	}
	request := p.request(".", 0, "tree")
	binding := p.binding(t, request, ".")
	for name, mutate := range map[string]func(*signedauth.Binding){
		"other source grant":     func(b *signedauth.Binding) { b.SourceGrantID = "other" },
		"other peer":             func(b *signedauth.Binding) { b.SourceNodeID = "other-node" },
		"other destination":      func(b *signedauth.Binding) { b.DestinationNodeID = "other-node" },
		"move operation":         func(b *signedauth.Binding) { b.Operation = "transfer_move_batch" },
		"no options digest":      func(b *signedauth.Binding) { b.JobOptionsDigest = "" },
		"other destination root": func(b *signedauth.Binding) { b.DestinationRoot = "elsewhere" },
	} {
		changed := binding
		mutate(&changed)
		envelope, err := signLeaseOrEmpty(p, changed, p.rules())
		if err != nil {
			continue // the signer already refuses an invalid binding
		}
		if _, _, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, envelope, "request", p.keys); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if jobs, err := p.destination.jobs.List(context.Background(), 10); err != nil || len(jobs) != 0 {
		t.Fatalf("a refused request left jobs behind: %+v %v", jobs, err)
	}
}

func signLeaseOrEmpty(p *signedPull, binding signedauth.Binding, rules []filetypes.Rule) (string, error) {
	bound, err := signedauth.JobLeaseBinding(binding, 1)
	if err != nil {
		return "", err
	}
	policy, err := json.Marshal(filetypes.Context{Version: 1, Rules: rules})
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	return signedauth.Sign(signedauth.Claims{Version: signedauth.Version, KeyID: "key", Binding: bound, IssuedAt: now.Unix(), ExpiresAt: now.Add(25 * time.Second).Unix(), Context: policy}, p.key)
}

func TestSignedPullWaitsForRenewalWhenTheLeaseExpiresAndResumes(t *testing.T) {
	p := newSignedPull(t)
	content := bytes.Repeat([]byte("0123456789abcdef"), 16<<10) // 256 KiB
	p.write(t, p.source, "big.bin", string(content))
	job, binding, err := p.create(t, p.request(".", 32<<10, "big.bin"), 3*time.Second, p.rules())
	if err != nil {
		t.Fatal(err)
	}
	parked := p.wait(t, job.ID, 20*time.Second, func(j entities.Job) bool {
		return j.Phase == "waiting_authorization" && j.State == "waiting_validation"
	})
	if parked.Error == "" {
		t.Fatalf("parked job=%+v", parked)
	}
	if _, err := os.Stat(filepath.Join(p.destination.root, "big.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination published without authorization: %v", err)
	}
	envelope := p.lease(t, binding, 2, 25*time.Second, p.rules())
	if _, err := p.destination.store.RenewJobAuthorization(context.Background(), job.ID, p.destination.identity.NodeID, envelope, binding, p.keys, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	done := p.wait(t, job.ID, 40*time.Second, func(j entities.Job) bool { return j.State == "completed" || j.State == "failed" })
	if done.State != "completed" {
		t.Fatalf("job=%+v", done)
	}
	if got, err := os.ReadFile(filepath.Join(p.destination.root, "big.bin")); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("copy differs after resume: len=%d err=%v", len(got), err)
	}
}

func TestSignedPullDoesNotRunWithoutExecutionOrALease(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "a.txt", "alpha")
	request := p.request(".", 0, "a.txt")
	binding := p.binding(t, request, ".")
	envelope := p.lease(t, binding, 1, 25*time.Second, p.rules())
	job, _, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, envelope, "request", p.keys)
	if err != nil {
		t.Fatal(err)
	}
	// Created, but its first lease was never registered.
	time.Sleep(1200 * time.Millisecond)
	current, err := p.destination.jobs.Get(context.Background(), job.ID)
	if err != nil || current.State != "waiting_validation" {
		t.Fatalf("job=%+v err=%v", current, err)
	}
	if _, err := os.Stat(filepath.Join(p.destination.root, "a.txt")); !os.IsNotExist(err) {
		t.Fatalf("a job without a lease ran: %v", err)
	}
	// Repeating the request returns the same job without planning again.
	again, repeated, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, p.lease(t, binding, 1, 25*time.Second, p.rules()), "request", p.keys)
	if err != nil || !repeated || again.ID != job.ID {
		t.Fatalf("repeat=%+v repeated=%v err=%v", again, repeated, err)
	}
}

// The policy may change between planning and running. The executor judges each
// planned item again with the lease it actually holds.
func TestSignedPullRejudgesPlannedItemsWithTheCurrentPolicy(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/a.txt", "alpha")
	p.write(t, p.source, "tree/b.txt", "beta")
	p.write(t, p.source, "tree/c.txt", "gamma")
	request := p.request(".", 0, "tree")
	binding := p.binding(t, request, ".")
	planned := p.lease(t, binding, 1, 25*time.Second, p.rules())
	job, _, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, planned, "request", p.keys)
	if err != nil {
		t.Fatal(err)
	}
	narrower := p.rules(
		filetypes.Rule{PolicyID: "no-b", Path: p.base(p.source) + "/tree/b.txt", Capabilities: []string{"deny", "read"}},
		filetypes.Rule{PolicyID: "no-c", Path: p.base(p.destination) + "/tree/c.txt", Capabilities: []string{"deny", "create"}},
	)
	if _, err := p.destination.store.RenewJobAuthorization(context.Background(), job.ID, p.destination.identity.NodeID, p.lease(t, binding, 1, 25*time.Second, narrower), binding, p.keys, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	done := p.wait(t, job.ID, 20*time.Second, func(j entities.Job) bool {
		return j.State == "completed" || j.State == "completed_with_warnings" || j.State == "failed"
	})
	if done.State != "completed_with_warnings" || !strings.HasSuffix(done.Error, "2 remote item(s) could not be copied") {
		t.Fatalf("job=%+v", done)
	}
	if got, err := os.ReadFile(filepath.Join(p.destination.root, "tree/a.txt")); err != nil || string(got) != "alpha" {
		t.Fatalf("permitted file: %q %v", got, err)
	}
	for _, name := range []string{"tree/b.txt", "tree/c.txt"} {
		if _, err := os.Stat(filepath.Join(p.destination.root, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was copied although the policy no longer allowed it: %v", name, err)
		}
	}
	items, err := p.destination.jobs.ListItems(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if strings.Contains(item.Error, "b.txt") || strings.Contains(item.Error, "c.txt") {
			t.Fatalf("an item error names the file: %+v", item)
		}
	}
}

func TestSignedPullPreviewNeverNamesWhatThePolicyHides(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/public.txt", "public")
	p.write(t, p.source, "tree/secret.pem", "private key")
	p.write(t, p.source, "tree/vault/inner.txt", "inner")
	hidden := []filetypes.Rule{
		{PolicyID: "pem", Path: p.base(p.source) + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "vault", Path: p.base(p.source) + "/tree/vault/**", Capabilities: []string{"deny"}},
	}
	request := p.request(".", 0, "tree")
	binding := p.binding(t, request, ".")
	envelope := p.lease(t, binding, 1, 25*time.Second, p.rules(hidden...))
	plan, err := p.destination.transfers.PlanSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, envelope, p.keys)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(plan)
	text := string(encoded)
	for _, forbidden := range []string{"secret", ".pem", "vault", "inner"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the preview named a hidden entry (%q): %s", forbidden, text)
		}
	}
	// A hidden file and a hidden directory are each one omission; what is inside
	// a hidden directory is not walked or counted.
	if plan.SourcesOmitted != 2 || plan.FilesTotal != 1 || !strings.Contains(text, "public.txt") {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := os.Stat(filepath.Join(p.destination.root, "tree")); !os.IsNotExist(err) {
		t.Fatalf("previewing created something: %v", err)
	}
	if jobsList, err := p.destination.jobs.List(context.Background(), 10); err != nil || len(jobsList) != 0 {
		t.Fatalf("previewing created a job: %+v %v", jobsList, err)
	}
	// An envelope for another scope previews nothing.
	other := binding
	other.SourceGrantID = "other"
	forged, err := signLeaseOrEmpty(p, other, p.rules())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.destination.transfers.PlanSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, forged, p.keys); err == nil {
		t.Fatal("a lease for another grant produced a preview")
	}
}

// previewMove plans a move under a lease and returns its confirmation.
func (p *signedPull) previewMove(t *testing.T, request transfers.BatchPullRequest, rules []filetypes.Rule) (entities.CopyPlan, error) {
	t.Helper()
	binding := p.binding(t, request, ".")
	return p.destination.transfers.PlanSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, p.lease(t, binding, 1, 25*time.Second, rules), p.keys)
}

// confirmMove creates the move with a plan's confirmation.
func (p *signedPull) confirmMove(t *testing.T, request transfers.BatchPullRequest, plan *entities.MovePlanInfo, rules []filetypes.Rule, key string) (entities.Job, signedauth.Binding, error) {
	t.Helper()
	request.MovePlanID, request.MovePlanToken = plan.PlanID, plan.Token
	binding := p.binding(t, request, ".")
	envelope := p.lease(t, binding, 1, 25*time.Second, rules)
	job, _, err := p.destination.transfers.CreateSignedBatchPull(context.Background(), request, p.destination.identity.NodeID, envelope, key, p.keys)
	if err != nil {
		return entities.Job{}, binding, err
	}
	if _, err := p.destination.store.RenewJobAuthorization(context.Background(), job.ID, p.destination.identity.NodeID, envelope, binding, p.keys, time.Now().UTC()); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	return job, binding, nil
}

func (p *signedPull) exists(node *testNode, name string) bool {
	_, err := os.Stat(filepath.Join(node.root, name))
	return err == nil
}

func TestSignedMoveCopiesThenDeletesTheSourceOnlyAfterConfirmation(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/a.txt", "alpha")
	p.write(t, p.source, "tree/deep/b.txt", "beta")
	request := p.moveRequest(".", 0, "tree")
	plan, err := p.previewMove(t, request, p.moveRules())
	if err != nil || plan.MovePlan == nil || plan.MovePlan.Token == "" || plan.FilesTotal != 2 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	// Planning changes nothing, anywhere.
	if p.exists(p.destination, "tree") || !p.exists(p.source, "tree/a.txt") {
		t.Fatal("planning moved something")
	}
	if jobsList, err := p.destination.jobs.List(context.Background(), 10); err != nil || len(jobsList) != 0 {
		t.Fatalf("planning created a job: %+v %v", jobsList, err)
	}
	job, _, err := p.confirmMove(t, request, plan.MovePlan, p.moveRules(), "move-1")
	if err != nil {
		t.Fatal(err)
	}
	done := p.wait(t, job.ID, 20*time.Second, func(j entities.Job) bool {
		return j.State == "completed" || j.State == "completed_with_warnings" || j.State == "failed"
	})
	if done.State != "completed" {
		t.Fatalf("job=%+v", done)
	}
	for name, want := range map[string]string{"tree/a.txt": "alpha", "tree/deep/b.txt": "beta"} {
		if got, err := os.ReadFile(filepath.Join(p.destination.root, name)); err != nil || string(got) != want {
			t.Fatalf("destination %s: %q %v", name, got, err)
		}
	}
	if p.exists(p.source, "tree") {
		t.Fatal("the source survived a completed move")
	}
	// The confirmation is single-use: another job cannot ride on it.
	if _, _, err := p.confirmMove(t, request, plan.MovePlan, p.moveRules(), "move-2"); err == nil {
		t.Fatal("a consumed plan was accepted again")
	}
}

func TestSignedMoveRefusesWhatChangedHiddenOrWasNotConfirmed(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/a.txt", "alpha")
	request := p.moveRequest(".", 0, "tree")

	// Something the operator never saw cannot be moved by confirming another plan.
	plan, err := p.previewMove(t, request, p.moveRules())
	if err != nil {
		t.Fatal(err)
	}
	p.write(t, p.source, "tree/a.txt", "ALPHA, edited after the plan")
	if _, _, err := p.confirmMove(t, request, plan.MovePlan, p.moveRules(), "k1"); !errors.Is(err, jobs.ErrTreeChanged) {
		t.Fatalf("a changed source was confirmed: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(p.source.root, "tree/a.txt")); string(got) != "ALPHA, edited after the plan" {
		t.Fatalf("a refused move touched the source: %q", got)
	}

	// A wrong token, another subject or an unknown plan are refused.
	fresh, err := p.previewMove(t, request, p.moveRules())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*entities.MovePlanInfo){
		"wrong token":  func(m *entities.MovePlanInfo) { m.Token += "x" },
		"unknown plan": func(m *entities.MovePlanInfo) { m.PlanID = "plan_unknown" },
	} {
		changed := *fresh.MovePlan
		mutate(&changed)
		if _, _, err := p.confirmMove(t, request, &changed, p.moveRules(), "k-"+strings.ReplaceAll(name, " ", "-")); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	other := request
	other.SubjectType = "service_account"
	if _, _, err := p.confirmMove(t, other, fresh.MovePlan, p.moveRules(), "k-subject"); err == nil {
		t.Fatal("a plan was consumed by another kind of subject")
	}
	if !p.exists(p.source, "tree/a.txt") || p.exists(p.destination, "tree") {
		t.Fatal("a refused confirmation changed a tree")
	}

	// A move that would leave a hidden entry behind is refused outright.
	p.write(t, p.source, "tree/secret.pem", "private key")
	hidden := filetypes.Rule{PolicyID: "pem", Path: p.base(p.source) + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}
	if _, err := p.previewMove(t, request, p.moveRules(hidden)); !errors.Is(err, transfers.ErrMoveIncomplete) {
		t.Fatalf("a move with a hidden entry was planned: %v", err)
	}
	// A copy of the same tree is still fine, and reports the omission.
	copyRequest := p.request(".", 0, "tree")
	copyPlan, err := p.destination.transfers.PlanSignedBatchPull(context.Background(), copyRequest, p.destination.identity.NodeID,
		p.lease(t, p.binding(t, copyRequest, "."), 1, 25*time.Second, p.rules(hidden)), p.keys)
	if err != nil || copyPlan.SourcesOmitted != 1 {
		t.Fatalf("copy preview=%+v err=%v", copyPlan, err)
	}
}

func TestSignedMoveNeverDeletesWhatTheLeaseDoesNotLetTheActorDelete(t *testing.T) {
	p := newSignedPull(t)
	p.write(t, p.source, "tree/a.txt", "alpha")
	request := p.moveRequest(".", 0, "tree")
	noDelete := []filetypes.Rule{
		{PolicyID: "read", Path: p.base(p.source) + "/**", Capabilities: []string{"list", "read", "update"}},
		{PolicyID: "write", Path: p.base(p.destination) + "/**", Capabilities: []string{"list", "read", "create", "update"}},
	}
	plan, err := p.previewMove(t, request, noDelete)
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := p.confirmMove(t, request, plan.MovePlan, noDelete, "move-no-delete")
	if err != nil {
		t.Fatal(err)
	}
	done := p.wait(t, job.ID, 30*time.Second, func(j entities.Job) bool { return j.State == "completed" || j.State == "failed" })
	if done.State != "failed" {
		t.Fatalf("job=%+v", done)
	}
	if got, err := os.ReadFile(filepath.Join(p.source.root, "tree/a.txt")); err != nil || string(got) != "alpha" {
		t.Fatalf("the source was deleted without the delete capability: %q %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(p.destination.root, "tree/a.txt")); err != nil || string(got) != "alpha" {
		t.Fatalf("the copy half did not run: %q %v", got, err)
	}
}
