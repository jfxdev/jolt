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
		Permissions: entities.GrantPermissions{Read: true}, VisibleToPeer: true, Enabled: true, CorrelationID: "cor-source-grant",
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

func (p *signedPull) binding(t *testing.T, request transfers.BatchPullRequest, destinationRoot string) signedauth.Binding {
	t.Helper()
	_, digest, err := p.destination.transfers.PrepareSignedBatchPull(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return signedauth.Binding{
		ActorID: "actor", CredentialID: "credential", Operation: "transfer_pull_batch",
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
	move := p.request(".", 0, "tree")
	move.Operation = "move"
	if _, _, err := p.destination.transfers.PrepareSignedBatchPull(context.Background(), move); !errors.Is(err, transfers.ErrInvalid) {
		t.Fatalf("a move was prepared: %v", err)
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
