package jobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedEnv struct {
	service   *Service
	store     *db.Store
	mountID   string
	mountPath string
	key       ed25519.PrivateKey
	keys      map[string]ed25519.PublicKey
}

func newSignedEnv(t *testing.T, enabled bool) *signedEnv {
	t.Helper()
	service, files, mountID := testService(t)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	env := &signedEnv{service: service, store: service.store.(*db.Store), mountID: mountID, mountPath: mount.LocalPath, key: key, keys: map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}}
	service.ConfigureChunkSize(32 << 10)
	if enabled {
		service.ConfigureSignedExecution(env.store, "node", env.keys)
	}
	if _, err := service.Start(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *signedEnv) write(t *testing.T, name string, data []byte) {
	t.Helper()
	target := filepath.Join(e.mountPath, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *signedEnv) rules(extra ...filetypes.Rule) []filetypes.Rule {
	base := "nodes/node/files/mounts/" + e.mountID
	return append([]filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}, extra...)
}

func (e *signedEnv) denyPEM() filetypes.Rule {
	return filetypes.Rule{PolicyID: "pem", Path: "nodes/node/files/mounts/" + e.mountID + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}
}

func (e *signedEnv) lease(t *testing.T, binding signedauth.Binding, revision uint64, ttl time.Duration, rules []filetypes.Rule) string {
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
	token, err := signedauth.Sign(signedauth.Claims{Version: signedauth.Version, KeyID: "key", Binding: bound, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), Context: policy}, e.key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// create persists a signed local copy through the production creation path and
// records its first lease, as the Control Tower would.
func (e *signedEnv) create(t *testing.T, request CreateRequest, ttl time.Duration, rules []filetypes.Rule) (entities.Job, signedauth.Binding) {
	t.Helper()
	request.Type, request.MountID = "copy_local", e.mountID
	_, digest, err := e.service.PrepareSignedLocalCopy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	binding := signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "copy_local", SourceNodeID: "node", SourceMountID: e.mountID, SourceRoot: request.SourcePath, DestinationNodeID: "node", DestinationMountID: e.mountID, DestinationRoot: request.Destination, PlanID: "signedjob", JobOptionsDigest: digest}
	envelope := e.lease(t, binding, 1, ttl, rules)
	job, _, err := e.service.CreateAwaitingSignedAuthorization(context.Background(), request, "node", envelope, "request", e.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.RenewJobAuthorization(context.Background(), job.ID, "node", envelope, binding, e.keys, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	e.service.notify()
	return job, binding
}

func (e *signedEnv) renew(t *testing.T, job entities.Job, binding signedauth.Binding, revision uint64, ttl time.Duration, rules []filetypes.Rule) {
	t.Helper()
	envelope := e.lease(t, binding, revision, ttl, rules)
	if _, err := e.store.RenewJobAuthorization(context.Background(), job.ID, "node", envelope, binding, e.keys, time.Now().UTC()); err != nil {
		t.Fatalf("renew revision %d: %v", revision, err)
	}
	e.service.notify()
}

func (e *signedEnv) wait(t *testing.T, id string, timeout time.Duration, done func(entities.Job) bool) entities.Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		job, err := e.service.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if done(job) {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for job: %+v", job)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSignedCopyOmitsHiddenSourcesAndReportsOnlyTheCount(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "source/public.txt", []byte("public"))
	env.write(t, "source/secret.pem", []byte("private key"))
	job, _ := env.create(t, CreateRequest{SourcePath: "source", Destination: "destination", ConflictPolicy: "fail", SourceChangePolicy: "fail"}, 25*time.Second, env.rules(env.denyPEM()))
	finished := env.wait(t, job.ID, 20*time.Second, func(j entities.Job) bool {
		return j.State == "completed" || j.State == "completed_with_warnings" || j.State == "failed"
	})
	if finished.State != "completed_with_warnings" || !strings.HasSuffix(finished.Error, "1 source entries were not accessible") {
		t.Fatalf("job=%+v", finished)
	}
	if got, err := os.ReadFile(filepath.Join(env.mountPath, "destination/public.txt")); err != nil || string(got) != "public" {
		t.Fatalf("visible file was not copied: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "destination/secret.pem")); !os.IsNotExist(err) {
		t.Fatalf("hidden file was copied: %v", err)
	}
	events, err := env.service.ListEvents(context.Background(), 0, job.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	omittedEvents := 0
	for _, event := range events {
		if strings.Contains(event.Message, "secret") || strings.Contains(event.Message, ".pem") {
			t.Fatalf("hidden name leaked in an event: %+v", event)
		}
		if event.Type == "job.sources_omitted" {
			omittedEvents++
		}
	}
	if omittedEvents != 1 {
		t.Fatalf("omission events=%d", omittedEvents)
	}
}

func TestSignedCopyWaitsForRenewalWhenLeaseExpiresAndResumes(t *testing.T) {
	env := newSignedEnv(t, true)
	content := bytes.Repeat([]byte("0123456789abcdef"), 12<<10) // 192 KiB
	env.write(t, "big.bin", content)
	job, binding := env.create(t, CreateRequest{SourcePath: "big.bin", Destination: "copy.bin", ConflictPolicy: "fail", SourceChangePolicy: "fail", BandwidthLimit: 32 << 10}, 3*time.Second, env.rules())
	parked := env.wait(t, job.ID, 20*time.Second, func(j entities.Job) bool {
		return j.Phase == "waiting_authorization" && j.State == "waiting_validation"
	})
	if parked.Attempt != 0 || parked.Error == "" {
		t.Fatalf("parked job=%+v", parked)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "copy.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination published before authorization: %v", err)
	}
	items, err := env.service.ListItems(context.Background(), job.ID)
	if err != nil || len(items) != 1 || items[0].BytesCompleted >= int64(len(content)) {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	// A newer lease queues the job by itself and the copy continues.
	env.renew(t, job, binding, 2, 25*time.Second, env.rules())
	finished := env.wait(t, job.ID, 30*time.Second, func(j entities.Job) bool { return j.State == "completed" || j.State == "failed" })
	if finished.State != "completed" {
		t.Fatalf("job=%+v", finished)
	}
	if got, err := os.ReadFile(filepath.Join(env.mountPath, "copy.bin")); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("copy differs after resume: len=%d err=%v", len(got), err)
	}
}

func TestSignedCopyStopsWhenPolicyContextChanges(t *testing.T) {
	env := newSignedEnv(t, true)
	env.write(t, "big.bin", bytes.Repeat([]byte("0123456789abcdef"), 12<<10))
	job, binding := env.create(t, CreateRequest{SourcePath: "big.bin", Destination: "copy.bin", ConflictPolicy: "fail", SourceChangePolicy: "fail", BandwidthLimit: 32 << 10}, 25*time.Second, env.rules())
	env.wait(t, job.ID, 10*time.Second, func(j entities.Job) bool { return j.State == "running" && j.Phase == "transfer" })
	// Renewing a running job with a different policy context must stop it.
	env.renew(t, job, binding, 2, 25*time.Second, env.rules(env.denyPEM()))
	parked := env.wait(t, job.ID, 10*time.Second, func(j entities.Job) bool { return j.Phase == "waiting_authorization" })
	if parked.State != "waiting_validation" {
		t.Fatalf("job=%+v", parked)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "copy.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination published after the policy changed: %v", err)
	}
}

func TestSignedCopyKeepsRunningWhenLeaseIsRenewedWithSamePolicy(t *testing.T) {
	env := newSignedEnv(t, true)
	content := bytes.Repeat([]byte("0123456789abcdef"), 12<<10)
	env.write(t, "big.bin", content)
	job, binding := env.create(t, CreateRequest{SourcePath: "big.bin", Destination: "copy.bin", ConflictPolicy: "fail", SourceChangePolicy: "fail", BandwidthLimit: 32 << 10}, 4*time.Second, env.rules())
	env.wait(t, job.ID, 10*time.Second, func(j entities.Job) bool { return j.State == "running" && j.Phase == "transfer" })
	// Renew every second, as the Control Tower would, well beyond the first lease.
	for revision := uint64(2); revision < 8; revision++ {
		time.Sleep(time.Second)
		if current, _ := env.service.Get(context.Background(), job.ID); current.State == "completed" {
			break
		}
		env.renew(t, job, binding, revision, 4*time.Second, env.rules())
	}
	finished := env.wait(t, job.ID, 30*time.Second, func(j entities.Job) bool {
		return j.State == "completed" || j.State == "failed" || j.Phase == "waiting_authorization"
	})
	if finished.State != "completed" || finished.Attempt != 1 {
		t.Fatalf("job=%+v", finished)
	}
	if got, err := os.ReadFile(filepath.Join(env.mountPath, "copy.bin")); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("copy differs: len=%d err=%v", len(got), err)
	}
}

func TestSignedCopyDoesNotRunWithoutSignedExecution(t *testing.T) {
	env := newSignedEnv(t, false)
	env.write(t, "source.txt", []byte("data"))
	job, _ := env.create(t, CreateRequest{SourcePath: "source.txt", Destination: "copy.txt", ConflictPolicy: "fail", SourceChangePolicy: "fail"}, 25*time.Second, env.rules())
	time.Sleep(1500 * time.Millisecond)
	current, err := env.service.Get(context.Background(), job.ID)
	if err != nil || current.State != "queued" {
		t.Fatalf("job=%+v err=%v", current, err)
	}
	if _, err := os.Stat(filepath.Join(env.mountPath, "copy.txt")); !os.IsNotExist(err) {
		t.Fatalf("job ran without signed execution: %v", err)
	}
}
