package transfers_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/infra/mtlsapi"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"github.com/jfxdev/jolt/backend/internal/services/transfers"
)

type testNode struct {
	store        *db.Store
	identity     entities.Identity
	files        *filesystem.Service
	jobs         *jobs.Service
	pairing      *pairing.Service
	grants       *grants.Service
	certificates *joltcrypto.CertificateManager
	transfers    *transfers.Service
	mountID      string
	root         string
}

type singleConnectionListener struct {
	connection net.Conn
	accepted   bool
}

func (l *singleConnectionListener) Accept() (net.Conn, error) {
	if l.accepted {
		return nil, errors.New("listener closed")
	}
	l.accepted = true
	return l.connection, nil
}

func (l *singleConnectionListener) Close() error   { return nil }
func (l *singleConnectionListener) Addr() net.Addr { return pipeAddress("jolt-test") }

type pipeAddress string

func (a pipeAddress) Network() string { return "pipe" }
func (a pipeAddress) String() string  { return string(a) }

func pipeTLSDialer(handler http.Handler, config *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		listener := tls.NewListener(&singleConnectionListener{connection: server}, config)
		httpServer := &http.Server{Handler: handler}
		go func() {
			_ = httpServer.Serve(listener)
		}()
		return client, nil
	}
}

func newTransferTestNode(t *testing.T, name string) *testNode {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	dataDir, keysDir, filesDir := filepath.Join(root, "data"), filepath.Join(root, "keys"), filepath.Join(root, "files")
	for _, directory := range []string{dataDir, keysDir, filesDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := db.Open(filepath.Join(dataDir, "jolt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	identity, err := joltcrypto.LoadOrCreate(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	files := filesystem.New(store, keysDir, dataDir)
	mount, err := files.SaveMount(context.Background(), entities.Mount{
		Name: name, LocalPath: filesDir, Mode: "read_write", Published: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	jobService := jobs.New(store, files, 1)
	certificates, err := joltcrypto.LoadOrCreateCertificateManager(keysDir, identity, store)
	if err != nil {
		t.Fatal(err)
	}
	transferService := transfers.New(store, files, jobService, certificates, 64<<10)
	jobService.ConfigureRemoteExecutor(transferService)
	jobService.ConfigureChunkSize(64 << 10)
	return &testNode{
		store: store, identity: identity, files: files, jobs: jobService,
		pairing: pairing.New(store, identity), grants: grants.New(store, files),
		certificates: certificates, transfers: transferService, mountID: mount.ID, root: filesDir,
	}
}

func trustPeer(t *testing.T, local *testNode, remote *testNode, remoteMTLSEndpoint string) {
	t.Helper()
	request, err := local.pairing.CreateIncomingRequest(context.Background(), pairing.IncomingRequestInput{
		InviteID: "invite-" + remote.identity.NodeID, InviteToken: "12345678901234567890123456789012",
		IssuerNodeID: remote.identity.NodeID, IssuerName: remote.identity.NodeID,
		IssuerFingerprint: remote.identity.Fingerprint, IssuerEndpoint: "https://control.invalid",
		IssuerMTLSEndpoint: remoteMTLSEndpoint, TransferMode: "dual_channel",
		IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
		ExpiresAt: time.Now().UTC().Add(time.Hour), CorrelationID: "cor-pair",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.pairing.AcceptRequest(context.Background(), request.ID, remote.identity.Fingerprint, "cor-accept"); err != nil {
		t.Fatal(err)
	}
}

func TestPullTransferStreamsDirectlyBetweenTrustedNodes(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	if err := os.WriteFile(filepath.Join(source.root, "movie.bin"), []byte("direct mTLS transfer payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	destination.transfers.ConfigureDialContext(pipeTLSDialer(
		mtlsapi.New(source.identity, "source", source.transfers), source.certificates.TLSConfig(),
	))

	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true},
		VisibleToPeer: true, Enabled: true, CorrelationID: "cor-source-grant",
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail", "overwrite", "checksum"},
		VisibleToPeer:    true, Enabled: true, CorrelationID: "cor-destination-grant",
	})
	if err != nil {
		t.Fatal(err)
	}

	workerContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdownContext)
	})
	job, repeated, err := destination.transfers.CreatePull(context.Background(), transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "movie.bin",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "received.bin",
		ConflictPolicy: "fail", VerifyChecksum: true, CorrelationID: "cor-transfer",
	}, "transfer-idempotency")
	if err != nil || repeated {
		t.Fatalf("create transfer: job=%+v repeated=%v err=%v", job, repeated, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := destination.jobs.Get(context.Background(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "completed" {
			contents, readErr := os.ReadFile(filepath.Join(destination.root, "received.bin"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(contents) != "direct mTLS transfer payload" {
				t.Fatalf("unexpected destination contents %q", contents)
			}
			if current.BytesCompleted != int64(len(contents)) || current.SourceETag == "" {
				t.Fatalf("missing durable transfer progress: %+v", current)
			}
			return
		}
		if current.State == "failed" {
			t.Fatalf("transfer failed: %+v", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for direct transfer")
}

func TestPullTransferFetchesBoundedRangesConcurrently(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	content := bytes.Repeat([]byte("parallel-remote-range-"), 20_000)
	if err := os.WriteFile(filepath.Join(source.root, "large.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")

	baseHandler := mtlsapi.New(source.identity, "source", source.transfers)
	var active, maximum atomic.Int32
	var rangesMu sync.Mutex
	var ranges []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value := r.Header.Get("Range"); value != "" {
			current := active.Add(1)
			for {
				previous := maximum.Load()
				if current <= previous || maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			rangesMu.Lock()
			ranges = append(ranges, value)
			rangesMu.Unlock()
			time.Sleep(25 * time.Millisecond)
			defer active.Add(-1)
		}
		baseHandler.ServeHTTP(w, r)
	})
	destination.transfers.ConfigureDialContext(pipeTLSDialer(handler, source.certificates.TLSConfig()))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	workerContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdownContext)
	})
	job, repeated, err := destination.transfers.CreatePull(context.Background(), transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "large.bin",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "received.bin",
		ConflictPolicy: "fail", MaxParallelChunks: 3,
	}, "parallel-range-transfer")
	if err != nil || repeated {
		t.Fatalf("create transfer: job=%+v repeated=%v err=%v", job, repeated, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := destination.jobs.Get(context.Background(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "completed" {
			received, readErr := os.ReadFile(filepath.Join(destination.root, "received.bin"))
			if readErr != nil || !bytes.Equal(received, content) {
				t.Fatalf("parallel destination mismatch: bytes=%d err=%v", len(received), readErr)
			}
			if current.MaxParallelChunks != 3 || maximum.Load() < 2 {
				t.Fatalf("remote ranges were not concurrent: job=%+v maximum=%d", current, maximum.Load())
			}
			rangesMu.Lock()
			defer rangesMu.Unlock()
			if len(ranges) < 3 {
				t.Fatalf("expected multiple bounded ranges, got %v", ranges)
			}
			for _, value := range ranges {
				parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
				if len(parts) != 2 || parts[1] == "" {
					t.Fatalf("range is not explicitly bounded: %q", value)
				}
				start, startErr := strconv.ParseInt(parts[0], 10, 64)
				end, endErr := strconv.ParseInt(parts[1], 10, 64)
				if startErr != nil || endErr != nil || end < start || end-start+1 > 64<<10 {
					t.Fatalf("invalid bounded range %q", value)
				}
			}
			return
		}
		if current.State == "failed" {
			t.Fatalf("parallel transfer failed: %+v", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for parallel remote transfer")
}

func TestParallelPullRejectsChangedETagBeforePublication(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	content := bytes.Repeat([]byte("etag-range-"), 20_000)
	sourcePath := filepath.Join(source.root, "changing.bin")
	if err := os.WriteFile(sourcePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	baseHandler := mtlsapi.New(source.identity, "source", source.transfers)
	var changed atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" && changed.CompareAndSwap(false, true) {
			replacement := append([]byte(nil), content...)
			replacement[0] ^= 0xff
			if err := os.WriteFile(sourcePath, replacement, 0o600); err != nil {
				t.Errorf("change source: %v", err)
			}
		}
		baseHandler.ServeHTTP(w, r)
	})
	destination.transfers.ConfigureDialContext(pipeTLSDialer(handler, source.certificates.TLSConfig()))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := destination.transfers.CreatePull(context.Background(), transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "changing.bin",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "received.bin",
		ConflictPolicy: "fail", MaxParallelChunks: 3,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	written, err := destination.transfers.ExecutePull(context.Background(), job, func(int64, int64) error { return nil })
	if !errors.Is(err, filesystem.ErrSourceChanged) || written != 0 {
		t.Fatalf("changed ETag was not rejected at the batch checkpoint: written=%d err=%v", written, err)
	}
	if _, err := os.Stat(filepath.Join(destination.root, "received.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination was published after ETag divergence: %v", err)
	}
}

func TestParallelPullRetriesNetworkInterruptionFromDurableBatch(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	const chunkSize = int64(64 << 10)
	content := bytes.Repeat([]byte("retry-range-"), 64_000)
	sourcePath := filepath.Join(source.root, "interrupted.bin")
	if err := os.WriteFile(sourcePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	etag := fmt.Sprintf(`"%x-%x"`, info.Size(), info.ModTime().UTC().UnixNano())
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	baseHandler := mtlsapi.New(source.identity, "source", source.transfers)
	failedRange := fmt.Sprintf("bytes=%d-%d", 2*chunkSize, 3*chunkSize-1)
	var failed atomic.Bool
	var requestsMu sync.Mutex
	requestCounts := make(map[string]int)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		byteRange := r.Header.Get("Range")
		if byteRange != "" {
			requestsMu.Lock()
			requestCounts[byteRange]++
			requestsMu.Unlock()
		}
		if byteRange == failedRange && failed.CompareAndSwap(false, true) {
			w.Header().Set("ETag", etag)
			w.Header().Set("X-Jolt-File-Size", strconv.FormatInt(info.Size(), 10))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", 2*chunkSize, 3*chunkSize-1, info.Size()))
			w.Header().Set("Content-Length", strconv.FormatInt(chunkSize, 10))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(content[2*chunkSize : 2*chunkSize+chunkSize/2])
			return
		}
		baseHandler.ServeHTTP(w, r)
	})
	destination.transfers.ConfigureDialContext(pipeTLSDialer(handler, source.certificates.TLSConfig()))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := destination.transfers.CreatePull(context.Background(), transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "interrupted.bin",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "received.bin",
		ConflictPolicy: "fail", MaxParallelChunks: 2,
	}, "network-interruption")
	if err != nil {
		t.Fatal(err)
	}
	job.MaxAttempts = 3
	if err := destination.store.UpdateJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	workerContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdownContext)
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := destination.jobs.Get(context.Background(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "completed" {
			received, readErr := os.ReadFile(filepath.Join(destination.root, "received.bin"))
			if readErr != nil || !bytes.Equal(received, content) {
				t.Fatalf("retried destination mismatch: bytes=%d err=%v", len(received), readErr)
			}
			if current.Attempt != 2 {
				t.Fatalf("network interruption did not consume exactly one retry: %+v", current)
			}
			requestsMu.Lock()
			firstRangeRequests := requestCounts["bytes=0-65535"]
			failedRangeRequests := requestCounts[failedRange]
			requestsMu.Unlock()
			if firstRangeRequests != 1 || failedRangeRequests != 2 {
				t.Fatalf("retry did not resume from the durable batch: requests=%v", requestCounts)
			}
			return
		}
		if current.State == "failed" {
			t.Fatalf("network-interrupted transfer failed: %+v", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for network-interrupted retry")
}

func TestSourceGrantRejectsDifferentTrustedPeer(t *testing.T) {
	source, allowed, other := newTransferTestNode(t, "source"), newTransferTestNode(t, "allowed"), newTransferTestNode(t, "other")
	trustPeer(t, source, allowed, "https://allowed.invalid:8443")
	trustPeer(t, source, other, "https://other.invalid:8443")
	grant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: allowed.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true},
		VisibleToPeer: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := source.transfers.OpenSource(context.Background(), other.identity.NodeID, grant.ID, "anything", false)
	if file.File != nil {
		file.File.Close()
	}
	if err == nil {
		t.Fatal("expected an exact-peer grant rejection")
	}
}

func TestDirectoryPullPlansAndTransfersNestedItems(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	for name, contents := range map[string]string{
		"library/readme.txt":         "remote directory manifest",
		"library/assets/texture.bin": "texture payload",
	} {
		fullPath := filepath.Join(source.root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	destination.transfers.ConfigureDialContext(pipeTLSDialer(
		mtlsapi.New(source.identity, "source", source.transfers), source.certificates.TLSConfig(),
	))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true},
		VisibleToPeer: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail", "overwrite", "ask"},
		VisibleToPeer:    true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	firstPage, err := source.transfers.OpenManifest(context.Background(), destination.identity.NodeID,
		sourceGrant.ID, "library", false, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Items) != 2 || firstPage.NextAfter != 2 || firstPage.Total != 4 {
		t.Fatalf("unexpected first manifest page: %+v", firstPage)
	}
	secondPage, err := source.transfers.OpenManifest(context.Background(), destination.identity.NodeID,
		sourceGrant.ID, "library", false, firstPage.NextAfter, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Items) != 2 || secondPage.NextAfter != 0 {
		t.Fatalf("unexpected second manifest page: %+v", secondPage)
	}

	request := transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "library",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "restored",
		ConflictPolicy: "fail", CorrelationID: "cor-directory", MaxParallelFiles: 2,
	}
	plan, err := destination.transfers.PlanDirectoryPull(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes := int64(len("remote directory manifest") + len("texture payload"))
	if plan.FilesTotal != 2 || plan.CopyCount != 2 || plan.BytesTotal != expectedBytes || len(plan.Items) != 4 {
		t.Fatalf("unexpected remote directory plan: %+v", plan)
	}

	workerContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdownContext)
	})
	job, repeated, err := destination.transfers.CreateDirectoryPull(context.Background(), request, "directory-idempotency")
	if err != nil || repeated {
		t.Fatalf("create directory transfer: job=%+v repeated=%v err=%v", job, repeated, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := destination.jobs.Get(context.Background(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "completed" {
			if current.FilesCompleted != 2 || current.BytesCompleted != expectedBytes || current.MaxParallelFiles != 2 {
				t.Fatalf("unexpected completed progress: %+v", current)
			}
			items, listErr := destination.jobs.ListItems(context.Background(), job.ID)
			if listErr != nil || len(items) != 4 {
				t.Fatalf("unexpected durable items: items=%+v err=%v", items, listErr)
			}
			for name, expected := range map[string]string{
				"restored/readme.txt":         "remote directory manifest",
				"restored/assets/texture.bin": "texture payload",
			} {
				contents, readErr := os.ReadFile(filepath.Join(destination.root, filepath.FromSlash(name)))
				if readErr != nil || string(contents) != expected {
					t.Fatalf("unexpected destination %s: contents=%q err=%v", name, contents, readErr)
				}
			}
			return
		}
		if current.State == "failed" {
			t.Fatalf("directory transfer failed: %+v", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for remote directory transfer")
}

func TestDirectoryPullAskConflictCanBeOverridden(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	if err := os.MkdirAll(filepath.Join(source.root, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source.root, "folder", "file.txt"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destination.root, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination.root, "target", "file.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	destination.transfers.ConfigureDialContext(pipeTLSDialer(
		mtlsapi.New(source.identity, "source", source.transfers), source.certificates.TLSConfig(),
	))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"ask"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	workerContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdownContext)
	})
	job, _, err := destination.transfers.CreateDirectoryPull(context.Background(), transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "folder",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "target", ConflictPolicy: "ask",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := destination.jobs.Get(context.Background(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "waiting_user_decision" {
			items, listErr := destination.jobs.ListItems(context.Background(), job.ID)
			if listErr != nil {
				t.Fatal(listErr)
			}
			var conflictOrdinal = -1
			for _, item := range items {
				if item.Type == "file" && item.Action == "conflict" {
					conflictOrdinal = item.Ordinal
				}
			}
			if conflictOrdinal < 0 {
				t.Fatalf("missing file conflict: %+v", items)
			}
			if _, overrideErr := destination.jobs.OverrideItem(context.Background(), job.ID, conflictOrdinal, "overwrite", false); overrideErr != nil {
				t.Fatal(overrideErr)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, _ := destination.jobs.Get(context.Background(), job.ID)
		if current.State == "completed" {
			contents, readErr := os.ReadFile(filepath.Join(destination.root, "target", "file.txt"))
			if readErr != nil || string(contents) != "new" {
				t.Fatalf("override did not publish remote file: contents=%q err=%v", contents, readErr)
			}
			return
		}
		if current.State == "failed" {
			t.Fatalf("overridden transfer failed: %+v", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for overridden remote directory transfer")
}

func TestPullWaitsWithoutSpendingRetryBudgetAndWakesWhenPeerReturns(t *testing.T) {
	source, destination := newTransferTestNode(t, "source"), newTransferTestNode(t, "destination")
	if err := os.WriteFile(filepath.Join(source.root, "file.txt"), []byte("available again"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustPeer(t, destination, source, "https://source.test")
	trustPeer(t, source, destination, "https://destination.invalid:8443")
	destination.transfers.ConfigureDialContext(pipeTLSDialer(
		mtlsapi.New(source.identity, "source", source.transfers), source.certificates.TLSConfig(),
	))
	sourceGrant, err := source.grants.Create(context.Background(), grants.Input{
		PeerNodeID: destination.identity.NodeID, MountID: source.mountID, Path: ".",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationGrant, err := destination.grants.Create(context.Background(), grants.Input{
		PeerNodeID: source.identity.NodeID, MountID: destination.mountID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := destination.transfers.CreatePull(context.Background(), transfers.PullRequest{
		PeerNodeID: source.identity.NodeID, SourceGrantID: sourceGrant.ID, SourcePath: "file.txt",
		DestinationGrantID: destinationGrant.ID, DestinationPath: "received.txt", ConflictPolicy: "fail",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.store.UpdatePeerHealth(context.Background(), source.identity.NodeID, "offline", nil, 3); err != nil {
		t.Fatal(err)
	}
	workerContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := destination.jobs.Start(workerContext, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = destination.jobs.Shutdown(shutdownContext)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := destination.jobs.Get(context.Background(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "waiting_peer" {
			if current.Attempt != 0 {
				t.Fatalf("waiting for a peer spent retry budget: %+v", current)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := destination.store.UpdatePeerHealth(context.Background(), source.identity.NodeID, "online", ptrTime(time.Now().UTC()), 0); err != nil {
		t.Fatal(err)
	}
	if count, err := destination.jobs.WakePeer(context.Background(), source.identity.NodeID); err != nil || count != 1 {
		t.Fatalf("wake waiting job: count=%d err=%v", count, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, _ := destination.jobs.Get(context.Background(), job.ID)
		if current.State == "completed" {
			contents, readErr := os.ReadFile(filepath.Join(destination.root, "received.txt"))
			if readErr != nil || string(contents) != "available again" {
				t.Fatalf("woken transfer contents=%q err=%v", contents, readErr)
			}
			return
		}
		if current.State == "failed" {
			t.Fatalf("woken transfer failed: %+v", current)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for peer-woken transfer")
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
