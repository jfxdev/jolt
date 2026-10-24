package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/httpapi"
	"github.com/jfxdev/jolt/backend/internal/infra/metrics"
	"github.com/jfxdev/jolt/backend/internal/infra/mtlsapi"
	"github.com/jfxdev/jolt/backend/internal/infra/recovery"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"github.com/jfxdev/jolt/backend/internal/services/peers"
	"github.com/jfxdev/jolt/backend/internal/services/transfers"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "snapshot" {
		if err := runSnapshot(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "snapshot failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "restore-diagnostics" {
		if err := runRestoreDiagnostics(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "restore diagnostics failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "recover-operational-token" {
		if err := runRecoverOperationalToken(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "operational token recovery failed:", err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	flags := flag.NewFlagSet("jolt-node", flag.ExitOnError)
	configFile := flags.String("config", "", "path to node.yaml")
	_ = flags.Parse(os.Args[1:])
	cfg, err := config.Load(*configFile)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	if err := db.RejectLegacy(cfg.DataDir); err != nil {
		logger.Error("legacy state is not supported", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		logger.Error("create data directory", "error", err)
		os.Exit(1)
	}
	instanceLock, err := recovery.AcquireLock(cfg.DataDir)
	if err != nil {
		logger.Error("acquire instance lock", "error", err)
		os.Exit(1)
	}
	defer instanceLock.Close()
	identity, err := joltcrypto.LoadOrCreate(cfg.KeysDir)
	if err != nil {
		logger.Error("load node identity", "error", err)
		os.Exit(1)
	}
	store, err := db.Open(cfg.DataDir, cfg.EncryptionKey)
	if err != nil {
		logger.Error("open encrypted YAML state", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	mounts, grantsConfig := cfg.Resources()
	if err := store.ApplyConfiguration(context.Background(), cfg.Revision, mounts, grantsConfig, cfg.PublicYAML); err != nil {
		logger.Error("apply node configuration", "error", err)
		os.Exit(1)
	}

	fileService := filesystem.New(store, cfg.ProtectedPaths()...)
	jobService := jobs.New(store, fileService, cfg.JobMaxAttempts)
	jobService.ConfigureChunkSize(cfg.CopyChunkSize)
	jobService.ConfigureBandwidth(cfg.NodeBandwidthLimit)
	jobService.ConfigureParallelism(cfg.MaxParallelFilesPerJob, cfg.MaxParallelChunksPerFile)
	jobService.ConfigureTimeouts(cfg.JobValidationTimeout, cfg.TransferChunkTimeout, cfg.JobNoProgressTimeout)
	jobContext, stopJobs := context.WithCancel(context.Background())
	defer stopJobs()
	pairingService := pairing.New(store, identity)
	grantService := grants.New(store, fileService)
	certificateManager, err := joltcrypto.LoadOrCreateCertificateManager(cfg.KeysDir, identity, store)
	if err != nil {
		logger.Error("load mTLS certificate state", "error", err)
		os.Exit(1)
	}
	transferService := transfers.New(store, fileService, jobService, certificateManager, cfg.CopyChunkSize)
	transferService.ConfigureTimeouts(cfg.TransferConnectTimeout, cfg.TransferIdleReadTimeout,
		cfg.TransferChunkTimeout, cfg.JobValidationTimeout)
	jobService.ConfigureRemoteExecutor(transferService)
	registry := metrics.NewRegistry()
	registerNodeMetrics(registry, cfg)
	go sweepUploadSessions(jobContext, store, fileService, logger, cfg.UploadSessionTTL)
	recoveredJobs, err := jobService.Start(jobContext, cfg.MaxConcurrentJobs)
	if err != nil {
		logger.Error("start job workers", "error", err)
		os.Exit(1)
	}
	if recoveredJobs > 0 {
		logger.Warn("recovered interrupted jobs", "count", recoveredJobs)
	}
	peerMonitor := peers.NewMonitor(store, certificateManager, cfg.PeerHeartbeatInterval,
		cfg.PeerHeartbeatTimeout, cfg.PeerFailureThreshold, logger)
	peerMonitor.ConfigurePeerOnline(func(ctx context.Context, peerNodeID string) {
		if count, wakeErr := jobService.WakePeer(ctx, peerNodeID); wakeErr != nil {
			logger.Error("wake jobs waiting for peer", "peer_node_id", peerNodeID, "error", wakeErr)
		} else if count > 0 {
			logger.Info("jobs resumed after peer heartbeat", "peer_node_id", peerNodeID, "count", count)
		}
	})
	go peerMonitor.Run(jobContext)
	server := &http.Server{
		Addr:              cfg.APIAddress,
		Handler:           httpapi.New(cfg, identity, fileService, jobService, pairingService, grantService, logger, store, certificateManager, transferService, registry),
		ReadHeaderTimeout: 10 * 1e9,
		IdleTimeout:       120 * 1e9,
	}
	if cfg.APITLSEnabled() {
		apiTLS, tlsErr := apiTLSConfig(cfg)
		if tlsErr != nil {
			logger.Error("load API TLS material", "error", tlsErr)
			os.Exit(1)
		}
		server.TLSConfig = apiTLS
	}
	mtlsServer := &http.Server{
		Addr: cfg.MTLSAddress, Handler: mtlsapi.New(identity, cfg.NodeName, transferService),
		TLSConfig:         certificateManager.TLSConfig(),
		ReadHeaderTimeout: 10 * 1e9, IdleTimeout: 120 * 1e9,
	}
	go func() {
		scheme := "http"
		if cfg.APITLSEnabled() {
			scheme = "https"
		}
		logger.Info("jolt node started", "node_id", identity.NodeID, "fingerprint", identity.Fingerprint,
			"address", cfg.APIAddress, "scheme", scheme, "client_certificate_required", cfg.APITLSClientCAFile != "")
		if !cfg.APITLSEnabled() {
			logger.Warn("control API is serving plaintext HTTP; the operational token and file bytes " +
				"are exposed on the wire. Set api_tls_cert_file and api_tls_key_file in node.yaml, or keep this " +
				"listener on a private network. See docs/REVERSE_PROXY.md")
		}
		var err error
		if cfg.APITLSEnabled() {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()
	go func() {
		logger.Info("jolt mTLS peer listener started", "address", cfg.MTLSAddress)
		if err := mtlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("mTLS peer listener stopped", "error", err)
			os.Exit(1)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	failed := false
	select {
	case <-signals:
	case <-store.Failure():
		logger.Error("persistent state failure; stopping node")
		failed = true
		stopJobs()
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
	if err := mtlsServer.Shutdown(ctx); err != nil {
		logger.Error("mTLS graceful shutdown failed", "error", err)
	}
	stopJobs()
	if err := jobService.Shutdown(ctx); err != nil {
		logger.Error("job worker shutdown failed", "error", err)
	}
	if failed {
		os.Exit(1)
	}
}

// registerNodeMetrics declares every metric the node exposes. Declaring them
// up front means a scrape before the first request still returns a complete,
// zero-valued series set instead of an empty page.
func registerNodeMetrics(registry *metrics.Registry, cfg config.Config) {
	registry.Counter("jolt_http_requests_total",
		"Control API requests by method, matched route and status.", "method", "route", "status")
	registry.Histogram("jolt_http_request_duration_seconds",
		"Control API request latency in seconds.", nil, "route")
	registry.Counter("jolt_http_response_bytes_total",
		"Bytes written to control API responses.", "route")
	registry.Counter("jolt_uploads_started_total", "Resumable upload sessions opened.")
	registry.Counter("jolt_uploads_completed_total", "Resumable uploads published to their destination.")
	registry.Counter("jolt_uploads_failed_total", "Resumable uploads that failed verification.")
	registry.Counter("jolt_uploads_aborted_total", "Resumable uploads discarded by the client.")
	registry.Counter("jolt_upload_bytes_total", "Bytes accepted from resumable uploads.")
	registry.Gauge("jolt_uploads_active", "Resumable upload sessions currently open.")
	registry.Counter("jolt_jobs_total", "Jobs by type and terminal state.", "type", "state")
	registry.Counter("jolt_job_bytes_total", "Bytes moved by jobs.", "type")
	registry.Gauge("jolt_jobs_active", "Jobs currently running.")
	registry.GaugeFunc("jolt_node_info", "Always 1; present so a scrape confirms the node is up.",
		func() float64 { return 1 })
	registry.GaugeFunc("jolt_max_concurrent_jobs", "Configured job worker count.",
		func() float64 { return float64(cfg.MaxConcurrentJobs) })
	registry.RegisterRuntime()
}

// sweepUploadSessions discards resumable uploads whose client never came back,
// removing the partial file before the row so a crash mid-sweep cannot leave an
// orphan partial with no session pointing at it.
func sweepUploadSessions(ctx context.Context, store contracts.UploadStore, files *filesystem.Service,
	logger *slog.Logger, ttl time.Duration) {
	interval := ttl / 4
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > time.Hour {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		expired, err := store.ExpiredUploadSessions(ctx, time.Now().UTC())
		if err != nil {
			logger.Error("list expired upload sessions", "error", err)
			continue
		}
		for _, session := range expired {
			if err := files.AbortUpload(ctx, session.MountID, session.Destination, session.ID); err != nil {
				logger.Error("remove expired upload partial", "upload_id", session.ID, "error", err)
				continue
			}
			if err := store.DeleteUploadSession(ctx, session.ID); err != nil {
				logger.Error("delete expired upload session", "upload_id", session.ID, "error", err)
				continue
			}
			logger.Info("expired upload session swept", "upload_id", session.ID,
				"mount_id", session.MountID, "destination", session.Destination)
		}
	}
}

// apiTLSConfig builds the TLS configuration for the control API listener. The
// certificate is reloaded from disk on every handshake so a renewal (certbot,
// cert-manager, a homelab CA script) takes effect without restarting the node
// and interrupting running transfers. When a client CA is configured the
// listener also requires a verified client certificate, which turns the
// operational token into a second factor instead of the only one.
func apiTLSConfig(cfg config.Config) (*tls.Config, error) {
	load := func() (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(cfg.APITLSCertFile, cfg.APITLSKeyFile)
		if err != nil {
			return nil, err
		}
		return &pair, nil
	}
	if _, err := load(); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return load()
		},
	}
	if cfg.APITLSClientCAFile != "" {
		pem, err := os.ReadFile(cfg.APITLSClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("API_TLS_CLIENT_CA_FILE contains no usable certificate")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

func runSnapshot(arguments []string) error {
	flags := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	configFile := flags.String("config", environmentOrDefault("JOLT_CONFIG_FILE", "./node.yaml"), "path to node.yaml")
	dataDir := flags.String("data-dir", "",
		"node data directory")
	keysDir := flags.String("keys-dir", "",
		"node keys directory")
	output := flags.String("output", "", "destination .tar.gz file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	publicConfig, err := config.Read(*configFile)
	if err != nil {
		return err
	}
	if *dataDir == "" {
		*dataDir = publicConfig.DataDir
	}
	if *keysDir == "" {
		*keysDir = publicConfig.KeysDir
	}
	if strings.TrimSpace(*output) == "" {
		return errors.New("--output is required")
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	absoluteKeys, err := filepath.Abs(*keysDir)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	encryptionKey, err := config.LoadEncryptionKey()
	if err != nil {
		return err
	}
	manifest, err := recovery.CreateSnapshot(context.Background(), absoluteData, absoluteKeys, absoluteOutput, encryptionKey, *configFile)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}

func runRestoreDiagnostics(arguments []string) error {
	flags := flag.NewFlagSet("restore-diagnostics", flag.ContinueOnError)
	configFile := flags.String("config", environmentOrDefault("JOLT_CONFIG_FILE", "./node.yaml"), "path to node.yaml")
	dataDir := flags.String("data-dir", "",
		"restored node data directory")
	keysDir := flags.String("keys-dir", "",
		"restored node keys directory")
	expectedNodeID := flags.String("expected-node-id", "", "expected stable node_id")
	expectedFingerprint := flags.String("expected-fingerprint", "", "expected identity fingerprint")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	publicConfig, err := config.Read(*configFile)
	if err != nil {
		return err
	}
	if *dataDir == "" {
		*dataDir = publicConfig.DataDir
	}
	if *keysDir == "" {
		*keysDir = publicConfig.KeysDir
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	absoluteKeys, err := filepath.Abs(*keysDir)
	if err != nil {
		return err
	}
	encryptionKey, err := config.LoadEncryptionKey()
	if err != nil {
		return err
	}
	report, err := recovery.DiagnoseRestore(context.Background(), absoluteData, absoluteKeys,
		strings.TrimSpace(*expectedNodeID), strings.TrimSpace(*expectedFingerprint), encryptionKey)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	if report.Status == "error" {
		return errors.New("blocking inconsistencies were found")
	}
	return nil
}

func runRecoverOperationalToken(arguments []string) error {
	flags := flag.NewFlagSet("recover-operational-token", flag.ContinueOnError)
	configFile := flags.String("config", environmentOrDefault("JOLT_CONFIG_FILE", "./node.yaml"), "path to node.yaml")
	dataDir := flags.String("data-dir", "",
		"offline node data directory")
	confirmation := flags.String("confirm", "",
		`required acknowledgement: "replace-operational-token"`)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	publicConfig, err := config.Read(*configFile)
	if err != nil {
		return err
	}
	if *dataDir == "" {
		*dataDir = publicConfig.DataDir
	}
	if *confirmation != "replace-operational-token" {
		return errors.New(`--confirm replace-operational-token is required`)
	}
	token := strings.TrimSpace(os.Getenv("JOLT_RECOVERY_OPERATIONAL_TOKEN"))
	if len(token) < 32 {
		return errors.New("JOLT_RECOVERY_OPERATIONAL_TOKEN must contain at least 32 characters")
	}
	encryptionKey, err := config.LoadEncryptionKey()
	if err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	instanceLock, err := recovery.AcquireLock(absoluteData)
	if err != nil {
		return err
	}
	defer instanceLock.Close()
	storage, err := db.OpenExistingForUpdate(absoluteData, encryptionKey)
	if err != nil {
		return err
	}
	defer storage.Close()
	digest := sha256.Sum256([]byte(token))
	correlationID, err := recoveryCorrelationID()
	if err != nil {
		return err
	}
	if err := storage.RecoverOperationalToken(context.Background(), hex.EncodeToString(digest[:]),
		correlationID, time.Now().UTC()); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "recovered", "credential": "operational_token",
		"environment_token_disabled": true, "correlation_id": correlationID,
	})
}

func recoveryCorrelationID() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "cor_recovery_" + hex.EncodeToString(random), nil
}

func environmentOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
