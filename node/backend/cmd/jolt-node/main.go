package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/jfxdev/jolt/backend/internal/infra/config"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/infra/httpapi"
	"github.com/jfxdev/jolt/backend/internal/infra/mtlsapi"
	"github.com/jfxdev/jolt/backend/internal/infra/recovery"
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
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
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
	store, err := db.Open(filepath.Join(cfg.DataDir, "jolt.db"))
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	fileService := filesystem.New(store, cfg.KeysDir, cfg.DataDir)
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
		Handler:           httpapi.New(cfg, identity, fileService, jobService, pairingService, grantService, logger, store, certificateManager, transferService),
		ReadHeaderTimeout: 10 * 1e9,
		IdleTimeout:       120 * 1e9,
	}
	mtlsServer := &http.Server{
		Addr: cfg.MTLSAddress, Handler: mtlsapi.New(identity, cfg.NodeName, transferService),
		TLSConfig:         certificateManager.TLSConfig(),
		ReadHeaderTimeout: 10 * 1e9, IdleTimeout: 120 * 1e9,
	}
	go func() {
		logger.Info("jolt node started", "node_id", identity.NodeID, "fingerprint", identity.Fingerprint, "address", cfg.APIAddress)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	<-signals
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
}

func runSnapshot(arguments []string) error {
	flags := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	dataDir := flags.String("data-dir", environmentOrDefault("JOLT_DATA_DIR", "./.jolt/data"),
		"node data directory")
	keysDir := flags.String("keys-dir", environmentOrDefault("JOLT_KEYS_DIR", "./.jolt/keys"),
		"node keys directory")
	output := flags.String("output", "", "destination .tar.gz file")
	if err := flags.Parse(arguments); err != nil {
		return err
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
	manifest, err := recovery.CreateSnapshot(context.Background(), absoluteData, absoluteKeys, absoluteOutput)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}

func runRestoreDiagnostics(arguments []string) error {
	flags := flag.NewFlagSet("restore-diagnostics", flag.ContinueOnError)
	dataDir := flags.String("data-dir", environmentOrDefault("JOLT_DATA_DIR", "./.jolt/data"),
		"restored node data directory")
	keysDir := flags.String("keys-dir", environmentOrDefault("JOLT_KEYS_DIR", "./.jolt/keys"),
		"restored node keys directory")
	expectedNodeID := flags.String("expected-node-id", "", "expected stable node_id")
	expectedFingerprint := flags.String("expected-fingerprint", "", "expected identity fingerprint")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	absoluteKeys, err := filepath.Abs(*keysDir)
	if err != nil {
		return err
	}
	report, err := recovery.DiagnoseRestore(context.Background(), absoluteData, absoluteKeys,
		strings.TrimSpace(*expectedNodeID), strings.TrimSpace(*expectedFingerprint))
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
	dataDir := flags.String("data-dir", environmentOrDefault("JOLT_DATA_DIR", "./.jolt/data"),
		"offline node data directory")
	confirmation := flags.String("confirm", "",
		`required acknowledgement: "replace-operational-token"`)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *confirmation != "replace-operational-token" {
		return errors.New(`--confirm replace-operational-token is required`)
	}
	token := strings.TrimSpace(os.Getenv("JOLT_RECOVERY_OPERATIONAL_TOKEN"))
	if len(token) < 32 {
		return errors.New("JOLT_RECOVERY_OPERATIONAL_TOKEN must contain at least 32 characters")
	}
	absoluteData, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	databasePath := filepath.Join(absoluteData, "jolt.db")
	if info, err := os.Stat(databasePath); err != nil {
		return fmt.Errorf("open existing node database: %w", err)
	} else if !info.Mode().IsRegular() {
		return errors.New("node database is not a regular file")
	}
	instanceLock, err := recovery.AcquireLock(absoluteData)
	if err != nil {
		return err
	}
	defer instanceLock.Close()
	storage, err := db.Open(databasePath)
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
