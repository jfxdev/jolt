package config

import (
	"testing"
	"time"
)

func TestCopyChunkSizeConfiguration(t *testing.T) {
	t.Setenv("CONTROL_TOWER_TOKEN", "test-token")
	t.Setenv("JOLT_DATA_DIR", t.TempDir())
	t.Setenv("JOLT_KEYS_DIR", t.TempDir())
	t.Setenv("COPY_CHUNK_SIZE_BYTES", "65536")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CopyChunkSize != 64<<10 {
		t.Fatalf("copy chunk size=%d want=%d", cfg.CopyChunkSize, 64<<10)
	}
}

func TestInvalidCopyChunkSizeUsesDefault(t *testing.T) {
	t.Setenv("CONTROL_TOWER_TOKEN", "test-token")
	t.Setenv("JOLT_DATA_DIR", t.TempDir())
	t.Setenv("JOLT_KEYS_DIR", t.TempDir())
	t.Setenv("COPY_CHUNK_SIZE_BYTES", "1024")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CopyChunkSize != 16<<20 {
		t.Fatalf("copy chunk size=%d want default=%d", cfg.CopyChunkSize, 16<<20)
	}
}

func TestPeerHeartbeatConfiguration(t *testing.T) {
	t.Setenv("CONTROL_TOWER_TOKEN", "test-token")
	t.Setenv("JOLT_DATA_DIR", t.TempDir())
	t.Setenv("JOLT_KEYS_DIR", t.TempDir())
	t.Setenv("MTLS_PUBLIC_ENDPOINT", "https://node.example.test:8443/")
	t.Setenv("PEER_HEARTBEAT_INTERVAL", "30s")
	t.Setenv("PEER_HEARTBEAT_TIMEOUT", "4s")
	t.Setenv("PEER_FAILURE_THRESHOLD", "4")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTLSPublicEndpoint != "https://node.example.test:8443" ||
		cfg.PeerHeartbeatInterval != 30*time.Second || cfg.PeerHeartbeatTimeout != 4*time.Second ||
		cfg.PeerFailureThreshold != 4 {
		t.Fatalf("unexpected heartbeat configuration: %+v", cfg)
	}
}

func TestTransferTimeoutConfiguration(t *testing.T) {
	t.Setenv("CONTROL_TOWER_TOKEN", "test-token")
	t.Setenv("JOLT_DATA_DIR", t.TempDir())
	t.Setenv("JOLT_KEYS_DIR", t.TempDir())
	t.Setenv("TRANSFER_CONNECT_TIMEOUT", "3s")
	t.Setenv("TRANSFER_IDLE_READ_TIMEOUT", "45s")
	t.Setenv("TRANSFER_CHUNK_TIMEOUT", "4m")
	t.Setenv("JOB_VALIDATION_TIMEOUT", "90s")
	t.Setenv("JOB_NO_PROGRESS_TIMEOUT", "8m")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TransferConnectTimeout != 3*time.Second ||
		cfg.TransferIdleReadTimeout != 45*time.Second ||
		cfg.TransferChunkTimeout != 4*time.Minute ||
		cfg.JobValidationTimeout != 90*time.Second ||
		cfg.JobNoProgressTimeout != 8*time.Minute {
		t.Fatalf("unexpected timeout configuration: %+v", cfg)
	}
}

func TestNodeBandwidthConfiguration(t *testing.T) {
	t.Setenv("CONTROL_TOWER_TOKEN", "test-token")
	t.Setenv("JOLT_DATA_DIR", t.TempDir())
	t.Setenv("JOLT_KEYS_DIR", t.TempDir())
	t.Setenv("NODE_BANDWIDTH_LIMIT_BYTES_PER_SECOND", "1048576")
	t.Setenv("MAX_PARALLEL_FILES_PER_JOB", "6")
	t.Setenv("MAX_PARALLEL_CHUNKS_PER_FILE", "4")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeBandwidthLimit != 1<<20 {
		t.Fatalf("node bandwidth limit=%d want=%d", cfg.NodeBandwidthLimit, 1<<20)
	}
	if cfg.MaxParallelFilesPerJob != 6 {
		t.Fatalf("max parallel files=%d want=6", cfg.MaxParallelFilesPerJob)
	}
	if cfg.MaxParallelChunksPerFile != 4 {
		t.Fatalf("max parallel chunks=%d want=4", cfg.MaxParallelChunksPerFile)
	}
}
