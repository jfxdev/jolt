package config

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	NodeName                 string
	APIAddress               string
	MTLSAddress              string
	MTLSPublicEndpoint       string
	DataDir                  string
	KeysDir                  string
	ControlTowerToken        string
	PublicHealth             bool
	ShutdownTimeout          time.Duration
	MaxConcurrentJobs        int
	JobMaxAttempts           int
	CopyChunkSize            int64
	NodeBandwidthLimit       int64
	MaxParallelFilesPerJob   int
	MaxParallelChunksPerFile int
	TransferConnectTimeout   time.Duration
	TransferIdleReadTimeout  time.Duration
	TransferChunkTimeout     time.Duration
	JobValidationTimeout     time.Duration
	JobNoProgressTimeout     time.Duration
	PeerHeartbeatInterval    time.Duration
	PeerHeartbeatTimeout     time.Duration
	PeerFailureThreshold     int
}

func Load() (Config, error) {
	c := Config{
		NodeName:                 value("NODE_NAME", "jolt-node"),
		APIAddress:               value("API_ADDRESS", ":8080"),
		MTLSAddress:              value("MTLS_ADDRESS", ":8443"),
		MTLSPublicEndpoint:       strings.TrimRight(value("MTLS_PUBLIC_ENDPOINT", ""), "/"),
		DataDir:                  value("JOLT_DATA_DIR", "./.jolt/data"),
		KeysDir:                  value("JOLT_KEYS_DIR", "./.jolt/keys"),
		PublicHealth:             boolValue("PUBLIC_HEALTHCHECK", true),
		ShutdownTimeout:          15 * time.Second,
		MaxConcurrentJobs:        intValue("MAX_CONCURRENT_JOBS", 2, 1, 32),
		JobMaxAttempts:           intValue("JOB_MAX_ATTEMPTS", 3, 1, 20),
		CopyChunkSize:            int64Value("COPY_CHUNK_SIZE_BYTES", 16<<20, 64<<10, 1<<30),
		NodeBandwidthLimit:       nonNegativeInt64Value("NODE_BANDWIDTH_LIMIT_BYTES_PER_SECOND", 0, 1<<40),
		MaxParallelFilesPerJob:   intValue("MAX_PARALLEL_FILES_PER_JOB", 2, 1, 32),
		MaxParallelChunksPerFile: intValue("MAX_PARALLEL_CHUNKS_PER_FILE", 1, 1, 16),
		TransferConnectTimeout:   durationValue("TRANSFER_CONNECT_TIMEOUT", 10*time.Second, time.Second, 5*time.Minute),
		TransferIdleReadTimeout:  durationValue("TRANSFER_IDLE_READ_TIMEOUT", 60*time.Second, time.Second, 30*time.Minute),
		TransferChunkTimeout:     durationValue("TRANSFER_CHUNK_TIMEOUT", 5*time.Minute, time.Second, 24*time.Hour),
		JobValidationTimeout:     durationValue("JOB_VALIDATION_TIMEOUT", 2*time.Minute, time.Second, 30*time.Minute),
		JobNoProgressTimeout:     durationValue("JOB_NO_PROGRESS_TIMEOUT", 10*time.Minute, time.Second, 24*time.Hour),
		PeerHeartbeatInterval:    durationValue("PEER_HEARTBEAT_INTERVAL", 15*time.Second, time.Second, 10*time.Minute),
		PeerHeartbeatTimeout:     durationValue("PEER_HEARTBEAT_TIMEOUT", 5*time.Second, time.Second, time.Minute),
		PeerFailureThreshold:     intValue("PEER_FAILURE_THRESHOLD", 3, 1, 20),
	}
	c.ControlTowerToken = strings.TrimSpace(os.Getenv("CONTROL_TOWER_TOKEN"))
	if c.ControlTowerToken == "" {
		return Config{}, errors.New("CONTROL_TOWER_TOKEN is required")
	}
	var err error
	if c.DataDir, err = filepath.Abs(c.DataDir); err != nil {
		return Config{}, err
	}
	if c.KeysDir, err = filepath.Abs(c.KeysDir); err != nil {
		return Config{}, err
	}
	if c.DataDir == c.KeysDir {
		return Config{}, errors.New("JOLT_DATA_DIR and JOLT_KEYS_DIR must be different")
	}
	if c.MTLSPublicEndpoint != "" {
		endpoint, err := url.Parse(c.MTLSPublicEndpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
			return Config{}, errors.New("MTLS_PUBLIC_ENDPOINT must be an absolute https URL")
		}
	}
	return c, nil
}

func nonNegativeInt64Value(key string, fallback, maximum int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed < 0 || parsed > maximum {
		return fallback
	}
	return parsed
}

func durationValue(key string, fallback, minimum, maximum time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func int64Value(key string, fallback, minimum, maximum int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func intValue(key string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func value(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func boolValue(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
