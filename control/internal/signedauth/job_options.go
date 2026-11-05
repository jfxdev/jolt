package signedauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// JobOptions is the immutable execution configuration bound to a job lease.
// Its JSON representation is shared with the node.
type JobOptions struct {
	Overwrite          bool   `json:"overwrite"`
	Recursive          bool   `json:"recursive"`
	ConflictPolicy     string `json:"conflict_policy"`
	SourceChangePolicy string `json:"source_change_policy"`
	VerifyChecksum     bool   `json:"verify_checksum"`
	BandwidthLimit     int64  `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int    `json:"max_parallel_files"`
	MaxParallelChunks  int    `json:"max_parallel_chunks"`
	MaxAttempts        int    `json:"max_attempts"`
}

func JobOptionsDigest(options JobOptions) string {
	payload, _ := json.Marshal(options)
	sum := sha256.Sum256(append([]byte("jolt-job-options-v1\x00"), payload...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validJobOptionsDigest(digest string) bool {
	if digest == "" {
		return true
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == digest
}
