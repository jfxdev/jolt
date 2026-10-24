package entities

import "time"

type Mount struct {
	ID         string    `json:"mount_id" yaml:"mount_id"`
	Name       string    `json:"name" yaml:"name"`
	LocalPath  string    `json:"-" yaml:"local_path"`
	TargetType string    `json:"target_type" yaml:"target_type"`
	Mode       string    `json:"mode" yaml:"mode"`
	Published  bool      `json:"published" yaml:"published"`
	Enabled    bool      `json:"enabled" yaml:"enabled"`
	State      string    `json:"state" yaml:"state"`
	Readable   bool      `json:"readable" yaml:"readable"`
	Writable   bool      `json:"writable" yaml:"writable"`
	ModeBits   string    `json:"mode_bits,omitempty" yaml:"mode_bits"`
	CreatedAt  time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" yaml:"updated_at"`
}

type FileEntry struct {
	Name       string    `json:"name" yaml:"name"`
	Path       string    `json:"path" yaml:"path"`
	Type       string    `json:"type" yaml:"type"`
	Size       int64     `json:"size" yaml:"size"`
	ModifiedAt time.Time `json:"modified_at" yaml:"modified_at"`
	Checksum   string    `json:"checksum,omitempty" yaml:"checksum"`
}

type Job struct {
	ParentJobID        string     `json:"-"`
	ID                 string     `json:"job_id" yaml:"job_id"`
	Type               string     `json:"type" yaml:"type"`
	State              string     `json:"state" yaml:"state"`
	Phase              string     `json:"phase" yaml:"phase"`
	MountID            string     `json:"mount_id" yaml:"mount_id"`
	PeerNodeID         string     `json:"peer_node_id,omitempty" yaml:"peer_node_id"`
	SourceGrantID      string     `json:"source_grant_id,omitempty" yaml:"source_grant_id"`
	DestinationGrantID string     `json:"destination_grant_id,omitempty" yaml:"destination_grant_id"`
	SourceETag         string     `json:"source_etag,omitempty" yaml:"source_etag"`
	SourcePath         string     `json:"source_path,omitempty" yaml:"source_path"`
	Destination        string     `json:"destination_path,omitempty" yaml:"destination_path"`
	BytesTotal         int64      `json:"bytes_total" yaml:"bytes_total"`
	BytesCompleted     int64      `json:"bytes_completed" yaml:"bytes_completed"`
	BytesPerSecond     float64    `json:"bytes_per_second,omitempty" yaml:"bytes_per_second"`
	ETASeconds         *int64     `json:"eta_seconds,omitempty" yaml:"eta_seconds"`
	ETAConfidence      string     `json:"eta_confidence,omitempty" yaml:"eta_confidence"`
	FilesTotal         int        `json:"files_total" yaml:"files_total"`
	FilesCompleted     int        `json:"files_completed" yaml:"files_completed"`
	FilesFailed        int        `json:"files_failed" yaml:"files_failed"`
	ConflictPolicy     string     `json:"conflict_policy,omitempty" yaml:"conflict_policy"`
	SourceChangePolicy string     `json:"source_change_policy,omitempty" yaml:"source_change_policy"`
	VerifyChecksum     bool       `json:"verify_checksum,omitempty" yaml:"verify_checksum"`
	BandwidthLimit     int64      `json:"bandwidth_limit_bytes_per_second,omitempty" yaml:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int        `json:"max_parallel_files,omitempty" yaml:"max_parallel_files"`
	MaxParallelChunks  int        `json:"max_parallel_chunks,omitempty" yaml:"max_parallel_chunks"`
	Overwrite          bool       `json:"overwrite,omitempty" yaml:"overwrite"`
	Recursive          bool       `json:"recursive,omitempty" yaml:"recursive"`
	Attempt            int        `json:"attempt" yaml:"attempt"`
	MaxAttempts        int        `json:"max_attempts" yaml:"max_attempts"`
	Error              string     `json:"error,omitempty" yaml:"error"`
	CorrelationID      string     `json:"correlation_id" yaml:"correlation_id"`
	CreatedAt          time.Time  `json:"created_at" yaml:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" yaml:"updated_at"`
	StartedAt          *time.Time `json:"started_at,omitempty" yaml:"started_at"`
	NextAttemptAt      *time.Time `json:"next_attempt_at,omitempty" yaml:"next_attempt_at"`
	CompletedAt        *time.Time `json:"completed_at,omitempty" yaml:"completed_at"`
}

type JobItem struct {
	JobID           string    `json:"job_id,omitempty" yaml:"job_id"`
	Ordinal         int       `json:"ordinal" yaml:"ordinal"`
	RelativePath    string    `json:"relative_path" yaml:"relative_path"`
	SourcePath      string    `json:"source_path" yaml:"source_path"`
	DestinationPath string    `json:"destination_path" yaml:"destination_path"`
	Type            string    `json:"type" yaml:"type"`
	Size            int64     `json:"size" yaml:"size"`
	ModifiedAt      time.Time `json:"modified_at" yaml:"modified_at"`
	Checksum        string    `json:"checksum,omitempty" yaml:"checksum"`
	// SourceRoot marks an item selected directly by a batch request. Cleanup
	// checkpoints remain on every expanded item so move never recursively
	// removes an unchecked source tree.
	SourceRoot         bool      `json:"source_root,omitempty" yaml:"source_root"`
	SourceCleanupState string    `json:"source_cleanup_state,omitempty" yaml:"source_cleanup_state"`
	Action             string    `json:"action" yaml:"action"`
	State              string    `json:"state" yaml:"state"`
	BytesCompleted     int64     `json:"bytes_completed" yaml:"bytes_completed"`
	Attempt            int       `json:"attempt" yaml:"attempt"`
	Error              string    `json:"error,omitempty" yaml:"error"`
	UpdatedAt          time.Time `json:"updated_at" yaml:"updated_at"`
}

type CopyPlan struct {
	SourcePath      string    `json:"source_path" yaml:"source_path"`
	DestinationPath string    `json:"destination_path" yaml:"destination_path"`
	ConflictPolicy  string    `json:"conflict_policy" yaml:"conflict_policy"`
	BytesTotal      int64     `json:"bytes_total" yaml:"bytes_total"`
	FilesTotal      int       `json:"files_total" yaml:"files_total"`
	CopyCount       int       `json:"copy_count" yaml:"copy_count"`
	SkipCount       int       `json:"skip_count" yaml:"skip_count"`
	RenameCount     int       `json:"rename_count" yaml:"rename_count"`
	ConflictCount   int       `json:"conflict_count" yaml:"conflict_count"`
	Items           []JobItem `json:"items" yaml:"items"`
	Truncated       bool      `json:"truncated,omitempty" yaml:"truncated"`
}

type JobEvent struct {
	ID             int64     `json:"event_id" yaml:"event_id"`
	JobID          string    `json:"job_id" yaml:"job_id"`
	Type           string    `json:"type" yaml:"type"`
	State          string    `json:"state" yaml:"state"`
	Phase          string    `json:"phase" yaml:"phase"`
	BytesTotal     int64     `json:"bytes_total" yaml:"bytes_total"`
	BytesCompleted int64     `json:"bytes_completed" yaml:"bytes_completed"`
	BytesPerSecond float64   `json:"bytes_per_second,omitempty" yaml:"bytes_per_second"`
	ETASeconds     *int64    `json:"eta_seconds,omitempty" yaml:"eta_seconds"`
	ETAConfidence  string    `json:"eta_confidence,omitempty" yaml:"eta_confidence"`
	FilesTotal     int       `json:"files_total" yaml:"files_total"`
	FilesCompleted int       `json:"files_completed" yaml:"files_completed"`
	FilesFailed    int       `json:"files_failed" yaml:"files_failed"`
	Message        string    `json:"message,omitempty" yaml:"message"`
	CorrelationID  string    `json:"correlation_id" yaml:"correlation_id"`
	CreatedAt      time.Time `json:"created_at" yaml:"created_at"`
}

type Identity struct {
	NodeID      string `json:"node_id" yaml:"node_id"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	PublicKey   string `json:"public_key" yaml:"public_key"`
	Epoch       int    `json:"identity_epoch" yaml:"identity_epoch"`
}

type OperationalTokenState struct {
	StagedHash       string    `json:"-" yaml:"staged_hash"`
	ActiveHash       string    `json:"-" yaml:"active_hash"`
	EnvTokenDisabled bool      `json:"env_token_disabled" yaml:"env_token_disabled"`
	UpdatedAt        time.Time `json:"updated_at" yaml:"updated_at"`
	CorrelationID    string    `json:"correlation_id" yaml:"correlation_id"`
}

type PairingInvite struct {
	ID            string     `json:"invite_id" yaml:"invite_id"`
	TargetNodeID  string     `json:"target_node_id,omitempty" yaml:"target_node_id"`
	TransferMode  string     `json:"transfer_mode" yaml:"transfer_mode"`
	IssuerRole    string     `json:"issuer_role" yaml:"issuer_role"`
	InviteeRole   string     `json:"invitee_role" yaml:"invitee_role"`
	Purpose       string     `json:"purpose,omitempty" yaml:"purpose"`
	ClusterID     string     `json:"cluster_id,omitempty" yaml:"cluster_id"`
	OneTime       bool       `json:"one_time" yaml:"one_time"`
	Status        string     `json:"status" yaml:"status"`
	ExpiresAt     time.Time  `json:"expires_at" yaml:"expires_at"`
	CreatedAt     time.Time  `json:"created_at" yaml:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at"`
	CorrelationID string     `json:"correlation_id" yaml:"correlation_id"`
}

type PairingRequest struct {
	ID                  string    `json:"request_id" yaml:"request_id"`
	InviteID            string    `json:"invite_id" yaml:"invite_id"`
	IssuerNodeID        string    `json:"issuer_node_id" yaml:"issuer_node_id"`
	IssuerName          string    `json:"issuer_name" yaml:"issuer_name"`
	IssuerFingerprint   string    `json:"issuer_fingerprint" yaml:"issuer_fingerprint"`
	IssuerIdentityEpoch int       `json:"issuer_identity_epoch" yaml:"issuer_identity_epoch"`
	IssuerEndpoint      string    `json:"issuer_endpoint" yaml:"issuer_endpoint"`
	IssuerMTLSEndpoint  string    `json:"issuer_mtls_endpoint" yaml:"issuer_mtls_endpoint"`
	TransferMode        string    `json:"transfer_mode" yaml:"transfer_mode"`
	IssuerRole          string    `json:"issuer_role" yaml:"issuer_role"`
	InviteeRole         string    `json:"invitee_role" yaml:"invitee_role"`
	Purpose             string    `json:"purpose,omitempty" yaml:"purpose"`
	ClusterID           string    `json:"cluster_id,omitempty" yaml:"cluster_id"`
	Status              string    `json:"status" yaml:"status"`
	ExpiresAt           time.Time `json:"expires_at" yaml:"expires_at"`
	CreatedAt           time.Time `json:"created_at" yaml:"created_at"`
	CorrelationID       string    `json:"correlation_id" yaml:"correlation_id"`
}

type Peer struct {
	NodeID              string     `json:"node_id" yaml:"node_id"`
	Name                string     `json:"name" yaml:"name"`
	Fingerprint         string     `json:"fingerprint" yaml:"fingerprint"`
	PreviousFingerprint string     `json:"previous_fingerprint,omitempty" yaml:"previous_fingerprint"`
	IdentityEpoch       int        `json:"identity_epoch" yaml:"identity_epoch"`
	Endpoint            string     `json:"endpoint" yaml:"endpoint"`
	MTLSEndpoint        string     `json:"mtls_endpoint" yaml:"mtls_endpoint"`
	TransferMode        string     `json:"transfer_mode" yaml:"transfer_mode"`
	LocalRole           string     `json:"local_role" yaml:"local_role"`
	RemoteRole          string     `json:"remote_role" yaml:"remote_role"`
	ClusterID           string     `json:"cluster_id,omitempty" yaml:"cluster_id"`
	State               string     `json:"state" yaml:"state"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty" yaml:"last_seen_at"`
	ConsecutiveFailures int        `json:"consecutive_failures" yaml:"consecutive_failures"`
	TrustedAt           time.Time  `json:"trusted_at" yaml:"trusted_at"`
	CorrelationID       string     `json:"correlation_id" yaml:"correlation_id"`
}

// PeerStateRevokedByPeer marks a peer whose mTLS listener rejected our
// certificate: trust still exists locally, but the counterpart has dropped it.
// It is deliberately distinct from "offline", which means unreachable.
const PeerStateRevokedByPeer = "revoked_by_peer"

// TrustedPeerState reports whether a peer state still authorizes data-plane
// traffic. Single definition shared by grant validation, transfer
// authorization and mTLS certificate verification.
func TrustedPeerState(state string) bool {
	switch state {
	case "trusted", "unknown", "online", "offline", "degraded":
		return true
	default:
		return false
	}
}

type GrantPermissions struct {
	Read   bool `json:"read" yaml:"read"`
	Write  bool `json:"write" yaml:"write"`
	Delete bool `json:"delete" yaml:"delete"`
	Rename bool `json:"rename" yaml:"rename"`
}

type TransferPathGrant struct {
	ConfiguredEnabled bool             `json:"configured_enabled" yaml:"-"`
	InactiveReason    string           `json:"inactive_reason,omitempty" yaml:"-"`
	ID                string           `json:"grant_id" yaml:"grant_id"`
	PeerNodeID        string           `json:"peer_node_id" yaml:"peer_node_id"`
	MountID           string           `json:"mount_id" yaml:"mount_id"`
	Path              string           `json:"path" yaml:"path"`
	Direction         string           `json:"direction" yaml:"direction"`
	Permissions       GrantPermissions `json:"permissions" yaml:"permissions"`
	ConflictPolicies  []string         `json:"conflict_policies" yaml:"conflict_policies"`
	VisibleToPeer     bool             `json:"visible_to_peer" yaml:"visible_to_peer"`
	Enabled           bool             `json:"enabled" yaml:"enabled"`
	CorrelationID     string           `json:"correlation_id" yaml:"correlation_id"`
	CreatedAt         time.Time        `json:"created_at" yaml:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at" yaml:"updated_at"`
}

// UploadSession tracks a client-driven resumable upload. The partial file on
// disk is the source of truth for how many bytes arrived; this row records
// what the upload is for so it survives a node restart and can be resumed or
// swept.
type UploadSession struct {
	ID            string    `json:"upload_id" yaml:"upload_id"`
	MountID       string    `json:"mount_id" yaml:"mount_id"`
	Destination   string    `json:"destination_path" yaml:"destination_path"`
	Size          int64     `json:"size" yaml:"size"`
	Offset        int64     `json:"offset" yaml:"offset"`
	Overwrite     bool      `json:"overwrite" yaml:"overwrite"`
	Checksum      string    `json:"checksum,omitempty" yaml:"checksum"`
	ChunkSize     int64     `json:"chunk_size" yaml:"chunk_size"`
	CorrelationID string    `json:"correlation_id,omitempty" yaml:"correlation_id"`
	CreatedAt     time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" yaml:"updated_at"`
	ExpiresAt     time.Time `json:"expires_at" yaml:"expires_at"`
}
