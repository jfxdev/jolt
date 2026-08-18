package entities

import "time"

type Mount struct {
	ID         string    `json:"mount_id"`
	Name       string    `json:"name"`
	LocalPath  string    `json:"-"`
	TargetType string    `json:"target_type"`
	Mode       string    `json:"mode"`
	Published  bool      `json:"published"`
	Enabled    bool      `json:"enabled"`
	State      string    `json:"state"`
	Readable   bool      `json:"readable"`
	Writable   bool      `json:"writable"`
	ModeBits   string    `json:"mode_bits,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type FileEntry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"modified_at"`
	Checksum   string    `json:"checksum,omitempty"`
}

type Job struct {
	ParentJobID        string     `json:"-"`
	ID                 string     `json:"job_id"`
	Type               string     `json:"type"`
	State              string     `json:"state"`
	Phase              string     `json:"phase"`
	MountID            string     `json:"mount_id"`
	PeerNodeID         string     `json:"peer_node_id,omitempty"`
	SourceGrantID      string     `json:"source_grant_id,omitempty"`
	DestinationGrantID string     `json:"destination_grant_id,omitempty"`
	SourceETag         string     `json:"source_etag,omitempty"`
	SourcePath         string     `json:"source_path,omitempty"`
	Destination        string     `json:"destination_path,omitempty"`
	BytesTotal         int64      `json:"bytes_total"`
	BytesCompleted     int64      `json:"bytes_completed"`
	BytesPerSecond     float64    `json:"bytes_per_second,omitempty"`
	ETASeconds         *int64     `json:"eta_seconds,omitempty"`
	ETAConfidence      string     `json:"eta_confidence,omitempty"`
	FilesTotal         int        `json:"files_total"`
	FilesCompleted     int        `json:"files_completed"`
	FilesFailed        int        `json:"files_failed"`
	ConflictPolicy     string     `json:"conflict_policy,omitempty"`
	SourceChangePolicy string     `json:"source_change_policy,omitempty"`
	VerifyChecksum     bool       `json:"verify_checksum,omitempty"`
	BandwidthLimit     int64      `json:"bandwidth_limit_bytes_per_second,omitempty"`
	MaxParallelFiles   int        `json:"max_parallel_files,omitempty"`
	MaxParallelChunks  int        `json:"max_parallel_chunks,omitempty"`
	Overwrite          bool       `json:"overwrite,omitempty"`
	Recursive          bool       `json:"recursive,omitempty"`
	Attempt            int        `json:"attempt"`
	MaxAttempts        int        `json:"max_attempts"`
	Error              string     `json:"error,omitempty"`
	CorrelationID      string     `json:"correlation_id"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	NextAttemptAt      *time.Time `json:"next_attempt_at,omitempty"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
}

type JobItem struct {
	JobID           string    `json:"job_id,omitempty"`
	Ordinal         int       `json:"ordinal"`
	RelativePath    string    `json:"relative_path"`
	SourcePath      string    `json:"source_path"`
	DestinationPath string    `json:"destination_path"`
	Type            string    `json:"type"`
	Size            int64     `json:"size"`
	ModifiedAt      time.Time `json:"modified_at"`
	Checksum        string    `json:"checksum,omitempty"`
	Action          string    `json:"action"`
	State           string    `json:"state"`
	BytesCompleted  int64     `json:"bytes_completed"`
	Attempt         int       `json:"attempt"`
	Error           string    `json:"error,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CopyPlan struct {
	SourcePath      string    `json:"source_path"`
	DestinationPath string    `json:"destination_path"`
	ConflictPolicy  string    `json:"conflict_policy"`
	BytesTotal      int64     `json:"bytes_total"`
	FilesTotal      int       `json:"files_total"`
	CopyCount       int       `json:"copy_count"`
	SkipCount       int       `json:"skip_count"`
	RenameCount     int       `json:"rename_count"`
	ConflictCount   int       `json:"conflict_count"`
	Items           []JobItem `json:"items"`
	Truncated       bool      `json:"truncated,omitempty"`
}

type JobEvent struct {
	ID             int64     `json:"event_id"`
	JobID          string    `json:"job_id"`
	Type           string    `json:"type"`
	State          string    `json:"state"`
	Phase          string    `json:"phase"`
	BytesTotal     int64     `json:"bytes_total"`
	BytesCompleted int64     `json:"bytes_completed"`
	BytesPerSecond float64   `json:"bytes_per_second,omitempty"`
	ETASeconds     *int64    `json:"eta_seconds,omitempty"`
	ETAConfidence  string    `json:"eta_confidence,omitempty"`
	FilesTotal     int       `json:"files_total"`
	FilesCompleted int       `json:"files_completed"`
	FilesFailed    int       `json:"files_failed"`
	Message        string    `json:"message,omitempty"`
	CorrelationID  string    `json:"correlation_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type Identity struct {
	NodeID      string `json:"node_id"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	Epoch       int    `json:"identity_epoch"`
}

type OperationalTokenState struct {
	StagedHash       string    `json:"-"`
	ActiveHash       string    `json:"-"`
	EnvTokenDisabled bool      `json:"env_token_disabled"`
	UpdatedAt        time.Time `json:"updated_at"`
	CorrelationID    string    `json:"correlation_id"`
}

type PairingInvite struct {
	ID            string     `json:"invite_id"`
	TargetNodeID  string     `json:"target_node_id,omitempty"`
	TransferMode  string     `json:"transfer_mode"`
	IssuerRole    string     `json:"issuer_role"`
	InviteeRole   string     `json:"invitee_role"`
	Purpose       string     `json:"purpose,omitempty"`
	ClusterID     string     `json:"cluster_id,omitempty"`
	OneTime       bool       `json:"one_time"`
	Status        string     `json:"status"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CorrelationID string     `json:"correlation_id"`
}

type PairingRequest struct {
	ID                  string    `json:"request_id"`
	InviteID            string    `json:"invite_id"`
	IssuerNodeID        string    `json:"issuer_node_id"`
	IssuerName          string    `json:"issuer_name"`
	IssuerFingerprint   string    `json:"issuer_fingerprint"`
	IssuerIdentityEpoch int       `json:"issuer_identity_epoch"`
	IssuerEndpoint      string    `json:"issuer_endpoint"`
	IssuerMTLSEndpoint  string    `json:"issuer_mtls_endpoint"`
	TransferMode        string    `json:"transfer_mode"`
	IssuerRole          string    `json:"issuer_role"`
	InviteeRole         string    `json:"invitee_role"`
	Purpose             string    `json:"purpose,omitempty"`
	ClusterID           string    `json:"cluster_id,omitempty"`
	Status              string    `json:"status"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	CorrelationID       string    `json:"correlation_id"`
}

type Peer struct {
	NodeID              string     `json:"node_id"`
	Name                string     `json:"name"`
	Fingerprint         string     `json:"fingerprint"`
	PreviousFingerprint string     `json:"previous_fingerprint,omitempty"`
	IdentityEpoch       int        `json:"identity_epoch"`
	Endpoint            string     `json:"endpoint"`
	MTLSEndpoint        string     `json:"mtls_endpoint"`
	TransferMode        string     `json:"transfer_mode"`
	LocalRole           string     `json:"local_role"`
	RemoteRole          string     `json:"remote_role"`
	ClusterID           string     `json:"cluster_id,omitempty"`
	State               string     `json:"state"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	TrustedAt           time.Time  `json:"trusted_at"`
	CorrelationID       string     `json:"correlation_id"`
}

type GrantPermissions struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	Delete bool `json:"delete"`
	Rename bool `json:"rename"`
}

type TransferPathGrant struct {
	ID               string           `json:"grant_id"`
	PeerNodeID       string           `json:"peer_node_id"`
	MountID          string           `json:"mount_id"`
	Path             string           `json:"path"`
	Direction        string           `json:"direction"`
	Permissions      GrantPermissions `json:"permissions"`
	ConflictPolicies []string         `json:"conflict_policies"`
	VisibleToPeer    bool             `json:"visible_to_peer"`
	Enabled          bool             `json:"enabled"`
	CorrelationID    string           `json:"correlation_id"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}
