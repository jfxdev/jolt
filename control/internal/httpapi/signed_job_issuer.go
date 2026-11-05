package httpapi

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// signedLocalJob describes metadata obtained from the node, never the client.
type signedLocalJob struct {
	ID                 string `json:"job_id"`
	Type               string `json:"type"`
	State              string `json:"state"`
	MountID            string `json:"mount_id"`
	Source             string `json:"source_path"`
	Destination        string `json:"destination_path"`
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

func (job signedLocalJob) optionsDigest() string {
	return signedauth.JobOptionsDigest(signedauth.JobOptions{Overwrite: job.Overwrite, Recursive: job.Recursive, ConflictPolicy: job.ConflictPolicy, SourceChangePolicy: job.SourceChangePolicy, VerifyChecksum: job.VerifyChecksum, BandwidthLimit: job.BandwidthLimit, MaxParallelFiles: job.MaxParallelFiles, MaxParallelChunks: job.MaxParallelChunks, MaxAttempts: job.MaxAttempts})
}

// issueSignedLocalJobLease builds an authorization for a persisted local job.
// It is not wired to an API or scheduler until durable actor linkage, renewal,
// and execution-time enforcement are implemented.
func (s *Server) issueSignedLocalJobLease(r *http.Request, nodeID string, job signedLocalJob, revision uint64, now time.Time) (string, error) {
	if len(s.config.AuthorizationSigningKey) == 0 || !signedauth.ValidKeyID(s.config.AuthorizationSigningKeyID) || !validPathIdentifier(nodeID) || !validPathIdentifier(job.ID) || !validPathIdentifier(job.MountID) {
		return "", errSignedReadUnavailable
	}
	actor, actorType := currentUser(r), currentActorType(r)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if !actor.Enabled || actor.ID == "" || credential == "" || digest == "" {
		return "", errSignedReadUnavailable
	}
	// Serialize current credential, group and policy lookup with administrative
	// changes. A signed context is a short-lived snapshot, not a permanent grant.
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	var credentialExpiry *time.Time
	switch actorType {
	case "user":
		current, expiry, err := s.store.SessionUserAndExpiry(r.Context(), digest)
		if err != nil || !current.Enabled || current.ID != actor.ID || !strings.HasPrefix(credential, "session-") {
			return "", errSignedReadUnavailable
		}
		actor, credentialExpiry = current, &expiry
	case "service_account":
		account, key, err := s.revalidateServiceCredential(r)
		if err != nil || !account.Enabled || account.Kind != "automation" || account.ID != actor.ID || credential != "token-"+key.ID || r.Context().Value(agentKey) != nil {
			return "", errSignedReadUnavailable
		}
		groups, err := s.store.ServiceAccountGroupIDs(r.Context(), account.ID, true)
		if err != nil {
			return "", err
		}
		member := false
		for _, group := range groups {
			allowed, err := s.store.NodeInAccessGroup(r.Context(), group, nodeID)
			if err != nil {
				return "", err
			}
			member = member || allowed
		}
		if !member {
			return "", errSignedReadUnavailable
		}
		actor = store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: true}
		credentialExpiry = key.ExpiresAt
	default:
		return "", errSignedReadUnavailable
	}
	policies, temporaryExpiry, err := s.signedPolicySnapshotLocked(r.Context(), actorType, actor.ID)
	if err != nil {
		return "", err
	}
	expanded := rbac.ExpandCompatibilityRules(policies)
	admin := actorType == "user" && actor.Role == "admin"
	if !admin {
		decision := rbac.Evaluate(expanded, "nodes/"+nodeID+"/jobs/"+job.ID, "execute")
		if !decision.Allowed || decision.Denied {
			return "", errSignedReadUnavailable
		}
	}
	base := "nodes/" + nodeID + "/files/mounts/" + job.MountID
	source := fileScope(base, job.Source)
	destination := fileScope(base, job.Destination)
	var required []authorizationRequirement
	binding := signedauth.Binding{ActorID: actor.ID, CredentialID: credential, Operation: job.Type, SourceNodeID: nodeID, SourceMountID: job.MountID, SourceRoot: job.Source, PlanID: job.ID, JobOptionsDigest: job.optionsDigest()}
	switch job.Type {
	case "delete":
		required = []authorizationRequirement{{Path: source, Capability: "delete"}}
	case "move_local":
		binding.DestinationNodeID, binding.DestinationMountID, binding.DestinationRoot = nodeID, job.MountID, job.Destination
		// Require both destination capabilities until conflict handling and
		// final destinations are revalidated during execution.
		required = []authorizationRequirement{{Path: source, Capability: "read"}, {Path: source, Capability: "update"}, {Path: destination, Capability: "create"}, {Path: destination, Capability: "update"}}
	case "copy_local":
		binding.DestinationNodeID, binding.DestinationMountID, binding.DestinationRoot = nodeID, job.MountID, job.Destination
		// Persisted item decisions can rename or overwrite. Until they can be
		// individually revalidated, authorize the entire destination parent.
		parent := fileScope(base, path.Dir(job.Destination))
		required = []authorizationRequirement{{Path: source, Capability: "read"}, {Path: parent, Capability: "create"}, {Path: parent, Capability: "update"}}
	default:
		return "", errSignedReadUnavailable
	}
	binding, err = signedauth.JobLeaseBinding(binding, revision)
	if err != nil {
		return "", errSignedReadUnavailable
	}
	for _, requirement := range required {
		if requirement.Path == "" || rbac.DeniesWithin(expanded, requirement.Path) {
			return "", errSignedReadUnavailable
		}
	}
	if admin {
		policies = []rbac.Policy{{ID: "builtin-admin", Rules: []rbac.Rule{{Path: base + "/**", Capabilities: []string{"read", "list", "create", "update", "delete"}}}}}
	}
	compiled, err := buildMountAccessContext(policies, base)
	if err != nil {
		return "", err
	}
	filter, err := compiled.Compile()
	if err != nil {
		return "", err
	}
	for _, requirement := range required {
		if !filter.Evaluate(requirement.Path, requirement.Capability, "directory").Allowed && !filter.Evaluate(requirement.Path, requirement.Capability, "file").Allowed {
			return "", errSignedReadUnavailable
		}
	}
	contextJSON, err := json.Marshal(compiled)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	expires := now.Add(signedauth.MaxLifetime)
	for _, deadline := range []*time.Time{credentialExpiry, temporaryExpiry} {
		if deadline != nil && deadline.Before(expires) {
			expires = *deadline
		}
	}
	if deadline, ok := r.Context().Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	claims := signedauth.Claims{Version: signedauth.Version, KeyID: s.config.AuthorizationSigningKeyID, Binding: binding, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), Context: contextJSON}
	if err := r.Context().Err(); err != nil {
		return "", err
	}
	token, err := signedauth.Sign(claims, s.config.AuthorizationSigningKey)
	if err != nil {
		return "", errSignedReadUnavailable
	}
	return token, nil
}
