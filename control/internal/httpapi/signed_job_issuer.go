package httpapi

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
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
	// Set only on node-to-node copies, which the destination node runs.
	PeerNodeID         string `json:"peer_node_id"`
	SourceGrantID      string `json:"source_grant_id"`
	DestinationGrantID string `json:"destination_grant_id"`
}

func (job signedLocalJob) optionsDigest() string {
	return signedauth.JobOptionsDigest(signedauth.JobOptions{Overwrite: job.Overwrite, Recursive: job.Recursive, ConflictPolicy: job.ConflictPolicy, SourceChangePolicy: job.SourceChangePolicy, VerifyChecksum: job.VerifyChecksum, BandwidthLimit: job.BandwidthLimit, MaxParallelFiles: job.MaxParallelFiles, MaxParallelChunks: job.MaxParallelChunks, MaxAttempts: job.MaxAttempts})
}

// leaseSubject is the authenticated actor behind a lease, as the current
// credential, groups and policies describe it. It is a snapshot: a lease is a
// short-lived grant, never a permanent one.
type leaseSubject struct {
	actor            store.User
	actorType        string
	credential       string
	credentialExpiry *time.Time
	policies         []rbac.Policy
	expanded         []rbac.Policy
	temporaryExpiry  *time.Time
	admin            bool
}

// resolveLeaseSubject revalidates the credential and reads the policies while
// holding the lock that serializes them with administrative changes; the caller
// must call release. Service accounts must reach every named node through an
// active access group.
func (s *Server) resolveLeaseSubject(r *http.Request, nodeIDs ...string) (leaseSubject, func(), error) {
	actor, actorType := currentUser(r), currentActorType(r)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if !actor.Enabled || actor.ID == "" || credential == "" || digest == "" {
		return leaseSubject{}, nil, errSignedReadUnavailable
	}
	s.agentMu.Lock()
	release := func() { s.agentMu.Unlock() }
	fail := func(err error) (leaseSubject, func(), error) {
		release()
		return leaseSubject{}, nil, err
	}
	var credentialExpiry *time.Time
	switch actorType {
	case "user":
		current, expiry, err := s.store.SessionUserAndExpiry(r.Context(), digest)
		if err != nil || !current.Enabled || current.ID != actor.ID || !strings.HasPrefix(credential, "session-") {
			return fail(errSignedReadUnavailable)
		}
		actor, credentialExpiry = current, &expiry
	case "service_account":
		account, key, err := s.revalidateServiceCredential(r)
		if err != nil || !account.Enabled || account.Kind != "automation" || account.ID != actor.ID || credential != "token-"+key.ID || r.Context().Value(agentKey) != nil {
			return fail(errSignedReadUnavailable)
		}
		groups, err := s.store.ServiceAccountGroupIDs(r.Context(), account.ID, true)
		if err != nil {
			return fail(err)
		}
		for _, nodeID := range nodeIDs {
			member := false
			for _, group := range groups {
				allowed, err := s.store.NodeInAccessGroup(r.Context(), group, nodeID)
				if err != nil {
					return fail(err)
				}
				member = member || allowed
			}
			if !member {
				return fail(errSignedReadUnavailable)
			}
		}
		actor = store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: true}
		credentialExpiry = key.ExpiresAt
	default:
		return fail(errSignedReadUnavailable)
	}
	policies, temporaryExpiry, err := s.signedPolicySnapshotLocked(r.Context(), actorType, actor.ID)
	if err != nil {
		return fail(err)
	}
	return leaseSubject{actor: actor, actorType: actorType, credential: credential, credentialExpiry: credentialExpiry, policies: policies,
		expanded: rbac.ExpandCompatibilityRules(policies), temporaryExpiry: temporaryExpiry, admin: actorType == "user" && actor.Role == "admin"}, release, nil
}

// effectivePolicies is what the lease context is built from: an administrator
// holds every file capability on the mounts a lease names.
func (subject leaseSubject) effectivePolicies(bases ...string) []rbac.Policy {
	if !subject.admin {
		return subject.policies
	}
	rules := make([]rbac.Rule, 0, len(bases))
	for _, base := range bases {
		rules = append(rules, rbac.Rule{Path: base + "/**", Capabilities: []string{"read", "list", "create", "update", "delete"}})
	}
	return []rbac.Policy{{ID: "builtin-admin", Rules: rules}}
}

// signLease turns a prepared context into a signed lease after checking every
// required capability against it, never trusting the coarse checks alone. The
// lease ends at the earliest of 30 seconds, the credential, a temporary grant
// and the request deadline.
func (s *Server) signLease(r *http.Request, subject leaseSubject, binding signedauth.Binding, access filetypes.Context, required []authorizationRequirement, revision uint64, now time.Time) (string, error) {
	binding, err := signedauth.JobLeaseBinding(binding, revision)
	if err != nil {
		return "", errSignedReadUnavailable
	}
	filter, err := access.Compile()
	if err != nil {
		return "", err
	}
	for _, requirement := range required {
		if requirement.Path == "" || s.deniesBeyondFilter(subject.expanded, requirement.Path) {
			return "", errSignedReadUnavailable
		}
		if !filter.Evaluate(requirement.Path, requirement.Capability, "directory").Allowed && !filter.Evaluate(requirement.Path, requirement.Capability, "file").Allowed {
			return "", errSignedReadUnavailable
		}
	}
	contextJSON, err := json.Marshal(access)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	expires := now.Add(signedauth.MaxLifetime)
	for _, deadline := range []*time.Time{subject.credentialExpiry, subject.temporaryExpiry} {
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

// issueSignedJobLease builds the lease of any signed job the node runs.
func (s *Server) issueSignedJobLease(r *http.Request, nodeID string, job signedLocalJob, revision uint64, now time.Time) (string, error) {
	if job.Type == "transfer_pull_batch" {
		return s.issueSignedTransferLease(r, nodeID, job, revision, now)
	}
	return s.issueSignedLocalJobLease(r, nodeID, job, revision, now)
}

// issueSignedLocalJobLease builds the authorization of a local copy, delete or
// move, from the current permissions of the authenticated actor.
func (s *Server) issueSignedLocalJobLease(r *http.Request, nodeID string, job signedLocalJob, revision uint64, now time.Time) (string, error) {
	if len(s.config.AuthorizationSigningKey) == 0 || !signedauth.ValidKeyID(s.config.AuthorizationSigningKeyID) || !validPathIdentifier(nodeID) || !validPathIdentifier(job.ID) || !validPathIdentifier(job.MountID) {
		return "", errSignedReadUnavailable
	}
	subject, release, err := s.resolveLeaseSubject(r, nodeID)
	if err != nil {
		return "", err
	}
	defer release()
	if !subject.admin {
		decision := rbac.Evaluate(subject.expanded, "nodes/"+nodeID+"/jobs/"+job.ID, "execute")
		if !decision.Allowed || decision.Denied {
			return "", errSignedReadUnavailable
		}
	}
	base := "nodes/" + nodeID + "/files/mounts/" + job.MountID
	source := fileScope(base, job.Source)
	destination := fileScope(base, job.Destination)
	var required []authorizationRequirement
	binding := signedauth.Binding{ActorID: subject.actor.ID, CredentialID: subject.credential, Operation: job.Type, SourceNodeID: nodeID, SourceMountID: job.MountID, SourceRoot: job.Source, PlanID: job.ID, JobOptionsDigest: job.optionsDigest()}
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
	access, err := buildMountAccessContext(subject.effectivePolicies(base), base)
	if err != nil {
		return "", err
	}
	return s.signLease(r, subject, binding, access, required, revision, now)
}
