package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

// transferScope is what a node-to-node copy was authorized to read and write.
// It is saved once, when the job is created, so every renewal re-checks the
// same selection instead of trusting whatever the node reports later. Paths are
// relative to their mount, "." being the mount root.
type transferScope struct {
	SourceNodeID    string   `json:"source_node_id"`
	SourceMountID   string   `json:"source_mount_id"`
	SourceGrantRoot string   `json:"source_grant_root"`
	SourcePaths     []string `json:"source_paths"`
	DestinationPath string   `json:"destination_path"`
	MayOverwrite    bool     `json:"may_overwrite"`
}

func rootPath(value string) string {
	if value == "" {
		return "."
	}
	return value
}

// mergeAccessContexts joins the contexts of the two mounts a copy touches. The
// result must still fit one signed context; it is never truncated.
func mergeAccessContexts(parts ...filetypes.Context) (filetypes.Context, error) {
	merged := filetypes.Context{Version: 1, Rules: []filetypes.Rule{}}
	for _, part := range parts {
		merged.Rules = append(merged.Rules, part.Rules...)
	}
	if len(merged.Rules) > filetypes.MaxContextRules {
		return filetypes.Context{}, errors.New("authorization context has too many rules")
	}
	if _, err := merged.Compile(); err != nil {
		return filetypes.Context{}, err
	}
	return merged, nil
}

// issueSignedTransferLease issues the next lease of a node-to-node copy from
// the scope saved when it was created.
func (s *Server) issueSignedTransferLease(r *http.Request, destinationNodeID string, job signedLocalJob, revision uint64, now time.Time) (string, error) {
	raw, err := s.store.GetJobAuthorizationScope(r.Context(), destinationNodeID, job.ID)
	if err != nil {
		return "", errSignedReadUnavailable
	}
	var scope transferScope
	if json.Unmarshal(raw, &scope) != nil {
		return "", errSignedReadUnavailable
	}
	return s.issueSignedTransferLeaseFor(r, destinationNodeID, job, scope, revision, now)
}

// issueSignedTransferLeaseFor builds the lease from an explicit scope. The job
// must describe exactly that scope: a node that reports anything else gets no
// lease.
func (s *Server) issueSignedTransferLeaseFor(r *http.Request, destinationNodeID string, job signedLocalJob, scope transferScope, revision uint64, now time.Time) (string, error) {
	if len(s.config.AuthorizationSigningKey) == 0 || !signedauth.ValidKeyID(s.config.AuthorizationSigningKeyID) || !validPathIdentifier(destinationNodeID) || !validPathIdentifier(job.ID) ||
		!validPathIdentifier(job.MountID) || !validPathIdentifier(scope.SourceNodeID) || !validPathIdentifier(scope.SourceMountID) || len(scope.SourcePaths) == 0 || scope.SourceNodeID == destinationNodeID {
		return "", errSignedReadUnavailable
	}
	if job.Type != "transfer_pull_batch" || job.PeerNodeID != scope.SourceNodeID || rootPath(job.Source) != rootPath(scope.SourceGrantRoot) ||
		rootPath(job.Destination) != rootPath(scope.DestinationPath) || job.SourceGrantID == "" || job.DestinationGrantID == "" {
		return "", errSignedReadUnavailable
	}
	subject, release, err := s.resolveLeaseSubject(r, destinationNodeID, scope.SourceNodeID)
	if err != nil {
		return "", err
	}
	defer release()
	if !subject.admin {
		decision := rbac.Evaluate(subject.expanded, "nodes/"+destinationNodeID+"/transfers", "execute")
		if !decision.Allowed || decision.Denied {
			return "", errSignedReadUnavailable
		}
	}
	sourceBase := "nodes/" + scope.SourceNodeID + "/files/mounts/" + scope.SourceMountID
	destinationBase := "nodes/" + destinationNodeID + "/files/mounts/" + job.MountID
	var required []authorizationRequirement
	for _, root := range scope.SourcePaths {
		required = append(required, authorizationRequirement{Path: fileScope(sourceBase, root), Capability: "read"})
	}
	destination := fileScope(destinationBase, scope.DestinationPath)
	required = append(required, authorizationRequirement{Path: destination, Capability: "create"})
	if scope.MayOverwrite {
		required = append(required, authorizationRequirement{Path: destination, Capability: "update"})
	}
	policies := subject.effectivePolicies(sourceBase, destinationBase)
	sourceContext, err := buildMountAccessContext(policies, sourceBase)
	if err != nil {
		return "", err
	}
	destinationContext, err := buildMountAccessContext(policies, destinationBase)
	if err != nil {
		return "", err
	}
	access, err := mergeAccessContexts(sourceContext, destinationContext)
	if err != nil {
		return "", err
	}
	binding := signedauth.Binding{
		ActorID: subject.actor.ID, CredentialID: subject.credential, Operation: "transfer_pull_batch",
		SourceNodeID: scope.SourceNodeID, SourceGrantID: job.SourceGrantID, SourceMountID: scope.SourceMountID, SourceRoot: rootPath(scope.SourceGrantRoot),
		DestinationNodeID: destinationNodeID, DestinationGrantID: job.DestinationGrantID, DestinationMountID: job.MountID, DestinationRoot: rootPath(scope.DestinationPath),
		PlanID: job.ID, JobOptionsDigest: job.optionsDigest(),
	}
	return s.signLease(r, subject, binding, access, required, revision, now)
}
