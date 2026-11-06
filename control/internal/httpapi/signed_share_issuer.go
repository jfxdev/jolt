package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// issueSignedShareRead uses the current share and creator state, never a
// browser session or a client-supplied authorization context.
func (s *Server) issueSignedShareRead(r *http.Request, share store.Share, root, operation string, now time.Time) (string, error) {
	if len(s.signingKey()) == 0 || !signedauth.ValidKeyID(s.signingKeyID()) || !validPathIdentifier(share.NodeID) || !validPathIdentifier(share.MountID) {
		return "", errSignedReadUnavailable
	}
	if root == "" {
		root = "."
	}
	if strings.TrimSpace(root) != root || strings.HasPrefix(root, "/") || strings.ContainsAny(root, "\\\x00") || path.Clean(root) != root || root == ".." || strings.HasPrefix(root, "../") {
		return "", errSignedReadUnavailable
	}
	capability := "read"
	if operation == "list" {
		capability = "list"
	} else if operation != "content" && operation != "archive" {
		return "", errSignedReadUnavailable
	}
	current, err := s.store.GetShare(r.Context(), share.ID)
	if err != nil || !current.Active(now) || current.CreatedBy != share.CreatedBy || current.CreatedByType != share.CreatedByType || current.CreatedCredentialID != share.CreatedCredentialID || current.NodeID != share.NodeID || current.MountID != share.MountID || current.Path != share.Path || current.Kind != share.Kind {
		return "", errSignedReadUnavailable
	}
	owner, actorType, credentialExpiry, err := s.currentShareCreator(r, current, now)
	if err != nil {
		return "", errSignedReadUnavailable
	}
	policies, temporaryExpiry, err := s.signedPolicySnapshot(r.Context(), actorType, owner.ID)
	if err != nil {
		return "", err
	}
	base := "nodes/" + current.NodeID + "/files/mounts/" + current.MountID
	scope := fileScope(base, root)
	shareRoot := fileScope(base, current.Path)
	if scope == "" || shareRoot == "" || scope != shareRoot && !strings.HasPrefix(scope, shareRoot+"/") {
		return "", errSignedReadUnavailable
	}
	if current.Kind == "file" && (operation != "content" || scope != shareRoot) || operation == "archive" && !current.AllowArchive {
		return "", errSignedReadUnavailable
	}
	if operation == "archive" && rbac.UntypedDeniesWithin(rbac.ExpandCompatibilityRules(policies), scope) {
		return "", errSignedReadUnavailable
	}
	if actorType == "user" && owner.Role == "admin" {
		admin := []rbac.Policy{{ID: "builtin-admin", Rules: []rbac.Rule{{Path: base + "/**", Capabilities: []string{"read", "list"}}}}}
		for _, policy := range policies {
			var denies []rbac.Rule
			for _, rule := range policy.Rules {
				if rule.FileTypes == nil {
					continue
				}
				for _, item := range rule.Capabilities {
					if strings.EqualFold(strings.TrimSpace(item), "deny") {
						denies = append(denies, rule)
						break
					}
				}
			}
			if len(denies) != 0 {
				policy.Rules = denies
				admin = append(admin, policy)
			}
		}
		policies = admin
	}
	compiled, err := buildMountAccessContext(policies, base)
	if err != nil {
		return "", err
	}
	filter, err := compiled.Compile()
	if err != nil {
		return "", err
	}
	allowed := filter.Evaluate(scope, capability, "directory").Allowed
	if operation == "content" {
		allowed = allowed || filter.Evaluate(scope, capability, "file").Allowed
	}
	if !allowed {
		return "", errSignedReadUnavailable
	}
	encoded, err := json.Marshal(compiled)
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	now = now.UTC()
	expires := now.Add(signedauth.MaxLifetime)
	if temporaryExpiry != nil && temporaryExpiry.Before(expires) {
		expires = *temporaryExpiry
	}
	if current.ExpiresAt != nil && current.ExpiresAt.Before(expires) {
		expires = *current.ExpiresAt
	}
	if credentialExpiry != nil && credentialExpiry.Before(expires) {
		expires = *credentialExpiry
	}
	if deadline, ok := r.Context().Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	signingID, signingKey := s.signing()
	claims := signedauth.Claims{Version: signedauth.Version, KeyID: signingID, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), Context: encoded,
		Binding: signedauth.Binding{ActorID: owner.ID, CredentialID: "share-" + current.ID, Operation: operation, RequestID: "auth_" + hex.EncodeToString(nonce[:]), SourceNodeID: current.NodeID, SourceMountID: current.MountID, SourceRoot: root}}
	if err := r.Context().Err(); err != nil {
		return "", err
	}
	return signedauth.Sign(claims, signingKey)
}
