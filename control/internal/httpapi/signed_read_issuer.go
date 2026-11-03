package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

var errSignedReadUnavailable = errors.New("signed local read unavailable")

// issueSignedLocalRead builds a short-lived context from the authenticated
// subject's current policies. Other operations still require separate
// integration before typed policies can be enabled.
func (s *Server) issueSignedLocalRead(r *http.Request, nodeID, mountID, root, operation string, now time.Time) (string, error) {
	return s.issueSignedAccess(r, nodeID, mountID, root, operation, "", "", 0, now)
}

func (s *Server) issueSignedAccess(r *http.Request, nodeID, mountID, root, operation, planID, previousCredential string, revision uint64, now time.Time) (string, error) {
	if len(s.config.AuthorizationSigningKey) == 0 || !signedauth.ValidKeyID(s.config.AuthorizationSigningKeyID) || !validPathIdentifier(nodeID) || !validPathIdentifier(mountID) {
		return "", errSignedReadUnavailable
	}
	if root == "" {
		root = "."
	}
	if strings.TrimSpace(root) != root || strings.HasPrefix(root, "/") || strings.ContainsAny(root, "\\\x00") || path.Clean(root) != root || root == ".." || strings.HasPrefix(root, "../") {
		return "", errSignedReadUnavailable
	}
	capability, kinds := "", []string{"directory"}
	switch operation {
	case "list", "search", "disk_usage":
		capability = "list"
	case "content":
		// The node decides the real filesystem type. Permit a possible
		// directory match so a typed denial is not exposed as a Control Tower
		// 403 before the node can return the configured hidden/visible result.
		capability, kinds = "read", []string{"file", "directory"}
	case "metadata":
		capability, kinds = "read", []string{"file", "directory"}
	case "archive", "archive_plan":
		capability = "read"
	case "upload_create", "upload_chunk", "upload_complete", "upload_abort", "upload_reauthorize", "upload_simple":
		if planID == "" {
			return "", errSignedReadUnavailable
		}
		capability, kinds = "create", []string{"file"}
	default:
		return "", errSignedReadUnavailable
	}
	actor := currentUser(r)
	actorType := currentActorType(r)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if !actor.Enabled || actor.ID == "" || credential == "" || digest == "" || (actorType != "user" && actorType != "service_account") {
		return "", errSignedReadUnavailable
	}
	var credentialExpiry *time.Time
	var currentAgentLimits *store.AgentLimits
	if actorType == "user" {
		current, expiry, err := s.store.SessionUserAndExpiry(r.Context(), digest)
		if err != nil || !current.Enabled || current.ID != actor.ID || !strings.HasPrefix(credential, "session-") {
			return "", errSignedReadUnavailable
		}
		actor, credentialExpiry = current, &expiry
	} else {
		account, key, err := s.store.AuthenticateServiceAccount(r.Context(), digest)
		if err != nil || !account.Enabled || account.ID != actor.ID || credential != "token-"+key.ID {
			return "", errSignedReadUnavailable
		}
		actor = store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: true}
		credentialExpiry = key.ExpiresAt
		_, hasAgentContext := r.Context().Value(agentKey).(agentContext)
		if account.Kind == "agent" {
			if capability == "create" {
				return "", errSignedReadUnavailable
			}
			if !hasAgentContext || key.ExpiresAt == nil || !key.ExpiresAt.After(now) {
				return "", errSignedReadUnavailable
			}
			limits, err := normalizeAgentLimits(key.AgentLimits)
			if err != nil || !addressAllowed(r, limits, s.config.TrustedProxies) {
				return "", errSignedReadUnavailable
			}
			currentAgentLimits = &limits
		} else if account.Kind != "automation" || hasAgentContext {
			return "", errSignedReadUnavailable
		}
	}
	if actorType == "service_account" {
		member := false
		groups, err := s.store.ServiceAccountGroupIDs(r.Context(), actor.ID, true)
		if err != nil {
			return "", err
		}
		for _, groupID := range groups {
			allowed, err := s.store.NodeInAccessGroup(r.Context(), groupID, nodeID)
			if err != nil {
				return "", err
			}
			member = member || allowed
		}
		if !member {
			return "", errSignedReadUnavailable
		}
	}
	policies, err := s.store.RBACPoliciesForSubject(r.Context(), actorType, actor.ID)
	if err != nil {
		return "", err
	}
	base := "nodes/" + nodeID + "/files/mounts/" + mountID
	scope := fileScope(base, root)
	if scope == "" {
		return "", errSignedReadUnavailable
	}
	if operation == "search" || operation == "disk_usage" || operation == "archive" || operation == "archive_plan" {
		if rbac.UntypedDeniesWithin(rbac.ExpandCompatibilityRules(policies), scope) {
			return "", errSignedReadUnavailable
		}
	}
	if actorType == "user" && actor.Role == "admin" {
		// Existing admins bypass legacy policies, but new typed denies still
		// take precedence over the built-in grant when a node evaluates a file.
		adminPolicies := []rbac.Policy{{ID: "builtin-admin", Rules: []rbac.Rule{{Path: base + "/**", Capabilities: []string{"read", "list", "create", "update"}}}}}
		for _, policy := range policies {
			var denies []rbac.Rule
			for _, rule := range policy.Rules {
				if rule.FileTypes == nil {
					continue
				}
				for _, capability := range rule.Capabilities {
					if strings.EqualFold(strings.TrimSpace(capability), "deny") {
						denies = append(denies, rule)
						break
					}
				}
			}
			if len(denies) > 0 {
				policy.Rules = denies
				adminPolicies = append(adminPolicies, policy)
			}
		}
		policies = adminPolicies
	}
	if currentAgentLimits != nil {
		allowed := map[string]bool{"read": true, "list": true}
		if currentAgentLimits.Capabilities != nil {
			allowed = map[string]bool{}
			for _, item := range *currentAgentLimits.Capabilities {
				allowed[item] = true
			}
		}
		if !allowed[capability] {
			return "", errSignedReadUnavailable
		}
		for pi := range policies {
			rules := policies[pi].Rules[:0]
			for _, rule := range policies[pi].Rules {
				isDeny := false
				for _, item := range rule.Capabilities {
					isDeny = isDeny || strings.EqualFold(strings.TrimSpace(item), "deny")
				}
				if !isDeny {
					caps := make([]string, 0, 2)
					for _, item := range rule.Capabilities {
						item = strings.ToLower(strings.TrimSpace(item))
						if allowed[item] {
							caps = append(caps, item)
						}
					}
					if len(caps) == 0 {
						continue
					}
					rule.Capabilities = caps
				}
				rules = append(rules, rule)
			}
			policies[pi].Rules = rules
		}
	}
	compiled, err := buildMountAccessContext(policies, base)
	if err != nil {
		return "", err
	}
	filter, err := compiled.Compile()
	if err != nil {
		return "", err
	}
	allowed := false
	for _, kind := range kinds {
		allowed = allowed || filter.Evaluate(scope, capability, kind).Allowed
	}
	if !allowed {
		return "", errSignedReadUnavailable
	}
	contextJSON, err := json.Marshal(compiled)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	expires := now.Add(signedauth.MaxLifetime)
	if credentialExpiry != nil && credentialExpiry.Before(expires) {
		expires = *credentialExpiry
	}
	if deadline, ok := r.Context().Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	binding := signedauth.Binding{ActorID: actor.ID, CredentialID: credential, Operation: operation, RequestID: "auth_" + hex.EncodeToString(nonce[:])}
	if operation == "upload_reauthorize" {
		binding.RequestID = signedauth.UploadReauthorizationRequestID(planID, previousCredential, revision)
	}
	if capability == "create" {
		binding.DestinationNodeID, binding.DestinationMountID, binding.DestinationRoot, binding.PlanID = nodeID, mountID, root, planID
	} else {
		binding.SourceNodeID, binding.SourceMountID, binding.SourceRoot = nodeID, mountID, root
	}
	claims := signedauth.Claims{Version: signedauth.Version, KeyID: s.config.AuthorizationSigningKeyID,
		Binding:  binding,
		IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), Context: contextJSON}
	if err := r.Context().Err(); err != nil {
		return "", err
	}
	token, err := signedauth.Sign(claims, s.config.AuthorizationSigningKey)
	if err != nil {
		return "", errSignedReadUnavailable
	}
	return token, nil
}
