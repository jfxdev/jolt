package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
	"github.com/jfxdev/jolt/control/internal/workload"
)

// shareCookiePrefix scopes a password unlock to one share. The cookie path is
// the share's own URL, so unlocking one share never unlocks another.
const shareCookiePrefix = "jolt_share_"

// shareMaxTTL caps how long a public link can live. An unbounded link is the
// one most likely to be forgotten while still serving data.
const shareMaxTTL = 365 * 24 * time.Hour

type createShareRequest struct {
	NodeID       string `json:"node_id"`
	MountID      string `json:"mount_id"`
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	Password     string `json:"password"`
	AllowArchive *bool  `json:"allow_archive"`
	MaxDownloads int64  `json:"max_downloads"`
	ExpiresInSec int64  `json:"expires_in_seconds"`
}

// createShare issues a public link. The caller must hold read access to the
// exact subpath being shared: a share can never widen what its creator could
// already reach.
func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	var request createShareRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	nodeID := strings.TrimSpace(request.NodeID)
	mountID := strings.TrimSpace(request.MountID)
	if !validPathIdentifier(nodeID) || !validPathIdentifier(mountID) {
		writeError(w, r, http.StatusBadRequest, "invalid_target",
			"node_id e mount_id são obrigatórios.")
		return
	}
	// A link would hand out content, which a locked mount never serves.
	if s.mountLockedByID(r.Context(), nodeID, mountID) {
		writeError(w, r, http.StatusForbidden, "mount_locked", lockedMountMessage)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(request.Kind))
	if kind == "" {
		kind = "file"
	}
	if kind != "file" && kind != "directory" {
		writeError(w, r, http.StatusBadRequest, "invalid_kind",
			"kind aceita apenas file ou directory.")
		return
	}
	if request.MaxDownloads < 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_max_downloads",
			"max_downloads não pode ser negativo.")
		return
	}
	if request.ExpiresInSec < 0 || request.ExpiresInSec > int64(shareMaxTTL/time.Second) {
		writeError(w, r, http.StatusBadRequest, "invalid_expiry",
			"expires_in_seconds deve ficar entre 0 e um ano.")
		return
	}
	if request.Password != "" && len(request.Password) < 8 {
		writeError(w, r, http.StatusBadRequest, "weak_share_password",
			"A senha do link precisa ter ao menos 8 caracteres.")
		return
	}
	scope := fileScope("nodes/"+nodeID+"/files/mounts/"+mountID, request.Path)
	if scope == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_path", "O caminho informado é inválido.")
		return
	}
	// Creating the link requires both the right to publish links and read
	// access to the exact path, checked as the caller, not as the share.
	if !s.authorize(w, r, "control-tower/shares", "create", "permission_denied",
		"A policy atual não permite criar links públicos.") {
		return
	}
	// The kind says what the entry is, so a typed rule is judged for that
	// type; the node still decides by the real type on every public request.
	typed := withEntryType(r, kind)
	if !s.authorize(w, typed, scope, "read", "permission_denied",
		"Você não pode compartilhar um caminho que não pode ler.") {
		return
	}
	if kind == "directory" && !s.authorize(w, typed, scope, "list", "permission_denied",
		"Você não pode compartilhar uma pasta que não pode listar.") {
		return
	}
	if _, err := s.store.GetNode(r.Context(), nodeID); err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}

	token, tokenHash, err := security.RandomToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	passwordHash := ""
	if request.Password != "" {
		if passwordHash, err = security.HashPassword(request.Password); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	allowArchive := kind == "directory"
	if request.AllowArchive != nil {
		allowArchive = *request.AllowArchive
	}
	now := time.Now().UTC()
	share := store.Share{
		ID: randomID("shr"), TokenHash: tokenHash, NodeID: nodeID, MountID: mountID,
		Path: normalizeSharePath(request.Path), Kind: kind, Name: shareDisplayName(request.Path),
		PasswordHash: passwordHash, AllowArchive: allowArchive,
		MaxDownloads: request.MaxDownloads, CreatedBy: currentUser(r).ID, CreatedByType: currentActorType(r), CreatedAt: now,
	}
	if share.CreatedByType == "service_account" {
		credential, _ := r.Context().Value(credentialKey).(string)
		if !strings.HasPrefix(credential, "token-") || len(credential) <= len("token-") {
			writeError(w, r, http.StatusForbidden, "permission_denied", "A credencial da conta não pôde ser vinculada ao link.")
			return
		}
		share.CreatedCredentialID = strings.TrimPrefix(credential, "token-")
	}
	if request.ExpiresInSec > 0 {
		expiry := now.Add(time.Duration(request.ExpiresInSec) * time.Second)
		share.ExpiresAt = &expiry
	}
	if identity, ok := r.Context().Value(workloadIdentityKey).(workload.Identity); ok {
		if !identity.ExpiresAt.After(now) {
			writeError(w, r, http.StatusUnauthorized, "invalid_service_token", "Credencial de workload expirada.")
			return
		}
		if share.ExpiresAt == nil || identity.ExpiresAt.Before(*share.ExpiresAt) {
			expiry := identity.ExpiresAt.UTC()
			share.ExpiresAt = &expiry
		}
	}
	if err := s.store.CreateShare(r.Context(), share); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "create", "control-tower/shares/"+share.ID, "allowed")
	s.registry.Inc("jolt_control_shares_created_total")
	share.HasPassword = passwordHash != ""
	// The token is returned exactly once: only its digest is stored.
	writeJSON(w, http.StatusCreated, map[string]any{
		"share": share,
		"token": token,
		"url":   s.shareURL(r, token),
	})
}

// listShares returns the caller's own shares, or every share when the caller
// administers them.
func (s *Server) listShares(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "control-tower/shares", "list", "permission_denied",
		"A policy atual não permite listar links públicos.") {
		return
	}
	owner := currentUser(r).ID
	if decision, err := s.evaluateAuthorization(r, "control-tower/shares", "sudo"); err == nil &&
		decision.Allowed {
		owner = ""
	}
	shares, err := s.store.ListShares(r.Context(), owner, currentActorType(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": shares})
}

// revokeShare disables a link immediately. The row is kept so the audit trail
// still shows the link existed and when it stopped working.
func (s *Server) revokeShare(w http.ResponseWriter, r *http.Request) {
	share, err := s.store.GetShare(r.Context(), r.PathValue("shareID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "share_not_found", "Link não encontrado.")
		return
	}
	if !s.authorizeShareMutation(w, r, share) {
		return
	}
	if err := s.store.RevokeShare(r.Context(), share.ID, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusConflict, "share_already_revoked", "Este link já foi revogado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "revoke", "control-tower/shares/"+share.ID, "allowed")
	s.registry.Inc("jolt_control_shares_revoked_total")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteShare(w http.ResponseWriter, r *http.Request) {
	share, err := s.store.GetShare(r.Context(), r.PathValue("shareID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "share_not_found", "Link não encontrado.")
		return
	}
	if !s.authorizeShareMutation(w, r, share) {
		return
	}
	if err := s.store.DeleteShare(r.Context(), share.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", "control-tower/shares/"+share.ID, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

// authorizeShareMutation lets an owner manage their own link, and anyone with
// sudo on shares manage all of them.
func (s *Server) authorizeShareMutation(w http.ResponseWriter, r *http.Request, share store.Share) bool {
	if share.CreatedBy == currentUser(r).ID && share.CreatedByType == currentActorType(r) {
		return s.authorize(w, r, "control-tower/shares", "delete", "permission_denied",
			"A policy atual não permite remover links públicos.")
	}
	return s.authorize(w, r, "control-tower/shares", "sudo", "sudo_required",
		"Apenas um administrador pode remover links de outros usuários.")
}

func (s *Server) shareURL(r *http.Request, token string) string {
	base := s.config.PublicBaseURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/s/" + token
}

func normalizeSharePath(value string) string {
	return strings.Trim(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"), "/")
}

func shareDisplayName(value string) string {
	normalized := normalizeSharePath(value)
	if normalized == "" {
		return "/"
	}
	return path.Base(normalized)
}

// --- public surface -------------------------------------------------------
//
// Everything below runs without a session. It is strictly read-only, resolves
// the node token server-side, and re-evaluates the creator's authorization on
// every request so revoking the creator's access also kills their links.

type publicShare struct {
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	HasPassword  bool       `json:"has_password"`
	Unlocked     bool       `json:"unlocked"`
	AllowArchive bool       `json:"allow_archive"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Remaining    *int64     `json:"remaining_downloads,omitempty"`
}

// publicShareMetadata describes a link without serving any content, so the UI
// can render a landing page and prompt for a password when one is set.
func (s *Server) publicShareMetadata(w http.ResponseWriter, r *http.Request) {
	share, ok := s.loadPublicShare(w, r, false)
	if !ok {
		return
	}
	_ = s.store.TouchShare(r.Context(), share.ID, time.Now().UTC())
	view := publicShare{
		Name: share.Name, Kind: share.Kind, HasPassword: share.HasPassword,
		Unlocked:     !share.HasPassword || s.shareUnlocked(r, share),
		AllowArchive: share.AllowArchive, ExpiresAt: share.ExpiresAt,
	}
	if share.MaxDownloads > 0 {
		remaining := share.MaxDownloads - share.DownloadCount
		view.Remaining = &remaining
	}
	writeJSON(w, http.StatusOK, map[string]any{"share": view})
}

type shareUnlockRequest struct {
	Password string `json:"password"`
}

// publicShareUnlock exchanges the link password for a short-lived cookie scoped
// to this one share. Attempts are rate limited through the same lockout table
// as logins, because a share password is a credential like any other.
func (s *Server) publicShareUnlock(w http.ResponseWriter, r *http.Request) {
	share, ok := s.loadPublicShare(w, r, false)
	if !ok {
		return
	}
	if !share.HasPassword {
		writeJSON(w, http.StatusOK, map[string]any{"unlocked": true})
		return
	}
	var request shareUnlockRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	now := time.Now().UTC()
	key := "share:" + share.ID + "|" + clientIP(r)
	if until, err := s.store.LoginLockedUntil(r.Context(), key, now); err != nil {
		s.fail(w, r, err)
		return
	} else if !until.IsZero() {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(time.Until(until).Seconds())+1, 10))
		writeError(w, r, http.StatusTooManyRequests, "share_locked",
			"Muitas tentativas. Tente novamente mais tarde.")
		return
	}
	if !security.VerifyPassword(share.PasswordHash, request.Password) {
		if err := s.store.RegisterLoginFailure(r.Context(), key, now); err != nil {
			s.log.Error("register share failure", "share_id", share.ID, "error", err)
		}
		s.registry.Inc("jolt_control_share_unlock_failures_total")
		writeError(w, r, http.StatusUnauthorized, "invalid_share_password", "Senha incorreta.")
		return
	}
	if err := s.store.ClearLoginFailures(r.Context(), key); err != nil {
		s.log.Error("clear share failures", "share_id", share.ID, "error", err)
	}
	expiry := now.Add(shareUnlockTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     shareCookiePrefix + share.ID,
		Value:    s.signShareUnlock(share, expiry),
		Path:     "/",
		HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteLaxMode,
		MaxAge: int(shareUnlockTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": true})
}

// shareUnlockTTL bounds how long one password check stays valid.
const shareUnlockTTL = 12 * time.Hour

// signShareUnlock mints a stateless unlock ticket: "<expiry>.<hmac>". Keeping
// it stateless means an unlock survives a restart and costs no server memory,
// and binding the HMAC to the stored password hash invalidates every
// outstanding ticket the moment the share password changes.
func (s *Server) signShareUnlock(share store.Share, expiry time.Time) string {
	unix := strconv.FormatInt(expiry.Unix(), 10)
	return unix + "." + s.shareUnlockMAC(share, unix)
}

func (s *Server) shareUnlockMAC(share store.Share, unix string) string {
	mac := hmac.New(sha256.New, s.config.EncryptionKey)
	mac.Write([]byte("jolt-share-unlock"))
	mac.Write([]byte{0})
	mac.Write([]byte(share.ID))
	mac.Write([]byte{0})
	mac.Write([]byte(share.PasswordHash))
	mac.Write([]byte{0})
	mac.Write([]byte(unix))
	return hex.EncodeToString(mac.Sum(nil))
}

// shareUnlocked reports whether the request carries a valid unlock ticket.
func (s *Server) shareUnlocked(r *http.Request, share store.Share) bool {
	cookie, err := r.Cookie(shareCookiePrefix + share.ID)
	if err != nil || cookie.Value == "" {
		return false
	}
	unix, signature, found := strings.Cut(cookie.Value, ".")
	if !found {
		return false
	}
	expiry, err := strconv.ParseInt(unix, 10, 64)
	if err != nil || time.Now().UTC().After(time.Unix(expiry, 0)) {
		return false
	}
	return hmac.Equal([]byte(signature), []byte(s.shareUnlockMAC(share, unix)))
}

// publicShareList lists a shared directory, scoped to the share's own subtree.
func (s *Server) publicShareList(w http.ResponseWriter, r *http.Request) {
	share, ok := s.loadPublicShare(w, r, true)
	if !ok {
		return
	}
	if share.Kind != "directory" {
		writeError(w, r, http.StatusBadRequest, "not_a_directory", "Este link aponta para um arquivo.")
		return
	}
	relative, ok := s.resolveSharePath(w, r, share)
	if !ok {
		return
	}
	if !s.authorizeSharePath(w, r, share, relative, "list") {
		return
	}
	query := url.Values{}
	query.Set("path", relative)
	if after := r.URL.Query().Get("after"); after != "" {
		query.Set("after", after)
	}
	if limit := strings.TrimSpace(r.URL.Query().Get("limit")); limit != "" {
		query.Set("limit", limit)
	}
	s.streamShareResource(w, r, share, "files", query, false)
}

// publicShareContent downloads one file from a share and consumes one download
// from the share's budget.
func (s *Server) publicShareContent(w http.ResponseWriter, r *http.Request) {
	share, ok := s.loadPublicShare(w, r, true)
	if !ok {
		return
	}
	relative, ok := s.resolveSharePath(w, r, share)
	if !ok {
		return
	}
	if !s.authorizeSharePath(w, r, share, relative, "read") {
		return
	}
	query := url.Values{}
	query.Set("path", relative)
	if r.URL.Query().Get("disposition") == "inline" {
		query.Set("disposition", "inline")
	}
	s.streamShareResource(w, r, share, "files/content", query, true)
}

// publicShareArchive downloads a shared directory, or a selection inside it, as
// a ZIP.
func (s *Server) publicShareArchive(w http.ResponseWriter, r *http.Request) {
	share, ok := s.loadPublicShare(w, r, true)
	if !ok {
		return
	}
	if !share.AllowArchive {
		writeError(w, r, http.StatusForbidden, "archive_disabled",
			"Este link não permite baixar pastas compactadas.")
		return
	}
	relative, ok := s.resolveSharePath(w, r, share)
	if !ok {
		return
	}
	if !s.authorizeSharePath(w, r, share, relative, "read") {
		return
	}
	for _, name := range r.URL.Query()["name"] {
		if strings.TrimSpace(name) == "" {
			continue
		}
		selected := fileScope(relative, name)
		if selected == "" || !s.authorizeSharePath(w, r, share, selected, "read") {
			if selected == "" {
				writeError(w, r, http.StatusBadRequest, "invalid_path", "Caminho inválido.")
			}
			return
		}
	}
	query := url.Values{}
	query.Set("path", relative)
	for _, name := range r.URL.Query()["name"] {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			query.Add("name", trimmed)
		}
	}
	s.streamShareResource(w, r, share, "files/archive", query, true)
}

// loadPublicShare resolves the token and rechecks the creator's access for
// every public operation. Content requests also require the password gate.
func (s *Server) loadPublicShare(w http.ResponseWriter, r *http.Request, forContent bool) (store.Share, bool) {
	token := strings.TrimSpace(r.PathValue("token"))
	if token == "" {
		writeError(w, r, http.StatusNotFound, "share_not_found", "Link não encontrado.")
		return store.Share{}, false
	}
	share, err := s.store.ShareByTokenHash(r.Context(), security.Digest(token))
	if err != nil {
		// A wrong token and a revoked token answer identically so the endpoint
		// cannot be used to enumerate which links exist.
		writeError(w, r, http.StatusNotFound, "share_not_found", "Link não encontrado.")
		return store.Share{}, false
	}
	if !share.Active(time.Now().UTC()) {
		writeError(w, r, http.StatusGone, "share_exhausted", "Este link não está mais disponível.")
		return store.Share{}, false
	}
	if forContent && share.HasPassword && !s.shareUnlocked(r, share) {
		writeError(w, r, http.StatusUnauthorized, "share_password_required",
			"Este link exige senha.")
		return store.Share{}, false
	}
	if !s.shareCreatorStillAuthorized(r, share) {
		// Revoking the creator's access must revoke their links too, otherwise
		// a departed operator's shares keep serving data indefinitely.
		writeError(w, r, http.StatusGone, "share_revoked",
			"Este link não está mais disponível.")
		return store.Share{}, false
	}
	return share, true
}

// shareCreatorStillAuthorized re-evaluates the creator's access to the shared
// path on every public request, so revoking it also revokes their links.
//
// The role check mirrors the built-in admin override in evaluateAuthorization:
// an administrator is authorized without any explicit policy, so reading only
// their policies would make every admin-created link fail. The role is read
// from storage rather than trusted from the share, so demoting an admin
// likewise stops their links.
func (s *Server) shareCreatorStillAuthorized(r *http.Request, share store.Share) bool {
	// The root of a share has a known type, so its answer is the exact one: a
	// file the creator can no longer read stops being offered, instead of being
	// offered and then answered as missing by the node.
	return s.shareCreatorAuthorizedPath(r, share, share.Path, "read", share.Kind == "directory", share.Kind)
}

func (s *Server) authorizeSharePath(w http.ResponseWriter, r *http.Request, share store.Share, relative, capability string) bool {
	if !s.shareCreatorAuthorizedPath(r, share, relative, capability, false, "") {
		writeError(w, r, http.StatusGone, "share_revoked", "Este link não está mais disponível.")
		return false
	}
	return true
}

// entryType is the type of the entry when it is known (a share's own root) and
// empty when the node must decide per entry.
func (s *Server) shareCreatorAuthorizedPath(r *http.Request, share store.Share, relative, capability string, checkSubtree bool, entryType string) bool {
	creator, actorType, _, err := s.currentShareCreator(r, share, time.Now())
	if err != nil {
		return false
	}
	scope := fileScope("nodes/"+share.NodeID+"/files/mounts/"+share.MountID, relative)
	if scope == "" {
		return false
	}
	policies, err := s.store.RBACPoliciesForSubject(r.Context(), actorType, share.CreatedBy)
	if err != nil {
		return false
	}
	expanded := rbac.ExpandCompatibilityRules(policies)
	// A deny rule inside the shared subtree still wins, even for an admin, so
	// an archive of a shared folder cannot reach a denied descendant.
	if checkSubtree && s.deniesBeyondFilter(expanded, scope) {
		return false
	}
	if actorType == "user" && creator.Role == "admin" {
		return true
	}
	// A public share is served through a signed read, so the node filters it.
	decision := rbac.Evaluate(expanded, scope, capability)
	if s.config.TypedPolicies {
		decision = rbac.EvaluateTyped(expanded, scope, capability, rbac.NodeFiltered)
		if entryType == "file" || entryType == "directory" {
			decision = rbac.EvaluateEntry(expanded, scope, capability, entryType).Decision
		}
	}
	return decision.Allowed && !decision.Denied
}

// Legacy shares default to user ownership. Automation shares persist their
// issuing credential so deactivation, group removal and token revocation take
// effect on the next public request.
func (s *Server) currentShareCreator(r *http.Request, share store.Share, now time.Time) (store.User, string, *time.Time, error) {
	switch share.CreatedByType {
	case "user", "":
		user, err := s.store.GetUser(r.Context(), share.CreatedBy)
		if err != nil || !user.Enabled {
			return store.User{}, "", nil, errSignedReadUnavailable
		}
		return user, "user", nil, nil
	case "service_account":
		account, err := s.store.GetServiceAccount(r.Context(), share.CreatedBy)
		if err != nil || !account.Enabled || account.Kind != "automation" || share.CreatedCredentialID == "" {
			return store.User{}, "", nil, errSignedReadUnavailable
		}
		credential, err := s.store.GetActiveServiceAccountToken(r.Context(), account.ID, share.CreatedCredentialID, now)
		if err != nil {
			return store.User{}, "", nil, errSignedReadUnavailable
		}
		identity, err := s.store.GetWorkloadIdentity(r.Context(), account.ID, share.CreatedCredentialID)
		if err == nil {
			if !identity.Enabled || identity.Revoked || s.config.WorkloadProviders == nil || !s.config.WorkloadProviders.AllowsMapping(identity.ProviderID, identity.Issuer, identity.Subject, identity.Audience) {
				return store.User{}, "", nil, errSignedReadUnavailable
			}
			active, err := s.store.ActiveWorkloadIdentity(r.Context(), identity.ProviderID, identity.Issuer, identity.Subject, identity.Audience)
			if err != nil || active.CredentialID != credential.ID || active.ServiceAccountID != account.ID {
				return store.User{}, "", nil, errSignedReadUnavailable
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return store.User{}, "", nil, errSignedReadUnavailable
		}
		groups, err := s.store.ServiceAccountGroupIDs(r.Context(), account.ID, true)
		if err != nil {
			return store.User{}, "", nil, err
		}
		for _, group := range groups {
			member, err := s.store.NodeInAccessGroup(r.Context(), group, share.NodeID)
			if err != nil {
				return store.User{}, "", nil, err
			}
			if member {
				return store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: true}, "service_account", credential.ExpiresAt, nil
			}
		}
	}
	return store.User{}, "", nil, errSignedReadUnavailable
}

// resolveSharePath joins the caller-supplied subpath onto the share's root and
// confines it there, so a share of one folder can never serve a sibling.
func (s *Server) resolveSharePath(w http.ResponseWriter, r *http.Request, share store.Share) (string, bool) {
	requested := normalizeSharePath(r.URL.Query().Get("path"))
	if share.Kind == "file" {
		if requested != "" {
			writeError(w, r, http.StatusBadRequest, "invalid_path",
				"Este link aponta para um único arquivo.")
			return "", false
		}
		return share.Path, true
	}
	if requested == "" {
		return share.Path, true
	}
	// fileScope rejects "..", so a confined join is enough to keep the request
	// inside the shared subtree.
	joined := fileScope(share.Path, requested)
	if joined == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_path", "Caminho inválido.")
		return "", false
	}
	if share.Path == "" {
		joined = requested
	}
	return joined, true
}

// streamShareResource proxies one read-only node call using the node's stored
// token. The public caller never sees the node endpoint or the token.
func (s *Server) streamShareResource(w http.ResponseWriter, r *http.Request, share store.Share,
	resource string, query url.Values, download bool) {
	node, err := s.store.GetNode(r.Context(), share.NodeID)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node está indisponível.")
		return
	}
	signedToken := ""
	if s.config.SignedLocalReads {
		operation, capability := "", "signed_local_read_v1"
		switch resource {
		case "files":
			operation = "list"
		case "files/content":
			operation = "content"
		case "files/archive":
			operation, capability = "archive", "signed_local_tree_read_v1"
		default:
			writeError(w, r, http.StatusConflict, "signed_context_unsupported", "Este acesso não suporta autorização assinada.")
			return
		}
		var info struct {
			NodeID       string   `json:"node_id"`
			Capabilities []string `json:"capabilities"`
		}
		if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
			writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível verificar a proteção do link no node.")
			return
		}
		found := false
		for _, item := range info.Capabilities {
			found = found || item == capability
		}
		if info.NodeID != node.ID || !found {
			writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node para proteger este link.")
			return
		}
		root := query.Get("path")
		if root == "" {
			root = "."
		}
		now := time.Now()
		var err error
		signedToken, err = s.issueSignedShareRead(r, share, root, operation, now)
		if err != nil {
			writeError(w, r, http.StatusGone, "share_revoked", "Este link não está mais disponível.")
			return
		}
		claims, _, err := signedauth.VerifyLocalRead(signedToken, s.verificationKeys(), node.ID, operation, share.MountID, root, now)
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "signed_authorization_unavailable", "Não foi possível validar a autorização do link.")
			return
		}
		deadline := time.Unix(claims.ExpiresAt, 0)
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(deadline); err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "signed_authorization_unavailable", "Não foi possível limitar o prazo do link.")
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer func() {
			expired := ctx.Err() != nil || !time.Now().Before(deadline)
			cancel()
			if expired {
				panic(http.ErrAbortHandler)
			}
			_ = controller.SetWriteDeadline(time.Time{})
		}()
		r = r.WithContext(ctx)
		w = &signedProxyWriter{ResponseWriter: w, ctx: ctx}
	}
	token, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	target := fmt.Sprintf("%s/api/v1/mounts/%s/%s?%s", node.Endpoint,
		url.PathEscape(share.MountID), resource, query.Encode())
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Correlation-ID", r.Header.Get("X-Correlation-ID"))
	request.Header.Set("X-Jolt-Internal-Canary", "1")
	if signedToken != "" {
		request.Header.Set(signedAuthorizationHeader, signedToken)
	}
	if value := r.Header.Get("Range"); value != "" && download {
		request.Header.Set("Range", value)
	}
	response, err := s.client.Do(request)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node está indisponível.")
		return
	}
	defer response.Body.Close()
	if signedToken != "" && response.Header.Get("X-Jolt-Access-Applied") != "v1" {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "O node não confirmou a proteção do link.")
		return
	}
	if download && response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		// Reserve before sending any response bytes. Failed node/capability
		// checks do not consume a download; concurrent successful requests
		// still compete on the store's atomic counter, including Range reads.
		if err := s.store.RegisterShareDownload(r.Context(), share.ID, time.Now().UTC()); err != nil {
			writeError(w, r, http.StatusGone, "share_exhausted", "Este link não está mais disponível.")
			return
		}
		s.registry.Inc("jolt_control_share_downloads_total")
	}
	if response.Header.Get("X-Jolt-Canary") == "1" {
		s.auditCanary(r, share.CreatedBy, "share", "shares/"+share.ID+"/"+resource, response.StatusCode)
	}
	for _, header := range []string{"Content-Type", "Content-Length", "Content-Disposition",
		"Accept-Ranges", "Content-Range", "X-Jolt-Archive-Files", "X-Jolt-Archive-Bytes"} {
		if value := response.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	// A public link must never be cached by a shared proxy: the URL is the
	// credential.
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(response.StatusCode)
	_, copyErr := io.Copy(w, response.Body)
	if signedToken != "" && copyErr != nil {
		panic(http.ErrAbortHandler)
	}
	s.auditShareAccess(r, share, resource, response.StatusCode)
}

func (s *Server) auditShareAccess(r *http.Request, share store.Share, resource string, status int) {
	s.store.AuditActor(r.Context(), share.CreatedBy, "share", "read",
		"shares/"+share.ID+"/"+resource, resultForStatus(status), r.Header.Get("X-Correlation-ID"))
}
