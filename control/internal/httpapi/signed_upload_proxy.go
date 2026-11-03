package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

func signedUploadOperation(resource, method string) (operation, sessionID string) {
	parts := strings.Split(resource, "/")
	if len(parts) == 4 && parts[0] == "mounts" && validPathIdentifier(parts[1]) && parts[2] == "files" && parts[3] == "content" && method == http.MethodPut {
		return "upload_simple", ""
	}
	if len(parts) < 4 || parts[0] != "mounts" || !validPathIdentifier(parts[1]) || parts[2] != "files" || parts[3] != "uploads" {
		return "", ""
	}
	if len(parts) == 4 && method == http.MethodPost {
		return "upload_create", ""
	}
	if len(parts) == 5 && validPathIdentifier(parts[4]) && method == http.MethodPatch {
		return "upload_chunk", parts[4]
	}
	if len(parts) == 5 && validPathIdentifier(parts[4]) && method == http.MethodDelete {
		return "upload_abort", parts[4]
	}
	if len(parts) == 6 && validPathIdentifier(parts[4]) && parts[5] == "complete" && method == http.MethodPost {
		return "upload_complete", parts[4]
	}
	if len(parts) == 6 && validPathIdentifier(parts[4]) && parts[5] == "authorize" && method == http.MethodPost {
		return "upload_reauthorize", parts[4]
	}
	return "", ""
}

func (s *Server) prepareSignedProxyUpload(w http.ResponseWriter, r *http.Request, node store.Node, resource, operation, sessionID string, targets fileTargets) (string, time.Time, bool) {
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível verificar a autorização de upload no node.")
		return "", time.Time{}, false
	}
	found := false
	requiredCapability := "signed_upload_sessions_v1"
	if operation == "upload_reauthorize" {
		requiredCapability = "signed_upload_reauthorize_v1"
	} else if operation == "upload_simple" {
		requiredCapability = "signed_simple_upload_v1"
	}
	for _, capability := range info.Capabilities {
		found = found || capability == requiredCapability
	}
	if info.NodeID != node.ID || !found {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node e configure as chaves para uploads autorizados.")
		return "", time.Time{}, false
	}
	if len(targets.Paths) != 1 || targets.Paths[0] == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_file_request", "Não foi possível determinar o destino do upload.")
		return "", time.Time{}, false
	}
	root := targets.Paths[0]
	plan := sessionID
	var body []byte
	if operation == "upload_simple" {
		if len(r.URL.Query()["path"]) != 1 || len(r.Header.Values("Idempotency-Key")) > 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_file_request", "Caminho ou chave de idempotência inválida.")
			return "", time.Time{}, false
		}
		plan = signedauth.SimpleUploadPlanID(r.URL.RawQuery, r.Header.Get("Idempotency-Key"))
	}
	if operation == "upload_create" {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(body) == 0 || len(body) > 1<<20 {
			writeError(w, r, http.StatusBadRequest, "invalid_file_request", "O corpo do upload é inválido.")
			return "", time.Time{}, false
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		plan = signedauth.UploadAdmissionBodyID(body)
	}
	mount := mountIDFromResource(resource)
	now := time.Now()
	if operation == "upload_reauthorize" && targets.PreviousActorID != "" && targets.PreviousActorID != currentUser(r).ID {
		writeError(w, r, http.StatusForbidden, "signed_authorization_unavailable", "A sessão pertence a outro ator.")
		return "", time.Time{}, false
	}
	token, err := s.issueSignedAccess(r, node.ID, mount, root, operation, plan, targets.PreviousCredentialID, targets.AuthorizationRevision, now)
	if err != nil {
		writeError(w, r, http.StatusForbidden, "signed_authorization_unavailable", "Não foi possível autorizar o upload com as permissões atuais.")
		return "", time.Time{}, false
	}
	key := s.config.AuthorizationSigningKey.Public().(ed25519.PublicKey)
	keys := map[string]ed25519.PublicKey{s.config.AuthorizationSigningKeyID: key}
	var claims signedauth.Claims
	if operation == "upload_create" {
		claims, _, err = signedauth.VerifyUploadAdmission(token, keys, node.ID, mount, root, body, now)
	} else if operation == "upload_simple" {
		claims, _, err = signedauth.VerifySimpleUpload(token, keys, node.ID, mount, root, r.URL.RawQuery, r.Header.Get("Idempotency-Key"), now)
	} else if operation == "upload_reauthorize" {
		claims, _, err = signedauth.VerifyUploadReauthorization(token, keys, targets.PreviousActorID, targets.PreviousCredentialID, node.ID, mount, root, sessionID, targets.AuthorizationRevision, now)
	} else {
		credential, _ := r.Context().Value(credentialKey).(string)
		claims, _, err = signedauth.VerifyLocalUpload(token, keys, currentUser(r).ID, credential, node.ID, operation, mount, root, sessionID, now)
	}
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "signed_authorization_unavailable", "Não foi possível validar a autorização do upload.")
		return "", time.Time{}, false
	}
	return token, time.Unix(claims.ExpiresAt, 0), true
}
