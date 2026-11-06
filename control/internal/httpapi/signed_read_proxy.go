package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

const signedAuthorizationHeader = "X-Jolt-Access-Authorization"

// signedReadOperation recognizes only the node endpoints that enforce the
// envelope. Unknown paths must never accidentally inherit an authorization.
func signedReadOperation(resource, method string) string {
	if method != http.MethodGet {
		return ""
	}
	parts := strings.Split(resource, "/")
	if len(parts) < 3 || parts[0] != "mounts" || !validPathIdentifier(parts[1]) || parts[2] != "files" {
		return ""
	}
	switch strings.Join(parts[3:], "/") {
	case "":
		return "list"
	case "metadata", "content", "search":
		return parts[3]
	case "disk-usage":
		return "disk_usage"
	case "archive":
		return "archive"
	case "archive/plan":
		return "archive_plan"
	default:
		return ""
	}
}

func (s *Server) prepareSignedProxyRead(w http.ResponseWriter, r *http.Request, node store.Node, resource, operation string) (string, time.Time, bool) {
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível verificar a autorização assinada no node.")
		return "", time.Time{}, false
	}
	capability := "signed_local_read_v1"
	if operation == "search" || operation == "disk_usage" || operation == "archive" || operation == "archive_plan" {
		capability = "signed_local_tree_read_v1"
	}
	supported := false
	for _, c := range info.Capabilities {
		supported = supported || c == capability
	}
	if info.NodeID != node.ID || !supported {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node e configure as chaves de autorização para esta leitura.")
		return "", time.Time{}, false
	}
	if len(r.URL.Query()["path"]) > 1 {
		writeError(w, r, http.StatusBadRequest, "invalid_file_request", "Informe apenas um caminho para esta leitura.")
		return "", time.Time{}, false
	}
	root := r.URL.Query().Get("path")
	if root == "" {
		root = "."
	}
	mount := mountIDFromResource(resource)
	now := time.Now()
	token, err := s.issueSignedLocalRead(r, node.ID, mount, root, operation, now)
	if err != nil {
		writeError(w, r, http.StatusForbidden, "signed_authorization_unavailable", "Não foi possível autorizar esta leitura com as permissões atuais.")
		return "", time.Time{}, false
	}
	claims, _, err := signedauth.VerifyLocalRead(token, s.verificationKeys(), node.ID, operation, mount, root, now)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "signed_authorization_unavailable", "Não foi possível validar a autorização desta leitura.")
		return "", time.Time{}, false
	}
	return token, time.Unix(claims.ExpiresAt, 0), true
}

// The deadline is also imposed on downstream writes: canceling the node
// request alone cannot interrupt an already blocked write to a slow client.
type signedProxyWriter struct {
	http.ResponseWriter
	ctx context.Context
}

func (w *signedProxyWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(p)
}
