package httpapi

import (
	"context"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

const signedAuthorizationHeader = "X-Jolt-Access-Authorization"

type signedAccessKey struct{}

func signedAccessFilter(r *http.Request) *filesystem.AccessFilter {
	filter, _ := r.Context().Value(signedAccessKey{}).(*filesystem.AccessFilter)
	return filter
}

// A signed context must never be ignored by a handler that cannot enforce it.
// Until other operations support contexts, reject those requests explicitly.
func (s *Server) guardSignedContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values(signedAuthorizationHeader)) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		upload := len(parts) >= 6 && len(parts) <= 8 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "mounts" && parts[3] != "" && parts[4] == "files" && parts[5] == "uploads" && ((len(parts) == 6 && r.Method == http.MethodPost) || (len(parts) == 7 && (r.Method == http.MethodPatch || r.Method == http.MethodDelete)) || (len(parts) == 8 && (parts[7] == "complete" || parts[7] == "authorize") && r.Method == http.MethodPost))
		if upload {
			next.ServeHTTP(w, r)
			return
		}
		valid := (r.Method == http.MethodGet || r.Method == http.MethodHead) && len(parts) >= 5 && len(parts) <= 7 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "mounts" && parts[3] != "" && parts[4] == "files"
		if valid && len(parts) == 6 {
			valid = parts[5] == "metadata" || parts[5] == "content" || parts[5] == "archive" || parts[5] == "search" || parts[5] == "disk-usage"
		}
		if valid && len(parts) == 7 {
			valid = parts[5] == "archive" && parts[6] == "plan"
		}
		if !valid {
			writeError(w, r, http.StatusConflict, "signed_context_unsupported", "Esta operação ainda não suporta autorização assinada.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) signedLocalRead(operation string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header.Values(signedAuthorizationHeader)
		if len(headers) == 0 {
			next(w, r)
			return
		}
		paths := r.URL.Query()["path"]
		if len(headers) != 1 || len(paths) > 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_signed_context", "Autorização assinada inválida.", nil)
			return
		}
		root := r.URL.Query().Get("path")
		if root == "" {
			root = "."
		}
		if strings.TrimSpace(root) != root || strings.HasPrefix(root, "/") || strings.ContainsAny(root, "\\\x00") || path.Clean(root) != root || root == ".." || strings.HasPrefix(root, "../") {
			writeError(w, r, http.StatusBadRequest, "invalid_signed_context", "Autorização assinada inválida.", nil)
			return
		}
		mount := r.PathValue("mountID")
		claims, compiled, err := signedauth.VerifyLocalRead(headers[0], s.config.AuthorizationKeys, s.identity.NodeID, operation, mount, root, time.Now())
		if err != nil {
			writeError(w, r, http.StatusForbidden, "invalid_signed_context", "Autorização assinada inválida ou expirada.", nil)
			return
		}
		filter, err := filesystem.NewAccessFilter(compiled, "nodes/"+s.identity.NodeID+"/files/mounts/"+mount)
		if err != nil {
			writeError(w, r, http.StatusForbidden, "invalid_signed_context", "Autorização assinada inválida.", nil)
			return
		}
		deadline := time.Unix(claims.ExpiresAt, 0)
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(deadline); err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "signed_context_unavailable", "Não foi possível aplicar o prazo da autorização.", nil)
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		limited := &signedDeadlineWriter{ResponseWriter: w, ctx: ctx}
		defer func() {
			aborted := limited.aborted || ctx.Err() != nil
			cancel()
			if aborted {
				panic(http.ErrAbortHandler)
			}
			_ = controller.SetWriteDeadline(time.Time{})
		}()
		w.Header().Set("X-Jolt-Access-Applied", "v1")
		next(limited, r.WithContext(context.WithValue(ctx, signedAccessKey{}, filter)))
	}
}

type signedDeadlineWriter struct {
	http.ResponseWriter
	ctx     context.Context
	aborted bool
}

func (w *signedDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *signedDeadlineWriter) WriteHeader(status int) {
	if w.ctx.Err() != nil {
		w.aborted = true
		return
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *signedDeadlineWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		w.aborted = true
		return 0, err
	}
	n, err := w.ResponseWriter.Write(data)
	if err != nil {
		w.aborted = true
	}
	return n, err
}

func (w *signedDeadlineWriter) Flush() {
	if w.ctx.Err() != nil {
		w.aborted = true
		return
	}
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		w.aborted = true
	}
}
