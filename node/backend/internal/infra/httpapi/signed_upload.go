package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedUploadIdentityKey struct{}

func (s *Server) signedUpload(operation string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header.Values(signedAuthorizationHeader)
		var session entities.UploadSession
		if operation != "upload_create" && operation != "upload_simple" {
			var err error
			session, err = s.store.GetUploadSession(r.Context(), r.PathValue("uploadID"))
			if err != nil && !errors.Is(err, contracts.ErrNotFound) {
				s.fail(w, r, err)
				return
			}
			if err != nil || session.MountID != r.PathValue("mountID") {
				writeError(w, r, http.StatusNotFound, "upload_not_found", "Upload não encontrado.", nil)
				return
			}
		}
		if len(headers) == 0 {
			if operation == "upload_reauthorize" || session.AuthorizationActorID != "" || session.AuthorizationCredentialID != "" {
				writeError(w, r, http.StatusForbidden, "signed_context_required", "Esta sessão exige autorização assinada.", nil)
				return
			}
			next(w, r)
			return
		}
		if len(headers) != 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_signed_context", "Autorização assinada inválida.", nil)
			return
		}
		var claims signedauth.Claims
		var compiled *filetypes.Filter
		var err error
		if operation == "upload_create" {
			body, readErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
			var input createUploadRequest
			if readErr != nil || len(body) > 1<<20 || json.Unmarshal(body, &input) != nil {
				writeError(w, r, http.StatusBadRequest, "invalid_json", "O corpo do upload é inválido.", nil)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			claims, compiled, err = signedauth.VerifyUploadAdmission(headers[0], s.config.AuthorizationKeys, s.identity.NodeID, r.PathValue("mountID"), input.Path, body, time.Now())
		} else if operation == "upload_simple" {
			paths := r.URL.Query()["path"]
			if len(paths) != 1 || len(r.Header.Values("Idempotency-Key")) > 1 {
				writeError(w, r, http.StatusBadRequest, "invalid_file_request", "Caminho ou chave de idempotência inválida.", nil)
				return
			}
			claims, compiled, err = signedauth.VerifySimpleUpload(headers[0], s.config.AuthorizationKeys, s.identity.NodeID, r.PathValue("mountID"), paths[0], r.URL.RawQuery, r.Header.Get("Idempotency-Key"), time.Now())
		} else if operation == "upload_reauthorize" {
			if (session.AuthorizationActorID == "") != (session.AuthorizationCredentialID == "") {
				writeError(w, r, http.StatusForbidden, "invalid_signed_context", "Vínculo de autorização da sessão inválido.", nil)
				return
			}
			claims, compiled, err = signedauth.VerifyUploadReauthorization(headers[0], s.config.AuthorizationKeys, session.AuthorizationActorID, session.AuthorizationCredentialID, s.identity.NodeID, session.MountID, session.Destination, session.ID, session.AuthorizationRevision, time.Now())
		} else {
			claims, compiled, err = signedauth.VerifyLocalUpload(headers[0], s.config.AuthorizationKeys, session.AuthorizationActorID, session.AuthorizationCredentialID, s.identity.NodeID, operation, session.MountID, session.Destination, session.ID, time.Now())
		}
		if err != nil {
			writeError(w, r, http.StatusForbidden, "invalid_signed_context", "Autorização assinada inválida ou expirada.", nil)
			return
		}
		filter, err := filesystem.NewAccessFilter(compiled, "nodes/"+s.identity.NodeID+"/files/mounts/"+r.PathValue("mountID"))
		if err != nil {
			writeError(w, r, http.StatusForbidden, "invalid_signed_context", "Autorização assinada inválida.", nil)
			return
		}
		deadline := time.Unix(claims.ExpiresAt, 0)
		controller := http.NewResponseController(w)
		if controller.SetWriteDeadline(deadline) != nil {
			writeError(w, r, http.StatusServiceUnavailable, "signed_context_unavailable", "Não foi possível aplicar o prazo da autorização.", nil)
			return
		}
		if (operation == "upload_chunk" || operation == "upload_simple") && controller.SetReadDeadline(deadline) != nil {
			_ = controller.SetWriteDeadline(time.Time{})
			writeError(w, r, http.StatusServiceUnavailable, "signed_context_unavailable", "Não foi possível limitar o prazo do envio.", nil)
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		limited := &signedDeadlineWriter{ResponseWriter: w, ctx: ctx}
		defer func() {
			aborted := limited.aborted || ctx.Err() != nil || !time.Now().Before(deadline)
			cancel()
			if aborted {
				panic(http.ErrAbortHandler)
			}
			_ = controller.SetWriteDeadline(time.Time{})
			if operation == "upload_chunk" || operation == "upload_simple" {
				_ = controller.SetReadDeadline(time.Time{})
			}
		}()
		ctx = context.WithValue(ctx, signedAccessKey{}, filter)
		ctx = context.WithValue(ctx, signedUploadIdentityKey{}, claims.Binding)
		w.Header().Set("X-Jolt-Access-Applied", "v1")
		next(limited, r.WithContext(ctx))
	}
}

func signedSimpleUploadIdempotency(r *http.Request) string {
	key := idempotencyKey(r)
	if key == "" {
		return ""
	}
	binding, ok := r.Context().Value(signedUploadIdentityKey{}).(signedauth.Binding)
	if !ok || binding.Operation != "upload_simple" {
		return key
	}
	sum := sha256.Sum256([]byte(binding.ActorID + "\x00" + binding.CredentialID + "\x00" + binding.DestinationNodeID + "\x00" + binding.DestinationMountID + "\x00" + binding.DestinationRoot + "\x00" + binding.PlanID))
	return fmt.Sprintf("signed-upload-%x", sum)
}
