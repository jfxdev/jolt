package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/pki"
)

// knownSerial reports whether the Control Tower issued, or lists, a
// certificate with this serial. Revoking a number nobody issued would only fill
// the bundle.
func (s *Server) knownSerial(r *http.Request, authority *pki.Manager, serial string) (subject string, notAfter time.Time, ok bool) {
	for _, item := range authority.Inventory() {
		if item.Serial == serial {
			return item.Kind + " " + item.Subject, item.NotAfter, true
		}
	}
	managed, err := s.store.ListManagedNodes(r.Context())
	if err != nil {
		return "", time.Time{}, false
	}
	for _, record := range managed {
		if record.CertSerial == serial {
			return "node " + record.NodeID, record.CertNotAfter, true
		}
	}
	return "", time.Time{}, false
}

type revokeRequest struct {
	Serial string `json:"serial"`
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

// revokeCertificate adds a serial to the bundle, naming it by serial or by the
// node whose API certificate it is.
func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	var request revokeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	serial := strings.ToLower(strings.TrimSpace(request.Serial))
	reason := strings.TrimSpace(request.Reason)
	if len(reason) > 200 {
		writeError(w, r, http.StatusBadRequest, "invalid_reason", "O motivo tem no máximo 200 caracteres.")
		return
	}
	if request.NodeID != "" {
		if serial != "" {
			writeError(w, r, http.StatusBadRequest, "invalid_revocation", "Informe o serial ou o node, não os dois.")
			return
		}
		managed, err := s.store.ListManagedNodes(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, record := range managed {
			if record.NodeID == request.NodeID {
				serial = record.CertSerial
			}
		}
		if serial == "" {
			writeError(w, r, http.StatusNotFound, "node_not_managed", "Esse node não foi enrolado na autoridade.")
			return
		}
	}
	if serial == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_revocation", "Informe o serial ou o node.")
		return
	}
	subject, notAfter, ok := s.knownSerial(r, authority, serial)
	if !ok {
		writeError(w, r, http.StatusNotFound, "unknown_certificate", "Nenhum certificado emitido por esta autoridade tem esse serial.")
		return
	}
	err := authority.Revoke(r.Context(), pki.Revocation{Serial: serial, Subject: subject, Reason: reason, NotAfter: notAfter})
	switch {
	case errors.Is(err, pki.ErrUseRotation):
		writeError(w, r, http.StatusConflict, "use_rotation", "Essa é a intermediária em uso: gire-a em vez de revogá-la.")
		return
	case errors.Is(err, pki.ErrCannotRevokeRoot):
		writeError(w, r, http.StatusConflict, "root_not_revocable", "Uma raiz não se revoga; troque-a pela rotação de raiz.")
		return
	case errors.Is(err, pki.ErrTooManyRevoked):
		writeError(w, r, http.StatusConflict, "revocation_list_full", "A lista de revogados está cheia; aguarde certificados vencidos saírem dela.")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r, "revoke", certificateResource+"/"+serial, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"serial": serial, "bundle_version": authority.Bundle().Version})
}

// listRevocations is what the bundle revokes.
func (s *Server) listRevocations(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "read", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	items, err := authority.Revocations(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type rotateIntermediateRequest struct {
	RevokePrevious bool   `json:"revoke_previous"`
	Reason         string `json:"reason"`
}

// rotateIntermediate issues a new intermediate; with revoke_previous it also
// revokes the ones already issued, which is the answer to a leaked issuing key.
func (s *Server) rotateIntermediate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	var request rotateIntermediateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := authority.RotateIntermediate(r.Context(), request.RevokePrevious, strings.TrimSpace(request.Reason)); err != nil {
		s.lifecycleError(w, r, err)
		return
	}
	s.audit(r, "rotate", certificateResource+"/intermediate", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"bundle_version": authority.Bundle().Version})
}

// beginRootRotation publishes the next root beside the active one.
func (s *Server) beginRootRotation(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	if err := authority.BeginRootRotation(r.Context()); err != nil {
		s.lifecycleError(w, r, err)
		return
	}
	s.audit(r, "rotate", certificateResource+"/root/begin", "allowed")
	writeJSON(w, http.StatusAccepted, map[string]any{"rotation": authority.Rotation(), "bundle_version": authority.Bundle().Version})
}

type promoteRootRequest struct {
	// Force promotes although a node has not confirmed the bundle that carries
	// the next root. That node trusts only the old root and can no longer be
	// reached until it is enrolled again.
	Force bool `json:"force"`
}

// promoteRoot makes the next root the one that signs. It waits for every
// enrolled node to confirm the bundle that carries it: a node that has not
// would stop trusting the Control Tower.
func (s *Server) promoteRoot(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", certificateResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	var request promoteRootRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if authority.Rotation().Phase != "prepared" {
		writeError(w, r, http.StatusConflict, "no_rotation_prepared", "Não há uma raiz nova preparada.")
		return
	}
	if !request.Force {
		managed, err := s.store.ListManagedNodes(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		var behind []string
		current := authority.Bundle().Version
		for _, record := range managed {
			if record.BundleVersion < current {
				behind = append(behind, record.NodeID)
			}
		}
		if len(behind) > 0 {
			writeError(w, r, http.StatusConflict, "nodes_behind", "Estes nodes ainda não confirmaram o pacote com a raiz nova: "+strings.Join(behind, ", ")+". Aguarde ou promova com force.")
			return
		}
	}
	if err := authority.PromoteRoot(r.Context()); err != nil {
		s.lifecycleError(w, r, err)
		return
	}
	s.audit(r, "rotate", certificateResource+"/root/promote", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"rotation": authority.Rotation(), "bundle_version": authority.Bundle().Version})
}

func (s *Server) lifecycleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pki.ErrRootUnavailable):
		writeError(w, r, http.StatusConflict, "root_unavailable", "A chave da raiz não está no banco. Traga-a de volta com jolt-control ca import-root.")
	case errors.Is(err, pki.ErrRotationBusy):
		writeError(w, r, http.StatusConflict, "rotation_busy", "Já há uma rotação de raiz em andamento.")
	case errors.Is(err, pki.ErrNoRotation):
		writeError(w, r, http.StatusConflict, "no_rotation", "Não há rotação de raiz nesse estado.")
	case errors.Is(err, pki.ErrTooManyIssuers):
		writeError(w, r, http.StatusConflict, "intermediate_limit", "Uma intermediária anterior ainda está em uso; revogue-a ou aguarde ela sair do pacote.")
	default:
		s.fail(w, r, err)
	}
}
