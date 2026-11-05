package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
)

type destructivePlanRequest struct {
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	Operation       string `json:"operation"`
	SourcePath      string `json:"source_path"`
	DestinationPath string `json:"destination_path"`
	Overwrite       bool   `json:"overwrite"`
}

type destructiveAcceptRequest struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Token       string `json:"token"`
}

func decodeStrict(w http.ResponseWriter, r *http.Request, target any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || filetypes.ValidateUniqueJSON(body) != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.", nil)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.", nil)
		return false
	}
	return true
}

// createDestructivePlan inspects a tree and returns what the operator must
// confirm. The subject comes from the Control Tower, which authenticated the
// actor; the operational bearer token is what makes that claim trustworthy.
func (s *Server) createDestructivePlan(w http.ResponseWriter, r *http.Request) {
	if !s.signedExecutionEnabled() {
		writeError(w, r, http.StatusServiceUnavailable, "destructive_plans_unavailable", "Os planos destrutivos estão indisponíveis neste node.", nil)
		return
	}
	var request destructivePlanRequest
	if !decodeStrict(w, r, &request) {
		return
	}
	summary, err := s.jobs.CreateDestructivePlan(r.Context(), jobs.DestructivePlanRequest{
		SubjectType: request.SubjectType, SubjectID: request.SubjectID, Operation: request.Operation,
		MountID: r.PathValue("mountID"), Source: request.SourcePath, Destination: request.DestinationPath, Overwrite: request.Overwrite,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Jolt-Destructive-Plan", "v1")
	writeJSON(w, http.StatusCreated, summary)
}

// acceptDestructivePlan consumes the confirmation and creates the job, which
// then waits for its signed authorization.
func (s *Server) acceptDestructivePlan(w http.ResponseWriter, r *http.Request) {
	if !s.signedExecutionEnabled() {
		writeError(w, r, http.StatusServiceUnavailable, "destructive_plans_unavailable", "Os planos destrutivos estão indisponíveis neste node.", nil)
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] == "" || len(keys[0]) > 256 {
		writeError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "Informe uma chave de idempotência.", nil)
		return
	}
	var request destructiveAcceptRequest
	if !decodeStrict(w, r, &request) {
		return
	}
	job, repeated, err := s.jobs.AcceptDestructivePlan(r.Context(), request.SubjectType, request.SubjectID, r.PathValue("planID"), request.Token, keys[0], r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Jolt-Destructive-Plan", "v1")
	status := http.StatusAccepted
	if repeated {
		status = http.StatusOK
	}
	writeJSON(w, status, job)
}
