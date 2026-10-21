package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
)

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(r.Context())
	}
	return context.WithTimeout(r.Context(), timeout)
}

type createUploadRequest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Overwrite bool   `json:"overwrite"`
	Checksum  string `json:"checksum"`
	ChunkSize int64  `json:"chunk_size"`
}

// createUploadSession opens a resumable upload. The client declares the total
// size up front so the node can cap what it writes and verify completeness,
// which is what makes a resumed upload trustworthy.
func (s *Server) createUploadSession(w http.ResponseWriter, r *http.Request) {
	var request createUploadRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Size < 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_size", "size não pode ser negativo.", nil)
		return
	}
	if request.Checksum != "" && !isHexSHA256(request.Checksum) {
		writeError(w, r, http.StatusBadRequest, "invalid_checksum",
			"checksum precisa ser um SHA-256 hexadecimal.", nil)
		return
	}
	mountID := r.PathValue("mountID")
	s.uploadAdmission.Lock()
	defer s.uploadAdmission.Unlock()
	if !s.admitUpload(w, r, mountID, request.Path, request.Size) {
		return
	}

	// Resolving now rejects a traversing or unwritable destination before a
	// session row exists, so an invalid upload never occupies a destination.
	if _, err := s.files.UploadOffset(r.Context(), mountID, request.Path, "probe"); err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	chunkSize := request.ChunkSize
	if chunkSize <= 0 || chunkSize > s.config.CopyChunkSize {
		chunkSize = s.config.CopyChunkSize
	}
	session := entities.UploadSession{
		ID: newUploadID(), MountID: mountID, Destination: request.Path,
		Size: request.Size, Overwrite: request.Overwrite, Checksum: request.Checksum,
		ChunkSize: chunkSize, CorrelationID: r.Header.Get("X-Correlation-ID"),
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(s.config.UploadSessionTTL),
	}
	if err := s.store.CreateUploadSession(r.Context(), session); err != nil {
		if errors.Is(err, db.ErrUploadSessionExists) {
			writeError(w, r, http.StatusConflict, "upload_in_progress",
				"Outro upload retomável já está enviando para este caminho.", nil)
			return
		}
		s.fail(w, r, err)
		return
	}
	s.registry.Inc("jolt_uploads_started_total")
	s.registry.AddGauge("jolt_uploads_active", 1)
	writeJSON(w, http.StatusCreated, session)
}

// getUploadSession reports the durable offset so a client that lost its state
// knows exactly where to resume.
func (s *Server) getUploadSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadUploadSession(w, r)
	if !ok {
		return
	}
	offset, err := s.files.UploadOffset(r.Context(), session.MountID, session.Destination, session.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	session.Offset = offset
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) listUploadSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListUploadSessions(r.Context(), r.PathValue("mountID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for index := range sessions {
		offset, offsetErr := s.files.UploadOffset(r.Context(), sessions[index].MountID,
			sessions[index].Destination, sessions[index].ID)
		if offsetErr == nil {
			sessions[index].Offset = offset
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

var contentRangePattern = regexp.MustCompile(`^bytes (\d+)-(\d+)/(\d+|\*)$`)

// appendUploadChunk writes one chunk at the offset named by Content-Range. A
// mismatch answers 409 with the real offset in X-Jolt-Upload-Offset so the
// client can seek instead of guessing or restarting from zero.
func (s *Server) appendUploadChunk(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadUploadSession(w, r)
	if !ok {
		return
	}
	if r.ContentLength > session.ChunkSize {
		writeError(w, r, http.StatusRequestEntityTooLarge, "upload_chunk_too_large", "O chunk excede o limite da sessão.", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, session.ChunkSize)
	offset, _, err := parseContentRange(r.Header.Get("Content-Range"), session.Size)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_content_range",
			"Content-Range precisa ser bytes <inicio>-<fim>/<total>.", nil)
		return
	}
	job, _, err := s.jobs.CreateInline(r.Context(), jobsCreateUpload(session), "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer s.jobs.ReleaseBandwidthLimiter(job.ID)
	written, appendErr := s.files.AppendUpload(r.Context(), session.MountID, session.Destination,
		session.ID, offset, session.Size, r.Body, s.jobs.BandwidthLimiter(job))
	_ = s.jobs.Complete(r.Context(), &job, written-offset, appendErr)
	if appendErr != nil {
		var maxError *http.MaxBytesError
		if errors.As(appendErr, &maxError) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "upload_chunk_too_large", "O chunk excede o limite da sessão.", nil)
			return
		}
		if errors.Is(appendErr, filesystem.ErrOffsetMismatch) {
			w.Header().Set("X-Jolt-Upload-Offset", strconv.FormatInt(written, 10))
			writeError(w, r, http.StatusConflict, "upload_offset_mismatch",
				fmt.Sprintf("O upload está em %d bytes.", written), map[string]any{"offset": written})
			return
		}
		s.fail(w, r, appendErr)
		return
	}
	s.registry.Add("jolt_upload_bytes_total", written-offset)
	now := time.Now().UTC()
	if err := s.store.TouchUploadSession(r.Context(), session.ID, now,
		now.Add(s.config.UploadSessionTTL)); err != nil && !errors.Is(err, db.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	session.Offset = written
	w.Header().Set("X-Jolt-Upload-Offset", strconv.FormatInt(written, 10))
	writeJSON(w, http.StatusOK, session)
}

// completeUploadSession verifies and publishes the assembled file.
func (s *Server) completeUploadSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadUploadSession(w, r)
	if !ok {
		return
	}
	size, checksum, err := s.files.CompleteUpload(r.Context(), session.MountID, session.Destination,
		session.ID, session.Size, session.Checksum, session.Overwrite)
	if err != nil {
		s.registry.Inc("jolt_uploads_failed_total")
		s.fail(w, r, err)
		return
	}
	// The session row goes away only after the rename succeeded, so a failure
	// anywhere above leaves the upload resumable.
	if err := s.store.DeleteUploadSession(r.Context(), session.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.registry.Inc("jolt_uploads_completed_total")
	s.registry.AddGauge("jolt_uploads_active", -1)
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_id": session.ID, "destination_path": session.Destination,
		"size": size, "checksum": checksum,
	})
}

// abortUploadSession discards a resumable upload and its partial file.
func (s *Server) abortUploadSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.loadUploadSession(w, r)
	if !ok {
		return
	}
	if err := s.files.AbortUpload(r.Context(), session.MountID, session.Destination, session.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteUploadSession(r.Context(), session.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.registry.Inc("jolt_uploads_aborted_total")
	s.registry.AddGauge("jolt_uploads_active", -1)
	w.WriteHeader(http.StatusNoContent)
}

// loadUploadSession fetches the session and checks it belongs to the mount in
// the route, so an upload ID from one mount cannot be replayed against another.
func (s *Server) loadUploadSession(w http.ResponseWriter, r *http.Request) (entities.UploadSession, bool) {
	session, err := s.store.GetUploadSession(r.Context(), r.PathValue("uploadID"))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "upload_not_found", "Upload não encontrado.", nil)
			return entities.UploadSession{}, false
		}
		s.fail(w, r, err)
		return entities.UploadSession{}, false
	}
	if session.MountID != r.PathValue("mountID") {
		writeError(w, r, http.StatusNotFound, "upload_not_found", "Upload não encontrado.", nil)
		return entities.UploadSession{}, false
	}
	if !session.ExpiresAt.IsZero() && time.Now().UTC().After(session.ExpiresAt) {
		writeError(w, r, http.StatusGone, "upload_expired",
			"Este upload expirou. Inicie um novo envio.", nil)
		return entities.UploadSession{}, false
	}
	return session, true
}

// parseContentRange reads "bytes start-end/total". The end is informational:
// the node writes wherever start says and stops at the declared total, so a
// client that miscounts the end cannot create a hole.
func parseContentRange(value string, declaredSize int64) (int64, int64, error) {
	matches := contentRangePattern.FindStringSubmatch(strings.TrimSpace(value))
	if matches == nil {
		return 0, 0, errors.New("malformed Content-Range")
	}
	start, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	end, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if end < start {
		return 0, 0, errors.New("Content-Range end precedes start")
	}
	if matches[3] != "*" {
		total, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		if total != declaredSize {
			return 0, 0, errors.New("Content-Range total does not match the session size")
		}
	}
	if start > declaredSize || end >= declaredSize && declaredSize > 0 && end != declaredSize-1 {
		return 0, 0, errors.New("Content-Range is outside the session size")
	}
	return start, end, nil
}

func newUploadID() string { return randomID("upl") }

// jobsCreateUpload describes the inline job that accounts for one chunk, so a
// resumable upload shows up in the job list and honours bandwidth limits like
// every other write.
func jobsCreateUpload(session entities.UploadSession) jobs.CreateRequest {
	return jobs.CreateRequest{
		Type: "upload", MountID: session.MountID, Destination: session.Destination,
		CorrelationID: session.CorrelationID, Overwrite: session.Overwrite,
	}
}

func isHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'f':
		default:
			return false
		}
	}
	return true
}
