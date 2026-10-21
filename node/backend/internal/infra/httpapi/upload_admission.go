package httpapi

import (
	"net/http"
	"time"

	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

// Caller holds uploadAdmission through insertion so concurrent declarations
// cannot all observe the same count or unreserved space.
func (s *Server) admitUpload(w http.ResponseWriter, r *http.Request, mountID, path string, size int64) bool {
	if size > s.config.UploadMaxBytes {
		s.fail(w, r, filesystem.ErrUploadTooLarge)
		return false
	}
	mounts, err := s.store.ListMounts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	count, reserved := 0, int64(0)
	now := time.Now().UTC()
	for _, mount := range mounts {
		sessions, err := s.store.ListUploadSessions(r.Context(), mount.ID)
		if err != nil {
			s.fail(w, r, err)
			return false
		}
		for _, session := range sessions {
			if !session.ExpiresAt.IsZero() && now.After(session.ExpiresAt) {
				continue
			}
			count++
			remaining := session.Size
			if offset, err := s.files.UploadOffset(r.Context(), session.MountID, session.Destination, session.ID); err == nil && offset >= 0 && offset <= remaining {
				remaining -= offset
			}
			if remaining > s.config.UploadMaxReservedBytes-reserved {
				s.fail(w, r, filesystem.ErrInsufficientSpace)
				return false
			}
			reserved += remaining
		}
	}
	if count >= s.config.UploadMaxSessions {
		w.Header().Set("Retry-After", "60")
		writeError(w, r, http.StatusTooManyRequests, "upload_session_limit", "O node atingiu o limite de uploads pendentes. Conclua ou descarte um envio.", nil)
		return false
	}
	if size > s.config.UploadMaxReservedBytes-reserved {
		s.fail(w, r, filesystem.ErrInsufficientSpace)
		return false
	}
	if err := s.files.CheckUploadCapacity(r.Context(), mountID, path, size+reserved); err != nil {
		s.fail(w, r, err)
		return false
	}
	return true
}
