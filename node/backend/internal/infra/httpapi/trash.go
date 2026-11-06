package httpapi

import (
	"net/http"
)

// The trash routes are operational: they act on whole entries a mount kept
// when they were deleted. The Control Tower decides who may list, restore or
// purge, against the path an entry had; the node only checks the mount.

func (s *Server) listTrash(w http.ResponseWriter, r *http.Request) {
	items, err := s.files.ListTrash(r.Context(), r.PathValue("mountID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getTrash(w http.ResponseWriter, r *http.Request) {
	item, err := s.files.GetTrash(r.Context(), r.PathValue("mountID"), r.PathValue("trashID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) restoreTrash(w http.ResponseWriter, r *http.Request) {
	item, err := s.files.RestoreTrash(r.Context(), r.PathValue("mountID"), r.PathValue("trashID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) purgeTrash(w http.ResponseWriter, r *http.Request) {
	item, err := s.files.PurgeTrash(r.Context(), r.PathValue("mountID"), r.PathValue("trashID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
