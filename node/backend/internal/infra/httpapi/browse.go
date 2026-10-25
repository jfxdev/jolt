package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

// archive streams a ZIP of a directory, or of the selected entries inside it.
// The size is measured first so an oversized selection is refused with a real
// status code: once the ZIP starts streaming the status is already committed
// and a failure can only appear as a truncated download.
func (s *Server) archive(w http.ResponseWriter, r *http.Request) {
	mountID := r.PathValue("mountID")
	relative := r.URL.Query().Get("path")
	options := filesystem.ArchiveOptions{
		Names:      archiveNames(r),
		Compress:   boolQuery(r, "compress"),
		MaxEntries: s.config.ArchiveMaxEntries,
		MaxBytes:   s.config.ArchiveMaxBytes,
	}
	plan, err := s.files.PlanArchive(r.Context(), mountID, relative, options)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name := filesystem.ArchiveName(relative)
	if len(options.Names) == 1 {
		name = filesystem.ArchiveName(options.Names[0])
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition("attachment", name))
	// The archive is generated on the fly, so there is no length to advertise
	// and no value in letting a proxy cache it.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Jolt-Archive-Files", strconv.Itoa(plan.Entries))
	w.Header().Set("X-Jolt-Archive-Bytes", strconv.FormatInt(plan.Bytes, 10))
	if plan.SkippedSymlink > 0 {
		w.Header().Set("X-Jolt-Archive-Skipped-Symlinks", strconv.Itoa(plan.SkippedSymlink))
	}
	result, err := s.files.Archive(r.Context(), mountID, relative, options, w)
	if err != nil {
		// Headers are already sent; log and drop the connection so the client
		// sees a truncated transfer rather than a valid but incomplete ZIP.
		s.log.Error("archive stream failed", "mount_id", mountID, "path", relative,
			"entries", result.Entries, "bytes", result.Bytes, "error", err)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		panic(http.ErrAbortHandler)
	}
}

// archivePlan reports what an archive would contain so the UI can confirm a
// large download before starting it.
func (s *Server) archivePlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.files.PlanArchive(r.Context(), r.PathValue("mountID"), r.URL.Query().Get("path"),
		filesystem.ArchiveOptions{
			Names:      archiveNames(r),
			MaxEntries: s.config.ArchiveMaxEntries,
			MaxBytes:   s.config.ArchiveMaxBytes,
		})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"files":            plan.Entries,
		"bytes":            plan.Bytes,
		"skipped_symlinks": plan.SkippedSymlink,
		"max_files":        s.config.ArchiveMaxEntries,
		"max_bytes":        s.config.ArchiveMaxBytes,
	})
}

func archiveNames(r *http.Request) []string {
	names := make([]string, 0, 8)
	for _, value := range r.URL.Query()["name"] {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

// search walks a subtree under a bounded deadline. The deadline is enforced
// here rather than in the service so the response can still be written: a
// truncated result with a reason is more useful than a timeout error.
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	options := filesystem.SearchOptions{
		Query:      r.URL.Query().Get("query"),
		Type:       strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type"))),
		Extensions: splitList(r.URL.Query().Get("extensions")),
		MinSize:    int64Query(r, "min_size"),
		MaxSize:    int64Query(r, "max_size"),
		MaxResults: s.config.SearchMaxResults,
		MaxEntries: s.config.SearchMaxEntries,
	}
	if limit := int(int64Query(r, "limit")); limit > 0 && limit < options.MaxResults {
		options.MaxResults = limit
	}
	if options.Type != "" && options.Type != "file" && options.Type != "directory" {
		writeError(w, r, http.StatusBadRequest, "invalid_type",
			"O filtro type aceita apenas file ou directory.", nil)
		return
	}
	var err error
	if options.ModifiedAfter, err = timeQuery(r, "modified_after"); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_modified_after",
			"modified_after precisa ser uma data RFC 3339.", nil)
		return
	}
	if options.ModifiedBefore, err = timeQuery(r, "modified_before"); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_modified_before",
			"modified_before precisa ser uma data RFC 3339.", nil)
		return
	}
	ctx, cancel := contextWithTimeout(r, s.config.SearchTimeout)
	defer cancel()
	result, err := s.files.Search(ctx, r.PathValue("mountID"), r.URL.Query().Get("path"), options)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func int64Query(r *http.Request, name string) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func timeQuery(r *http.Request, name string) (time.Time, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

// metrics serves the Prometheus exposition. It is gated on its own token so a
// scraper never needs the operational token, and it stays unroutable when no
// token is configured.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.registry.Write(w); err != nil {
		s.log.Error("write metrics", "error", err)
	}
}
