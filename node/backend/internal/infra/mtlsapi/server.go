package mtlsapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/transfers"
)

func New(identity entities.Identity, nodeName string, transferServices ...*transfers.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /peer/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "online", "node_id": identity.NodeID, "name": nodeName,
			"fingerprint": identity.Fingerprint, "identity_epoch": identity.Epoch,
			"observed_at": time.Now().UTC(),
		})
	})
	if len(transferServices) > 0 && transferServices[0] != nil {
		service := transferServices[0]
		content := func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
				writeError(w, http.StatusUnauthorized, "peer_certificate_required", "A verified peer certificate is required.")
				return
			}
			source, err := service.OpenSource(r.Context(), r.TLS.PeerCertificates[0].Subject.CommonName,
				r.PathValue("grantID"), r.URL.Query().Get("path"), r.URL.Query().Get("checksum") == "true")
			if err != nil {
				status, code := http.StatusInternalServerError, "transfer_failed"
				if errors.Is(err, transfers.ErrForbidden) {
					status, code = http.StatusForbidden, "grant_forbidden"
				} else if errors.Is(err, filesystem.ErrNotFound) {
					status, code = http.StatusNotFound, "file_not_found"
				} else if errors.Is(err, filesystem.ErrTraversal) || errors.Is(err, filesystem.ErrInvalid) {
					status, code = http.StatusBadRequest, "invalid_path"
				}
				writeError(w, status, code, err.Error())
				return
			}
			defer source.File.Close()
			if match := r.Header.Get("If-Match"); match != "" && match != source.ETag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			w.Header().Set("ETag", source.ETag)
			w.Header().Set("X-Jolt-File-Size", formatInt(source.Info.Size()))
			if source.Checksum != "" {
				w.Header().Set("X-Jolt-SHA256", source.Checksum)
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Last-Modified", source.Info.ModTime().UTC().Format(http.TimeFormat))
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", formatInt(source.Info.Size()))
				w.WriteHeader(http.StatusOK)
				return
			}
			start, end, status, rangeErr := requestedRange(r.Header.Get("Range"), source.Info.Size())
			if rangeErr != nil {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", source.Info.Size()))
				writeError(w, http.StatusRequestedRangeNotSatisfiable, "invalid_range", rangeErr.Error())
				return
			}
			if _, err := source.File.Seek(start, io.SeekStart); err != nil {
				writeError(w, http.StatusInternalServerError, "transfer_failed", err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Trailer", "X-Jolt-Final-ETag")
			if status == http.StatusPartialContent {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, source.Info.Size()))
			}
			w.WriteHeader(status)
			_, _ = io.CopyN(w, source.File, end-start+1)
			if finalETag, statErr := source.CurrentETag(); statErr == nil {
				w.Header().Set("X-Jolt-Final-ETag", finalETag)
			}
		}
		mux.HandleFunc("GET /peer/v1/grants/{grantID}/content", content)
		mux.HandleFunc("HEAD /peer/v1/grants/{grantID}/content", content)
		mux.HandleFunc("GET /peer/v1/grants/{grantID}/manifest", func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
				writeError(w, http.StatusUnauthorized, "peer_certificate_required", "A verified peer certificate is required.")
				return
			}
			after, afterErr := strconv.Atoi(r.URL.Query().Get("after"))
			limit, limitErr := strconv.Atoi(r.URL.Query().Get("limit"))
			if (r.URL.Query().Get("after") != "" && afterErr != nil) || (r.URL.Query().Get("limit") != "" && limitErr != nil) {
				writeError(w, http.StatusBadRequest, "invalid_pagination", "Manifest pagination values must be integers.")
				return
			}
			page, err := service.OpenManifest(r.Context(), r.TLS.PeerCertificates[0].Subject.CommonName,
				r.PathValue("grantID"), r.URL.Query().Get("path"), r.URL.Query().Get("checksum") == "true", after, limit)
			if err != nil {
				status, code := http.StatusInternalServerError, "manifest_failed"
				if errors.Is(err, transfers.ErrForbidden) {
					status, code = http.StatusForbidden, "grant_forbidden"
				} else if errors.Is(err, filesystem.ErrNotFound) {
					status, code = http.StatusNotFound, "directory_not_found"
				} else if errors.Is(err, filesystem.ErrTraversal) || errors.Is(err, filesystem.ErrInvalid) ||
					errors.Is(err, transfers.ErrInvalid) {
					status, code = http.StatusBadRequest, "invalid_path"
				}
				writeError(w, status, code, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(page)
		})
	}
	return mux
}

func requestedRange(value string, size int64) (int64, int64, int, error) {
	if value == "" {
		if size == 0 {
			return 0, -1, http.StatusOK, nil
		}
		return 0, size - 1, http.StatusOK, nil
	}
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return 0, 0, 0, errors.New("only one byte range is supported")
	}
	parts := strings.SplitN(strings.TrimPrefix(value, "bytes="), "-", 2)
	if len(parts) != 2 || parts[0] == "" {
		return 0, 0, 0, errors.New("range start is required")
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, 0, errors.New("range start is outside the file")
	}
	end := size - 1
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil || end < start || end >= size {
			return 0, 0, 0, errors.New("range end is outside the file")
		}
	}
	return start, end, http.StatusPartialContent, nil
}

func formatInt(value int64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
