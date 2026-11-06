package httpapi

import (
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/trust"
)

const maxTrustBody = 256 << 10

var dnsName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// managedTrust answers for a node the Control Tower's authority enrolled. A
// node configured by hand has no such routes.
func (s *Server) managedTrust(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.trust == nil || !s.trust.Managed() {
			writeError(w, r, http.StatusNotFound, "managed_tls_disabled", "This node is not enrolled in a managed certificate authority.", nil)
			return
		}
		next(w, r)
	}
}

// trustStatus tells the Control Tower which bundle and certificate the node
// holds, so it can send only what is missing.
func (s *Server) trustStatus(w http.ResponseWriter, _ *http.Request) {
	end, serial := s.trust.CertificateEnd()
	writeJSON(w, http.StatusOK, map[string]any{
		"bundle_version": s.trust.BundleVersion(),
		"api_certificate": map[string]any{
			"not_after": end.UTC().Format(time.RFC3339),
			"serial":    serial,
		},
	})
}

// adoptTrustBundle takes a bundle the Control Tower pushes. The node decides
// for itself whether to trust it: the channel being authenticated is not enough.
func (s *Server) adoptTrustBundle(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTrustBody))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "The request body could not be read.", nil)
		return
	}
	bundle, err := trust.ParseBundle(data)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_trust_bundle", err.Error(), nil)
		return
	}
	if err := s.trust.Adopt(r.Context(), bundle); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "trust_bundle_refused", err.Error(), nil)
		return
	}
	s.log.Info("trust bundle adopted", "version", bundle.Version, "correlation_id", r.Header.Get("X-Correlation-ID"))
	s.trustStatus(w, r)
}

type certificateRequestInput struct {
	Names []string `json:"names"`
}

// prepareAPICertificate makes a new key for the API listener and returns a
// signing request for it. The key never leaves the node.
func (s *Server) prepareAPICertificate(w http.ResponseWriter, r *http.Request) {
	var input certificateRequestInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Names) == 0 || len(input.Names) > 16 {
		writeError(w, r, http.StatusBadRequest, "invalid_names", "Between one and sixteen names are required.", nil)
		return
	}
	for _, name := range input.Names {
		if _, err := netip.ParseAddr(name); err != nil && !(len(name) <= 253 && dnsName.MatchString(name)) {
			writeError(w, r, http.StatusBadRequest, "invalid_names", "Each name must be a DNS name or an IP address.", nil)
			return
		}
	}
	request, err := s.trust.PrepareCSR(r.Context(), s.identity.NodeID, input.Names)
	if err != nil {
		writeError(w, r, http.StatusConflict, "certificate_request_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"csr_pem": string(request)})
}

type certificateInput struct {
	CertificatePEM string `json:"certificate_pem"`
}

// installAPICertificate puts the issued certificate into service when it
// matches the pending key and chains to the bundle.
func (s *Server) installAPICertificate(w http.ResponseWriter, r *http.Request) {
	var input certificateInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.CertificatePEM) == "" || len(input.CertificatePEM) > 32<<10 {
		writeError(w, r, http.StatusBadRequest, "invalid_certificate", "A certificate chain is required.", nil)
		return
	}
	if err := s.trust.InstallCertificate(r.Context(), input.CertificatePEM); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "certificate_refused", err.Error(), nil)
		return
	}
	s.log.Info("API certificate renewed", "correlation_id", r.Header.Get("X-Correlation-ID"))
	s.trustStatus(w, r)
}
