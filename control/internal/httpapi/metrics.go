package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/metrics"
)

// registerControlMetrics declares every metric the Control Tower exposes, so a
// scrape taken before the first request still returns a complete series set.
func registerControlMetrics(registry *metrics.Registry) {
	registry.Counter("jolt_control_http_requests_total",
		"Control Tower requests by method, matched route and status.", "method", "route", "status")
	registry.Histogram("jolt_control_http_request_duration_seconds",
		"Control Tower request latency in seconds.", nil, "route")
	registry.Counter("jolt_control_login_failures_total", "Rejected login attempts.")
	registry.Counter("jolt_control_login_lockouts_total", "Logins refused because the key was locked.")
	registry.Counter("jolt_control_logins_total", "Accepted logins.")
	registry.Counter("jolt_control_authorization_denied_total",
		"Authorization decisions that denied a request.", "capability")
	registry.Counter("jolt_control_node_proxy_total",
		"Proxied node calls by node and outcome.", "node_id", "result")
	registry.Counter("jolt_control_shares_created_total", "Public share links created.")
	registry.Counter("jolt_control_shares_revoked_total", "Public share links revoked.")
	registry.Counter("jolt_control_share_downloads_total", "Downloads served through share links.")
	registry.Counter("jolt_control_share_unlock_failures_total", "Wrong passwords on share links.")
	registry.GaugeFunc("jolt_control_info",
		"Always 1; present so a scrape confirms the Control Tower is up.",
		func() float64 { return 1 })
	registry.RegisterRuntime()
}

// instrument records request counts and latency. The route label is the matched
// pattern rather than the raw path, so a mount with thousands of files cannot
// explode Prometheus cardinality.
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.registry == nil {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			route := routeLabel(r)
			s.registry.Inc("jolt_control_http_requests_total", r.Method, route,
				strconv.Itoa(recorder.status))
			s.registry.ObserveDuration("jolt_control_http_request_duration_seconds", start, route)
		}()
		next.ServeHTTP(recorder, r)
	})
}

// routeLabel reduces a request to a bounded set of label values. A public share
// token must never become a label: it is a credential and the cardinality is
// unbounded.
func routeLabel(r *http.Request) string {
	pattern := r.Pattern
	if pattern == "" {
		return "unmatched"
	}
	if _, path, found := strings.Cut(pattern, " "); found {
		pattern = path
	}
	return pattern
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if !w.wrote {
		w.status, w.wrote = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(data []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(data)
}

// Flush keeps SSE streaming working through the recorder.
func (w *statusRecorder) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// metricsHandler serves the Prometheus exposition behind its own bearer token,
// so a scraper never needs an operator session.
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) ||
		!secureCompare(strings.TrimPrefix(header, prefix), s.config.MetricsToken) {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Token de métricas inválido.")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.registry.Write(w); err != nil {
		s.log.Error("write metrics", "error", err)
	}
}

// secureCompare compares two secrets without leaking their relationship
// through timing. An empty configured token never matches.
func secureCompare(received, expected string) bool {
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(received), []byte(expected)) == 1
}
