package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxRequestBytes bounds one MCP request: write_text carries up to 1 MiB of
// text, which JSON escaping can grow.
const maxRequestBytes = 8 << 20

// credentialKey holds the caller's bearer token in TokenInfo.Extra.
const credentialKey = "jolt_credential"

// HTTPOptions configures the HTTP transport.
type HTTPOptions struct {
	// AllowedOrigins are browser origins allowed to call the server, such as
	// https://agents.example.com. They get CORS preflight answers and headers;
	// requests from other origins are refused; requests without an Origin
	// header (non-browser clients) are accepted.
	AllowedOrigins []string
}

// Handler serves MCP over Streamable HTTP at /mcp and a liveness probe at
// /health. Each request must carry its own bearer token, which is passed to
// the Control Tower as is: the server holds no credential of its own.
func (s *Server) Handler(options HTTPOptions) (http.Handler, error) {
	if !s.fromRequest {
		return nil, fmt.Errorf("the HTTP transport needs WithRequestCredential")
	}
	protection := http.NewCrossOriginProtection()
	for _, origin := range options.AllowedOrigins {
		if err := protection.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("invalid allowed origin %q", origin)
		}
	}
	server := s.MCP()
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,
		MaxRequestBodyBytes: maxRequestBytes,
	})
	bearer := auth.RequireBearerToken(verifyBearer, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})
	mux := http.NewServeMux()
	mux.Handle("/mcp", rejectForeignOrigins(options.AllowedOrigins, allowCORS(protection.Handler(bearer(streamable)))))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	return mux, nil
}

// rejectForeignOrigins refuses every browser origin not allowed, including
// same-site ones, so a page cannot drive the server with a token it holds.
// CrossOriginProtection alone lets same-origin requests through.
func rejectForeignOrigins(allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !originAllowed(allowed, origin) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allowCORS lets an allowed browser origin use the server: it answers the
// preflight itself, since the browser sends it without the Authorization
// header the bearer check needs, and marks the responses readable by that
// origin. It runs after rejectForeignOrigins, so any Origin here is allowed.
func allowCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		header := w.Header()
		header.Add("Vary", "Origin")
		header.Set("Access-Control-Allow-Origin", origin)
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			header.Add("Vary", "Access-Control-Request-Method")
			header.Add("Vary", "Access-Control-Request-Headers")
			header.Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
			header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID")
			header.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		header.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		next.ServeHTTP(w, r)
	})
}

func originAllowed(allowed []string, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, candidate := range allowed {
		want, err := url.Parse(candidate)
		if err == nil && strings.EqualFold(want.Scheme, parsed.Scheme) && strings.EqualFold(want.Host, parsed.Host) {
			return true
		}
	}
	return false
}

// verifyBearer checks only the token's shape: the Control Tower authenticates
// it on every call. The subject is a hash, so logs never carry the token.
func verifyBearer(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if !validCredential(token) {
		return nil, auth.ErrInvalidToken
	}
	sum := sha256.Sum256([]byte(token))
	return &auth.TokenInfo{UserID: "sha256:" + hex.EncodeToString(sum[:8]), Extra: map[string]any{credentialKey: token}}, nil
}
