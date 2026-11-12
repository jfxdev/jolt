// Package mcpserver exposes the Control Tower API over MCP.
package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxCredentialBytes = 8192
const maxResponseBytes = 2 << 20
const maxTextBytes = 1 << 20

type Server struct {
	base           *url.URL
	credentialFile string
	client         *http.Client

	// caFile, when set, is the only source of trust for the Control Tower's
	// certificate. The client is rebuilt when the file changes, so a root
	// stored by `jolt-mcp trust` applies without restarting the server.
	caFile  string
	mu      sync.Mutex
	stamp   fileStamp
	trusted *http.Client

	// fromRequest takes the credential from the bearer token of each HTTP
	// request instead of the file, so every client acts as itself.
	fromRequest bool
	insecure    bool
	toolsets    map[string]bool
	readOnly    bool
	logger      *slog.Logger
}

// fileStamp tells a rewritten file from the one already loaded. `trust`
// replaces the file by rename, so the identity changes even if size and time
// do not.
type fileStamp struct {
	info os.FileInfo
}

func (f fileStamp) same(other fileStamp) bool {
	return f.info != nil && other.info != nil && os.SameFile(f.info, other.info) && f.info.ModTime().Equal(other.info.ModTime()) && f.info.Size() == other.info.Size()
}

// Option changes how the server reaches the Control Tower.
type Option func(*Server)

// WithCAFile makes the server trust only the roots stored in filename.
func WithCAFile(filename string) Option { return func(s *Server) { s.caFile = filename } }

// WithRequestCredential makes every tool call use the bearer token of the HTTP
// request that carried it. No credential file is read.
func WithRequestCredential() Option { return func(s *Server) { s.fromRequest = true } }

// WithInsecureControlURL accepts a plain HTTP Control Tower outside loopback,
// for a private container network where TLS ends elsewhere.
func WithInsecureControlURL() Option { return func(s *Server) { s.insecure = true } }

// WithToolsets offers only the tools of the named toolsets.
func WithToolsets(names ...string) Option {
	return func(s *Server) {
		s.toolsets = map[string]bool{}
		for _, name := range names {
			s.toolsets[name] = true
		}
	}
}

// WithReadOnly drops every tool that can change state, whatever its toolset.
func WithReadOnly() Option { return func(s *Server) { s.readOnly = true } }

// WithLogger logs one line per tool call. The credential is never logged.
func WithLogger(logger *slog.Logger) Option { return func(s *Server) { s.logger = logger } }

// New refuses credentials in URLs and plaintext connections outside loopback.
// Credentials are read from the file for every request to support rotation.
func New(rawURL, credentialFile string, options ...Option) (*Server, error) {
	server := &Server{credentialFile: credentialFile, client: newClient(nil), toolsets: map[string]bool{ToolsetFiles: true}}
	for _, option := range options {
		option(server)
	}
	base, err := url.Parse(rawURL)
	if err != nil || base == nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || credentialFile == "" && !server.fromRequest {
		return nil, errors.New("invalid Control Tower URL or credential file")
	}
	host := base.Hostname()
	ip := net.ParseIP(host)
	if base.Scheme != "https" && !(base.Scheme == "http" && (server.insecure || strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("Control Tower must use HTTPS outside loopback")
	}
	for name := range server.toolsets {
		if !slices.Contains(Toolsets, name) {
			return nil, fmt.Errorf("unknown toolset %q", name)
		}
	}
	server.base = base
	return server, nil
}

func newClient(roots *x509.CertPool) *http.Client {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if roots != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		client.Transport = transport
	}
	return client
}

// httpClient returns the client for the next request. Without a CA file it is
// the system's trust; with one, only the roots in it.
func (s *Server) httpClient() (*http.Client, error) {
	if s.caFile == "" {
		return s.client, nil
	}
	info, err := os.Stat(s.caFile)
	if err != nil {
		return nil, errors.New("CA file unavailable: run jolt-mcp trust")
	}
	stamp := fileStamp{info}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trusted != nil && s.stamp.same(stamp) {
		return s.trusted, nil
	}
	loaded, err := LoadRoots(s.caFile)
	if err != nil {
		return nil, errors.New("CA file invalid: run jolt-mcp trust")
	}
	pool := x509.NewCertPool()
	for _, root := range loaded {
		pool.AddCert(root)
	}
	if s.trusted != nil {
		s.trusted.CloseIdleConnections()
	}
	s.trusted, s.stamp = newClient(pool), stamp
	return s.trusted, nil
}

// MCP builds the MCP server with the tools of the configured toolsets.
func (s *Server) MCP() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "jolt-mcp", Version: "1.1.0"}, &mcp.ServerOptions{Instructions: s.instructions()})
	if s.logger != nil {
		server.AddReceivingMiddleware(s.logCalls)
	}
	for _, tool := range s.catalog() {
		if !s.toolsets[tool.toolset] || s.readOnly && tool.kind != kindRead {
			continue
		}
		tool.register(server)
	}
	return server
}

// toolKind sets a tool's annotations and whether a read-only server offers it.
// kindWrite is for additive changes only: a tool that can replace or remove
// existing data is kindDestructive, so clients warn before calling it.
type toolKind int

const (
	kindRead toolKind = iota
	kindWrite
	kindDestructive
)

// annotations leaves destructive tools without any: the MCP defaults already
// say a tool may destroy and is not read-only, and the bytes are paid by every
// agent that lists the tools.
func (k toolKind) annotations() *mcp.ToolAnnotations {
	switch k {
	case kindRead:
		return &mcp.ToolAnnotations{ReadOnlyHint: true}
	case kindWrite:
		return &mcp.ToolAnnotations{DestructiveHint: new(false)}
	default:
		return nil
	}
}

// catalogEntry is one tool and the toolset that offers it.
type catalogEntry struct {
	toolset  string
	kind     toolKind
	register func(*mcp.Server)
}

func (s *Server) catalog() []catalogEntry {
	entries := s.fileTools()
	entries = append(entries, s.diagnosticTools()...)
	for _, route := range routeTools() {
		entries = append(entries, catalogEntry{toolset: route.toolset, kind: route.kind, register: func(server *mcp.Server) { s.addRoute(server, route) }})
	}
	for _, group := range groupTools() {
		actions := group.offered(s.readOnly)
		if len(actions) == 0 {
			continue
		}
		entries = append(entries, catalogEntry{toolset: group.toolset, kind: groupKind(actions), register: func(server *mcp.Server) { s.addGroup(server, group, actions) }})
	}
	return entries
}

// instructions hold what every tool shares, sent once at initialization
// instead of in each tool's schema.
func (s *Server) instructions() string {
	lines := []string{
		"Jolt files through its Control Tower, which enforces permissions, approvals and audit on every call.",
		"IDs (node_id, mount_id, job_id...) come from list tools. path arguments are relative to the mount: \"\" is its root, no leading / or \"..\"; reuse paths the server returns.",
		"A refused call reports HTTP status, code, message and correlation_id; search_audit with the correlation_id shows the decision.",
	}
	if !s.readOnly && (s.toolsets[ToolsetFilesWrite] || s.toolsets[ToolsetJobs] || s.toolsets[ToolsetAdmin]) {
		lines = append(lines,
			"Changes run as jobs: follow the returned job with get_job. A result with state pending_approval waits for a person: follow it with get_pending_operation.",
			"Changing tools accept idempotency_key: reuse it when retrying the same call so it applies once.",
		)
	}
	return strings.Join(lines, "\n")
}

// request is one call to the Control Tower API.
type request struct {
	method string
	// path is already escaped.
	path  string
	query url.Values
	// body is sent as JSON when set; raw is sent as is.
	body        any
	raw         []byte
	contentType string
	// text expects a UTF-8 text response instead of JSON.
	text           bool
	idempotencyKey string
}

// controlError is a refusal from the Control Tower, kept whole so the agent
// can tell a missing permission from a missing file.
type controlError struct {
	Status        int    `json:"status"`
	Code          string `json:"code,omitempty"`
	Message       string `json:"message,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

func (e *controlError) Error() string {
	text := fmt.Sprintf("Control Tower returned HTTP %d", e.Status)
	if e.Code != "" {
		text += " " + e.Code
	}
	if e.Message != "" {
		text += ": " + e.Message
	}
	if e.CorrelationID != "" {
		text += " (correlation_id " + e.CorrelationID + ")"
	}
	return text
}

// credential is the bearer token for this call: the HTTP request's own token,
// or the file's content, read again for every call to support rotation.
func (s *Server) credential(req *mcp.CallToolRequest) (string, error) {
	if !s.fromRequest {
		value, err := readCredential(s.credentialFile)
		if err != nil {
			return "", errors.New("credential file unavailable or invalid")
		}
		return value, nil
	}
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return "", errors.New("bearer token required")
	}
	value, _ := req.Extra.TokenInfo.Extra[credentialKey].(string)
	if !validCredential(value) {
		return "", errors.New("bearer token required")
	}
	return value, nil
}

// call sends one request and returns the body, checked against the limits.
func (s *Server) call(ctx context.Context, req *mcp.CallToolRequest, r request) ([]byte, int, error) {
	credential, err := s.credential(req)
	if err != nil {
		return nil, 0, err
	}
	target := *s.base
	target.Path, target.RawPath = "", ""
	parsed, err := url.Parse(r.path)
	if err != nil {
		return nil, 0, errors.New("could not create Control Tower request")
	}
	target.Path, target.RawPath = parsed.Path, parsed.RawPath
	if r.query != nil {
		target.RawQuery = r.query.Encode()
	}
	var body io.Reader
	contentType := r.contentType
	switch {
	case r.raw != nil:
		body = bytes.NewReader(r.raw)
	case r.body != nil:
		encoded, err := json.Marshal(r.body)
		if err != nil {
			return nil, 0, errors.New("could not encode the request body")
		}
		body, contentType = bytes.NewReader(encoded), "application/json"
	}
	method := r.method
	if method == "" {
		method = http.MethodGet
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, 0, errors.New("could not create Control Tower request")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+credential)
	httpRequest.Header.Set("X-Correlation-ID", randomHex("mcp_", 12))
	if contentType != "" {
		httpRequest.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet {
		key := r.idempotencyKey
		if key == "" {
			key = randomHex("", 16)
		}
		httpRequest.Header.Set("Idempotency-Key", key)
	}
	client, err := s.httpClient()
	if err != nil {
		return nil, 0, err
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, 0, errors.New("Control Tower request failed")
	}
	defer response.Body.Close()
	limit := int64(maxResponseBytes)
	if r.text && response.StatusCode == http.StatusOK {
		limit = maxTextBytes
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, 0, errors.New("response unavailable or exceeds the MCP limit")
	}
	if bytes.Contains(data, []byte(credential)) {
		return nil, 0, errors.New("response contains the configured credential")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, 0, refusal(response, data)
	}
	if response.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(data)) == 0 {
		if r.text {
			return []byte{}, response.StatusCode, nil
		}
		return []byte(`{"ok":true}`), response.StatusCode, nil
	}
	if r.text {
		if !utf8.Valid(data) || bytes.IndexFunc(data, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f }) >= 0 {
			return nil, 0, errors.New("file is not UTF-8 text")
		}
	} else if !json.Valid(data) {
		return nil, 0, errors.New("invalid Control Tower response")
	}
	return data, response.StatusCode, nil
}

// refusal keeps the code and message of the Control Tower's error body.
func refusal(response *http.Response, data []byte) error {
	failure := &controlError{Status: response.StatusCode, CorrelationID: response.Header.Get("X-Correlation-ID")}
	var payload struct {
		Error struct {
			Code          string `json:"code"`
			Message       string `json:"message"`
			CorrelationID string `json:"correlation_id"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &payload) == nil {
		failure.Code = clip(payload.Error.Code, 128)
		failure.Message = clip(payload.Error.Message, 512)
		if payload.Error.CorrelationID != "" {
			failure.CorrelationID = clip(payload.Error.CorrelationID, 128)
		}
	}
	return failure
}

func clip(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// run calls the Control Tower and wraps the body as the tool result.
func (s *Server) run(ctx context.Context, req *mcp.CallToolRequest, r request) (*mcp.CallToolResult, any, error) {
	data, status, err := s.call(ctx, req, r)
	if err != nil {
		return nil, nil, err
	}
	return result(data, status), nil, nil
}

func result(data []byte, status int) *mcp.CallToolResult {
	content := []mcp.Content{&mcp.TextContent{Text: string(data)}}
	if status == http.StatusAccepted && bytes.Contains(data, []byte(`"pending_approval"`)) {
		content = append(content, &mcp.TextContent{Text: "The operation waits for a person to approve it. Follow it with get_pending_operation using pending_operation_id."})
	}
	return &mcp.CallToolResult{Content: content}
}

func randomHex(prefix string, size int) string {
	value := make([]byte, size)
	_, _ = rand.Read(value)
	return prefix + hex.EncodeToString(value)
}

// logCalls logs each tool call with its outcome and duration.
func (s *Server) logCalls(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		call, ok := req.(*mcp.CallToolRequest)
		if !ok {
			return next(ctx, method, req)
		}
		started := time.Now()
		res, err := next(ctx, method, req)
		attrs := []any{"tool", call.Params.Name, "duration_ms", time.Since(started).Milliseconds()}
		if extra := call.GetExtra(); extra != nil && extra.TokenInfo != nil {
			attrs = append(attrs, "subject", extra.TokenInfo.UserID)
		}
		outcome := "ok"
		if err != nil {
			outcome = "error"
		} else if toolResult, ok := res.(*mcp.CallToolResult); ok && toolResult.IsError {
			outcome = "tool_error"
		}
		s.logger.Info("tool call", append(attrs, "outcome", outcome)...)
		return res, err
	}
}

func identifier(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 255 {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e || strings.ContainsRune("/\\?#%", c) {
			return false
		}
	}
	return true
}

func relativePath(value string) bool {
	return len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsAny(value, "\\\x00") && !strings.HasPrefix(value, "/") && (value == "" || path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../"))
}

func readCredential(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil || len(data) > maxCredentialBytes {
		return "", errors.New("invalid credential")
	}
	value := strings.TrimSpace(string(data))
	if !validCredential(value) {
		return "", errors.New("invalid credential")
	}
	return value, nil
}

// validCredential accepts one bearer token: base64url, JWT or opaque text.
func validCredential(value string) bool {
	if value == "" || len(value) > maxCredentialBytes {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/=", c)) {
			return false
		}
	}
	return true
}
