// Package mcpserver exposes the read-only Control Tower API over MCP.
package mcpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
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

type fileArgs struct {
	NodeID  string `json:"node_id" jsonschema:"Registered node ID"`
	MountID string `json:"mount_id" jsonschema:"Mount ID"`
	Path    string `json:"path" jsonschema:"Mount-relative path; empty means the mount root"`
}

type listArgs struct {
	fileArgs
	After string `json:"after,omitempty" jsonschema:"Opaque cursor from the previous page"`
}

type searchArgs struct {
	fileArgs
	Query string `json:"query" jsonschema:"Text to search for in entry names"`
}

// New refuses credentials in URLs and plaintext connections outside loopback.
// Credentials are read from the file for every request to support rotation.
func New(rawURL, credentialFile string, options ...Option) (*Server, error) {
	base, err := url.Parse(rawURL)
	if err != nil || base == nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || credentialFile == "" {
		return nil, errors.New("invalid Control Tower URL or credential file")
	}
	host := base.Hostname()
	ip := net.ParseIP(host)
	if base.Scheme != "https" && !(base.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("Control Tower must use HTTPS outside loopback")
	}
	server := &Server{base: base, credentialFile: credentialFile, client: newClient(nil)}
	for _, option := range options {
		option(server)
	}
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

func (s *Server) MCP() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "jolt-mcp", Version: "1.0.0"}, nil)
	tool := func(name, description string) *mcp.Tool {
		return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
	}
	mcp.AddTool(server, tool("list", "List entries in a mount-relative directory."), s.list)
	mcp.AddTool(server, tool("search", "Search entry names within a mount-relative directory."), s.search)
	mcp.AddTool(server, tool("disk_usage", "Report disk usage within a mount-relative directory."), s.diskUsage)
	mcp.AddTool(server, tool("read_text", "Read a UTF-8 text file, up to 1 MiB."), s.readText)
	return server
}

func (s *Server) list(ctx context.Context, _ *mcp.CallToolRequest, args listArgs) (*mcp.CallToolResult, any, error) {
	query := url.Values{"limit": {"200"}}
	if args.After != "" {
		query.Set("after", args.After)
	}
	return s.run(ctx, args.fileArgs, "", query, false)
}

func (s *Server) search(ctx context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Query) == "" || len(args.Query) > 1024 {
		return nil, nil, errors.New("invalid search query")
	}
	return s.run(ctx, args.fileArgs, "/search", url.Values{"query": {args.Query}, "limit": {"200"}}, false)
}

func (s *Server) diskUsage(ctx context.Context, _ *mcp.CallToolRequest, args fileArgs) (*mcp.CallToolResult, any, error) {
	return s.run(ctx, args, "/disk-usage", url.Values{}, false)
}

func (s *Server) readText(ctx context.Context, _ *mcp.CallToolRequest, args fileArgs) (*mcp.CallToolResult, any, error) {
	if args.Path == "" || args.Path == "." {
		return nil, nil, errors.New("a file path is required")
	}
	return s.run(ctx, args, "/content", url.Values{}, true)
}

func (s *Server) run(ctx context.Context, args fileArgs, suffix string, query url.Values, textOnly bool) (*mcp.CallToolResult, any, error) {
	if !identifier(args.NodeID) || !identifier(args.MountID) || !relativePath(args.Path) {
		return nil, nil, errors.New("invalid node, mount or path")
	}
	credential, err := readCredential(s.credentialFile)
	if err != nil {
		return nil, nil, errors.New("credential file unavailable or invalid")
	}
	query.Set("path", args.Path)
	target := *s.base
	target.Path = "/api/v1/nodes/" + args.NodeID + "/mounts/" + args.MountID + "/files" + suffix
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, nil, errors.New("could not create Control Tower request")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	client, err := s.httpClient()
	if err != nil {
		return nil, nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.New("Control Tower request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("Control Tower returned HTTP %d", response.StatusCode)
	}
	limit := int64(maxResponseBytes)
	if textOnly {
		limit = maxTextBytes
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, nil, errors.New("response unavailable or exceeds the MCP limit")
	}
	if bytes.Contains(body, []byte(credential)) {
		return nil, nil, errors.New("response contains the configured credential")
	}
	if textOnly {
		if !utf8.Valid(body) || bytes.IndexFunc(body, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f }) >= 0 {
			return nil, nil, errors.New("file is not UTF-8 text")
		}
	} else if !json.Valid(body) {
		return nil, nil, errors.New("invalid Control Tower response")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
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
	if value == "" {
		return "", errors.New("invalid credential")
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/=", c)) {
			return "", errors.New("invalid credential")
		}
	}
	return value, nil
}
