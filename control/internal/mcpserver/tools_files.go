package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Toolsets group the tools so a deployment offers only what its agents need.
const (
	ToolsetFiles      = "files"
	ToolsetInspect    = "inspect"
	ToolsetFilesWrite = "files_write"
	ToolsetJobs       = "jobs"
	ToolsetAdmin      = "admin"
)

// Toolsets lists every toolset name.
var Toolsets = []string{ToolsetFiles, ToolsetInspect, ToolsetFilesWrite, ToolsetJobs, ToolsetAdmin}

// DefaultHTTPToolsets is what `jolt-mcp serve` offers unless told otherwise.
// Admin stays opt-in: it manages identities and policies.
var DefaultHTTPToolsets = []string{ToolsetFiles, ToolsetInspect, ToolsetFilesWrite, ToolsetJobs}

type fileArgs struct {
	NodeID  string `json:"node_id"`
	MountID string `json:"mount_id"`
	Path    string `json:"path"`
}

type listArgs struct {
	fileArgs
	After string `json:"after,omitempty" jsonschema:"next_after of the previous page"`
}

type searchArgs struct {
	fileArgs
	Query string `json:"query" jsonschema:"text in entry names"`
}

type writeTextArgs struct {
	fileArgs
	Content   string `json:"content"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

func (s *Server) fileTools() []catalogEntry {
	tool := func(name, description string, kind toolKind) *mcp.Tool {
		return &mcp.Tool{Name: name, Description: description, Annotations: kind.annotations()}
	}
	return []catalogEntry{
		{ToolsetFiles, kindRead, func(server *mcp.Server) {
			mcp.AddTool(server, tool("list", "List a directory, 200 entries per page.", kindRead), s.list)
		}},
		{ToolsetFiles, kindRead, func(server *mcp.Server) {
			mcp.AddTool(server, tool("search", "Search entry names under a directory.", kindRead), s.search)
		}},
		{ToolsetFiles, kindRead, func(server *mcp.Server) {
			mcp.AddTool(server, tool("disk_usage", "Disk usage under a directory.", kindRead), s.diskUsage)
		}},
		{ToolsetFiles, kindRead, func(server *mcp.Server) {
			mcp.AddTool(server, tool("read_text", "Read a UTF-8 text file, up to 1 MiB.", kindRead), s.readText)
		}},
		{ToolsetFilesWrite, kindWrite, func(server *mcp.Server) {
			mcp.AddTool(server, tool("write_text", "Write a UTF-8 text file, up to 1 MiB; an existing file needs overwrite.", kindWrite), s.writeText)
		}},
	}
}

func (s *Server) list(ctx context.Context, req *mcp.CallToolRequest, args listArgs) (*mcp.CallToolResult, any, error) {
	query := url.Values{"limit": {"200"}}
	if args.After != "" {
		query.Set("after", args.After)
	}
	return s.files(ctx, req, args.fileArgs, "", query, false)
}

func (s *Server) search(ctx context.Context, req *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Query) == "" || len(args.Query) > 1024 {
		return nil, nil, errors.New("invalid search query")
	}
	return s.files(ctx, req, args.fileArgs, "/search", url.Values{"query": {args.Query}, "limit": {"200"}}, false)
}

func (s *Server) diskUsage(ctx context.Context, req *mcp.CallToolRequest, args fileArgs) (*mcp.CallToolResult, any, error) {
	return s.files(ctx, req, args, "/disk-usage", url.Values{}, false)
}

func (s *Server) readText(ctx context.Context, req *mcp.CallToolRequest, args fileArgs) (*mcp.CallToolResult, any, error) {
	if args.Path == "" || args.Path == "." {
		return nil, nil, errors.New("a file path is required")
	}
	return s.files(ctx, req, args, "/content", url.Values{}, true)
}

func (s *Server) writeText(ctx context.Context, req *mcp.CallToolRequest, args writeTextArgs) (*mcp.CallToolResult, any, error) {
	if args.Path == "" || args.Path == "." {
		return nil, nil, errors.New("a file path is required")
	}
	if len(args.Content) > maxTextBytes || !utf8.ValidString(args.Content) {
		return nil, nil, errors.New("content must be UTF-8 text up to 1 MiB")
	}
	if !identifier(args.NodeID) || !identifier(args.MountID) || !relativePath(args.Path) {
		return nil, nil, errors.New("invalid node, mount or path")
	}
	query := url.Values{"path": {args.Path}, "overwrite": {strconv.FormatBool(args.Overwrite)}}
	return s.run(ctx, req, request{
		method: http.MethodPut, path: mountFiles(args.NodeID, args.MountID) + "/content", query: query,
		raw: []byte(args.Content), contentType: "application/octet-stream",
	})
}

func (s *Server) files(ctx context.Context, req *mcp.CallToolRequest, args fileArgs, suffix string, query url.Values, text bool) (*mcp.CallToolResult, any, error) {
	if !identifier(args.NodeID) || !identifier(args.MountID) || !relativePath(args.Path) {
		return nil, nil, errors.New("invalid node, mount or path")
	}
	query.Set("path", args.Path)
	return s.run(ctx, req, request{path: mountFiles(args.NodeID, args.MountID) + suffix, query: query, text: text})
}

// mountFiles is the files route of a mount. Both IDs must already be checked
// with identifier.
func mountFiles(nodeID, mountID string) string {
	return "/api/v1/nodes/" + url.PathEscape(nodeID) + "/mounts/" + url.PathEscape(mountID) + "/files"
}
