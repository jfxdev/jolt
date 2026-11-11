package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	controlAPI = "/api/v1/control-tower"
	nodeAPI    = "/api/v1/nodes/{node_id}"
	mountAPI   = nodeAPI + "/mounts/{mount_id}"
)

func inspectRoutes() []routeTool {
	read := func(name, description, route string, params ...param) routeTool {
		return routeTool{toolset: ToolsetInspect, name: name, description: description, kind: kindRead, method: http.MethodGet, path: route, params: params}
	}
	mountPath := param{name: "path", typ: typePath, in: inQuery, required: true}
	integer := func(name string) param { return param{name: name, typ: typeInteger, in: inQuery} }
	text := func(name string) param { return param{name: name, typ: typeString, in: inQuery} }
	return []routeTool{
		read("whoami", "This credential's identity.", controlAPI+"/auth/me"),
		read("about", "Control Tower version and features.", controlAPI+"/about"),
		{toolset: ToolsetInspect, name: "check_permissions", kind: kindRead, method: http.MethodPost, path: controlAPI + "/auth/permissions",
			description: "This credential's capabilities on up to 100 Node Paths (nodes/{node_id}/files/mounts/{mount_id}/{path}).",
			params:      []param{{name: "paths", typ: typeStrings, in: inBody, required: true}}},
		{toolset: ToolsetInspect, name: "effective_access", kind: kindRead, method: http.MethodPost, path: controlAPI + "/subjects/{actor_type}/{subject_id}/effective-access",
			description: "What another identity can do at Node Paths, with the deciding rules. Admin only.",
			params: []param{
				{name: "actor_type", typ: typeString, in: inPath, required: true, enum: []string{"user", "service_account"}},
				pathID("subject_id"),
				{name: "checks", typ: typeArray, in: inBody, required: true, description: "[{path,entry_type:file|directory}], up to 50"},
			}},
		read("list_nodes", "Registered nodes.", controlAPI+"/nodes"),
		read("node_info", "What a node reports: version, health, capabilities.", nodeAPI+"/node", nodeParam),
		read("node_trust", "A node's certificates and trust state.", controlAPI+"/nodes/{node_id}/trust", nodeParam),
		read("list_mounts", "", nodeAPI+"/mounts", nodeParam),
		read("get_mount", "", mountAPI, nodeParam, mountParam),
		read("stat", "Metadata of a file or directory.", mountAPI+"/files/metadata", nodeParam, mountParam, mountPath),
		read("archive_plan", "Size of a directory archive before downloading.", mountAPI+"/files/archive/plan", nodeParam, mountParam, mountPath),
		read("list_jobs", "Recent jobs, newest first.", nodeAPI+"/jobs", nodeParam, integer("limit")),
		read("job_summary", "Job counts by state.", nodeAPI+"/jobs/summary", nodeParam),
		read("get_job", "", nodeAPI+"/jobs/{job_id}", nodeParam, jobParam),
		read("list_job_items", "Per-file items of a job, to find which failed.", nodeAPI+"/jobs/{job_id}/items", nodeParam, jobParam, integer("after")),
		read("list_trash", "", mountAPI+"/trash", nodeParam, mountParam),
		read("get_trash_item", "", mountAPI+"/trash/{trash_id}", nodeParam, mountParam, pathID("trash_id")),
		read("list_peers", "", nodeAPI+"/peers", nodeParam),
		read("list_grants", "Grants a node offers its peers.", nodeAPI+"/grants", nodeParam),
		read("list_connections", "Connection requests between nodes.", controlAPI+"/connections"),
		read("list_pending_operations", "Operations waiting for approval.", controlAPI+"/pending-operations",
			text("state"), param{name: "mine", typ: typeBoolean, in: inQuery}),
		read("get_pending_operation", "", controlAPI+"/pending-operations/{operation_id}", pathID("operation_id")),
		read("search_audit", "Audit log, newest first; page with next_before_id.", controlAPI+"/audit",
			integer("limit"), integer("before_id"), text("actor_type"), text("action"), text("result"), text("correlation_id")),
		read("list_certificates", "Certificate authorities.", controlAPI+"/crypto/ca"),
		read("get_trust_bundle", "", controlAPI+"/crypto/trust-bundle"),
		read("list_revocations", "", controlAPI+"/crypto/revocations"),
	}
}

type nodeArgs struct {
	NodeID string `json:"node_id"`
}

func (s *Server) diagnosticTools() []catalogEntry {
	tool := func(name, description string) *mcp.Tool {
		return &mcp.Tool{Name: name, Description: description, Annotations: kindRead.annotations()}
	}
	return []catalogEntry{
		{ToolsetInspect, kindRead, func(server *mcp.Server) {
			mcp.AddTool(server, tool("diagnose_node", "One-call node check: node_info, node_trust, job_summary and list_mounts, each with its own error."), s.diagnoseNode)
		}},
		{ToolsetInspect, kindRead, func(server *mcp.Server) {
			mcp.AddTool(server, tool("diagnose_path", "Why access to a path fails: its metadata and this credential's capabilities on it and each parent."), s.diagnosePath)
		}},
	}
}

// section is one part of a diagnosis: the data, or why it is missing.
type section struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error any             `json:"error,omitempty"`
}

func (s *Server) section(ctx context.Context, req *mcp.CallToolRequest, r request) section {
	data, _, err := s.call(ctx, req, r)
	if err != nil {
		var refused *controlError
		if errors.As(err, &refused) {
			return section{Error: refused}
		}
		return section{Error: err.Error()}
	}
	return section{Data: data}
}

func (s *Server) diagnoseNode(ctx context.Context, req *mcp.CallToolRequest, args nodeArgs) (*mcp.CallToolResult, any, error) {
	if !identifier(args.NodeID) {
		return nil, nil, errors.New("invalid node")
	}
	node := "/api/v1/nodes/" + url.PathEscape(args.NodeID)
	parts := map[string]string{
		"node":        node + "/node",
		"trust":       controlAPI + "/nodes/" + url.PathEscape(args.NodeID) + "/trust",
		"job_summary": node + "/jobs/summary",
		"mounts":      node + "/mounts",
	}
	report := map[string]section{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, route := range parts {
		wg.Go(func() {
			part := s.section(ctx, req, request{path: route})
			mu.Lock()
			report[name] = part
			mu.Unlock()
		})
	}
	wg.Wait()
	return marshalResult(map[string]any{"node_id": args.NodeID, "sections": report})
}

func (s *Server) diagnosePath(ctx context.Context, req *mcp.CallToolRequest, args fileArgs) (*mcp.CallToolResult, any, error) {
	if !identifier(args.NodeID) || !identifier(args.MountID) || !relativePath(args.Path) {
		return nil, nil, errors.New("invalid node, mount or path")
	}
	base := "nodes/" + args.NodeID + "/files/mounts/" + args.MountID
	paths := []string{base}
	if args.Path != "" {
		segments := strings.Split(args.Path, "/")
		for i := range segments {
			paths = append(paths, base+"/"+path.Join(segments[:i+1]...))
		}
	}
	metadata := s.section(ctx, req, request{path: mountFiles(args.NodeID, args.MountID) + "/metadata", query: url.Values{"path": {args.Path}}})
	permissions := s.section(ctx, req, request{method: http.MethodPost, path: controlAPI + "/auth/permissions", body: map[string]any{"paths": paths}})
	return marshalResult(map[string]any{
		"node_path":   paths[len(paths)-1],
		"metadata":    metadata,
		"permissions": permissions,
		"hint":        "A path missing a capability that a parent has is narrowed by a deny or typed rule; ask an administrator to run effective_access for the rule.",
	})
}

func marshalResult(value any) (*mcp.CallToolResult, any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, nil, errors.New("could not encode the result")
	}
	if len(data) > maxResponseBytes {
		return nil, nil, errors.New("response exceeds the MCP limit")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil, nil
}
