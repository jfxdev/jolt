package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// captured is one request the fake Control Tower received.
type captured struct {
	Method, Path, Query, Body, Idempotency, ContentType string
}

type fakeControl struct {
	*httptest.Server
	mu       sync.Mutex
	requests []captured
	respond  func(w http.ResponseWriter, r *http.Request) bool
}

func newFakeControl(t *testing.T) *fakeControl {
	fake := &fakeControl{}
	fake.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		fake.mu.Lock()
		fake.requests = append(fake.requests, captured{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(data), r.Header.Get("Idempotency-Key"), r.Header.Get("Content-Type")})
		respond := fake.respond
		fake.mu.Unlock()
		if respond != nil && respond(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	t.Cleanup(fake.Close)
	return fake
}

func (f *fakeControl) take() []captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := f.requests
	f.requests = nil
	return requests
}

func connect(t *testing.T, server *Server) *mcp.ClientSession {
	t.Helper()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := server.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func credentialFile(t *testing.T, value string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(file, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func toolNames(t *testing.T, session *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tool := range listed.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

func TestToolsetsReadOnlyAndAnnotations(t *testing.T) {
	fake := newFakeControl(t)
	file := credentialFile(t, "token")

	defaults, err := New(fake.URL, file)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range toolNames(t, connect(t, defaults)) {
		names = append(names, name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"disk_usage", "list", "read_text", "search"}) {
		t.Fatalf("default toolset changed: %v", names)
	}

	all, err := New(fake.URL, file, WithToolsets(Toolsets...))
	if err != nil {
		t.Fatal(err)
	}
	tools := toolNames(t, connect(t, all))
	registered := len(all.catalog())
	if len(tools) != registered {
		t.Fatalf("tool names are not unique: %d registered, %d listed", registered, len(tools))
	}
	for name, want := range map[string]string{"whoami": "read", "diagnose_node": "read", "mkdir": "write", "delete": "destructive", "purge_trash": "destructive", "control_job": "destructive", "manage_users": "destructive", "manage_policies": "destructive"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if got := kindOf(tool); got != want {
			t.Fatalf("%s is %s, want %s", name, got, want)
		}
	}

	readOnly, err := New(fake.URL, file, WithToolsets(Toolsets...), WithReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	readTools := toolNames(t, connect(t, readOnly))
	for name, tool := range readTools {
		if kindOf(tool) != "read" {
			t.Fatalf("read-only server offers %s", name)
		}
	}
	users, ok := readTools["manage_users"]
	if !ok || len(readTools) >= len(tools) {
		t.Fatalf("read-only server dropped read tools or kept writes: %d of %d", len(readTools), len(tools))
	}
	actions := users.InputSchema.(map[string]any)["properties"].(map[string]any)["action"].(map[string]any)["enum"]
	if !reflect.DeepEqual(actions, []any{"list", "list_policies", "list_roles", "list_temporary_policies"}) || strings.Contains(users.Description, "create(") {
		t.Fatalf("read-only manage_users offers %v: %s", actions, users.Description)
	}
	if _, ok := readTools["control_job"]; ok {
		t.Fatal("read-only server offers a group with no read action")
	}

	if _, err := New(fake.URL, file, WithToolsets("files", "everything")); err == nil {
		t.Fatal("unknown toolset accepted")
	}
}

func kindOf(tool *mcp.Tool) string {
	switch {
	case tool.Annotations == nil || tool.Annotations.DestructiveHint != nil && *tool.Annotations.DestructiveHint:
		return "destructive"
	case tool.Annotations.ReadOnlyHint:
		return "read"
	default:
		return "write"
	}
}

func TestRouteToolsShapeRequests(t *testing.T) {
	fake := newFakeControl(t)
	server, err := New(fake.URL, credentialFile(t, "token"), WithToolsets(Toolsets...))
	if err != nil {
		t.Fatal(err)
	}
	session := connect(t, server)
	ctx := context.Background()
	for _, tc := range []struct {
		tool string
		args map[string]any
		want captured
	}{
		{"whoami", nil, captured{Method: "GET", Path: "/api/v1/control-tower/auth/me"}},
		{"stat", map[string]any{"node_id": "n1", "mount_id": "m1", "path": "a b/c.txt"},
			captured{Method: "GET", Path: "/api/v1/nodes/n1/mounts/m1/files/metadata", Query: "path=a+b%2Fc.txt"}},
		{"list_jobs", map[string]any{"node_id": "n1", "limit": 5}, captured{Method: "GET", Path: "/api/v1/nodes/n1/jobs", Query: "limit=5"}},
		{"mkdir", map[string]any{"node_id": "n1", "mount_id": "m1", "path": "new"},
			captured{Method: "POST", Path: "/api/v1/nodes/n1/mounts/m1/files/directories", Body: `{"path":"new"}`, ContentType: "application/json"}},
		{"delete", map[string]any{"node_id": "n1", "mount_id": "m1", "path": "old", "recursive": true, "idempotency_key": "retry-1"},
			captured{Method: "DELETE", Path: "/api/v1/nodes/n1/mounts/m1/files", Query: "path=old&recursive=true", Idempotency: "retry-1"}},
		{"confirm_destructive", map[string]any{"node_id": "n1", "mount_id": "m1", "plan_id": "p1", "token": "t"},
			captured{Method: "POST", Path: "/api/v1/nodes/n1/mounts/m1/files/destructive-plans/p1/confirm", Body: `{"token":"t"}`, ContentType: "application/json"}},
		{"control_job", map[string]any{"action": "pause", "node_id": "n1", "job_id": "j1"},
			captured{Method: "POST", Path: "/api/v1/nodes/n1/jobs/j1/pause", Body: `{}`, ContentType: "application/json"}},
		{"check_permissions", map[string]any{"paths": []string{"nodes/n1"}},
			captured{Method: "POST", Path: "/api/v1/control-tower/auth/permissions", Body: `{"paths":["nodes/n1"]}`, ContentType: "application/json"}},
		{"effective_access", map[string]any{"actor_type": "service_account", "subject_id": "sa1", "checks": []any{map[string]any{"path": "nodes/n1", "entry_type": "directory"}}},
			captured{Method: "POST", Path: "/api/v1/control-tower/subjects/service_account/sa1/effective-access", Body: `{"checks":[{"entry_type":"directory","path":"nodes/n1"}]}`, ContentType: "application/json"}},
		{"manage_users", map[string]any{"action": "update", "user_id": "u1", "body": map[string]any{"enabled": false}},
			captured{Method: "PATCH", Path: "/api/v1/control-tower/users/u1", Body: `{"enabled":false}`, ContentType: "application/json"}},
		{"manage_users", map[string]any{"action": "grant_temporary_policy", "user_id": "u1", "policy_id": "p1", "duration_seconds": 60},
			captured{Method: "POST", Path: "/api/v1/control-tower/users/u1/policies/temporary", Body: `{"duration_seconds":60,"policy_id":"p1"}`, ContentType: "application/json"}},
		{"search_audit", map[string]any{"correlation_id": "cor_1", "limit": 10},
			captured{Method: "GET", Path: "/api/v1/control-tower/audit", Query: "correlation_id=cor_1&limit=10"}},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil || result.IsError {
			t.Fatalf("%s: result=%+v err=%v", tc.tool, result, err)
		}
		requests := fake.take()
		if len(requests) != 1 {
			t.Fatalf("%s: %d requests", tc.tool, len(requests))
		}
		got := requests[0]
		if tc.want.Idempotency == "" && got.Method != "GET" {
			if len(got.Idempotency) != 32 {
				t.Fatalf("%s: no generated Idempotency-Key: %q", tc.tool, got.Idempotency)
			}
			got.Idempotency = ""
		}
		if got.Method == "GET" && got.Idempotency != "" {
			t.Fatalf("%s: GET sent an Idempotency-Key", tc.tool)
		}
		if got != tc.want {
			t.Fatalf("%s:\n got %+v\nwant %+v", tc.tool, got, tc.want)
		}
	}

	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"stat", map[string]any{"node_id": "n1", "mount_id": "m1", "path": "../etc"}},
		{"stat", map[string]any{"node_id": "n1/../x", "mount_id": "m1", "path": "a"}},
		{"stat", map[string]any{"node_id": "n1", "mount_id": "m1"}},
		{"mkdir", map[string]any{"node_id": "n1", "mount_id": "m1", "path": "a", "extra": 1}},
		{"copy", map[string]any{"node_id": "n1", "mount_id": "m1", "source_path": "a", "destination_path": "b", "conflict_policy": "maybe"}},
		{"effective_access", map[string]any{"actor_type": "../users", "subject_id": "x", "checks": []any{}}},
		{"delete", map[string]any{"node_id": "n1", "mount_id": "m1", "path": "a", "idempotency_key": "bad key"}},
		{"control_job", map[string]any{"action": "explode", "node_id": "n1", "job_id": "j1"}},
		{"manage_users", map[string]any{"action": "delete"}},
		{"manage_users", map[string]any{"action": "list", "user_id": "u1"}},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err == nil && !result.IsError {
			t.Fatalf("%s accepted %v", tc.tool, tc.args)
		}
	}
	if requests := fake.take(); len(requests) != 0 {
		t.Fatalf("invalid arguments reached the Control Tower: %+v", requests)
	}
}

func TestWriteTextSendsRawContent(t *testing.T) {
	fake := newFakeControl(t)
	server, err := New(fake.URL, credentialFile(t, "token"), WithToolsets(ToolsetFilesWrite))
	if err != nil {
		t.Fatal(err)
	}
	session := connect(t, server)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "write_text", Arguments: map[string]any{
		"node_id": "n1", "mount_id": "m1", "path": "notes/a.txt", "content": "olá\n", "overwrite": true,
	}})
	if err != nil || result.IsError {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	got := fake.take()[0]
	if got.Method != "PUT" || got.Path != "/api/v1/nodes/n1/mounts/m1/files/content" || got.Query != "overwrite=true&path=notes%2Fa.txt" ||
		got.Body != "olá\n" || got.ContentType != "application/octet-stream" || got.Idempotency == "" {
		t.Fatalf("request=%+v", got)
	}
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "write_text", Arguments: map[string]any{
		"node_id": "n1", "mount_id": "m1", "path": "big.txt", "content": strings.Repeat("x", maxTextBytes+1),
	}})
	if err == nil && !result.IsError {
		t.Fatal("oversize content accepted")
	}
}

func TestResultsCarryRefusalsApprovalsAndDiagnoses(t *testing.T) {
	fake := newFakeControl(t)
	fake.respond = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/files") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"pending_operation_id":"op1","state":"pending_approval","operation":"delete"}`)
		case strings.HasSuffix(r.URL.Path, "/trust"):
			w.Header().Set("X-Correlation-ID", "cor_header")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"permission_denied","message":"A policy atual não permite.","correlation_id":"cor_body"}}`)
		default:
			return false
		}
		return true
	}
	server, err := New(fake.URL, credentialFile(t, "token"), WithToolsets(Toolsets...))
	if err != nil {
		t.Fatal(err)
	}
	session := connect(t, server)
	ctx := context.Background()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "node_trust", Arguments: map[string]any{"node_id": "n1"}})
	if err != nil || !result.IsError {
		t.Fatalf("refusal not reported: %+v %v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{"HTTP 403", "permission_denied", "A policy atual não permite.", "cor_body"} {
		if !strings.Contains(text, want) {
			t.Fatalf("refusal %q misses %q", text, want)
		}
	}

	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "delete", Arguments: map[string]any{"node_id": "n1", "mount_id": "m1", "path": "a"}})
	if err != nil || result.IsError || len(result.Content) != 2 || !strings.Contains(result.Content[1].(*mcp.TextContent).Text, "get_pending_operation") {
		t.Fatalf("approval not explained: %+v %v", result, err)
	}

	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "diagnose_node", Arguments: map[string]any{"node_id": "n1"}})
	if err != nil || result.IsError {
		t.Fatalf("diagnosis failed: %+v %v", result, err)
	}
	var report struct {
		Sections map[string]struct {
			Data  json.RawMessage `json:"data"`
			Error *controlError   `json:"error"`
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Sections) != 4 || report.Sections["trust"].Error == nil || report.Sections["trust"].Error.Code != "permission_denied" || report.Sections["mounts"].Data == nil {
		t.Fatalf("diagnosis=%+v", report)
	}
	fake.take()

	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "diagnose_path", Arguments: map[string]any{"node_id": "n1", "mount_id": "m1", "path": "a/b"}})
	if err != nil || result.IsError {
		t.Fatalf("path diagnosis failed: %+v %v", result, err)
	}
	for _, request := range fake.take() {
		if request.Method == http.MethodPost && request.Body != `{"paths":["nodes/n1/files/mounts/m1","nodes/n1/files/mounts/m1/a","nodes/n1/files/mounts/m1/a/b"]}` {
			t.Fatalf("permissions asked for %s", request.Body)
		}
	}
}

// TestToolListingStaysSmall keeps the cost of loading the tools in check: an
// agent pays for the whole listing in every conversation. Raise a budget only
// on purpose, after trying a shorter description or a group.
func TestToolListingStaysSmall(t *testing.T) {
	fake := newFakeControl(t)
	for _, tc := range []struct {
		toolsets []string
		budget   int
	}{
		{[]string{ToolsetFiles}, 2_000},
		{DefaultHTTPToolsets, 17_000},
		{Toolsets, 25_000},
	} {
		server, err := New(fake.URL, credentialFile(t, "token"), WithToolsets(tc.toolsets...))
		if err != nil {
			t.Fatal(err)
		}
		session := connect(t, server)
		listed, err := session.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(listed)
		if len(data) > tc.budget {
			t.Fatalf("%v lists %d bytes, budget %d", tc.toolsets, len(data), tc.budget)
		}
		if instructions := session.InitializeResult().Instructions; !strings.Contains(instructions, "relative to the mount") || len(instructions) > 1_000 {
			t.Fatalf("instructions=%q", instructions)
		}
	}
}
