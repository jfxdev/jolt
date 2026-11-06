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

func TestToolsUseControlTowerAndRotatedCredential(t *testing.T) {
	var mu sync.Mutex
	var auth, routes []string
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		routes = append(routes, r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		if strings.HasSuffix(r.URL.Path, "/content") {
			_, _ = io.WriteString(w, "hello world\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[],"next_after":"cursor"}`)
	}))
	defer node.Close()
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("first-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server, err := New(node.URL, credential)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := server.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("tool not read-only: %+v", tool)
		}
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"disk_usage", "list", "read_text", "search"}) {
		t.Fatalf("tools=%v", names)
	}
	for i, name := range []string{"list", "search", "disk_usage", "read_text"} {
		args := map[string]any{"node_id": "node", "mount_id": "media", "path": "folder/file.txt"}
		if name == "search" {
			args["query"] = "report"
		}
		if name == "list" {
			args["after"] = "page"
		}
		if i == 1 {
			if err := os.WriteFile(credential, []byte("second.jwt.token\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || result.IsError || len(result.Content) != 1 {
			t.Fatalf("%s result=%+v err=%v", name, result, err)
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "first-token") || strings.Contains(string(encoded), "second.jwt.token") {
			t.Fatalf("credential leaked: %s", encoded)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(auth, []string{"Bearer first-token", "Bearer second.jwt.token", "Bearer second.jwt.token", "Bearer second.jwt.token"}) {
		t.Fatalf("credential rotation failed: %v", auth)
	}
	for _, route := range routes {
		if !strings.HasPrefix(route, "/api/v1/nodes/node/mounts/media/files") || !strings.Contains(route, "path=folder%2Ffile.txt") {
			t.Fatalf("wrong route: %s", route)
		}
	}
}

func TestRequestRefusesRedirectsOversizeBinaryAndCredentialEcho(t *testing.T) {
	response := "ok"
	status := 200
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stolen" {
			t.Error("redirect was followed")
		}
		if status == 302 {
			w.Header().Set("Location", "/stolen")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	defer upstream.Close()
	credential := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(credential, []byte("private-token"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(upstream.URL, credential)
	if err != nil {
		t.Fatal(err)
	}
	args := fileArgs{NodeID: "n", MountID: "m", Path: "file.txt"}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{"private-token", 200}, {"binary\x00file", 200}, {"bad\x1bcontrol", 200}, {strings.Repeat("x", maxTextBytes+1), 200}, {"private-token", 403}, {"", 302},
	} {
		response, status = tc.body, tc.status
		result, _, err := s.readText(context.Background(), nil, args)
		if result != nil || err == nil || strings.Contains(err.Error(), "private-token") {
			t.Fatalf("response accepted or credential leaked: %+v %v", result, err)
		}
	}
	args.Path = "../escape"
	if _, _, err := s.readText(context.Background(), nil, args); err == nil {
		t.Fatal("traversal accepted")
	}
	args.Path, response, status = ".", `{"name":"private-token"}`, 200
	if result, _, err := s.list(context.Background(), nil, listArgs{fileArgs: args}); result != nil || err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("credential in JSON listing was not suppressed: %+v %v", result, err)
	}
}

func TestConfigurationRejectsUnsafeURLsAndInvalidCredentials(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?secret=x", "file:///tmp/file"} {
		if _, err := New(raw, "token"); err == nil {
			t.Fatalf("accepted URL %q", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:1234", "http://[::1]:1234", "https://example.com"} {
		if _, err := New(raw, "token"); err != nil {
			t.Fatalf("rejected URL %q: %v", raw, err)
		}
	}
	file := filepath.Join(t.TempDir(), "token")
	for _, data := range []string{"", "two tokens", "token\nother", strings.Repeat("x", maxCredentialBytes+1)} {
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(file); err == nil {
			t.Fatal("accepted invalid credential")
		}
	}
}
