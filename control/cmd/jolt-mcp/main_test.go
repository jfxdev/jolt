package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStdioBinaryReadOnlyAndCredentialRotation(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "jolt-mcp")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v %s", err, output)
	}
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/content") {
			_, _ = io.WriteString(w, "text from node")
			return
		}
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer upstream.Close()
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("first-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "JOLT_MCP_CONTROL_URL="+upstream.URL, "JOLT_MCP_CREDENTIAL_FILE="+credential)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"disk_usage", "list", "read_text", "search"}) {
		t.Fatalf("tools=%v", names)
	}
	args := map[string]any{"node_id": "node", "mount_id": "media", "path": "file.txt"}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list", Arguments: args})
	if err != nil || result.IsError {
		t.Fatalf("list=%+v err=%v", result, err)
	}
	if err := os.WriteFile(credential, []byte("rotated.jwt.token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "read_text", Arguments: args})
	if err != nil || result.IsError {
		t.Fatalf("read=%+v err=%v", result, err)
	}
	data, _ := json.Marshal(result)
	if bytes.Contains(data, []byte("rotated.jwt.token")) || !bytes.Contains(data, []byte("text from node")) {
		t.Fatalf("unexpected result %s", data)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "delete", Arguments: args})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("write tool was accepted")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "first-token") || strings.Contains(stderr.String(), "rotated.jwt.token") {
		t.Fatal("credential leaked to stderr")
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(seen, []string{"GET Bearer first-token", "GET Bearer rotated.jwt.token"}) {
		t.Fatalf("unexpected requests: %v", seen)
	}
}
