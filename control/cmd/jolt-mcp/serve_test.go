package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerOptionsReadTheEnvironment(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	if _, err := serverOptions(env(map[string]string{"JOLT_MCP_READ_ONLY": "maybe"}), nil); err == nil {
		t.Fatal("invalid boolean accepted")
	}
	if _, err := httpHandler(env(map[string]string{"JOLT_MCP_CONTROL_URL": "http://jolt-control:8090"})); err == nil {
		t.Fatal("plain HTTP outside loopback accepted without opting in")
	}
	if _, err := httpHandler(env(map[string]string{"JOLT_MCP_CONTROL_URL": "http://jolt-control:8090", "JOLT_MCP_INSECURE_CONTROL_URL": "true", "JOLT_MCP_TOOLSETS": "files, admin"})); err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	if _, err := httpHandler(env(map[string]string{"JOLT_MCP_CONTROL_URL": "https://ct.example.com", "JOLT_MCP_TOOLSETS": "files,nope"})); err == nil {
		t.Fatal("unknown toolset accepted")
	}
	if got := splitList(" files, ,inspect,"); strings.Join(got, "|") != "files|inspect" {
		t.Fatalf("splitList=%v", got)
	}
}

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func TestServeBinaryOverHTTPStopsOnSIGTERM(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "jolt-mcp")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v %s", err, output)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent.token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"actor_type":"service_account"}`)
	}))
	defer upstream.Close()
	cmd := exec.Command(binary, "serve", "--address", "127.0.0.1:0")
	cmd.Env = append(os.Environ(), "JOLT_MCP_CONTROL_URL="+upstream.URL, "JOLT_MCP_CA_FILE=")
	cmd.Env = append(cmd.Env, "HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	var logs bytes.Buffer
	lines := bufio.NewScanner(stderr)
	address := ""
	for address == "" && lines.Scan() {
		logs.WriteString(lines.Text() + "\n")
		if rest, ok := strings.CutPrefix(lines.Text(), "jolt-mcp serve: listening on "); ok {
			address = rest
		}
	}
	if address == "" {
		t.Fatalf("server did not start: %s", logs.String())
	}
	done := make(chan struct{})
	go func() {
		for lines.Scan() {
			logs.WriteString(lines.Text() + "\n")
		}
		close(done)
	}()
	response, err := http.Get("http://" + address + "/health")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health: %v %v", response, err)
	}
	response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport := &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp", HTTPClient: &http.Client{Transport: bearer("agent.token")}}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "serve-test"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil || result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "service_account") {
		t.Fatalf("whoami=%+v err=%v", result, err)
	}
	_ = session.Close()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	<-done
	if err := cmd.Wait(); err != nil {
		t.Fatalf("serve did not stop cleanly: %v", err)
	}
	if strings.Contains(logs.String(), "agent.token") {
		t.Fatal("token leaked to the logs")
	}
	if !strings.Contains(logs.String(), `"tool":"whoami"`) {
		t.Fatalf("tool call not logged: %s", logs.String())
	}
}
