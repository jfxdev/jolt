package mcpserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bearerTransport adds the agent's token to every MCP request.
type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func httpSession(t *testing.T, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	transport := &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &http.Client{Transport: bearerTransport{token}}}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "http-test"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestHTTPPassesEachCallersTokenToTheControlTower(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Query().Get("path")] = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer control.Close()
	server, err := New(control.URL, "", WithRequestCredential(), WithToolsets(DefaultHTTPToolsets...))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler(HTTPOptions{AllowedOrigins: []string{"https://agents.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(handler)
	defer front.Close()

	var wg sync.WaitGroup
	for i := range 4 {
		session := httpSession(t, front.URL+"/mcp", fmt.Sprintf("agent-%d.token", i))
		wg.Go(func() {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list", Arguments: map[string]any{
				"node_id": "n1", "mount_id": "m1", "path": fmt.Sprintf("dir%d", i),
			}})
			if err != nil || result.IsError {
				t.Errorf("agent %d: %+v %v", i, result, err)
			}
		})
	}
	wg.Wait()
	for i := range 4 {
		if got, want := seen[fmt.Sprintf("dir%d", i)], fmt.Sprintf("Bearer agent-%d.token", i); got != want {
			t.Fatalf("dir%d was listed with %q, want %q", i, got, want)
		}
	}
	tools := toolNames(t, httpSession(t, front.URL+"/mcp", "agent.token"))
	if _, ok := tools["mkdir"]; !ok {
		t.Fatal("default HTTP toolsets miss files_write")
	}
	if _, ok := tools["manage_users"]; ok {
		t.Fatal("admin tools offered without opting in")
	}

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`
	post := func(token, origin, body string) int {
		request, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if status := post("", "", initialize); status != http.StatusUnauthorized {
		t.Fatalf("no token: HTTP %d", status)
	}
	if status := post("bad,token", "", initialize); status != http.StatusUnauthorized {
		t.Fatalf("malformed token: HTTP %d", status)
	}
	if status := post("agent.token", "https://evil.example.com", initialize); status != http.StatusForbidden {
		t.Fatalf("foreign origin: HTTP %d", status)
	}
	if status := post("agent.token", front.URL, initialize); status != http.StatusForbidden {
		t.Fatalf("same-origin page not allowed explicitly: HTTP %d", status)
	}
	if status := post("agent.token", "https://agents.example.com", initialize); status != http.StatusOK {
		t.Fatalf("allowed origin: HTTP %d", status)
	}
	if status := post("agent.token", "", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"`+strings.Repeat("x", maxRequestBytes)+`"}}`); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: HTTP %d", status)
	}

	response, err := http.Get(front.URL + "/health")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health: %v %v", response, err)
	}
	response.Body.Close()
}

func TestHTTPNeedsRequestCredentials(t *testing.T) {
	server, err := New("http://127.0.0.1:1", credentialFile(t, "token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Handler(HTTPOptions{}); err == nil {
		t.Fatal("HTTP transport served a file credential to every caller")
	}
	if _, err := New("http://127.0.0.1:1", ""); err == nil {
		t.Fatal("no credential source accepted")
	}
	if _, err := New("http://jolt-control:8090", "", WithRequestCredential()); err == nil {
		t.Fatal("plain HTTP outside loopback accepted")
	}
	if _, err := New("http://jolt-control:8090", "", WithRequestCredential(), WithInsecureControlURL()); err != nil {
		t.Fatalf("opt-in plain HTTP refused: %v", err)
	}
	if _, err := New("ftp://jolt-control", "", WithRequestCredential(), WithInsecureControlURL()); err == nil {
		t.Fatal("non-HTTP scheme accepted")
	}
}
