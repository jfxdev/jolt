package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestAgentDisplayNamePreservesCanonicalPaths(t *testing.T) {
	name := "report\x1b[31m\u202e.txt"
	data, _ := json.Marshal(map[string]any{"items": []any{map[string]any{"name": name, "path": "dir/" + name, "size": int64(9007199254740993)}}})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data))), ContentLength: int64(len(data))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files?path=dir"))
	var result struct {
		Items []struct {
			Name        string `json:"name"`
			Path        string `json:"path"`
			DisplayName string `json:"display_name"`
			Size        int64  `json:"size"`
		} `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Items) != 1 {
		t.Fatalf("listing: %d %s", response.Code, response.Body.String())
	}
	item := result.Items[0]
	if item.Name != name || item.Path != "dir/"+name || item.Size != 9007199254740993 || item.DisplayName != "report⟦U+001B⟧[31m⟦U+202E⟧.txt" {
		t.Fatalf("unexpected item: %+v", item)
	}
}

func TestAgentDisplayNameLimitsAndMalformedEntries(t *testing.T) {
	if got := displayName(strings.Repeat("a", 256)); got != strings.Repeat("a", 255)+"…" {
		t.Fatalf("name was not truncated: %q", got)
	}
	for _, body := range []string{`{"items":null}`, `{"items":[{}]}`, `{"items":[]}{}`, `{"items":[null]}`} {
		if _, err := decorateAgentEntries(strings.NewReader(body), "items", 4096); err == nil {
			t.Fatalf("accepted malformed response %q", body)
		}
	}
	items := make([]map[string]string, 201)
	for i := range items {
		items[i] = map[string]string{"name": "file"}
	}
	data, _ := json.Marshal(map[string]any{"items": items})
	if _, err := decorateAgentEntries(strings.NewReader(string(data)), "items", int64(len(data))); err == nil {
		t.Fatal("accepted more than 200 entries")
	}
}

func TestAgentDisplayExpansionRespectsResponseLimit(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"items": []any{map[string]any{"name": strings.Repeat("\x1b", 130), "path": "file"}}})
	limits := store.DefaultAgentLimits()
	limits.MaxResponseBytes = 1024
	if len(data) >= int(limits.MaxResponseBytes) {
		t.Fatal("test input must fit before the display name is added")
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data))), ContentLength: int64(len(data))}, nil
	})}
	f := setupAgent(t, limits, client)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files"))
	if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "read_too_large") {
		t.Fatalf("expanded listing: %d %s", response.Code, response.Body.String())
	}
}
