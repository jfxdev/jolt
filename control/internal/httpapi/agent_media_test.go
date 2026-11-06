package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestAgentMediaRestrictionsAndRanges(t *testing.T) {
	contentType := "text/plain; charset=utf-8"
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusPartialContent, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader("sample-body")), ContentLength: 11}, nil
	})}
	limits := store.DefaultAgentLimits()
	limits.ReadMediaTypes = []string{"text/plain"}
	f := setupAgent(t, limits, client)
	request := func(path string) *httptest.ResponseRecorder {
		r := f.request("GET", path)
		r.Header.Set("Range", "bytes=1-3")
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		return w
	}
	path := "/api/v1/nodes/n1/mounts/m/files/content?path=file"
	if w := request(path); w.Code != http.StatusPartialContent || w.Body.String() != "sample-body" {
		t.Fatalf("allowed content: %d %s", w.Code, w.Body.String())
	}
	for _, value := range []string{"application/pdf", "multipart/byteranges; boundary=sample", "", "broken"} {
		contentType = value
		if w := request(path); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_media_type_denied") || strings.Contains(w.Body.String(), "sample-body") {
			t.Fatalf("content type %q: %d %s", value, w.Code, w.Body.String())
		}
	}
	before := calls
	if w := request("/api/v1/nodes/n1/mounts/m/files/archive?path=folder"); w.Code != http.StatusForbidden || calls != before {
		t.Fatalf("archive must fail before node access: %d %s", w.Code, w.Body.String())
	}
}

func TestAgentMediaTypeValidation(t *testing.T) {
	for _, bad := range []string{"text/*", "text/plain; charset=utf-8", "*/*", "not-a-type", ""} {
		limits := store.DefaultAgentLimits()
		limits.ReadMediaTypes = []string{bad}
		if _, err := normalizeAgentLimits(&limits); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	limits := store.DefaultAgentLimits()
	limits.ReadMediaTypes = []string{" TEXT/PLAIN ", "text/plain"}
	if _, err := normalizeAgentLimits(&limits); err == nil {
		t.Fatal("accepted duplicate media types")
	}
	limits.ReadMediaTypes = []string{" TEXT/PLAIN "}
	normalized, err := normalizeAgentLimits(&limits)
	if err != nil || normalized.ReadMediaTypes[0] != "text/plain" {
		t.Fatalf("normalization: %+v %v", normalized, err)
	}
}
