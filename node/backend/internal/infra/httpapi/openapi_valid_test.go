package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestOpenAPIDocumentsEveryFileRoute keeps the published spec honest. The node
// has no YAML dependency, so this checks the property that actually regresses:
// a route is added to the mux and the spec is forgotten.
func TestOpenAPIDocumentsEveryFileRoute(t *testing.T) {
	routes := []string{
		"/api/v1/mounts/{mountID}/files",
		"/api/v1/mounts/{mountID}/files/metadata",
		"/api/v1/mounts/{mountID}/files/content",
		"/api/v1/mounts/{mountID}/files/archive",
		"/api/v1/mounts/{mountID}/files/archive/plan",
		"/api/v1/mounts/{mountID}/files/search",
		"/api/v1/mounts/{mountID}/files/uploads",
		"/api/v1/mounts/{mountID}/files/uploads/{uploadID}",
		"/api/v1/mounts/{mountID}/files/uploads/{uploadID}/complete",
		"/api/v1/mounts/{mountID}/files/directories",
		"/api/v1/mounts/{mountID}/files/copy",
		"/api/v1/mounts/{mountID}/files/move",
	}
	for _, route := range routes {
		if !strings.Contains(openAPISpec, "\n  "+route+":") {
			t.Errorf("route %s is not documented in the OpenAPI spec", route)
		}
	}
}

// TestOpenAPISpecIndentationIsConsistent catches the failure mode of hand-edited
// embedded YAML: a tab, or a path entry at the wrong depth, which makes the
// whole document unparseable for clients.
func TestOpenAPISpecIndentationIsConsistent(t *testing.T) {
	if strings.Contains(openAPISpec, "\t") {
		t.Fatal("the OpenAPI spec contains a tab, which YAML forbids for indentation")
	}
	inPaths := false
	for _, line := range strings.Split(openAPISpec, "\n") {
		if line == "paths:" {
			inPaths = true
			continue
		}
		if inPaths && line != "" && !strings.HasPrefix(line, " ") {
			// A top-level key ends the paths block.
			inPaths = false
		}
		if !inPaths || line == "" {
			continue
		}
		if strings.HasPrefix(line, "  /") && !strings.HasSuffix(strings.TrimSpace(line), ":") {
			t.Errorf("path entry is not a mapping key: %q", line)
		}
	}
}

// TestDumpOpenAPI writes the spec out for external validation. It is a helper
// for local use, skipped unless a destination is given.
func TestDumpOpenAPI(t *testing.T) {
	target := os.Getenv("JOLT_OPENAPI_DUMP")
	if target == "" {
		t.Skip("set JOLT_OPENAPI_DUMP to write the spec")
	}
	if err := os.WriteFile(target, []byte(openAPISpec), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRecoverPropagatesAbortHandler pins the behaviour a streamed archive
// depends on: a deliberate abort must close the connection rather than be
// converted into a 500 written onto a response whose headers are already sent.
func TestRecoverPropagatesAbortHandler(t *testing.T) {
	server := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler := server.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if value := recover(); value != http.ErrAbortHandler {
			t.Fatalf("recover swallowed the abort: %v", value)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Fatal("the abort did not propagate")
}

// TestRecoverStillHandlesOrdinaryPanics keeps the safety net in place for a
// genuine bug, which must become a 500 rather than killing the connection.
func TestRecoverStillHandlesOrdinaryPanics(t *testing.T) {
	server := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler := server.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("unexpected nil dereference")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("ordinary panic produced %d", recorder.Code)
	}
}
