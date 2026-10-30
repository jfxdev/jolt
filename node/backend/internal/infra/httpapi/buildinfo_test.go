package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeExposesBuildInfo(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/node", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"build":{"version":"development","commit":"unknown","build_date":"unknown"}`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
