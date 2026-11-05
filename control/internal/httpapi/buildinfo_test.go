package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestAboutRequiresSessionAndReturnsBuildInfo(t *testing.T) {
	handler, _, session := testUserHandler(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true})
	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/control-tower/about", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", anonymous.Code)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/control-tower/about", session, nil))
	if response.Code != http.StatusOK || response.Body.String() != "{\"version\":\"development\",\"commit\":\"unknown\",\"build_date\":\"unknown\",\"features\":{\"typed_policies\":false}}\n" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAboutReportsTypedPoliciesOnlyWhenEnabled(t *testing.T) {
	for _, typed := range []bool{true, false} {
		h := newTypedHarness(t, typed, func(*http.Request) (int, http.Header, string) { return http.StatusNotFound, nil, "" })
		response := h.do("operator", http.MethodGet, "/api/v1/control-tower/about", nil)
		want := `"features":{"typed_policies":` + map[bool]string{true: "true", false: "false"}[typed] + `}`
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
			t.Fatalf("typed=%v status=%d body=%q", typed, response.Code, response.Body.String())
		}
	}
}
