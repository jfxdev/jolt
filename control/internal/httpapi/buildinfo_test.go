package httpapi

import (
	"net/http"
	"net/http/httptest"
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
	if response.Code != http.StatusOK || response.Body.String() != "{\"version\":\"development\",\"commit\":\"unknown\",\"build_date\":\"unknown\"}\n" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
