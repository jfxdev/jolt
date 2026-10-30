package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestReadinessDependsOnDatabase(t *testing.T) {
	handler, storage, _ := testUserHandler(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", response.Code, response.Body.String())
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed ready status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("live status=%d body=%s", response.Code, response.Body.String())
	}
}
