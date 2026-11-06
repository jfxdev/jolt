package pki

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func publicHandler(t *testing.T) (http.Handler, *Manager) {
	t.Helper()
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	return PublicHandler(m), m
}

func get(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestThePublicPageServesTheRootAndItsFingerprint(t *testing.T) {
	h, m := publicHandler(t)
	for _, path := range []string{"/ca.pem", "/.well-known/jolt/ca.pem"} {
		w := get(h, http.MethodGet, path)
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-pem-file" || w.Body.String() != string(m.RootPEM()) {
			t.Fatalf("%s: %d %q", path, w.Code, w.Header().Get("Content-Type"))
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" {
			t.Fatalf("%s: headers %v", path, w.Header())
		}
	}
	if w := get(h, http.MethodGet, "/ca/fingerprint"); strings.TrimSpace(w.Body.String()) != m.RootFingerprint() {
		t.Fatalf("fingerprint: %q", w.Body)
	}
	page := get(h, http.MethodGet, "/ca")
	if page.Code != 200 || !strings.Contains(page.Body.String(), DisplayFingerprint(m.RootFingerprint())) || !strings.Contains(page.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("page: %d", page.Code)
	}
	if strings.Contains(page.Body.String(), "<script") {
		t.Fatal("the page runs script")
	}
}

func TestThePublicPageIsReadOnlyAndOffersNothingElse(t *testing.T) {
	h, m := publicHandler(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if w := get(h, method, "/ca.pem"); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
			t.Errorf("%s: %d", method, w.Code)
		}
	}
	for _, path := range []string{"/", "/api/v1/control-tower/crypto/ca", "/ca.pem/extra", "/ca.key", "/metrics"} {
		if w := get(h, http.MethodGet, path); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	// The mux cleans a path with dots by redirecting; it never serves it.
	if w := get(h, http.MethodGet, "/../etc/passwd"); w.Code == http.StatusOK || w.Body.Len() > 200 {
		t.Errorf("traversal: %d", w.Code)
	}
	// Whatever is reachable carries no private material.
	for _, path := range []string{"/ca.pem", "/ca", "/ca/fingerprint"} {
		body := get(h, http.MethodGet, path).Body.String()
		if strings.Contains(body, "PRIVATE") || strings.Contains(body, strings.ToUpper(m.Bundle().SigningKeys[0].Key)) {
			t.Errorf("%s leaks", path)
		}
	}
	if w := get(h, http.MethodHead, "/ca.pem"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d %d", w.Code, w.Body.Len())
	}
}

func TestThePublicPageSaysSoWhenTheAuthorityIsNotReady(t *testing.T) {
	m := newManager(t, newMemoryRepo(), &clock{epoch})
	if w := get(PublicHandler(m), http.MethodGet, "/ca.pem"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("not ready: %d", w.Code)
	}
}

func TestTheNextRootIsOfferedOnlyWhileARotationIsUnderWay(t *testing.T) {
	h, m := publicHandler(t)
	if w := get(h, http.MethodGet, "/ca/next.pem"); w.Code != http.StatusNotFound {
		t.Fatalf("no rotation: %d", w.Code)
	}
	if page := get(h, http.MethodGet, "/ca"); strings.Contains(page.Body.String(), "next.pem") {
		t.Fatal("the page offers a next root with none prepared")
	}
	if err := m.BeginRootRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	next := get(h, http.MethodGet, "/ca/next.pem")
	if next.Code != 200 || next.Body.String() != string(m.NextRootPEM()) || next.Body.String() == string(m.RootPEM()) {
		t.Fatalf("next root: %d", next.Code)
	}
	page := get(h, http.MethodGet, "/ca")
	if !strings.Contains(page.Body.String(), "/ca/next.pem") || !strings.Contains(page.Body.String(), DisplayFingerprint(m.Rotation().Next)) {
		t.Fatal("the page does not show the next root and its fingerprint")
	}
	if w := get(h, http.MethodPost, "/ca/next.pem"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post: %d", w.Code)
	}
	if err := m.PromoteRoot(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := get(h, http.MethodGet, "/ca/next.pem"); w.Code != http.StatusNotFound {
		t.Fatalf("after promotion: %d", w.Code)
	}
}
