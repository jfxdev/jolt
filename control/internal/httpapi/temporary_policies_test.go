package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestTemporaryAgentAssignmentKeepsReadOnlyCeiling(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	base := "/api/v1/control-tower/service-accounts/" + f.accountID + "/policies/temporary"
	request := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, authenticatedRequest(method, path, f.adminSession, []byte(body)))
		return w
	}
	if w := request("POST", base, `{"policy_id":"wide"}`); w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "expires_at") {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	if w := request("GET", base, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"policy_id":"wide"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if w := request("POST", base, `{"policy_id":"wide","duration_seconds":3601}`); w.Code != http.StatusBadRequest {
		t.Fatalf("excessive duration: %d %s", w.Code, w.Body.String())
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("DELETE", "/api/v1/nodes/n1/mounts/m/files?path=test"))
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "agent_read_only") {
		t.Fatalf("temporary policy exceeded agent ceiling: %d %s", response.Code, response.Body.String())
	}
	if w := request("DELETE", base+"/wide", ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	events, _, err := f.storage.ListAuditEvents(context.Background(), store.AuditQuery{Limit: 100})
	found := false
	for _, event := range events {
		if event.Action == "grant_temporary_policy" && event.Detail["expires_at"] != nil {
			found = true
		}
	}
	if err != nil || !found {
		t.Fatalf("missing grant audit: %+v %v", events, err)
	}
}

func TestTemporaryAgentPolicyStopsActiveStreams(t *testing.T) {
	for _, mode := range []string{"expiry", "revoke", "grant"} {
		t.Run(mode, func(t *testing.T) {
			ready := make(chan struct{})
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: &cancelBody{ctx: r.Context(), ready: ready}}, nil
			})}
			f := setupAgent(t, store.DefaultAgentLimits(), client)
			if mode != "grant" {
				if err := f.storage.SetAccessGroupPolicies(context.Background(), "group", nil); err != nil {
					t.Fatal(err)
				}
			}
			base := "/api/v1/control-tower/service-accounts/" + f.accountID + "/policies/temporary"
			call := func(method, path, body string) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				f.handler.ServeHTTP(w, authenticatedRequest(method, path, f.adminSession, []byte(body)))
				return w
			}
			if mode != "grant" {
				duration := 60
				if mode == "expiry" {
					duration = 1
				}
				body := fmt.Sprintf(`{"policy_id":"wide","duration_seconds":%d}`, duration)
				if w := call("POST", base, body); w.Code != http.StatusCreated {
					t.Fatalf("grant: %d %s", w.Code, w.Body)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan any, 1)
			go func() {
				defer func() { done <- recover() }()
				f.handler.ServeHTTP(httptest.NewRecorder(), f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x").WithContext(ctx))
			}()
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("stream did not start")
			}
			if mode == "revoke" {
				if w := call("DELETE", base+"/wide", ""); w.Code != http.StatusNoContent {
					t.Fatalf("revoke: %d %s", w.Code, w.Body)
				}
			} else if mode == "grant" {
				if w := call("POST", base, `{"policy_id":"wide","duration_seconds":60}`); w.Code != http.StatusCreated {
					t.Fatalf("grant: %d %s", w.Code, w.Body)
				}
			}
			select {
			case value := <-done:
				if !errors.Is(asError(value), http.ErrAbortHandler) {
					t.Fatalf("stream did not abort: %v", value)
				}
			case <-ctx.Done():
				t.Fatal("stream outlived temporary policy change")
			}
			if mode != "grant" {
				w := httptest.NewRecorder()
				f.handler.ServeHTTP(w, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
				if w.Code != http.StatusForbidden {
					t.Fatalf("expired or revoked grant still allowed access: %d %s", w.Code, w.Body)
				}
			}
		})
	}
}
