package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestAgentSecretScanRequiresCompatibleNodeAndAuditsDetection(t *testing.T) {
	for _, tc := range []struct {
		name, capabilities, confirmation string
		upstreamStatus, want, calls      int
	}{
		{"old node", `[]`, "", 200, 409, 0},
		{"unconfirmed scan", `["agent_secret_scan_v1"]`, "", 200, 409, 1},
		{"secret detected", `["agent_secret_scan_v1"]`, "secrets", 403, 403, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v1/node" {
					body := `{"node_id":"n1","capabilities":` + tc.capabilities + `}`
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				}
				calls++
				if r.Header.Get("X-Jolt-Scan") != "secrets" {
					t.Error("missing required scan")
				}
				header := make(http.Header)
				header.Set("X-Jolt-Scan-Applied", tc.confirmation)
				if tc.upstreamStatus == 403 {
					header.Set("X-Jolt-Secret-Kind", "private_key")
				}
				body := `{"error":{"code":"secret_detected"}}`
				return &http.Response{StatusCode: tc.upstreamStatus, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}, nil
			})}
			f := setupAgentWithScanStub(t, store.DefaultAgentLimits(), client, false)
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
			if w.Code != tc.want || calls != tc.calls || w.Header().Get("X-Jolt-Secret-Kind") != "" || w.Header().Get("X-Jolt-Scan-Applied") != "" {
				t.Fatalf("status=%d calls=%d header=%v body=%s", w.Code, calls, w.Header(), w.Body.String())
			}
			if tc.upstreamStatus == 403 && tc.confirmation != "" {
				events, _, err := f.storage.ListAuditEvents(context.Background(), store.AuditQuery{Limit: 100})
				found := false
				for _, event := range events {
					if event.Action == "secret_detected" && event.Resource == "secret_scan/private_key" {
						found = true
					}
				}
				if err != nil || !found {
					t.Fatalf("missing detection audit: %+v %v", events, err)
				}
			}
		})
	}
}
