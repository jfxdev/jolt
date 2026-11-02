package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

type agentFixture struct {
	handler      http.Handler
	storage      *store.Store
	adminSession string
	token        string
	accountID    string
	tokenID      string
}

func setupAgent(t *testing.T, limits store.AgentLimits, client *http.Client) agentFixture {
	return setupAgentWithScanStub(t, limits, client, true)
}

func setupAgentWithScanStub(t *testing.T, limits store.AgentLimits, client *http.Client, stubScan bool) agentFixture {
	t.Helper()
	if stubScan {
		original := client
		client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("X-Jolt-Capability-Check") == "agent-secret-scan" {
				body := `{"node_id":"n1","capabilities":["agent_secret_scan_v1"]}`
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			}
			response, err := original.Do(r)
			if err == nil && r.Header.Get("X-Jolt-Scan") == "secrets" {
				if response.Header == nil {
					response.Header = make(http.Header)
				}
				response.Header.Set("X-Jolt-Scan-Applied", "secrets")
			}
			return response, err
		})}
	}
	handler, storage, admin := testUserHandlerWithClient(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true}, client)
	ctx, now := context.Background(), time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(ctx, store.Node{ID: "n1", Name: "node", Endpoint: "http://node.invalid", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	policy := store.Policy{ID: "wide", Name: "wide", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n1/files/mounts/m/**", Capabilities: []string{"read", "list", "create", "update", "delete", "execute", "sudo"}}}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	group := store.AccessGroup{ID: "group", Name: "group", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateAccessGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupNodes(ctx, group.ID, []string{"n1"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupPolicies(ctx, group.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"name": "test-agent", "kind": "agent", "group_ids": []string{"group"}, "agent_limits": limits})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/service-accounts", admin, payload))
	if response.Code != http.StatusCreated {
		t.Fatalf("create agent: %d %s", response.Code, response.Body)
	}
	var created struct {
		Account    store.ServiceAccount `json:"service_account"`
		Credential struct {
			Token     string     `json:"token"`
			ID        string     `json:"token_id"`
			ExpiresAt *time.Time `json:"expires_at"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Account.Kind != "agent" || created.Credential.ExpiresAt == nil || created.Credential.ExpiresAt.After(now.Add(30*24*time.Hour+time.Minute)) {
		t.Fatalf("unexpected agent: %+v", created)
	}
	return agentFixture{handler: handler, storage: storage, adminSession: admin, token: created.Credential.Token, accountID: created.Account.ID, tokenID: created.Credential.ID}
}

func (f agentFixture) request(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+f.token)
	return r
}

func TestAgentReadCeilingAndRateLimit(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Query().Get("limit") != "200" {
			t.Errorf("listing limit = %q", r.URL.Query().Get("limit"))
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"items":[]}`)), ContentLength: 12}, nil
	})}
	limits := store.DefaultAgentLimits()
	limits.Burst = 3
	limits.RequestsPerMinute = 1
	f := setupAgent(t, limits, client)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/api/v1/nodes/n1/mounts/m/files?limit=999", 200},
		{"DELETE", "/api/v1/nodes/n1/mounts/m/files?path=x", 403},
		{"GET", "/api/v1/nodes/n1/mounts/m/files", 200},
		{"GET", "/api/v1/nodes/n1/mounts/m/files", 429},
	} {
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, f.request(tc.method, tc.path))
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.method, response.Code, response.Body)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("node received forbidden request: %d", calls.Load())
	}
}

func TestAuditExportIncludesHashCheckpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	if err := f.storage.EnableAuditChain(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.storage.AuditActor(context.Background(), "admin", "user", "test_event", "test", "allowed", "test")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, authenticatedRequest("GET", "/api/v1/control-tower/audit?format=ndjson&after=0", f.adminSession, nil))
	if w.Code != http.StatusOK || w.Header().Get("X-Jolt-Checkpoint-Reason") != "activation" || len(w.Header().Get("X-Jolt-Checkpoint-Hash")) != 64 || !strings.Contains(w.Body.String(), `"chain_data"`) || !strings.Contains(w.Body.String(), `"chain_hash"`) {
		t.Fatalf("export: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
}

func TestAgentSearchRequiresNodeCapabilityAndEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name, capabilities, confirmation string
		want, searches                   int
	}{
		{"old node", `[]`, "", http.StatusConflict, 0},
		{"unconfirmed enforcement", `["agent_search_limits_v1"]`, "", http.StatusConflict, 1},
		{"supported node", `["agent_search_limits_v1"]`, "1", http.StatusOK, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			searches := 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := `{"node_id":"n1","capabilities":` + tc.capabilities + `}`
				header := make(http.Header)
				if strings.HasSuffix(r.URL.Path, "/files/search") {
					searches++
					if r.Header.Get("X-Jolt-Agent-Search") != "1" || r.URL.Query().Get("limit") != "200" {
						t.Errorf("search missing limits: %v %s", r.Header, r.URL.RawQuery)
					}
					header.Set("X-Jolt-Agent-Search-Applied", tc.confirmation)
					body = `{"entries":[],"scanned":0,"truncated":false}`
				}
				return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}, nil
			})}
			f := setupAgent(t, store.DefaultAgentLimits(), client)
			response := httptest.NewRecorder()
			f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/search?query=test&limit=999"))
			if response.Code != tc.want || searches != tc.searches {
				t.Fatalf("status=%d searches=%d body=%s", response.Code, searches, response.Body.String())
			}
			if response.Header().Get("X-Jolt-Agent-Search-Applied") != "" {
				t.Fatal("internal confirmation leaked to agent")
			}
		})
	}
}

func TestAgentReadQuotaAndOversizedResponse(t *testing.T) {
	var size atomic.Int64
	size.Store(2048)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n := size.Load()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), int(n)))), ContentLength: n}, nil
	})}
	limits := store.DefaultAgentLimits()
	limits.MaxResponseBytes = 1024
	limits.DailyBytes = 4096
	limits.Burst = 10
	f := setupAgent(t, limits, client)
	path := "/api/v1/nodes/n1/mounts/m/files/content?path=a.bin"
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", path))
	if response.Code != 413 || !strings.Contains(response.Body.String(), "read_too_large") {
		t.Fatalf("oversized: %d %s", response.Code, response.Body)
	}
	size.Store(900)
	for i := 0; i < 4; i++ {
		response = httptest.NewRecorder()
		f.handler.ServeHTTP(response, f.request("GET", path))
		if response.Code != 200 || response.Body.Len() != 900 {
			t.Fatalf("read %d: %d %d", i, response.Code, response.Body.Len())
		}
	}
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", path))
	if response.Code != 429 || !strings.Contains(response.Body.String(), "agent_daily_quota") {
		t.Fatalf("quota: %d %s", response.Code, response.Body)
	}
	used, err := f.storage.AgentUsage(context.Background(), f.tokenID, time.Now().UTC().Format("2006-01-02"))
	if err != nil || used < 3600 || used > 4096 {
		t.Fatalf("quota accounting = %d, %v", used, err)
	}
}

func TestAgentCIDRHonorsOnlyTrustedProxies(t *testing.T) {
	limits := store.DefaultAgentLimits()
	limits.AllowedCIDRs = []string{"192.168.0.0/16"}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.8:1000"
	r.Header.Set("X-Forwarded-For", "192.168.1.7")
	if addressAllowed(r, limits, nil) {
		t.Fatal("untrusted forwarded address was accepted")
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if !addressAllowed(r, limits, trusted) {
		t.Fatal("trusted proxy address not accepted")
	}
	r.Header.Set("X-Forwarded-For", "192.168.1.7, 198.51.100.2")
	if addressAllowed(r, limits, trusted) {
		t.Fatal("untrusted intermediary was skipped")
	}
}

func TestAgentCredentialCIDRAndImmutableKind(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"items":[]}`)), ContentLength: 12}, nil
	})}
	limits := store.DefaultAgentLimits()
	limits.AllowedCIDRs = []string{"10.2.0.0/16"}
	f := setupAgent(t, limits, client)
	path := "/api/v1/nodes/n1/mounts/m/files"
	denied := f.request("GET", path)
	denied.RemoteAddr = "203.0.113.5:1234"
	denied.Header.Set("X-Forwarded-For", "10.2.1.8")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, denied)
	if response.Code != 401 {
		t.Fatalf("untrusted source: %d %s", response.Code, response.Body)
	}
	allowed := f.request("GET", path)
	allowed.RemoteAddr = "10.2.1.8:1234"
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, allowed)
	if response.Code != 200 {
		t.Fatalf("allowed source: %d %s", response.Code, response.Body)
	}
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("PATCH", "/api/v1/control-tower/service-accounts/"+f.accountID, f.adminSession, []byte(`{"kind":"automation"}`)))
	if response.Code != 400 {
		t.Fatalf("kind update accepted: %d %s", response.Code, response.Body)
	}
	account, err := f.storage.GetServiceAccount(context.Background(), f.accountID)
	if err != nil || account.Kind != "agent" {
		t.Fatalf("kind changed: %+v %v", account, err)
	}
}

func TestAgentUnknownLengthStreamStopsAtResponseLimit(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 4096)))}, nil
	})}
	limits := store.DefaultAgentLimits()
	limits.MaxResponseBytes = 1024
	limits.DailyBytes = 8192
	f := setupAgent(t, limits, client)
	response := httptest.NewRecorder()
	var caught any
	func() {
		defer func() { caught = recover() }()
		f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
	}()
	if !errors.Is(asError(caught), http.ErrAbortHandler) || response.Body.Len() != 1024 {
		t.Fatalf("stream: panic=%v bytes=%d", caught, response.Body.Len())
	}
	used, err := f.storage.AgentUsage(context.Background(), f.tokenID, time.Now().UTC().Format("2006-01-02"))
	if err != nil || used != 1024 {
		t.Fatalf("charged=%d err=%v", used, err)
	}
	events, _, err := f.storage.ListAuditEvents(context.Background(), store.AuditQuery{Action: "agent_request", Limit: 10})
	if err != nil || len(events) != 1 || events[0].Detail["aborted_by"] != "quota" || events[0].Detail["bytes_out"] != float64(1024) {
		t.Fatalf("stream audit: %+v %v", events, err)
	}
}

func TestAgentAuditExportIncludesRequestMetadata(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 206, ContentLength: 3, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(strings.NewReader("abc"))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	r := f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=private.txt")
	r.Header.Set("Range", "bytes=3-5")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, r)
	if response.Code != 206 {
		t.Fatalf("read: %d %s", response.Code, response.Body)
	}
	events, _, err := f.storage.ListAuditEvents(context.Background(), store.AuditQuery{Action: "agent_request", Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("agent audit: %+v %v", events, err)
	}
	event := events[0]
	if event.ActorID != f.accountID || event.SourceIP != "192.0.2.1" || event.Detail["token_id"] != f.tokenID || event.Detail["range"] != "bytes=3-5" || event.Detail["bytes_out"] != float64(3) {
		t.Fatalf("unexpected audit: %+v", event)
	}
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("GET", "/api/v1/control-tower/audit?format=ndjson&after=0&limit=2", f.adminSession, nil))
	if response.Code != 200 || response.Header().Get("Content-Type") != "application/x-ndjson" || response.Header().Get("X-Jolt-Next-After") == "" {
		t.Fatalf("export: %d %s", response.Code, response.Body)
	}
	var last int64
	for _, line := range strings.Split(strings.TrimSpace(response.Body.String()), "\n") {
		var item store.AuditEvent
		if err := json.Unmarshal([]byte(line), &item); err != nil || item.ID <= last {
			t.Fatalf("invalid export ordering: %s %v", line, err)
		}
		last = item.ID
	}
}

func TestAgentCanaryIsAuditedWithoutExposingInternalHeader(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Jolt-Internal-Canary") != "1" {
			t.Error("node request did not request the internal canary signal")
		}
		return &http.Response{StatusCode: 200, ContentLength: 5, Header: http.Header{"Content-Type": []string{"text/plain"}, "X-Jolt-Canary": []string{"1"}}, Body: io.NopCloser(strings.NewReader("decoy"))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=honey.txt"))
	if response.Code != 200 || response.Body.String() != "decoy" || response.Header().Get("X-Jolt-Canary") != "" {
		t.Fatalf("canary response: %d %s %v", response.Code, response.Body, response.Header())
	}
	events, _, err := f.storage.ListAuditEvents(context.Background(), store.AuditQuery{Action: "canary", Limit: 10})
	if err != nil || len(events) != 1 || events[0].ActorID != f.accountID {
		t.Fatalf("canary audit: %+v %v", events, err)
	}
}

func TestAgentConcurrencyStopsThirdStream(t *testing.T) {
	ready := make(chan struct{}, 2)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: &signalCancelBody{ctx: r.Context(), ready: ready}}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer func() { _ = recover(); done <- struct{}{} }()
			f.handler.ServeHTTP(httptest.NewRecorder(), f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case <-time.After(3 * time.Second):
			t.Fatal("stream did not start")
		}
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
	if response.Code != 429 {
		t.Fatalf("third stream: %d %s", response.Code, response.Body)
	}
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("POST", "/api/v1/control-tower/service-accounts/disable?kind=agent", f.adminSession, nil))
	if response.Code != 200 {
		t.Fatalf("disable: %d %s", response.Code, response.Body)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("stream did not stop")
		}
	}
}

type signalCancelBody struct {
	ctx   context.Context
	ready chan<- struct{}
	once  sync.Once
}

func (b *signalCancelBody) Read(_ []byte) (int, error) {
	b.once.Do(func() { b.ready <- struct{}{} })
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *signalCancelBody) Close() error { return nil }

type cancelBody struct {
	ctx   context.Context
	ready chan struct{}
	once  sync.Once
}

func (b *cancelBody) Read(_ []byte) (int, error) {
	b.once.Do(func() { close(b.ready) })
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *cancelBody) Close() error { return nil }

func TestDisableAgentsCancelsActiveStream(t *testing.T) {
	ready := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: &cancelBody{ctx: r.Context(), ready: ready}}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f.handler.ServeHTTP(httptest.NewRecorder(), f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not start")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("POST", "/api/v1/control-tower/service-accounts/disable?kind=agent", f.adminSession, nil))
	if response.Code != 200 {
		t.Fatalf("disable: %d %s", response.Code, response.Body)
	}
	select {
	case value := <-done:
		if !errors.Is(asError(value), http.ErrAbortHandler) {
			t.Fatalf("stream did not abort: %v", value)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream still running")
	}
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files"))
	if response.Code != 401 {
		t.Fatalf("disabled agent authenticated: %d", response.Code)
	}
}

type blockedResponseWriter struct {
	header                 http.Header
	ready, released        chan struct{}
	writeOnce, releaseOnce sync.Once
}

func (w *blockedResponseWriter) Header() http.Header { return w.header }
func (w *blockedResponseWriter) WriteHeader(int)     {}
func (w *blockedResponseWriter) Write([]byte) (int, error) {
	w.writeOnce.Do(func() { close(w.ready) })
	<-w.released
	return 0, errors.New("write deadline")
}
func (w *blockedResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		w.releaseOnce.Do(func() { close(w.released) })
	}
	return nil
}

func TestDisableAgentsInterruptsBlockedDownstreamWrite(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(strings.NewReader("payload"))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	writer := &blockedResponseWriter{header: make(http.Header), ready: make(chan struct{}), released: make(chan struct{})}
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f.handler.ServeHTTP(writer, f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
	}()
	select {
	case <-writer.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not block")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("POST", "/api/v1/control-tower/service-accounts/disable?kind=agent", f.adminSession, nil))
	if response.Code != 200 {
		t.Fatalf("disable: %d %s", response.Code, response.Body)
	}
	select {
	case value := <-done:
		if !errors.Is(asError(value), http.ErrAbortHandler) {
			t.Fatalf("blocked write did not abort: %v", value)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked write still active")
	}
}

func TestAgentExpiryLimitsAndCancelsStream(t *testing.T) {
	ready := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: &cancelBody{ctx: r.Context(), ready: ready}}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	url := "/api/v1/control-tower/service-accounts/" + f.accountID + "/tokens"
	tooLate, _ := json.Marshal(map[string]any{"expires_at": time.Now().UTC().Add(31 * 24 * time.Hour)})
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("POST", url, f.adminSession, tooLate))
	if response.Code != 400 {
		t.Fatalf("long expiration accepted: %d %s", response.Code, response.Body)
	}
	short, _ := json.Marshal(map[string]any{"expires_at": time.Now().UTC().Add(700 * time.Millisecond), "revoke_existing": true})
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("POST", url, f.adminSession, short))
	if response.Code != 201 {
		t.Fatalf("short token: %d %s", response.Code, response.Body)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	f.token = issued.Token
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f.handler.ServeHTTP(httptest.NewRecorder(), f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not start")
	}
	select {
	case value := <-done:
		if !errors.Is(asError(value), http.ErrAbortHandler) {
			t.Fatalf("expired stream did not abort: %v", value)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expired stream still running")
	}
}

func TestAgentLimitUpdateCancelsStreamAndEnforcesNewCIDR(t *testing.T) {
	ready := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: &cancelBody{ctx: r.Context(), ready: ready}}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f.handler.ServeHTTP(httptest.NewRecorder(), f.request("GET", "/api/v1/nodes/n1/mounts/m/files/content?path=x"))
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not start")
	}
	limits := store.DefaultAgentLimits()
	limits.AllowedCIDRs = []string{"10.0.0.0/8"}
	payload, _ := json.Marshal(map[string]any{"agent_limits": limits})
	url := "/api/v1/control-tower/service-accounts/" + f.accountID + "/tokens/" + f.tokenID
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest("PATCH", url, f.adminSession, payload))
	if response.Code != 204 {
		t.Fatalf("update limits: %d %s", response.Code, response.Body)
	}
	select {
	case value := <-done:
		if !errors.Is(asError(value), http.ErrAbortHandler) {
			t.Fatalf("stream did not abort: %v", value)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream still running")
	}
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("GET", "/api/v1/nodes/n1/mounts/m/files"))
	if response.Code != 401 {
		t.Fatalf("new network limit ignored: %d %s", response.Code, response.Body)
	}
	tokens, err := f.storage.ListServiceAccountTokens(context.Background(), f.accountID)
	if err != nil || len(tokens) != 1 || tokens[0].AgentLimits == nil || tokens[0].AgentLimits.AllowedCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("new limits not persisted: %+v %v", tokens, err)
	}
}

func asError(value any) error {
	if err, ok := value.(error); ok {
		return err
	}
	return fmt.Errorf("%v", value)
}
