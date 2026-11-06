package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const (
	tokenPath  = "/api/v1/control-tower/enrollments/tokens"
	enrollPath = "/api/v1/control-tower/enroll"
)

type enrollHarness struct {
	*typedHarness
	authority *pki.Manager
}

func newEnrollHarness(t *testing.T, mutate ...func(*config.Config)) *enrollHarness {
	t.Helper()
	authority := managedAuthority(t)
	h := newTypedHarness(t, false, func(*http.Request) (int, http.Header, string) { return 404, nil, "{}" }, func(cfg *config.Config) {
		cfg.TLSMode, cfg.Authority, cfg.SigningSource = config.TLSManaged, authority, authority
		cfg.AuthorizationSigningKeyID, cfg.AuthorizationSigningKey = "", nil
		cfg.PublicBaseURL = "https://control.lan:8090"
		cfg.EnrollmentApproval = "auto"
		for _, m := range mutate {
			m(cfg)
		}
	})
	return &enrollHarness{typedHarness: h, authority: authority}
}

// public calls the endpoints a node reaches before it has any credential.
func (h *enrollHarness) public(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.RemoteAddr = "10.9.8.7:4000"
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, request)
	return w
}

type issuedToken struct {
	ID       string    `json:"token_id"`
	Token    string    `json:"token"`
	NodeName string    `json:"node_name"`
	Approval string    `json:"approval"`
	Expires  time.Time `json:"expires_at"`
	URL      string    `json:"control_url"`
}

func (h *enrollHarness) token(t *testing.T, body map[string]any) issuedToken {
	t.Helper()
	w := h.do("admin", http.MethodPost, tokenPath, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	var out issuedToken
	decodeBody(t, w, &out)
	return out
}

func (t issuedToken) secret() string { return strings.Split(t.Token, ":")[2] }

type nodeIdentity struct {
	key      *ecdsa.PrivateKey
	id, name string
}

func newNodeIdentity(t *testing.T, id, name string) *nodeIdentity {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &nodeIdentity{key: key, id: id, name: name}
}

func (n *nodeIdentity) csr(t *testing.T, commonName string) string {
	t.Helper()
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, n.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))
}

func (n *nodeIdentity) request(t *testing.T, token issuedToken) map[string]any {
	return map[string]any{
		"secret": token.secret(), "node_name": n.name, "node_id": n.id, "node_fingerprint": "AB:CD",
		"api_endpoint": "https://node.lan:8080", "csr_pem": n.csr(t, n.id), "operational_token": strings.Repeat("o", 43),
	}
}

func TestOnlyAnAdministratorMakesATokenAndItsSecretIsNeverStored(t *testing.T) {
	h := newEnrollHarness(t)
	if w := h.do("operator", http.MethodPost, tokenPath, map[string]any{"node_name": "alpha"}); w.Code != http.StatusForbidden {
		t.Fatalf("operator: %d", w.Code)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, tokenPath, strings.NewReader(`{"node_name":"alpha"}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	token := h.token(t, map[string]any{"node_name": "alpha"})
	parts := strings.SplitN(token.Token, ":", 5)
	if len(parts) != 5 || parts[0] != "jolt-join" || parts[1] != "v1" || len(parts[2]) != 43 || parts[3] != h.authority.RootFingerprint() || parts[4] != "https://control.lan:8090" {
		t.Fatalf("token format: %q", token.Token)
	}
	if token.Approval != "auto" || token.URL != "https://control.lan:8090" || time.Until(token.Expires) > 16*time.Minute || time.Until(token.Expires) < 14*time.Minute {
		t.Fatalf("token: %+v", token)
	}
	stored, _ := h.storage.ListJoinTokens(context.Background(), 10)
	if len(stored) != 1 || stored[0].SecretHash != security.Digest(token.secret()) || strings.Contains(stored[0].SecretHash, token.secret()) {
		t.Fatalf("stored: %+v", stored)
	}
	list := h.do("admin", http.MethodGet, tokenPath, nil)
	if list.Code != 200 || strings.Contains(list.Body.String(), token.secret()) || strings.Contains(list.Body.String(), stored[0].SecretHash) {
		t.Fatalf("the list leaks the secret or its hash: %s", list.Body)
	}
}

func TestTokenRequestsAreValidatedAndNeverWeakerThanThePolicy(t *testing.T) {
	h := newEnrollHarness(t)
	for name, body := range map[string]map[string]any{
		"no name":       {},
		"blank name":    {"node_name": "  "},
		"long name":     {"node_name": strings.Repeat("a", 65)},
		"control char":  {"node_name": "a\x07b"},
		"zero minutes":  {"node_name": "n", "valid_minutes": -1},
		"over a day":    {"node_name": "n", "valid_minutes": 24*60 + 1},
		"unknown mode":  {"node_name": "n", "approval": "whenever"},
		"unknown field": {"node_name": "n", "surprise": 1},
	} {
		if w := h.do("admin", http.MethodPost, tokenPath, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if token := h.token(t, map[string]any{"node_name": "n", "approval": "manual", "valid_minutes": 60}); token.Approval != "manual" || time.Until(token.Expires) < 59*time.Minute {
		t.Fatalf("a token may ask for manual approval and a longer life: %+v", token)
	}
	strict := newEnrollHarness(t, func(cfg *config.Config) { cfg.EnrollmentApproval = "manual" })
	if token := strict.token(t, map[string]any{"node_name": "n", "approval": "auto"}); token.Approval != "manual" {
		t.Fatalf("a token weakened the policy: %+v", token)
	}
	noURL := newEnrollHarness(t, func(cfg *config.Config) { cfg.PublicBaseURL = "" })
	if w := noURL.do("admin", http.MethodPost, tokenPath, map[string]any{"node_name": "n"}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "public_url_required") {
		t.Fatalf("no public URL: %d %s", w.Code, w.Body)
	}
	httpURL := newEnrollHarness(t, func(cfg *config.Config) { cfg.PublicBaseURL = "http://control.lan" })
	if w := httpURL.do("admin", http.MethodPost, tokenPath, map[string]any{"node_name": "n"}); w.Code != http.StatusConflict {
		t.Fatalf("plain http URL: %d", w.Code)
	}
}

func TestANodeEnrollsWithAValidTokenAndReceivesOnlyPublicThings(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha"})
	node := newNodeIdentity(t, "node-1", "alpha")
	w := h.public(http.MethodPost, enrollPath, node.request(t, token), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var out struct {
		Status      string          `json:"status"`
		Certificate string          `json:"certificate_pem"`
		Bundle      json.RawMessage `json:"bundle"`
	}
	decodeBody(t, w, &out)
	if out.Status != "issued" {
		t.Fatalf("status %q", out.Status)
	}
	// Everything the node needs to trust, checkable against the pin in its token.
	bundle, err := pki.ParseBundle(out.Bundle)
	if err != nil || pki.VerifyBundle(bundle, nil, h.authority.RootFingerprint(), time.Now()) != nil {
		t.Fatalf("the first bundle does not verify: %v", err)
	}
	roots, intermediates, _ := bundle.Certificates()
	block, rest := pem.Decode([]byte(out.Certificate))
	leaf, _ := x509.ParseCertificate(block.Bytes)
	issuer, _ := pem.Decode(rest)
	if leaf == nil || issuer == nil || leaf.VerifyHostname("node.lan") != nil || leaf.Subject.CommonName != "node-1" {
		t.Fatal("the certificate is not for the announced address")
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&node.key.PublicKey) {
		t.Fatal("the certificate is for a key the node does not hold")
	}
	if err := pki.Chain(leaf, roots, intermediates, x509.ExtKeyUsageServerAuth, time.Now()); err != nil {
		t.Fatalf("the certificate does not chain: %v", err)
	}
	for _, secret := range []string{strings.Repeat("o", 43), token.secret(), "PRIVATE"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("the answer carries %q", secret)
		}
	}
	// The node is registered, with the token it chose, sealed.
	registered, err := h.storage.GetNode(context.Background(), "node-1")
	if err != nil || registered.Name != "alpha" || registered.Endpoint != "https://node.lan:8080" {
		t.Fatalf("node: %+v %v", registered, err)
	}
	if opened, err := security.Decrypt(make([]byte, 32), registered.TokenEncrypted); err != nil || opened != strings.Repeat("o", 43) {
		t.Fatalf("the node's token: %q %v", opened, err)
	}
	managed, _ := h.storage.ListManagedNodes(context.Background())
	if len(managed) != 1 || managed[0].NodeID != "node-1" || managed[0].CertSerial != leaf.SerialNumber.Text(16) || managed[0].BundleVersion != bundle.Version {
		t.Fatalf("managed node: %+v", managed)
	}
	// The token is spent.
	if again := h.public(http.MethodPost, enrollPath, newNodeIdentity(t, "node-2", "alpha").request(t, token), nil); again.Code != http.StatusUnauthorized {
		t.Fatalf("a second node used a spent token: %d", again.Code)
	}
}

func TestARetryOfTheSameRequestGetsTheSameAnswer(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha"})
	node := newNodeIdentity(t, "node-1", "alpha")
	request := node.request(t, token)
	first := h.public(http.MethodPost, enrollPath, request, nil)
	second := h.public(http.MethodPost, enrollPath, request, nil)
	if first.Code != 200 || second.Code != 200 || first.Body.String() != second.Body.String() {
		t.Fatalf("retry: %d/%d\n%s\n%s", first.Code, second.Code, first.Body, second.Body)
	}
	if managed, _ := h.storage.ListManagedNodes(context.Background()); len(managed) != 1 {
		t.Fatalf("a retry registered %d nodes", len(managed))
	}
	// A different key under the same token is not a retry.
	other := newNodeIdentity(t, "node-1", "alpha")
	if w := h.public(http.MethodPost, enrollPath, other.request(t, token), nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("another request under a spent token: %d", w.Code)
	}
}

func TestEveryWayAnEnrollmentCanBeUnauthorizedLooksTheSame(t *testing.T) {
	h := newEnrollHarness(t)
	good := h.token(t, map[string]any{"node_name": "alpha"})
	revoked := h.token(t, map[string]any{"node_name": "gone"})
	if w := h.do("admin", http.MethodDelete, tokenPath+"/"+revoked.ID, nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", w.Code)
	}
	expired := store.JoinToken{ID: "old", SecretHash: security.Digest(strings.Repeat("e", 43)), NodeName: "alpha", Approval: "auto", CreatedBy: "admin",
		CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute)}
	if err := h.storage.CreateJoinToken(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	node := newNodeIdentity(t, "node-1", "alpha")
	cases := map[string]map[string]any{}
	unknown := node.request(t, good)
	unknown["secret"] = strings.Repeat("u", 43)
	cases["unknown secret"] = unknown
	wrongName := node.request(t, good)
	wrongName["node_name"] = "beta"
	cases["token for another node name"] = wrongName
	revokedRequest := node.request(t, revoked)
	revokedRequest["node_name"] = "gone"
	cases["revoked token"] = revokedRequest
	expiredRequest := node.request(t, good)
	expiredRequest["secret"] = strings.Repeat("e", 43)
	cases["expired token"] = expiredRequest
	var bodies []string
	for name, request := range cases {
		w := h.public(http.MethodPost, enrollPath, request, map[string]string{"X-Correlation-ID": "same"})
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		bodies = append(bodies, w.Body.String())
	}
	for _, body := range bodies[1:] {
		if body != bodies[0] {
			t.Fatalf("the answers differ, so one reveals more than the other:\n%s\n%s", bodies[0], body)
		}
	}
	// None of those spent the good token.
	if w := h.public(http.MethodPost, enrollPath, node.request(t, good), nil); w.Code != http.StatusOK {
		t.Fatalf("the good token was spent by other attempts: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", http.MethodDelete, tokenPath+"/"+good.ID, nil); w.Code != http.StatusNotFound {
		t.Fatalf("revoking a spent token: %d", w.Code)
	}
}

func TestRepeatedWrongTokensFromOneAddressAreSlowedDown(t *testing.T) {
	h := newEnrollHarness(t)
	node := newNodeIdentity(t, "node-1", "alpha")
	request := map[string]any{"secret": strings.Repeat("x", 43), "node_name": "alpha", "node_id": "node-1", "node_fingerprint": "AB", "api_endpoint": "https://node.lan:8080", "csr_pem": node.csr(t, "node-1"), "operational_token": strings.Repeat("o", 43)}
	for i := 0; i < 5; i++ {
		if w := h.public(http.MethodPost, enrollPath, request, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := h.public(http.MethodPost, enrollPath, request, nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("after five failures: %d", w.Code)
	}
	// Another address is not affected.
	other := httptest.NewRequest(http.MethodPost, enrollPath, bytes.NewReader(mustJSON(request)))
	other.RemoteAddr = "10.1.1.1:5000"
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, other)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("another address: %d", rec.Code)
	}
}

func mustJSON(v any) []byte { out, _ := json.Marshal(v); return out }

func TestMalformedRequestsAreRefusedWithoutSpendingTheToken(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha"})
	node := newNodeIdentity(t, "node-1", "alpha")
	mutate := func(key string, value any) map[string]any {
		r := node.request(t, token)
		r[key] = value
		return r
	}
	for name, request := range map[string]map[string]any{
		"http endpoint":      mutate("api_endpoint", "http://node.lan:8080"),
		"endpoint with path": mutate("api_endpoint", "https://node.lan:8080/x"),
		"endpoint with user": mutate("api_endpoint", "https://u@node.lan"),
		"no endpoint":        mutate("api_endpoint", ""),
		"csr for another id": mutate("csr_pem", node.csr(t, "node-9")),
		"garbage csr":        mutate("csr_pem", "nope"),
		"short operational":  mutate("operational_token", "short"),
		"long operational":   mutate("operational_token", strings.Repeat("o", 200)),
		"id with a slash":    mutate("node_id", "a/b"),
		"empty node id":      mutate("node_id", ""),
		"huge fingerprint":   mutate("node_fingerprint", strings.Repeat("f", 300)),
		"short secret":       mutate("secret", "short"),
		"bad name":           mutate("node_name", "a\x07"),
	} {
		if w := h.public(http.MethodPost, enrollPath, request, nil); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := h.public(http.MethodPost, enrollPath, map[string]any{"surprise": 1}, nil); w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", w.Code)
	}
	if w := h.public(http.MethodPost, enrollPath, node.request(t, token), nil); w.Code != http.StatusOK {
		t.Fatalf("the token did not survive malformed requests: %d %s", w.Code, w.Body)
	}
}

func TestAnEnrollmentThatNeedsApprovalWaitsForAnAdministrator(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha", "approval": "manual"})
	node := newNodeIdentity(t, "node-1", "alpha")
	w := h.public(http.MethodPost, enrollPath, node.request(t, token), nil)
	var pending struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
		Poll      string `json:"poll_secret"`
	}
	decodeBody(t, w, &pending)
	if w.Code != http.StatusAccepted || pending.Status != "pending" || pending.RequestID == "" || len(pending.Poll) < 40 || strings.Contains(w.Body.String(), "certificate_pem") {
		t.Fatalf("pending: %d %s", w.Code, w.Body)
	}
	if _, err := h.storage.GetNode(context.Background(), "node-1"); err == nil {
		t.Fatal("the node was registered before anyone approved it")
	}
	poll := func(secret string) *httptest.ResponseRecorder {
		return h.public(http.MethodGet, enrollPath+"/"+pending.RequestID, nil, map[string]string{"Authorization": "Bearer " + secret})
	}
	if w := poll(pending.Poll); w.Code != http.StatusAccepted {
		t.Fatalf("poll while pending: %d", w.Code)
	}
	for name, secret := range map[string]string{"wrong": "nope", "empty": "", "the join secret": token.secret()} {
		if w := poll(secret); w.Code != http.StatusUnauthorized {
			t.Errorf("poll with %s secret: %d", name, w.Code)
		}
	}
	// The administrator sees what the node announced, to compare.
	list := h.do("admin", http.MethodGet, "/api/v1/control-tower/enrollments?state=pending", nil)
	var listed struct {
		Items []store.Enrollment `json:"items"`
	}
	decodeBody(t, list, &listed)
	if len(listed.Items) != 1 || listed.Items[0].NodeFingerprint != "AB:CD" || listed.Items[0].NodeID != "node-1" || listed.Items[0].RemoteAddr != "10.9.8.7" {
		t.Fatalf("pending list: %+v", listed.Items)
	}
	if strings.Contains(list.Body.String(), "CERTIFICATE REQUEST") || strings.Contains(list.Body.String(), pending.Poll) {
		t.Fatal("the list carries the request or the poll secret")
	}
	approve := "/api/v1/control-tower/enrollments/" + pending.RequestID + "/approve"
	if w := h.do("operator", http.MethodPost, approve, nil); w.Code != http.StatusForbidden {
		t.Fatalf("operator approved: %d", w.Code)
	}
	if w := h.do("admin", http.MethodPost, approve, nil); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	done := poll(pending.Poll)
	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), `"status":"issued"`) || !strings.Contains(done.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("poll after approval: %d %s", done.Code, done.Body)
	}
	if _, err := h.storage.GetNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("the node was not registered after approval: %v", err)
	}
	if w := h.do("admin", http.MethodPost, approve, nil); w.Code != http.StatusConflict {
		t.Fatalf("approving twice: %d", w.Code)
	}
	if w := h.do("admin", http.MethodPost, "/api/v1/control-tower/enrollments/"+pending.RequestID+"/reject", nil); w.Code != http.StatusConflict {
		t.Fatalf("rejecting what was approved: %d", w.Code)
	}
}

func TestARejectedEnrollmentTellsTheNodeWhy(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha", "approval": "manual"})
	node := newNodeIdentity(t, "node-1", "alpha")
	var pending struct {
		RequestID string `json:"request_id"`
		Poll      string `json:"poll_secret"`
	}
	decodeBody(t, h.public(http.MethodPost, enrollPath, node.request(t, token), nil), &pending)
	reject := "/api/v1/control-tower/enrollments/" + pending.RequestID + "/reject"
	if w := h.do("operator", http.MethodPost, reject, map[string]any{"note": "mine"}); w.Code != http.StatusForbidden {
		t.Fatalf("an operator rejected an enrollment: %d", w.Code)
	}
	if still, _ := h.storage.GetEnrollment(context.Background(), pending.RequestID, time.Now()); still.State != store.EnrollmentPending {
		t.Fatalf("a refused rejection still decided it: %s", still.State)
	}
	if w := h.do("admin", http.MethodPost, reject, map[string]any{"note": strings.Repeat("n", 201)}); w.Code != http.StatusBadRequest {
		t.Fatalf("long note: %d", w.Code)
	}
	if w := h.do("admin", http.MethodPost, reject, map[string]any{"note": "not this host"}); w.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", w.Code, w.Body)
	}
	w := h.public(http.MethodGet, enrollPath+"/"+pending.RequestID, nil, map[string]string{"Authorization": "Bearer " + pending.Poll})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not this host") {
		t.Fatalf("poll after rejection: %d %s", w.Code, w.Body)
	}
	if _, err := h.storage.GetNode(context.Background(), "node-1"); err == nil {
		t.Fatal("a rejected node was registered")
	}
}

func TestAnEnrollmentNobodyDecidedExpires(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha", "approval": "manual"})
	node := newNodeIdentity(t, "node-1", "alpha")
	var pending struct {
		RequestID string `json:"request_id"`
		Poll      string `json:"poll_secret"`
	}
	decodeBody(t, h.public(http.MethodPost, enrollPath, node.request(t, token), nil), &pending)
	// Time passes: rewrite the stored deadline into the past.
	if _, err := h.storage.ExpireEnrollments(context.Background(), time.Now().Add(store.EnrollmentLifetime+time.Minute)); err != nil {
		t.Fatal(err)
	}
	w := h.public(http.MethodGet, enrollPath+"/"+pending.RequestID, nil, map[string]string{"Authorization": "Bearer " + pending.Poll})
	if w.Code != http.StatusGone {
		t.Fatalf("poll after expiry: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", http.MethodPost, "/api/v1/control-tower/enrollments/"+pending.RequestID+"/approve", nil); w.Code != http.StatusConflict {
		t.Fatalf("approving an expired enrollment: %d", w.Code)
	}
}

func TestAManualRetryGetsANewPollSecretAndTheOldOneStopsWorking(t *testing.T) {
	h := newEnrollHarness(t)
	token := h.token(t, map[string]any{"node_name": "alpha", "approval": "manual"})
	node := newNodeIdentity(t, "node-1", "alpha")
	request := node.request(t, token)
	var first, second struct {
		RequestID string `json:"request_id"`
		Poll      string `json:"poll_secret"`
	}
	decodeBody(t, h.public(http.MethodPost, enrollPath, request, nil), &first)
	w := h.public(http.MethodPost, enrollPath, request, nil)
	decodeBody(t, w, &second)
	if w.Code != http.StatusAccepted || second.RequestID != first.RequestID || second.Poll == first.Poll || second.Poll == "" {
		t.Fatalf("retry: %d %+v %+v", w.Code, first, second)
	}
	poll := func(secret string) int {
		return h.public(http.MethodGet, enrollPath+"/"+first.RequestID, nil, map[string]string{"Authorization": "Bearer " + secret}).Code
	}
	if poll(first.Poll) != http.StatusUnauthorized || poll(second.Poll) != http.StatusAccepted {
		t.Fatal("the old poll secret still works or the new one does not")
	}
}

func TestEnrollingAKnownNodeUpdatesItInsteadOfDuplicatingIt(t *testing.T) {
	h := newEnrollHarness(t)
	now := time.Now().UTC()
	sealed, _ := security.Encrypt(make([]byte, 32), "old-token")
	if err := h.storage.SaveNode(context.Background(), store.Node{ID: "node-1", Name: "Renamed by an admin", Endpoint: "http://10.0.0.5:8080", TokenEncrypted: sealed, State: "online", CreatedAt: now.Add(-time.Hour), UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := h.token(t, map[string]any{"node_name": "alpha"})
	if w := h.public(http.MethodPost, enrollPath, newNodeIdentity(t, "node-1", "alpha").request(t, token), nil); w.Code != 200 {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	got, err := h.storage.GetNode(context.Background(), "node-1")
	if err != nil || got.Name != "Renamed by an admin" || got.Endpoint != "https://node.lan:8080" {
		t.Fatalf("node: %+v %v", got, err)
	}
	if opened, _ := security.Decrypt(make([]byte, 32), got.TokenEncrypted); opened != strings.Repeat("o", 43) {
		t.Fatal("the token was not replaced")
	}
	nodes, _ := h.storage.ListNodes(context.Background())
	if len(nodes) != 2 { // the harness's own node plus this one
		t.Fatalf("%d nodes", len(nodes))
	}
}

func TestWithoutManagedTLSEveryEnrollmentRouteIsOff(t *testing.T) {
	h := newTypedHarness(t, false, func(*http.Request) (int, http.Header, string) { return 404, nil, "{}" })
	for _, route := range [][2]string{{"POST", tokenPath}, {"GET", tokenPath}, {"GET", "/api/v1/control-tower/enrollments"}, {"POST", enrollPath}, {"GET", enrollPath + "/x"}} {
		w := h.do("admin", route[0], route[1], map[string]any{"node_name": "n"})
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "managed_tls_disabled") {
			t.Errorf("%s %s: %d %s", route[0], route[1], w.Code, w.Body)
		}
	}
}
