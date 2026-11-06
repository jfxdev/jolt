package join

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/trust"
	"github.com/jfxdev/jolt/backend/internal/trust/trusttest"
)

type memoryStore struct {
	value entities.ManagedTrust
	set   bool
}

func (s *memoryStore) GetManagedTrust(context.Context) (entities.ManagedTrust, error) {
	if !s.set {
		return entities.ManagedTrust{}, contracts.ErrNotFound
	}
	return s.value, nil
}
func (s *memoryStore) PutManagedTrust(_ context.Context, v entities.ManagedTrust) error {
	s.value, s.set = v, true
	return nil
}

type memoryTokens struct {
	state entities.OperationalTokenState
	set   bool
}

func (t *memoryTokens) GetOperationalTokenState(context.Context) (entities.OperationalTokenState, error) {
	if !t.set {
		return entities.OperationalTokenState{}, contracts.ErrNotFound
	}
	return t.state, nil
}
func (t *memoryTokens) RecoverOperationalToken(_ context.Context, hash, _ string, _ time.Time) error {
	t.state, t.set = entities.OperationalTokenState{ActiveHash: hash, EnvTokenDisabled: true}, true
	return nil
}

// stub plays a Control Tower: it serves the root, and answers the enrollment
// the way the test says.
type stub struct {
	t      *testing.T
	ca     *trusttest.CA
	server *httptest.Server

	mu       sync.Mutex
	posts    int
	polls    int
	secrets  []string
	requests []enrollRequest
	// behaviour
	failFirst   int    // answer 503 this many times before anything else
	pendingFor  int    // answer pending for this many polls
	rejectNote  string // when set, the poll ends in a rejection
	status      int    // when set, the POST answers this status with no body
	bundleCA    *trusttest.CA
	wrongKey    bool // issue the certificate for another key
	issuedBytes []byte
	gone        bool          // the poll answers 410, as for an expired request
	serverCA    *trusttest.CA // signs the TLS certificate; the root served is always ca's
}

func newStub(t *testing.T) *stub {
	t.Helper()
	ca := trusttest.NewAt(t, time.Now())
	s := &stub{t: t, ca: ca, bundleCA: ca}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return s.start(key)
}

// newStubSignedBy serves one authority's public root behind a certificate from
// another: what a man in the middle who has read the public root can do.
func newStubSignedBy(t *testing.T) *stub {
	t.Helper()
	ca := trusttest.NewAt(t, time.Now())
	s := &stub{t: t, ca: ca, bundleCA: ca, serverCA: trusttest.NewAt(t, time.Now())}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return s.start(key)
}

func (s *stub) start(key *ecdsa.PrivateKey) *stub {
	t, ca := s.t, s.ca
	signer := ca
	if s.serverCA != nil {
		signer = s.serverCA
	}
	leaf := signer.Leaf(t, &key.PublicKey, "control", x509.ExtKeyUsageServerAuth, time.Now().Add(24*time.Hour), "127.0.0.1")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jolt/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, trusttest.PEM(ca.Root))
	})
	mux.HandleFunc("POST /api/v1/control-tower/enroll", s.enroll)
	mux.HandleFunc("GET /api/v1/control-tower/enroll/{id}", s.poll)
	s.server = httptest.NewUnstartedServer(mux)
	s.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, signer.Issuer.Raw}, PrivateKey: key}}}
	s.server.StartTLS()
	t.Cleanup(s.server.Close)
	return s
}

func (s *stub) token() Token {
	return Token{Secret: strings.Repeat("s", 43), RootPin: s.ca.Pin(), ControlURL: s.server.URL}
}

func (s *stub) issue(request enrollRequest) enrollResponse {
	block, _ := pem.Decode([]byte(request.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		s.t.Fatalf("the node sent a bad request: %v", err)
	}
	public := csr.PublicKey
	if s.wrongKey {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		public = &other.PublicKey
	}
	cert := s.ca.Leaf(s.t, public, csr.Subject.CommonName, x509.ExtKeyUsageServerAuth, time.Now().Add(90*24*time.Hour), "node.lan")
	bundle, _ := s.bundleCA.Bundle(s.t, 1, "k1", nil, "k1").Marshal()
	return enrollResponse{Status: "issued", Certificate: trusttest.PEM(cert, s.ca.Issuer), Bundle: bundle}
}

func (s *stub) enroll(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFirst > 0 {
		s.failFirst--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var request enrollRequest
	_ = json.NewDecoder(r.Body).Decode(&request)
	s.posts++
	s.secrets = append(s.secrets, request.Secret)
	s.requests = append(s.requests, request)
	if s.status != 0 {
		w.WriteHeader(s.status)
		_, _ = io.WriteString(w, `{"error":{"code":"x"}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.pendingFor > 0 || s.rejectNote != "" || s.gone {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(enrollResponse{Status: "pending", RequestID: "enr_1", PollSecret: "poll-secret", ExpiresAt: time.Now().Add(time.Minute)})
		return
	}
	_ = json.NewEncoder(w).Encode(s.issue(request))
}

func (s *stub) poll(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.polls++
	if r.Header.Get("Authorization") != "Bearer poll-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.gone {
		w.WriteHeader(http.StatusGone)
		return
	}
	if s.rejectNote != "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(enrollResponse{Status: "rejected", Note: s.rejectNote})
		return
	}
	if s.polls <= s.pendingFor {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(enrollResponse{Status: "pending", RequestID: "enr_1"})
		return
	}
	_ = json.NewEncoder(w).Encode(s.issue(s.requests[0]))
}

type harness struct {
	manager *trust.Manager
	store   *memoryStore
	tokens  *memoryTokens
	options Options
}

func newHarness(t *testing.T, s *stub) *harness {
	t.Helper()
	store := &memoryStore{}
	manager, err := trust.Load(context.Background(), store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens := &memoryTokens{}
	return &harness{manager: manager, store: store, tokens: tokens, options: Options{
		Token: s.token(), NodeName: "alpha", NodeID: "node-1", Fingerprint: "AB:CD", APIEndpoint: "https://node.lan:8080",
		Manager: manager, Tokens: tokens, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Deadline: 20 * time.Second, PollMin: 10 * time.Millisecond, PollMax: 20 * time.Millisecond,
	}}
}

func TestANodeEnrollsWithAValidToken(t *testing.T) {
	s := newStub(t)
	h := newHarness(t, s)
	if err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if !h.manager.Managed() || h.manager.BundleVersion() != 1 {
		t.Fatal("the node is not enrolled")
	}
	if len(s.requests) != 1 {
		t.Fatalf("requests: %d", len(s.requests))
	}
	request := s.requests[0]
	if request.Secret != strings.Repeat("s", 43) || request.NodeName != "alpha" || request.NodeID != "node-1" || request.NodeFingerprint != "AB:CD" || request.APIEndpoint != "https://node.lan:8080" {
		t.Fatalf("request: %+v", request)
	}
	// The node chose its operational token, told the Control Tower, and keeps only its hash.
	sum := sha256.Sum256([]byte(request.OperationalToken))
	if len(request.OperationalToken) < 40 || h.store.value.OperationalHash != hex.EncodeToString(sum[:]) || h.tokens.state.ActiveHash != hex.EncodeToString(sum[:]) || !h.tokens.state.EnvTokenDisabled {
		t.Fatal("the operational token was not installed")
	}
	if strings.Contains(h.store.value.Bundle, request.OperationalToken) || strings.Contains(h.store.value.APICertPEM, request.OperationalToken) {
		t.Fatal("the token itself is stored")
	}
}

func TestANodeThatCannotMatchThePinSendsNothing(t *testing.T) {
	s := newStub(t)
	h := newHarness(t, s)
	h.options.Token.RootPin = trusttest.NewAt(t, time.Now()).Pin()
	err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want a fingerprint error, got %v", err)
	}
	if s.posts != 0 || len(s.secrets) != 0 {
		t.Fatalf("the join secret went to a server that did not prove itself: %d posts", s.posts)
	}
	if h.manager.Managed() {
		t.Fatal("enrolled against the wrong root")
	}
}

func TestAnImpostorServingItsOwnRootUnderTheRightNameSendsNothing(t *testing.T) {
	real := newStub(t)
	impostor := newStub(t) // a different authority at the address the token names
	h := newHarness(t, real)
	h.options.Token.ControlURL = impostor.server.URL
	if err := Run(context.Background(), h.options); err == nil {
		t.Fatal("enrolled with an impostor")
	}
	if impostor.posts != 0 {
		t.Fatal("the impostor received the secret")
	}
}

func TestAPendingEnrollmentWaitsForTheDecisionAndThenEnrolls(t *testing.T) {
	s := newStub(t)
	s.pendingFor = 2
	h := newHarness(t, s)
	if err := Run(context.Background(), h.options); err != nil {
		t.Fatal(err)
	}
	if !h.manager.Managed() || s.polls < 3 || s.posts != 1 {
		t.Fatalf("managed=%v polls=%d posts=%d", h.manager.Managed(), s.polls, s.posts)
	}
}

func TestARejectedEnrollmentEndsWithTheReason(t *testing.T) {
	s := newStub(t)
	s.rejectNote = "not this host"
	h := newHarness(t, s)
	err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "not this host") {
		t.Fatalf("got %v", err)
	}
	if h.manager.Managed() {
		t.Fatal("enrolled after a rejection")
	}
}

func TestATemporaryFailureIsRetriedButARefusalIsNot(t *testing.T) {
	s := newStub(t)
	s.failFirst = 2
	h := newHarness(t, s)
	if err := Run(context.Background(), h.options); err != nil {
		t.Fatalf("a temporary failure ended the attempt: %v", err)
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusUnprocessableEntity, http.StatusBadRequest} {
		refusing := newStub(t)
		refusing.status = status
		refused := newHarness(t, refusing)
		if err := Run(context.Background(), refused.options); err == nil {
			t.Errorf("status %d: enrolled", status)
		}
		if refusing.posts != 1 {
			t.Errorf("status %d: retried %d times", status, refusing.posts)
		}
	}
}

func TestWhatTheControlTowerSendsIsCheckedBeforeItIsKept(t *testing.T) {
	foreign := newStub(t)
	foreign.bundleCA = trusttest.NewAt(t, time.Now()) // a bundle from another authority
	h := newHarness(t, foreign)
	if err := Run(context.Background(), h.options); err == nil || h.manager.Managed() {
		t.Fatalf("a bundle from another authority was kept: %v", err)
	}
	wrong := newStub(t)
	wrong.wrongKey = true // a certificate for a key the node does not have
	h = newHarness(t, wrong)
	if err := Run(context.Background(), h.options); err == nil || h.manager.Managed() || h.store.set {
		t.Fatalf("a certificate for another key was kept: %v", err)
	}
	if h.tokens.set {
		t.Fatal("a token was installed for an enrollment that failed")
	}
}

func TestTheAttemptEndsAtItsDeadline(t *testing.T) {
	s := newStub(t)
	s.pendingFor = 1 << 30
	h := newHarness(t, s)
	h.options.Deadline = 300 * time.Millisecond
	start := time.Now()
	if err := Run(context.Background(), h.options); err == nil {
		t.Fatal("waited forever and succeeded")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the deadline was ignored")
	}
}

func TestTokenParsing(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	secret := strings.Repeat("s", 43)
	good := "jolt-join:v1:" + secret + ":" + pin + ":https://control.lan:8090"
	token, err := ParseToken(" " + good + "\n")
	if err != nil || token.Secret != secret || token.RootPin != pin || token.ControlURL != "https://control.lan:8090" {
		t.Fatalf("good token: %+v %v", token, err)
	}
	if token, err := ParseToken(good + "/"); err != nil || token.ControlURL != "https://control.lan:8090" {
		t.Fatalf("trailing slash: %+v %v", token, err)
	}
	for name, value := range map[string]string{
		"empty":          "",
		"wrong prefix":   "jolt-join:v2:" + secret + ":" + pin + ":https://c",
		"no url":         "jolt-join:v1:" + secret + ":" + pin,
		"short secret":   "jolt-join:v1:short:" + pin + ":https://c",
		"short pin":      "jolt-join:v1:" + secret + ":abcd:https://c",
		"uppercase pin":  "jolt-join:v1:" + secret + ":" + strings.ToUpper(pin) + ":https://c",
		"non-hex pin":    "jolt-join:v1:" + secret + ":" + strings.Repeat("zz", 32) + ":https://c",
		"http url":       "jolt-join:v1:" + secret + ":" + pin + ":http://control.lan",
		"url with path":  "jolt-join:v1:" + secret + ":" + pin + ":https://control.lan/x",
		"url with user":  "jolt-join:v1:" + secret + ":" + pin + ":https://u@control.lan",
		"url with query": "jolt-join:v1:" + secret + ":" + pin + ":https://control.lan?x=1",
	} {
		if _, err := ParseToken(value); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestAServerThatKnowsOnlyThePublicRootCannotTakeTheSecret(t *testing.T) {
	mitm := newStubSignedBy(t)
	h := newHarness(t, mitm)
	h.options.Deadline = 2 * time.Second
	if err := Run(context.Background(), h.options); err == nil {
		t.Fatal("enrolled through a server whose certificate the pinned root never signed")
	}
	if mitm.posts != 0 {
		t.Fatal("the secret reached a server that could not prove itself under the pinned root")
	}
}

func TestAnExpiredRequestEndsTheAttemptWithoutWaiting(t *testing.T) {
	s := newStub(t)
	s.gone = true
	h := newHarness(t, s)
	start := time.Now()
	err := Run(context.Background(), h.options)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 5*time.Second || s.polls != 1 {
		t.Fatalf("kept asking an expired request (%d polls, %s)", s.polls, time.Since(start))
	}
}
