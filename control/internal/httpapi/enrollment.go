package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

const (
	enrollmentResource = "control-tower/enrollments"
	// enrollFailureKey groups the failed attempts of one address, so guessing a
	// token is slow and a flood from one place does not lock out the others.
	enrollFailurePrefix = "enroll|"
	maxEnrollBody       = 64 << 10
	defaultTokenMinutes = 15
	maxTokenMinutes     = 24 * 60
)

// joinTokenURL is how a token names this Control Tower. The node needs an
// address that reaches it and that the HTTPS certificate covers, which is the
// public base URL.
func (s *Server) joinTokenURL() (string, bool) {
	base := s.config.PublicBaseURL
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	return strings.TrimRight(base, "/"), true
}

type createTokenRequest struct {
	NodeName     string `json:"node_name"`
	Approval     string `json:"approval"`
	ValidMinutes int    `json:"valid_minutes"`
}

type createTokenResponse struct {
	TokenID    string    `json:"token_id"`
	Token      string    `json:"token"`
	NodeName   string    `json:"node_name"`
	Approval   string    `json:"approval"`
	ExpiresAt  time.Time `json:"expires_at"`
	ControlURL string    `json:"control_url"`
}

func validNodeName(name string) bool {
	return name != "" && len(name) <= 64 && utf8.ValidString(name) && name == strings.TrimSpace(name) && !strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// createJoinToken makes the one-use token an administrator hands to a node.
// The secret is shown once; only its hash is kept.
func (s *Server) createJoinToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", enrollmentResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	var request createTokenRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.NodeName = strings.TrimSpace(request.NodeName)
	if !validNodeName(request.NodeName) {
		writeError(w, r, http.StatusBadRequest, "invalid_node_name", "Informe o nome do node (até 64 caracteres).")
		return
	}
	minutes := request.ValidMinutes
	if minutes == 0 {
		minutes = defaultTokenMinutes
	}
	if minutes < 1 || minutes > maxTokenMinutes {
		writeError(w, r, http.StatusBadRequest, "invalid_validity", "A validade vai de 1 minuto a 24 horas.")
		return
	}
	// No token can be weaker than the policy of this Control Tower.
	approval := s.config.EnrollmentApproval
	if approval == "" {
		approval = "auto"
	}
	switch request.Approval {
	case "", "auto", "manual":
		if request.Approval == "manual" {
			approval = "manual"
		}
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_approval", "A aprovação deve ser auto ou manual.")
		return
	}
	address, ok := s.joinTokenURL()
	if !ok {
		writeError(w, r, http.StatusConflict, "public_url_required", "Defina CONTROL_TOWER_PUBLIC_BASE_URL com o endereço https que os nodes alcançam.")
		return
	}
	secret, hash, err := security.RandomToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	id := randomID("jt")
	token := store.JoinToken{ID: id, SecretHash: hash, NodeName: request.NodeName, Approval: approval, CreatedBy: currentUser(r).ID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(minutes) * time.Minute)}
	if err := s.store.CreateJoinToken(r.Context(), token); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "create", "enrollments/tokens/"+id, "allowed")
	writeJSON(w, http.StatusCreated, createTokenResponse{
		TokenID: id, NodeName: request.NodeName, Approval: approval, ExpiresAt: token.ExpiresAt, ControlURL: address,
		Token: "jolt-join:v1:" + secret + ":" + authority.RootFingerprint() + ":" + address,
	})
}

func (s *Server) listJoinTokens(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", enrollmentResource) {
		return
	}
	if s.authority(w, r) == nil {
		return
	}
	tokens, err := s.store.ListJoinTokens(r.Context(), 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if tokens == nil {
		tokens = []store.JoinToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens})
}

func (s *Server) revokeJoinToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "delete", enrollmentResource) {
		return
	}
	if s.authority(w, r) == nil {
		return
	}
	id := r.PathValue("tokenID")
	if err := s.store.RevokeJoinToken(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "token_not_found", "Token não encontrado ou já usado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", "enrollments/tokens/"+id, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", enrollmentResource) {
		return
	}
	if s.authority(w, r) == nil {
		return
	}
	state := r.URL.Query().Get("state")
	switch state {
	case "", store.EnrollmentPending, store.EnrollmentIssued, store.EnrollmentRejected, store.EnrollmentExpired:
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_state", "Estado inválido.")
		return
	}
	items, err := s.store.ListEnrollments(r.Context(), state, 100, time.Now().UTC())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []store.Enrollment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type enrollRequest struct {
	Secret           string `json:"secret"`
	NodeName         string `json:"node_name"`
	NodeID           string `json:"node_id"`
	NodeFingerprint  string `json:"node_fingerprint"`
	APIEndpoint      string `json:"api_endpoint"`
	CSR              string `json:"csr_pem"`
	OperationalToken string `json:"operational_token"`
}

// enrollPayload is what a node receives once it is enrolled. Nothing in it is
// secret: the certificate and the bundle are public.
type enrollPayload struct {
	Status      string          `json:"status"`
	Certificate string          `json:"certificate_pem,omitempty"`
	Bundle      json.RawMessage `json:"bundle,omitempty"`
	RequestID   string          `json:"request_id,omitempty"`
	PollSecret  string          `json:"poll_secret,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	Note        string          `json:"note,omitempty"`
}

func (s *Server) enrollFailed(r *http.Request) {
	_ = s.store.RegisterLoginFailure(r.Context(), enrollFailurePrefix+clientIP(r), time.Now().UTC())
	s.store.Audit(r.Context(), "", "enroll", "enrollments", "denied", r.Header.Get("X-Correlation-ID"))
}

func validAPIEndpoint(value string) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || len(value) > 253 {
		return nil, false
	}
	return parsed, true
}

// enroll is the public endpoint a node calls with a join token. The token is
// the only credential, so everything about it answers the same way when wrong.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	now := time.Now().UTC()
	key := enrollFailurePrefix + clientIP(r)
	if until, err := s.store.LoginLockedUntil(r.Context(), key, now); err != nil {
		s.fail(w, r, err)
		return
	} else if !until.IsZero() {
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
		writeError(w, r, http.StatusTooManyRequests, "too_many_attempts", "Muitas tentativas. Tente novamente mais tarde.")
		return
	}
	var request enrollRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "Corpo JSON inválido.")
		return
	}
	endpoint, ok := validAPIEndpoint(request.APIEndpoint)
	block, rest := pem.Decode([]byte(request.CSR))
	switch {
	case len(request.Secret) < 20 || len(request.Secret) > 128,
		!validNodeName(request.NodeName),
		!signedauth.ValidKeyID(request.NodeID),
		len(request.NodeFingerprint) > 200 || !utf8.ValidString(request.NodeFingerprint),
		len(request.OperationalToken) < 32 || len(request.OperationalToken) > 128,
		!ok,
		block == nil || block.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "":
		writeError(w, r, http.StatusUnprocessableEntity, "invalid_enrollment", "O pedido de adesão está incompleto ou malformado.")
		return
	}
	if csr, err := x509.ParseCertificateRequest(block.Bytes); err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != request.NodeID {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid_enrollment", "O pedido de adesão está incompleto ou malformado.")
		return
	}
	sealed, err := security.Encrypt(s.config.EncryptionKey, request.OperationalToken)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pollSecret, pollHash, err := security.RandomToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	csrDigest := sha256.Sum256([]byte(strings.TrimSpace(request.CSR)))
	enrollment := store.Enrollment{
		ID: randomID("enr"), State: store.EnrollmentPending, NodeName: request.NodeName, NodeID: request.NodeID, NodeFingerprint: request.NodeFingerprint,
		APIEndpoint: strings.TrimRight(endpoint.String(), "/"), RemoteAddr: clientIP(r), CSRPEM: request.CSR, CSRHash: hex.EncodeToString(csrDigest[:]),
		OperationalEncrypted: sealed, PollHash: pollHash, CreatedAt: now, ExpiresAt: now.Add(store.EnrollmentLifetime),
	}
	token, err := s.store.StartEnrollment(r.Context(), security.Digest(request.Secret), enrollment, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.enrollFailed(r)
		writeError(w, r, http.StatusUnauthorized, "invalid_join_token", "Token de adesão inválido, expirado ou já usado.")
		return
	case errors.Is(err, store.ErrTooManyEnrollments):
		writeError(w, r, http.StatusTooManyRequests, "too_many_pending", "Há adesões demais aguardando aprovação.")
		return
	case errors.Is(err, store.ErrTokenUsed):
		s.replayEnrollment(w, r, token, enrollment.CSRHash)
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.store.Audit(r.Context(), "", "enroll", "enrollments/"+enrollment.ID, "started", r.Header.Get("X-Correlation-ID"))
	if token.Approval == "manual" {
		writeJSON(w, http.StatusAccepted, enrollPayload{Status: "pending", RequestID: enrollment.ID, PollSecret: pollSecret, ExpiresAt: &enrollment.ExpiresAt})
		return
	}
	payload, status, err := s.completeEnrollment(r.Context(), authority, enrollment, "token:"+token.ID, now)
	if err != nil {
		writeError(w, r, status, "enrollment_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// replayEnrollment answers a retry of a request that already spent its token:
// the same request gets the same answer, any other gets nothing. This is what
// lets a node that lost the answer ask again without a second token.
func (s *Server) replayEnrollment(w http.ResponseWriter, r *http.Request, token store.JoinToken, csrHash string) {
	now := time.Now().UTC()
	existing, err := s.store.GetEnrollment(r.Context(), token.EnrollmentID, now)
	if err != nil || subtle.ConstantTimeCompare([]byte(existing.CSRHash), []byte(csrHash)) != 1 {
		s.enrollFailed(r)
		writeError(w, r, http.StatusUnauthorized, "invalid_join_token", "Token de adesão inválido, expirado ou já usado.")
		return
	}
	switch existing.State {
	case store.EnrollmentIssued:
		var payload enrollPayload
		if json.Unmarshal([]byte(existing.Response), &payload) != nil {
			writeError(w, r, http.StatusInternalServerError, "enrollment_failed", "Resposta indisponível.")
			return
		}
		writeJSON(w, http.StatusOK, payload)
	case store.EnrollmentPending:
		authority := s.config.Authority
		if token.Approval != "manual" && authority != nil {
			// The first attempt was cut short before it was answered.
			payload, status, err := s.completeEnrollment(r.Context(), authority, existing, "token:"+token.ID, now)
			if err != nil {
				writeError(w, r, status, "enrollment_failed", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, payload)
			return
		}
		secret, hash, err := security.RandomToken()
		if err != nil || s.store.ReplacePollSecret(r.Context(), existing.ID, hash) != nil {
			writeError(w, r, http.StatusInternalServerError, "enrollment_failed", "Não foi possível retomar a adesão.")
			return
		}
		writeJSON(w, http.StatusAccepted, enrollPayload{Status: "pending", RequestID: existing.ID, PollSecret: secret, ExpiresAt: &existing.ExpiresAt})
	default:
		writeError(w, r, http.StatusForbidden, "enrollment_closed", "A adesão foi encerrada.")
	}
}

// completeEnrollment issues the certificate, registers the node and records the
// answer. It is the one place an enrollment becomes real, whether the token or
// an administrator approved it.
func (s *Server) completeEnrollment(ctx context.Context, authority *pki.Manager, enrollment store.Enrollment, decidedBy string, now time.Time) (enrollPayload, int, error) {
	endpoint, _ := validAPIEndpoint(enrollment.APIEndpoint)
	chain, leaf, err := authority.IssueServerCertificate([]byte(enrollment.CSRPEM), enrollment.NodeID, endpoint.Hostname())
	if err != nil {
		_ = s.store.DecideEnrollment(ctx, enrollment.ID, store.EnrollmentRejected, decidedBy, "o pedido de certificado foi recusado", "", now)
		return enrollPayload{}, http.StatusUnprocessableEntity, errors.New("o pedido de certificado foi recusado")
	}
	existing, err := s.store.GetNode(ctx, enrollment.NodeID)
	node := store.Node{ID: enrollment.NodeID, Name: enrollment.NodeName, Endpoint: strings.TrimRight(endpoint.String(), "/"), TokenEncrypted: enrollment.OperationalEncrypted, State: "online", LastSeenAt: &now, CreatedAt: now, UpdatedAt: now}
	if err == nil {
		node.Name, node.CreatedAt = existing.Name, existing.CreatedAt
	} else if !errors.Is(err, store.ErrNotFound) {
		return enrollPayload{}, http.StatusInternalServerError, errors.New("não foi possível registrar o node")
	}
	bundle := authority.Bundle()
	if err := s.store.SaveNode(ctx, node); err != nil {
		return enrollPayload{}, http.StatusInternalServerError, errors.New("não foi possível registrar o node")
	}
	if err := s.store.SaveManagedNode(ctx, store.ManagedNode{NodeID: node.ID, EnrolledAt: now, BundleVersion: bundle.Version, CertSerial: leaf.SerialNumber.Text(16), CertNotBefore: leaf.NotBefore, CertNotAfter: leaf.NotAfter, CertFingerprint: pki.Fingerprint(leaf), CertIssuer: pki.IssuerSerial(chain)}); err != nil {
		return enrollPayload{}, http.StatusInternalServerError, errors.New("não foi possível registrar o node")
	}
	encoded, err := bundle.Marshal()
	if err != nil {
		return enrollPayload{}, http.StatusInternalServerError, errors.New("pacote de confiança indisponível")
	}
	payload := enrollPayload{Status: "issued", Certificate: chain, Bundle: encoded}
	stored, _ := json.Marshal(payload)
	if err := s.store.DecideEnrollment(ctx, enrollment.ID, store.EnrollmentIssued, decidedBy, "", string(stored), now); err != nil {
		return enrollPayload{}, http.StatusConflict, errors.New("a adesão já foi decidida")
	}
	s.store.Audit(ctx, "", "enroll", "enrollments/"+enrollment.ID, "issued", "")
	return payload, http.StatusOK, nil
}

// pollEnrollment lets a node whose enrollment waits for a person ask how it
// went. The poll secret it was given is the only credential.
func (s *Server) pollEnrollment(w http.ResponseWriter, r *http.Request) {
	if s.authority(w, r) == nil {
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	enrollment, err := s.store.GetEnrollment(r.Context(), r.PathValue("enrollmentID"), time.Now().UTC())
	if err != nil || secret == "" || subtle.ConstantTimeCompare([]byte(enrollment.PollHash), []byte(security.Digest(secret))) != 1 {
		s.enrollFailed(r)
		writeError(w, r, http.StatusUnauthorized, "invalid_join_token", "Token de adesão inválido, expirado ou já usado.")
		return
	}
	switch enrollment.State {
	case store.EnrollmentPending:
		writeJSON(w, http.StatusAccepted, enrollPayload{Status: "pending", RequestID: enrollment.ID, ExpiresAt: &enrollment.ExpiresAt})
	case store.EnrollmentIssued:
		var payload enrollPayload
		if json.Unmarshal([]byte(enrollment.Response), &payload) != nil {
			writeError(w, r, http.StatusInternalServerError, "enrollment_failed", "Resposta indisponível.")
			return
		}
		writeJSON(w, http.StatusOK, payload)
	case store.EnrollmentRejected:
		writeJSON(w, http.StatusForbidden, enrollPayload{Status: "rejected", Note: enrollment.Note})
	default:
		writeJSON(w, http.StatusGone, enrollPayload{Status: "expired"})
	}
}

type decideRequest struct {
	Note string `json:"note"`
}

// approveEnrollment lets an administrator who has compared the fingerprint
// enroll a node that waited for a decision.
func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "update", enrollmentResource) {
		return
	}
	authority := s.authority(w, r)
	if authority == nil {
		return
	}
	now := time.Now().UTC()
	enrollment, err := s.store.GetEnrollment(r.Context(), r.PathValue("enrollmentID"), now)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "enrollment_not_found", "Adesão não encontrada.")
		return
	}
	if enrollment.State != store.EnrollmentPending {
		writeError(w, r, http.StatusConflict, "enrollment_closed", "Esta adesão já foi decidida ou expirou.")
		return
	}
	if _, status, err := s.completeEnrollment(r.Context(), authority, enrollment, "user:"+currentUser(r).ID, now); err != nil {
		writeError(w, r, status, "enrollment_failed", err.Error())
		return
	}
	s.audit(r, "approve", "enrollments/"+enrollment.ID, "allowed")
	done, _ := s.store.GetEnrollment(r.Context(), enrollment.ID, now)
	writeJSON(w, http.StatusOK, done)
}

func (s *Server) rejectEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "update", enrollmentResource) {
		return
	}
	if s.authority(w, r) == nil {
		return
	}
	var request decideRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &request) {
		return
	}
	note := strings.TrimSpace(request.Note)
	if len(note) > 200 || !utf8.ValidString(note) {
		writeError(w, r, http.StatusBadRequest, "invalid_note", "O motivo deve ter até 200 caracteres.")
		return
	}
	now := time.Now().UTC()
	id := r.PathValue("enrollmentID")
	if _, err := s.store.GetEnrollment(r.Context(), id, now); err != nil {
		writeError(w, r, http.StatusNotFound, "enrollment_not_found", "Adesão não encontrada.")
		return
	}
	if err := s.store.DecideEnrollment(r.Context(), id, store.EnrollmentRejected, "user:"+currentUser(r).ID, note, "", now); err != nil {
		writeError(w, r, http.StatusConflict, "enrollment_closed", "Esta adesão já foi decidida ou expirou.")
		return
	}
	s.audit(r, "reject", "enrollments/"+id, "allowed")
	done, _ := s.store.GetEnrollment(r.Context(), id, now)
	writeJSON(w, http.StatusOK, done)
}
