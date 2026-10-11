package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/metrics"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const sessionCookie = "jolt_control_session"

type contextKey string

const (
	userKey      contextKey = "user"
	actorTypeKey contextKey = "actor_type"
	groupKey     contextKey = "group_ids"
)

type Server struct {
	config   config.Config
	store    *store.Store
	client   *http.Client
	registry *metrics.Registry
	log      *slog.Logger
}

// New builds the Control Tower handler. It fails when the configured node TLS
// material cannot be loaded: a node registered as https:// would otherwise
// fail every call with an opaque handshake error.
func New(cfg config.Config, storage *store.Store, logger *slog.Logger) (http.Handler, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	tlsConfig, err := nodeTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsConfig
	return newHandler(cfg, storage, logger, &http.Client{Transport: transport}), nil
}

// nodeTLSConfig trusts an extra CA bundle for node endpoints, so a homelab or
// internal CA works without disabling verification, and presents a client
// certificate when the node requires mutual TLS. With neither configured the
// system trust store applies unchanged.
func nodeTLSConfig(cfg config.Config) (*tls.Config, error) {
	if cfg.NodeCAFile == "" && cfg.NodeClientCertFile == "" {
		return nil, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.NodeCAFile != "" {
		pem, err := os.ReadFile(cfg.NodeCAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CONTROL_TOWER_NODE_CA_FILE contains no usable certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.NodeClientCertFile != "" {
		pair, err := tls.LoadX509KeyPair(cfg.NodeClientCertFile, cfg.NodeClientKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	return tlsConfig, nil
}

func newHandler(cfg config.Config, storage *store.Store, logger *slog.Logger, client *http.Client) http.Handler {
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: time.Second,
		}}
	}
	registry := metrics.NewRegistry()
	registerControlMetrics(registry)
	s := &Server{
		config:   cfg,
		store:    storage,
		client:   client,
		registry: registry,
		log:      logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	if cfg.MetricsToken != "" {
		mux.HandleFunc("GET /metrics", s.metricsHandler)
	}
	mux.HandleFunc("POST /api/v1/control-tower/auth/login", s.login)
	mux.Handle("POST /api/v1/control-tower/auth/logout", s.auth(http.HandlerFunc(s.logout)))
	mux.Handle("GET /api/v1/control-tower/auth/me", s.auth(http.HandlerFunc(s.me)))
	mux.Handle("POST /api/v1/control-tower/auth/permissions", s.auth(http.HandlerFunc(s.permissions)))
	mux.Handle("GET /api/v1/control-tower/users", s.auth(http.HandlerFunc(s.listUsers)))
	mux.Handle("POST /api/v1/control-tower/users", s.auth(http.HandlerFunc(s.createUser)))
	mux.Handle("PATCH /api/v1/control-tower/users/{userID}", s.auth(http.HandlerFunc(s.updateUser)))
	mux.Handle("DELETE /api/v1/control-tower/users/{userID}", s.auth(http.HandlerFunc(s.deleteUser)))
	mux.Handle("GET /api/v1/control-tower/service-accounts", s.auth(http.HandlerFunc(s.listServiceAccounts)))
	mux.Handle("POST /api/v1/control-tower/service-accounts", s.auth(http.HandlerFunc(s.createServiceAccount)))
	mux.Handle("PATCH /api/v1/control-tower/service-accounts/{serviceAccountID}", s.auth(http.HandlerFunc(s.updateServiceAccount)))
	mux.Handle("DELETE /api/v1/control-tower/service-accounts/{serviceAccountID}", s.auth(http.HandlerFunc(s.deleteServiceAccount)))
	mux.Handle("GET /api/v1/control-tower/service-accounts/{serviceAccountID}/tokens", s.auth(http.HandlerFunc(s.listServiceAccountTokens)))
	mux.Handle("POST /api/v1/control-tower/service-accounts/{serviceAccountID}/tokens", s.auth(http.HandlerFunc(s.createServiceAccountToken)))
	mux.Handle("DELETE /api/v1/control-tower/service-accounts/{serviceAccountID}/tokens/{tokenID}", s.auth(http.HandlerFunc(s.revokeServiceAccountToken)))
	mux.Handle("GET /api/v1/control-tower/access-groups", s.auth(http.HandlerFunc(s.listAccessGroups)))
	mux.Handle("POST /api/v1/control-tower/access-groups", s.auth(http.HandlerFunc(s.createAccessGroup)))
	mux.Handle("PATCH /api/v1/control-tower/access-groups/{groupID}", s.auth(http.HandlerFunc(s.updateAccessGroup)))
	mux.Handle("DELETE /api/v1/control-tower/access-groups/{groupID}", s.auth(http.HandlerFunc(s.deleteAccessGroup)))
	mux.Handle("GET /api/v1/control-tower/access-groups/{groupID}/nodes", s.auth(http.HandlerFunc(s.listAccessGroupNodes)))
	mux.Handle("PUT /api/v1/control-tower/access-groups/{groupID}/nodes", s.auth(http.HandlerFunc(s.assignAccessGroupNodes)))
	mux.Handle("GET /api/v1/control-tower/access-groups/{groupID}/policies", s.auth(http.HandlerFunc(s.listAccessGroupPolicies)))
	mux.Handle("PUT /api/v1/control-tower/access-groups/{groupID}/policies", s.auth(http.HandlerFunc(s.assignAccessGroupPolicies)))
	mux.Handle("GET /api/v1/control-tower/policies", s.auth(http.HandlerFunc(s.listPolicies)))
	mux.Handle("POST /api/v1/control-tower/policies", s.auth(http.HandlerFunc(s.createPolicy)))
	mux.Handle("PATCH /api/v1/control-tower/policies/{policyID}", s.auth(http.HandlerFunc(s.updatePolicy)))
	mux.Handle("DELETE /api/v1/control-tower/policies/{policyID}", s.auth(http.HandlerFunc(s.deletePolicy)))
	mux.Handle("GET /api/v1/control-tower/roles", s.auth(http.HandlerFunc(s.listRoles)))
	mux.Handle("POST /api/v1/control-tower/roles", s.auth(http.HandlerFunc(s.createRole)))
	mux.Handle("PATCH /api/v1/control-tower/roles/{roleID}", s.auth(http.HandlerFunc(s.updateRole)))
	mux.Handle("DELETE /api/v1/control-tower/roles/{roleID}", s.auth(http.HandlerFunc(s.deleteRole)))
	mux.Handle("GET /api/v1/control-tower/users/{userID}/policies", s.auth(http.HandlerFunc(s.listUserPolicies)))
	mux.Handle("PUT /api/v1/control-tower/users/{userID}/policies", s.auth(http.HandlerFunc(s.assignUserPolicies)))
	mux.Handle("GET /api/v1/control-tower/users/{userID}/roles", s.auth(http.HandlerFunc(s.listUserRoles)))
	mux.Handle("PUT /api/v1/control-tower/users/{userID}/roles", s.auth(http.HandlerFunc(s.assignUserRoles)))
	mux.Handle("GET /api/v1/control-tower/service-accounts/{serviceAccountID}/policies", s.auth(http.HandlerFunc(s.listServiceAccountPolicies)))
	mux.Handle("PUT /api/v1/control-tower/service-accounts/{serviceAccountID}/policies", s.auth(http.HandlerFunc(s.assignServiceAccountPolicies)))
	mux.Handle("GET /api/v1/control-tower/service-accounts/{serviceAccountID}/groups", s.auth(http.HandlerFunc(s.listServiceAccountGroups)))
	mux.Handle("PUT /api/v1/control-tower/service-accounts/{serviceAccountID}/groups", s.auth(http.HandlerFunc(s.assignServiceAccountGroups)))
	mux.Handle("GET /api/v1/control-tower/audit", s.auth(http.HandlerFunc(s.listAuditEvents)))
	mux.Handle("GET /api/v1/control-tower/nodes", s.auth(http.HandlerFunc(s.listNodes)))
	mux.Handle("POST /api/v1/control-tower/nodes", s.auth(http.HandlerFunc(s.createNode)))
	mux.Handle("POST /api/v1/control-tower/nodes/{nodeID}/rotate-token", s.auth(http.HandlerFunc(s.rotateNodeToken)))
	mux.Handle("POST /api/v1/control-tower/nodes/{nodeID}/rotate-identity", s.auth(http.HandlerFunc(s.rotateNodeIdentity)))
	mux.Handle("POST /api/v1/control-tower/nodes/{nodeID}/distribute-identity-handovers", s.auth(http.HandlerFunc(s.distributeNodeIdentityHandovers)))
	mux.Handle("POST /api/v1/control-tower/nodes/{nodeID}/distribute-mtls-rotation", s.auth(http.HandlerFunc(s.distributeNodeMTLSRotation)))
	mux.Handle("DELETE /api/v1/control-tower/nodes/{nodeID}", s.auth(http.HandlerFunc(s.deleteNode)))
	mux.Handle("GET /api/v1/control-tower/connections", s.auth(http.HandlerFunc(s.listConnections)))
	mux.Handle("POST /api/v1/control-tower/connections", s.auth(http.HandlerFunc(s.createConnectionRequest)))
	mux.Handle("POST /api/v1/control-tower/connections/{requestID}/approve", s.auth(http.HandlerFunc(s.approveConnection)))
	mux.Handle("POST /api/v1/control-tower/connections/{requestID}/reconcile", s.auth(http.HandlerFunc(s.reconcileConnection)))
	mux.Handle("POST /api/v1/control-tower/connections/{requestID}/reject", s.auth(http.HandlerFunc(s.rejectConnection)))
	mux.Handle("POST /api/v1/control-tower/connections/{requestID}/revoke", s.auth(http.HandlerFunc(s.revokeConnection)))
	mux.Handle("GET /api/v1/control-tower/nodes/{nodeID}/trust", s.auth(http.HandlerFunc(s.nodeTrust)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/transfers/targets", s.auth(http.HandlerFunc(s.transferTargets)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/transfers/plan", s.auth(http.HandlerFunc(s.planLogicalTransfer)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/transfers", s.auth(http.HandlerFunc(s.createLogicalTransfer)))
	mux.Handle("GET /api/v1/control-tower/shares", s.auth(http.HandlerFunc(s.listShares)))
	mux.Handle("POST /api/v1/control-tower/shares", s.auth(http.HandlerFunc(s.createShare)))
	mux.Handle("POST /api/v1/control-tower/shares/{shareID}/revoke", s.auth(http.HandlerFunc(s.revokeShare)))
	mux.Handle("DELETE /api/v1/control-tower/shares/{shareID}", s.auth(http.HandlerFunc(s.deleteShare)))
	// Public share endpoints are deliberately outside s.auth: they carry no
	// session and are read-only.
	mux.HandleFunc("GET /api/v1/public/shares/{token}", s.publicShareMetadata)
	mux.HandleFunc("POST /api/v1/public/shares/{token}/unlock", s.publicShareUnlock)
	mux.HandleFunc("GET /api/v1/public/shares/{token}/list", s.publicShareList)
	mux.HandleFunc("GET /api/v1/public/shares/{token}/content", s.publicShareContent)
	mux.HandleFunc("GET /api/v1/public/shares/{token}/archive", s.publicShareArchive)
	mux.Handle("/api/v1/nodes/{nodeID}/{resource...}", s.auth(http.HandlerFunc(s.proxyNode)))
	mux.HandleFunc("/", s.static)
	return s.recover(s.correlation(s.securityHeaders(s.instrument(s.csrf(mux)))))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
			s.authenticateServiceAccount(next, w, r, authorization)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "Faça login para continuar.")
			return
		}
		user, err := s.store.SessionUser(r.Context(), security.Digest(cookie.Value))
		if err != nil || !user.Enabled {
			writeError(w, r, http.StatusUnauthorized, "session_expired", "Sua sessão expirou.")
			return
		}
		ctx := context.WithValue(r.Context(), userKey, user)
		ctx = context.WithValue(ctx, actorTypeKey, "user")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authenticateServiceAccount(next http.Handler, w http.ResponseWriter, r *http.Request, authorization string) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) || strings.TrimSpace(strings.TrimPrefix(authorization, prefix)) == "" {
		writeError(w, r, http.StatusUnauthorized, "invalid_service_token", "Token de conta de serviço inválido.")
		return
	}
	plainToken := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	account, _, err := s.store.AuthenticateServiceAccount(r.Context(), security.Digest(plainToken))
	if err != nil {
		s.store.AuditActor(r.Context(), "", "service_account", "authenticate", "control-tower", "denied", r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusUnauthorized, "invalid_service_token", "Token de conta de serviço inválido, expirado ou revogado.")
		return
	}
	actor := store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: account.Enabled}
	groupIDs, err := s.store.ServiceAccountGroupIDs(r.Context(), account.ID, true)
	if err != nil || len(groupIDs) == 0 {
		writeError(w, r, http.StatusUnauthorized, "api_key_without_active_group", "A API key não possui um grupo de acesso ativo.")
		return
	}
	ctx := context.WithValue(r.Context(), userKey, actor)
	ctx = context.WithValue(ctx, actorTypeKey, "service_account")
	ctx = context.WithValue(ctx, groupKey, groupIDs)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if origin := r.Header.Get("Origin"); origin != "" {
				parsed, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
					writeError(w, r, http.StatusForbidden, "invalid_origin", "Origem da requisição não permitida.")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))
		if id == "" {
			id = randomID("cor")
		}
		r.Header.Set("X-Correlation-ID", id)
		w.Header().Set("X-Correlation-ID", id)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				s.log.Error("request panic", "error", value, "correlation_id", r.Header.Get("X-Correlation-ID"))
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Erro inesperado.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	now := time.Now().UTC()
	key := strings.ToLower(strings.TrimSpace(request.Username)) + "|" + clientIP(r)

	if until, err := s.store.LoginLockedUntil(r.Context(), key, now); err != nil {
		s.fail(w, r, err)
		return
	} else if !until.IsZero() {
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
		s.store.Audit(r.Context(), "", "login", "control-tower", "locked", r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusTooManyRequests, "too_many_attempts", "Muitas tentativas. Tente novamente mais tarde.")
		return
	}

	user, err := s.store.UserByUsername(r.Context(), strings.TrimSpace(request.Username))
	if err != nil || !user.Enabled || !security.VerifyPassword(user.PasswordHash, request.Password) {
		registerCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.registry.Inc("jolt_control_login_failures_total")
		registerErr := s.store.RegisterLoginFailure(registerCtx, key, now)
		cancel()
		if registerErr != nil {
			s.fail(w, r, registerErr)
			return
		}
		s.store.Audit(r.Context(), "", "login", "control-tower", "denied", r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Usuário ou senha inválidos.")
		return
	}
	if err := s.store.ClearLoginFailures(r.Context(), key); err != nil {
		s.fail(w, r, err)
		return
	}
	token, digest, err := security.RandomToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	expires := time.Now().UTC().Add(12 * time.Hour)
	if err := s.store.CreateSession(r.Context(), digest, user.ID, expires); err != nil {
		s.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode,
	})
	// A Secure cookie is dropped by the browser over plain HTTP unless the
	// origin is a secure context such as localhost. Silently issuing one makes
	// login appear to succeed and then fail, so the misconfiguration is
	// reported instead of guessed at.
	if s.config.SecureCookies && !requestIsSecureContext(r) {
		s.log.Error("refusing to issue a Secure session cookie over plaintext HTTP",
			"host", r.Host,
			"hint", "serve the Control Tower over HTTPS, or set CONTROL_TOWER_SECURE_COOKIES=false on a trusted network")
		writeError(w, r, http.StatusMisdirectedRequest, "insecure_transport",
			"A Control Tower exige HTTPS para manter a sessão. Acesse por HTTPS ou "+
				"defina CONTROL_TOWER_SECURE_COOKIES=false em uma rede confiável.")
		return
	}
	s.registry.Inc("jolt_control_logins_total")
	s.store.Audit(r.Context(), user.ID, "login", "control-tower", "allowed", r.Header.Get("X-Correlation-ID"))
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
}

// requestIsSecureContext reports whether the browser will accept a Secure
// cookie for this request. TLS terminated upstream is reported through
// X-Forwarded-Proto, which is trusted only for this decision: a client that
// spoofs it merely re-enables a cookie its own browser would then refuse to
// send, which harms nobody else. Loopback origins are secure contexts by
// specification, so a local `docker compose up` keeps working over HTTP.
func requestIsSecureContext(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	host := r.Host
	if parsed, _, err := net.SplitHostPort(r.Host); err == nil {
		host = parsed
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasSuffix(host, ".localhost")
}

// clientIP returns the direct TCP peer address. It deliberately ignores
// X-Forwarded-For: without a trusted reverse proxy in front of the Control
// Tower, that header is client-controlled and would let an attacker spoof
// their way around the login lockout. See docs/REVERSE_PROXY.md.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if currentActorType(r) == "service_account" {
		writeError(w, r, http.StatusBadRequest, "session_not_applicable", "Contas de serviço não possuem sessão de navegador.")
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), security.Digest(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode})
	s.audit(r, "logout", "control-tower", "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       publicUser(currentUser(r)),
		"actor_type": currentActorType(r),
	})
}

type permissionsRequest struct {
	Paths []string `json:"paths"`
}

func (s *Server) permissions(w http.ResponseWriter, r *http.Request) {
	var input permissionsRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Paths) == 0 || len(input.Paths) > 100 {
		writeError(w, r, http.StatusBadRequest, "invalid_paths", "Informe entre 1 e 100 Node Paths.")
		return
	}
	result := make(map[string][]string, len(input.Paths))
	capabilities := []string{"read", "list", "create", "update", "delete", "write", "execute", "sudo"}
	for _, inputPath := range input.Paths {
		path := rbac.NormalizePath(inputPath)
		// A concrete path may legitimately contain characters a policy rule may
		// not, such as "%" or "&" in a folder name, so the permissive check
		// applies here.
		if !rbac.ValidResourcePath(path) {
			writeError(w, r, http.StatusBadRequest, "invalid_path", "Um dos Node Paths é inválido.")
			return
		}
		for _, capability := range capabilities {
			decision, err := s.evaluateAuthorization(r, path, capability)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if decision.Allowed {
				result[path] = append(result[path], capability)
			}
		}
		if result[path] == nil {
			result[path] = []string{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": result})
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Enabled  *bool  `json:"enabled"`
}

type updateUserRequest struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	Role     *string `json:"role"`
	Enabled  *bool   `json:"enabled"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/users") {
		return
	}
	users, err := s.store.SearchUsers(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", "control-tower/users") {
		return
	}
	var request createUserRequest
	if !decodeJSON(w, r, &request) {
		s.auditUserMutation(r, "create", "control-tower/users", "denied")
		return
	}
	request.Username, request.Role = strings.TrimSpace(request.Username), strings.TrimSpace(request.Role)
	if request.Role == "" {
		request.Role = "operator"
	}
	if !validUsername(request.Username) || !validUserRole(request.Role) || len(request.Password) < 12 {
		s.auditUserMutation(r, "create", "control-tower/users", "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_user", "Use um nome de 3 a 64 caracteres, role válida e senha com pelo menos 12 caracteres.")
		return
	}
	passwordHash, err := security.HashPassword(request.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	now := time.Now().UTC()
	user := store.User{
		ID: randomID("usr"), Username: request.Username, PasswordHash: passwordHash,
		Role: request.Role, Enabled: enabled, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.auditUserMutation(r, "create", "control-tower/users", "denied")
			writeError(w, r, http.StatusConflict, "username_conflict", "Já existe um usuário com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.auditUserMutation(r, "create", "control-tower/users/"+user.ID, "allowed")
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("userID"))
	resource := "control-tower/users/" + id
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	current, err := s.store.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "user_not_found", "Usuário não encontrado.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var request updateUserRequest
	if !decodeJSON(w, r, &request) {
		s.auditUserMutation(r, "update", resource, "denied")
		return
	}
	if request.Username != nil {
		current.Username = strings.TrimSpace(*request.Username)
	}
	if request.Role != nil {
		current.Role = strings.TrimSpace(*request.Role)
	}
	if request.Enabled != nil {
		current.Enabled = *request.Enabled
	}
	password := ""
	if request.Password != nil {
		password = *request.Password
	}
	if !validUsername(current.Username) || !validUserRole(current.Role) || (password != "" && len(password) < 12) {
		s.auditUserMutation(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_user", "Nome, role ou senha inválidos.")
		return
	}
	actor := currentUser(r)
	if current.ID == actor.ID && (current.Role != "admin" || !current.Enabled) {
		s.auditUserMutation(r, "update", resource, "denied")
		writeError(w, r, http.StatusConflict, "self_lockout", "Você não pode remover seu próprio acesso administrativo.")
		return
	}
	passwordHash := ""
	if password != "" {
		passwordHash, err = security.HashPassword(password)
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	current.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), current, passwordHash); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			s.auditUserMutation(r, "update", resource, "denied")
			writeError(w, r, http.StatusConflict, "username_conflict", "Já existe um usuário com esse nome.")
		case errors.Is(err, store.ErrLastAdmin):
			s.auditUserMutation(r, "update", resource, "denied")
			writeError(w, r, http.StatusConflict, "last_admin", "Ao menos um administrador ativo deve permanecer.")
		default:
			s.fail(w, r, err)
		}
		return
	}
	s.auditUserMutation(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("userID"))
	resource := "control-tower/users/" + id
	if !s.requireAdmin(w, r, "delete", resource) {
		return
	}
	if id == currentUser(r).ID {
		s.auditUserMutation(r, "delete", resource, "denied")
		writeError(w, r, http.StatusConflict, "self_delete", "Você não pode remover o usuário da sessão atual.")
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "user_not_found", "Usuário não encontrado.")
		case errors.Is(err, store.ErrLastAdmin):
			s.auditUserMutation(r, "delete", resource, "denied")
			writeError(w, r, http.StatusConflict, "last_admin", "Ao menos um administrador ativo deve permanecer.")
		default:
			s.fail(w, r, err)
		}
		return
	}
	s.auditUserMutation(r, "delete", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, action, resource string) bool {
	evaluatedPath := resource
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	if len(segments) >= 2 && segments[0] == "control-tower" {
		evaluatedPath = strings.Join(segments[:2], "/")
	}
	return s.authorize(w, r, evaluatedPath, "sudo", "sudo_required", "Esta operação exige a capability sudo.")
}

func (s *Server) auditUserMutation(r *http.Request, action, resource, result string) {
	s.audit(r, action, resource, result)
}

func (s *Server) audit(r *http.Request, action, resource, result string) {
	s.store.AuditActor(r.Context(), currentUser(r).ID, currentActorType(r), action, resource, result, r.Header.Get("X-Correlation-ID"))
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, path, capability, code, message string) bool {
	decision, err := s.evaluateAuthorization(r, path, capability)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	s.auditAuthorizationDecision(r, decision)
	if decision.Allowed {
		return true
	}
	s.registry.Inc("jolt_control_authorization_denied_total", capability)
	writeError(w, r, http.StatusForbidden, code, message)
	return false
}

func (s *Server) auditAuthorizationDecision(r *http.Request, decision rbac.Decision) {
	result := "denied"
	if decision.Allowed {
		result = "allowed"
	}
	s.store.AuditDecision(r.Context(), currentUser(r).ID, currentActorType(r), "authorize", decision.Path, result,
		r.Header.Get("X-Correlation-ID"), decision.PolicyIDs, decision.Path, decision.Capability)
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/audit") {
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			writeError(w, r, http.StatusBadRequest, "invalid_limit", "O limite deve estar entre 1 e 500.")
			return
		}
		limit = parsed
	}
	var beforeID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("before_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_cursor", "O cursor de auditoria é inválido.")
			return
		}
		beforeID = parsed
	}
	actorType := strings.TrimSpace(r.URL.Query().Get("actor_type"))
	if actorType != "" && actorType != "user" && actorType != "service_account" && actorType != "recovery" {
		writeError(w, r, http.StatusBadRequest, "invalid_actor_type", "O tipo de ator deve ser user, service_account ou recovery.")
		return
	}
	result := strings.TrimSpace(r.URL.Query().Get("result"))
	if result != "" && result != "allowed" && result != "denied" {
		writeError(w, r, http.StatusBadRequest, "invalid_result", "O resultado deve ser allowed ou denied.")
		return
	}
	events, hasMore, err := s.store.ListAuditEvents(r.Context(), store.AuditQuery{
		BeforeID: beforeID, Limit: limit, ActorType: actorType,
		Action: strings.TrimSpace(r.URL.Query().Get("action")), Result: result,
		CorrelationID: strings.TrimSpace(r.URL.Query().Get("correlation_id")),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var nextBeforeID int64
	if hasMore && len(events) > 0 {
		nextBeforeID = events[len(events)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events, "has_more": hasMore, "next_before_id": nextBeforeID,
	})
}

func (s *Server) evaluateAuthorization(r *http.Request, path, capability string) (rbac.Decision, error) {
	if currentUser(r).Role == "admin" && currentActorType(r) == "user" {
		return rbac.Decision{
			Allowed: true, PolicyIDs: []string{"builtin-admin"}, Path: path, Capability: capability,
		}, nil
	}
	if currentActorType(r) == "service_account" {
		segments := strings.Split(rbac.NormalizePath(path), "/")
		if len(segments) >= 2 && segments[0] == "nodes" {
			member := false
			for _, groupID := range currentAccessGroupIDs(r) {
				allowed, err := s.store.NodeInAccessGroup(r.Context(), groupID, segments[1])
				if err != nil {
					return rbac.Decision{}, err
				}
				member = member || allowed
			}
			if !member {
				return rbac.Decision{Path: rbac.NormalizePath(path), Capability: capability}, nil
			}
		}
	}
	policies, err := s.store.RBACPoliciesForSubject(r.Context(), currentActorType(r), currentUser(r).ID)
	if err != nil {
		return rbac.Decision{}, err
	}
	return rbac.Evaluate(rbac.ExpandCompatibilityRules(policies), path, capability), nil
}

func currentAccessGroupIDs(r *http.Request) []string {
	value, _ := r.Context().Value(groupKey).([]string)
	return value
}

func validUserRole(role string) bool {
	return role == "admin" || role == "operator"
}

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > 64 {
		return false
	}
	for _, character := range username {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

type createServiceAccountRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	GroupIDs    []string   `json:"group_ids"`
	Enabled     *bool      `json:"enabled"`
	TokenName   string     `json:"token_name"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type updateServiceAccountRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Enabled     *bool   `json:"enabled"`
}

type createServiceAccountTokenRequest struct {
	Name           string     `json:"name"`
	ExpiresAt      *time.Time `json:"expires_at"`
	RevokeExisting bool       `json:"revoke_existing"`
}

func (s *Server) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/service-accounts") {
		return
	}
	accounts, err := s.store.SearchServiceAccounts(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": accounts})
}

func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	resource := "control-tower/service-accounts"
	if !s.requireAdmin(w, r, "create", resource) {
		return
	}
	var input createServiceAccountRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "create", resource, "denied")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.TokenName = strings.TrimSpace(input.TokenName)
	if input.TokenName == "" {
		input.TokenName = "initial"
	}
	if !validServiceAccountName(input.Name) || len(input.Description) > 512 || !validCredentialName(input.TokenName) ||
		(input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC())) {
		s.audit(r, "create", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_service_account", "Nome, descrição ou expiração da conta de serviço são inválidos.")
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	now := time.Now().UTC()
	input.GroupIDs = uniqueNonEmpty(input.GroupIDs)
	if len(input.GroupIDs) == 0 || len(input.GroupIDs) > 100 {
		s.audit(r, "create", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_access_groups", "Uma API key precisa ser associada a pelo menos um grupo de acesso.")
		return
	}
	for _, groupID := range input.GroupIDs {
		group, err := s.store.GetAccessGroup(r.Context(), groupID)
		if err != nil || !group.Enabled {
			s.audit(r, "create", resource, "denied")
			writeError(w, r, http.StatusBadRequest, "invalid_access_groups", "Cada grupo informado precisa existir e estar ativo.")
			return
		}
	}
	account := store.ServiceAccount{
		ID: randomID("svc"), Name: input.Name, Description: input.Description, Enabled: enabled,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateServiceAccount(r.Context(), account); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.audit(r, "create", resource, "denied")
			writeError(w, r, http.StatusConflict, "service_account_conflict", "Já existe uma conta de serviço com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	if err := s.store.SetServiceAccountGroups(r.Context(), account.ID, input.GroupIDs); err != nil {
		_ = s.store.DeleteServiceAccount(r.Context(), account.ID)
		s.fail(w, r, err)
		return
	}
	plain, digest, err := newServiceAccountToken()
	if err != nil {
		_ = s.store.DeleteServiceAccount(r.Context(), account.ID)
		s.fail(w, r, err)
		return
	}
	token := store.ServiceAccountToken{
		ID: randomID("sat"), ServiceAccountID: account.ID, Name: input.TokenName,
		TokenHash: digest, ExpiresAt: input.ExpiresAt, CreatedAt: now,
	}
	if err := s.store.CreateServiceAccountToken(r.Context(), token, false); err != nil {
		_ = s.store.DeleteServiceAccount(r.Context(), account.ID)
		s.fail(w, r, err)
		return
	}
	s.audit(r, "create", resource+"/"+account.ID, "allowed")
	writeJSON(w, http.StatusCreated, map[string]any{
		"service_account": account,
		"credential": map[string]any{
			"token_id": token.ID, "name": token.Name, "token": plain,
			"expires_at": token.ExpiresAt, "created_at": token.CreatedAt,
		},
	})
}

func (s *Server) updateServiceAccount(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + id
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	account, err := s.store.GetServiceAccount(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var input updateServiceAccountRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if input.Name != nil {
		account.Name = strings.TrimSpace(*input.Name)
	}
	if input.Description != nil {
		account.Description = strings.TrimSpace(*input.Description)
	}
	if input.Enabled != nil {
		account.Enabled = *input.Enabled
	}
	if !validServiceAccountName(account.Name) || len(account.Description) > 512 {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_service_account", "Nome ou descrição da conta de serviço são inválidos.")
		return
	}
	account.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateServiceAccount(r.Context(), account); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusConflict, "service_account_conflict", "Já existe uma conta de serviço com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, account)
}

func (s *Server) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + id
	if !s.requireAdmin(w, r, "delete", resource) {
		return
	}
	if err := s.store.DeleteServiceAccount(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listServiceAccountTokens(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + id + "/tokens"
	if !s.requireAdmin(w, r, "list", resource) {
		return
	}
	tokens, err := s.store.ListServiceAccountTokens(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens})
}

func (s *Server) createServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + id + "/tokens"
	if !s.requireAdmin(w, r, "create", resource) {
		return
	}
	var input createServiceAccountTokenRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "create", resource, "denied")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		input.Name = "rotated"
	}
	if !validCredentialName(input.Name) || (input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC())) {
		s.audit(r, "create", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_service_token", "Nome ou expiração da credencial são inválidos.")
		return
	}
	plain, digest, err := newServiceAccountToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	token := store.ServiceAccountToken{
		ID: randomID("sat"), ServiceAccountID: id, Name: input.Name, TokenHash: digest,
		ExpiresAt: input.ExpiresAt, CreatedAt: now,
	}
	if err := s.store.CreateServiceAccountToken(r.Context(), token, input.RevokeExisting); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "service_account_not_found", "Conta de serviço não encontrada.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "rotate", resource+"/"+token.ID, "allowed")
	writeJSON(w, http.StatusCreated, map[string]any{
		"token_id": token.ID, "name": token.Name, "token": plain,
		"expires_at": token.ExpiresAt, "created_at": token.CreatedAt,
	})
}

func (s *Server) revokeServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("serviceAccountID"))
	tokenID := strings.TrimSpace(r.PathValue("tokenID"))
	resource := "control-tower/service-accounts/" + accountID + "/tokens/" + tokenID
	if !s.requireAdmin(w, r, "delete", resource) {
		return
	}
	if err := s.store.RevokeServiceAccountToken(r.Context(), accountID, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "service_token_not_found", "Credencial ativa não encontrada.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "revoke", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func validServiceAccountName(name string) bool {
	if len(name) < 3 || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validCredentialName(name string) bool {
	return len(name) >= 1 && len(name) <= 64 && !strings.ContainsAny(name, "\r\n\t")
}

func newServiceAccountToken() (string, string, error) {
	plain, _, err := security.RandomToken()
	if err != nil {
		return "", "", err
	}
	plain = "jolt_svc_" + plain
	return plain, security.Digest(plain), nil
}

type accessGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
}

type updateAccessGroupRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Enabled     *bool   `json:"enabled"`
}

type accessGroupAssignmentRequest struct {
	IDs []string `json:"ids"`
}

func (s *Server) listAccessGroups(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/access-groups") {
		return
	}
	groups, err := s.store.SearchAccessGroups(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": groups})
}

func (s *Server) createAccessGroup(w http.ResponseWriter, r *http.Request) {
	resource := "control-tower/access-groups"
	if !s.requireAdmin(w, r, "create", resource) {
		return
	}
	var input accessGroupRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "create", resource, "denied")
		return
	}
	input.Name, input.Description = strings.TrimSpace(input.Name), strings.TrimSpace(input.Description)
	if !validServiceAccountName(input.Name) || len(input.Description) > 512 {
		s.audit(r, "create", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_access_group", "Nome ou descrição do grupo são inválidos.")
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	now := time.Now().UTC()
	group := store.AccessGroup{ID: randomID("grp"), Name: input.Name, Description: input.Description, Enabled: enabled, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateAccessGroup(r.Context(), group); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.audit(r, "create", resource, "denied")
			writeError(w, r, http.StatusConflict, "access_group_conflict", "Já existe um grupo com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	group.NodeIDs, group.PolicyIDs = []string{}, []string{}
	s.audit(r, "create", resource+"/"+group.ID, "allowed")
	writeJSON(w, http.StatusCreated, group)
}

func (s *Server) updateAccessGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("groupID"))
	resource := "control-tower/access-groups/" + id
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	group, err := s.store.GetAccessGroup(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "access_group_not_found", "Grupo de acesso não encontrado.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var input updateAccessGroupRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if input.Name != nil {
		group.Name = strings.TrimSpace(*input.Name)
	}
	if input.Description != nil {
		group.Description = strings.TrimSpace(*input.Description)
	}
	if input.Enabled != nil {
		group.Enabled = *input.Enabled
	}
	if !validServiceAccountName(group.Name) || len(group.Description) > 512 {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_access_group", "Nome ou descrição do grupo são inválidos.")
		return
	}
	group.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateAccessGroup(r.Context(), group); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, r, http.StatusConflict, "access_group_conflict", "Já existe um grupo com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, group)
}

func (s *Server) deleteAccessGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("groupID"))
	resource := "control-tower/access-groups/" + id
	if !s.requireAdmin(w, r, "delete", resource) {
		return
	}
	if err := s.store.DeleteAccessGroup(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "access_group_not_found", "Grupo de acesso não encontrado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAccessGroupNodes(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("groupID"))
	resource := "control-tower/access-groups/" + id + "/nodes"
	if !s.requireAdmin(w, r, "read", resource) {
		return
	}
	if _, err := s.store.GetAccessGroup(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "access_group_not_found", "Grupo de acesso não encontrado.")
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.store.AccessGroupNodeIDs(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_ids": ids})
}

func (s *Server) assignAccessGroupNodes(w http.ResponseWriter, r *http.Request) {
	s.assignAccessGroupIDs(w, r, "nodes")
}

func (s *Server) listAccessGroupPolicies(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("groupID"))
	resource := "control-tower/access-groups/" + id + "/policies"
	if !s.requireAdmin(w, r, "read", resource) {
		return
	}
	if _, err := s.store.GetAccessGroup(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "access_group_not_found", "Grupo de acesso não encontrado.")
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.store.AccessGroupPolicyIDs(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_ids": ids})
}

func (s *Server) assignAccessGroupPolicies(w http.ResponseWriter, r *http.Request) {
	s.assignAccessGroupIDs(w, r, "policies")
}

func (s *Server) assignAccessGroupIDs(w http.ResponseWriter, r *http.Request, kind string) {
	id := strings.TrimSpace(r.PathValue("groupID"))
	resource := "control-tower/access-groups/" + id + "/" + kind
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	var input accessGroupAssignmentRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if !validIDs(input.IDs, 100) {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_access_group_assignment", "A atribuição aceita no máximo 100 identificadores válidos.")
		return
	}
	input.IDs = uniqueNonEmpty(input.IDs)
	var err error
	if kind == "nodes" {
		err = s.store.SetAccessGroupNodes(r.Context(), id, input.IDs)
	} else {
		err = s.store.SetAccessGroupPolicies(r.Context(), id, input.IDs)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "assignment_target_not_found", "Grupo, node ou policy não encontrado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	if kind == "nodes" {
		writeJSON(w, http.StatusOK, map[string]any{"node_ids": input.IDs})
	} else {
		writeJSON(w, http.StatusOK, map[string]any{"policy_ids": input.IDs})
	}
}

type policyRequest struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rules       []rbac.Rule `json:"rules"`
}

type policyAssignmentRequest struct {
	PolicyIDs []string `json:"policy_ids"`
}

type roleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	PolicyIDs   []string `json:"policy_ids"`
}

type roleAssignmentRequest struct {
	RoleIDs []string `json:"role_ids"`
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/policies") {
		return
	}
	policies, err := s.store.SearchPolicies(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": policies})
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	resource := "control-tower/policies"
	if !s.requireAdmin(w, r, "create", resource) {
		return
	}
	var input policyRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "create", resource, "denied")
		return
	}
	if !normalizePolicyRequest(&input) {
		s.audit(r, "create", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_policy", "Nome, descrição, paths ou capabilities da policy são inválidos.")
		return
	}
	now := time.Now().UTC()
	policy := store.Policy{
		ID: randomID("pol"), Name: input.Name, Description: input.Description,
		Rules: input.Rules, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreatePolicy(r.Context(), policy); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.audit(r, "create", resource, "denied")
			writeError(w, r, http.StatusConflict, "policy_conflict", "Já existe uma policy com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "create", resource+"/"+policy.ID, "allowed")
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("policyID"))
	resource := "control-tower/policies/" + id
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	current, err := s.store.GetPolicy(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "policy_not_found", "Policy não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var input policyRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if !normalizePolicyRequest(&input) {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_policy", "Nome, descrição, paths ou capabilities da policy são inválidos.")
		return
	}
	current.Name = input.Name
	current.Description = input.Description
	current.Rules = input.Rules
	current.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdatePolicy(r.Context(), current); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusConflict, "policy_conflict", "Já existe uma policy com esse nome.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("policyID"))
	resource := "control-tower/policies/" + id
	if !s.requireAdmin(w, r, "delete", resource) {
		return
	}
	if err := s.store.DeletePolicy(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "policy_not_found", "Policy não encontrada.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "list", "control-tower/roles") {
		return
	}
	roles, err := s.store.SearchRoles(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": roles})
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	resource := "control-tower/roles"
	if !s.requireAdmin(w, r, "create", resource) {
		return
	}
	var input roleRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "create", resource, "denied")
		return
	}
	if !normalizeRoleRequest(&input) {
		s.audit(r, "create", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_role", "Nome, descrição ou policies da role são inválidos.")
		return
	}
	now := time.Now().UTC()
	role := store.Role{
		ID: randomID("rol"), Name: input.Name, Description: input.Description,
		PolicyIDs: input.PolicyIDs, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateRole(r.Context(), role); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			s.audit(r, "create", resource, "denied")
			writeError(w, r, http.StatusConflict, "role_conflict", "Já existe uma role com esse nome.")
		case errors.Is(err, store.ErrNotFound):
			s.audit(r, "create", resource, "denied")
			writeError(w, r, http.StatusNotFound, "policy_not_found", "Uma das policies informadas não existe.")
		default:
			s.fail(w, r, err)
		}
		return
	}
	s.audit(r, "create", resource+"/"+role.ID, "allowed")
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("roleID"))
	resource := "control-tower/roles/" + id
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	current, err := s.store.GetRole(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "role_not_found", "Role não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var input roleRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if !normalizeRoleRequest(&input) {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_role", "Nome, descrição ou policies da role são inválidos.")
		return
	}
	current.Name = input.Name
	current.Description = input.Description
	current.PolicyIDs = input.PolicyIDs
	current.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateRole(r.Context(), current); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusConflict, "role_conflict", "Já existe uma role com esse nome.")
		case errors.Is(err, store.ErrNotFound):
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusNotFound, "role_or_policy_not_found", "A role ou uma das policies não existe.")
		default:
			s.fail(w, r, err)
		}
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("roleID"))
	resource := "control-tower/roles/" + id
	if !s.requireAdmin(w, r, "delete", resource) {
		return
	}
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "role_not_found", "Role não encontrada.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listUserRoles(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	resource := "control-tower/users/" + userID + "/roles"
	if !s.requireAdmin(w, r, "read", resource) {
		return
	}
	if _, err := s.store.GetUser(r.Context(), userID); errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "user_not_found", "Usuário não encontrado.")
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.store.UserRoleIDs(r.Context(), userID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role_ids": ids})
}

func (s *Server) assignUserRoles(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	resource := "control-tower/users/" + userID + "/roles"
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	var input roleAssignmentRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if !validIDs(input.RoleIDs, 100) {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_assignment", "A atribuição aceita no máximo 100 roles válidas.")
		return
	}
	if err := s.store.SetUserRoles(r.Context(), userID, input.RoleIDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusNotFound, "assignment_target_not_found", "Usuário ou role não encontrado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"role_ids": uniqueNonEmpty(input.RoleIDs)})
}

func (s *Server) listUserPolicies(w http.ResponseWriter, r *http.Request) {
	s.listSubjectPolicies(w, r, "user", r.PathValue("userID"))
}

func (s *Server) assignUserPolicies(w http.ResponseWriter, r *http.Request) {
	s.assignSubjectPolicies(w, r, "user", r.PathValue("userID"))
}

func (s *Server) listServiceAccountPolicies(w http.ResponseWriter, r *http.Request) {
	s.listSubjectPolicies(w, r, "service_account", r.PathValue("serviceAccountID"))
}

func (s *Server) assignServiceAccountPolicies(w http.ResponseWriter, r *http.Request) {
	s.assignSubjectPolicies(w, r, "service_account", r.PathValue("serviceAccountID"))
}

func (s *Server) listServiceAccountGroups(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + id + "/groups"
	if !s.requireAdmin(w, r, "read", resource) {
		return
	}
	if _, err := s.store.GetServiceAccount(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_account_not_found", "API key não encontrada.")
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.store.ServiceAccountGroupIDs(r.Context(), id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group_ids": ids})
}

func (s *Server) assignServiceAccountGroups(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("serviceAccountID"))
	resource := "control-tower/service-accounts/" + id + "/groups"
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	var input accessGroupAssignmentRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	input.IDs = uniqueNonEmpty(input.IDs)
	if len(input.IDs) == 0 || len(input.IDs) > 100 {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_access_groups", "Uma API key precisa ser associada a pelo menos um grupo de acesso.")
		return
	}
	for _, groupID := range input.IDs {
		group, err := s.store.GetAccessGroup(r.Context(), groupID)
		if err != nil || !group.Enabled {
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusBadRequest, "invalid_access_groups", "Cada grupo informado precisa existir e estar ativo.")
			return
		}
	}
	if err := s.store.SetServiceAccountGroups(r.Context(), id, input.IDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "assignment_target_not_found", "API key ou grupo não encontrado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"group_ids": input.IDs})
}

func (s *Server) listSubjectPolicies(w http.ResponseWriter, r *http.Request, subjectType, subjectID string) {
	resource := subjectPolicyResource(subjectType, subjectID)
	if !s.requireAdmin(w, r, "read", resource) {
		return
	}
	if !s.subjectExists(r.Context(), subjectType, subjectID) {
		writeError(w, r, http.StatusNotFound, "subject_not_found", "Usuário ou conta de serviço não encontrado.")
		return
	}
	ids, err := s.store.SubjectPolicyIDs(r.Context(), subjectType, subjectID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_ids": ids})
}

func (s *Server) assignSubjectPolicies(w http.ResponseWriter, r *http.Request, subjectType, subjectID string) {
	resource := subjectPolicyResource(subjectType, subjectID)
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	var input policyAssignmentRequest
	if !decodeJSON(w, r, &input) {
		s.audit(r, "update", resource, "denied")
		return
	}
	if len(input.PolicyIDs) > 100 {
		s.audit(r, "update", resource, "denied")
		writeError(w, r, http.StatusBadRequest, "invalid_assignment", "Uma atribuição aceita no máximo 100 policies.")
		return
	}
	for _, id := range input.PolicyIDs {
		if strings.TrimSpace(id) == "" {
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusBadRequest, "invalid_assignment", "A lista de policies contém um identificador inválido.")
			return
		}
	}
	if err := s.store.SetSubjectPolicies(r.Context(), subjectType, subjectID, input.PolicyIDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.audit(r, "update", resource, "denied")
			writeError(w, r, http.StatusNotFound, "assignment_target_not_found", "Usuário, conta de serviço ou policy não encontrado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update", resource, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"policy_ids": input.PolicyIDs})
}

func (s *Server) subjectExists(ctx context.Context, subjectType, subjectID string) bool {
	if subjectType == "user" {
		_, err := s.store.GetUser(ctx, subjectID)
		return err == nil
	}
	_, err := s.store.GetServiceAccount(ctx, subjectID)
	return err == nil
}

func subjectPolicyResource(subjectType, subjectID string) string {
	if subjectType == "user" {
		return "control-tower/users/" + subjectID + "/policies"
	}
	return "control-tower/service-accounts/" + subjectID + "/policies"
}

func normalizePolicyRequest(input *policyRequest) bool {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if !validServiceAccountName(input.Name) || len(input.Description) > 512 || len(input.Rules) == 0 || len(input.Rules) > 100 {
		return false
	}
	for index := range input.Rules {
		rule := &input.Rules[index]
		rule.Path = rbac.NormalizePath(rule.Path)
		if !rbac.ValidPath(rule.Path) || len(rule.Capabilities) == 0 || len(rule.Capabilities) > 9 {
			return false
		}
		seen := map[string]bool{}
		normalized := make([]string, 0, len(rule.Capabilities))
		for _, capability := range rule.Capabilities {
			capability = strings.ToLower(strings.TrimSpace(capability))
			if !rbac.ValidCapability(capability) || seen[capability] {
				return false
			}
			seen[capability] = true
			normalized = append(normalized, capability)
		}
		if seen["deny"] && len(normalized) != 1 {
			return false
		}
		rule.Capabilities = normalized
	}
	return true
}

func normalizeRoleRequest(input *roleRequest) bool {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if !validServiceAccountName(input.Name) || len(input.Description) > 512 || !validIDs(input.PolicyIDs, 100) {
		return false
	}
	input.PolicyIDs = uniqueNonEmpty(input.PolicyIDs)
	return true
}

func validIDs(ids []string, maximum int) bool {
	if len(ids) > maximum {
		return false
	}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return false
		}
	}
	return true
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	allowedNodes := make([]store.Node, 0, len(nodes))
	for i := range nodes {
		path := "nodes/" + nodes[i].ID
		decision, decisionErr := s.evaluateAuthorization(r, path, "list")
		if decisionErr != nil {
			s.fail(w, r, decisionErr)
			return
		}
		s.auditAuthorizationDecision(r, decision)
		if !decision.Allowed {
			continue
		}
		s.refreshNodeState(r.Context(), &nodes[i])
		allowedNodes = append(allowedNodes, nodes[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": allowedNodes})
}

type nodeRequest struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", "control-tower/nodes") {
		return
	}
	var request nodeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Token = strings.TrimSpace(request.Token)
	endpoint, err := config.ValidateNodeEndpoint(request.Endpoint)
	if err != nil || request.Name == "" || request.Token == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_node", "Nome, endpoint e token válidos são obrigatórios.")
		return
	}
	nodeID, err := s.fetchNodeID(r.Context(), endpoint, request.Token)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unreachable", "Não foi possível autenticar no node informado.")
		return
	}
	encrypted, err := security.Encrypt(s.config.EncryptionKey, request.Token)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	node := store.Node{ID: nodeID, Name: request.Name, Endpoint: endpoint, TokenEncrypted: encrypted, State: "online", LastSeenAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := s.store.SaveNode(r.Context(), node); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "create", "nodes/"+node.ID, "allowed")
	writeJSON(w, http.StatusCreated, node)
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("nodeID"))
	if !s.requireAdmin(w, r, "delete", "control-tower/nodes/"+id) {
		return
	}
	if id == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_node", "Node inválido.")
		return
	}
	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "not_found", "Node não encontrado.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "delete", "nodes/"+id, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateNodeToken(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if !s.authorize(w, r, "control-tower/nodes/"+nodeID+"/token", "sudo",
		"sudo_required", "Esta operação exige a capability sudo.") {
		return
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.fail(w, r, err)
		return
	}
	newToken := "jolt_node_" + hex.EncodeToString(raw)
	correlationID := r.Header.Get("X-Correlation-ID")
	if err := s.callNodeJSON(r.Context(), node, http.MethodPost,
		"/api/v1/crypto/operational-token/prepare", map[string]string{"new_token": newToken},
		nil, correlationID); err != nil {
		writeError(w, r, http.StatusBadGateway, "token_rotation_prepare_failed",
			"O node não conseguiu preparar a nova credencial.")
		return
	}
	encrypted, err := security.Encrypt(s.config.EncryptionKey, newToken)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	if err := s.store.UpdateNodeToken(r.Context(), nodeID, encrypted, now); err != nil {
		s.fail(w, r, err)
		return
	}
	node.TokenEncrypted, node.UpdatedAt = encrypted, now
	if err := s.callNodeJSON(r.Context(), node, http.MethodPost,
		"/api/v1/crypto/operational-token/commit", map[string]any{}, nil, correlationID); err != nil {
		writeError(w, r, http.StatusBadGateway, "token_rotation_commit_pending",
			"A nova credencial já está válida, mas a invalidação da anterior precisa ser tentada novamente.")
		return
	}
	s.audit(r, "rotate", "control-tower/nodes/"+nodeID+"/token", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": nodeID, "rotation_state": "active", "old_token_invalidated": true,
	})
}

type identityHandover struct {
	NodeID              string    `json:"node_id"`
	PreviousEpoch       int       `json:"previous_epoch"`
	NextEpoch           int       `json:"next_epoch"`
	PreviousFingerprint string    `json:"previous_fingerprint"`
	NextFingerprint     string    `json:"next_fingerprint"`
	PreviousPublicKey   string    `json:"previous_public_key"`
	NextPublicKey       string    `json:"next_public_key"`
	IssuedAt            time.Time `json:"issued_at"`
	Nonce               string    `json:"nonce"`
	PreviousSignature   string    `json:"previous_signature"`
	NextSignature       string    `json:"next_signature"`
}

type nodePeer struct {
	NodeID              string     `json:"node_id"`
	Name                string     `json:"name"`
	Fingerprint         string     `json:"fingerprint"`
	PreviousFingerprint string     `json:"previous_fingerprint,omitempty"`
	IdentityEpoch       int        `json:"identity_epoch"`
	Endpoint            string     `json:"endpoint"`
	MTLSEndpoint        string     `json:"mtls_endpoint"`
	TransferMode        string     `json:"transfer_mode"`
	LocalRole           string     `json:"local_role"`
	RemoteRole          string     `json:"remote_role"`
	ClusterID           string     `json:"cluster_id,omitempty"`
	State               string     `json:"state"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	TrustedAt           time.Time  `json:"trusted_at"`
}

type identityRotationResponse struct {
	NextActive nodeMetadata     `json:"next_active"`
	Handover   identityHandover `json:"handover"`
}

type handoverDelivery struct {
	Acknowledged []string `json:"acknowledged_peer_node_ids"`
	Pending      []string `json:"pending_peer_node_ids"`
	Complete     bool     `json:"delivery_complete"`
}

type mtlsRolloutEnvelope struct {
	NodeID      string `json:"node_id"`
	Certificate struct {
		Serial              string `json:"serial"`
		CertificateSHA256   string `json:"certificate_sha256"`
		IdentityFingerprint string `json:"identity_fingerprint"`
		State               string `json:"state"`
	} `json:"certificate"`
	CertificatePEM string `json:"certificate_pem"`
}

type mtlsRolloutDelivery struct {
	Serial       string   `json:"serial"`
	Acknowledged []string `json:"acknowledged_peer_node_ids"`
	Pending      []string `json:"pending_peer_node_ids"`
	Complete     bool     `json:"delivery_complete"`
}

func (s *Server) rotateNodeIdentity(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if !s.authorize(w, r, "nodes/"+nodeID+"/keys/identity", "sudo",
		"sudo_required", "Esta operação exige a capability sudo.") {
		return
	}
	var input struct {
		ConfirmedFingerprint string `json:"confirmed_fingerprint"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	var rotation identityRotationResponse
	correlationID := r.Header.Get("X-Correlation-ID")
	if err := s.callNodeJSON(r.Context(), node, http.MethodPost, "/api/v1/crypto/identity/rotate",
		input, &rotation, correlationID); err != nil {
		writeError(w, r, http.StatusBadGateway, "identity_rotation_failed", err.Error())
		return
	}
	delivery := s.deliverIdentityHandovers(r.Context(), node, []identityHandover{rotation.Handover}, correlationID)
	s.audit(r, "rotate", "nodes/"+nodeID+"/keys/identity", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": rotation.NextActive.NodeID, "next_active": rotation.NextActive,
		"handover": rotation.Handover, "restart_required": true,
		"acknowledged_peer_node_ids": delivery.Acknowledged,
		"pending_peer_node_ids":      delivery.Pending,
		"delivery_complete":          delivery.Complete,
	})
}

func (s *Server) distributeNodeIdentityHandovers(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if !s.authorize(w, r, "nodes/"+nodeID+"/keys/identity", "sudo",
		"sudo_required", "Esta operação exige a capability sudo.") {
		return
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	var response struct {
		Items []identityHandover `json:"items"`
	}
	correlationID := r.Header.Get("X-Correlation-ID")
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet,
		"/api/v1/crypto/identity/handovers", nil, &response, correlationID); err != nil {
		writeError(w, r, http.StatusBadGateway, "identity_handovers_unavailable",
			"Não foi possível carregar a cadeia de passagem de confiança.")
		return
	}
	delivery := s.deliverIdentityHandovers(r.Context(), node, response.Items, correlationID)
	s.audit(r, "distribute", "nodes/"+nodeID+"/keys/identity", "allowed")
	writeJSON(w, http.StatusOK, delivery)
}

func (s *Server) deliverIdentityHandovers(ctx context.Context, source store.Node,
	handovers []identityHandover, correlationID string) handoverDelivery {
	result := handoverDelivery{Acknowledged: []string{}, Pending: []string{}}
	var sourcePeers struct {
		Items []nodePeer `json:"items"`
	}
	if err := s.callNodeJSON(ctx, source, http.MethodGet, "/api/v1/peers", nil, &sourcePeers, correlationID); err != nil {
		return result
	}
	registered, err := s.store.ListNodes(ctx)
	if err != nil {
		return result
	}
	nodesByID := make(map[string]store.Node, len(registered))
	for _, node := range registered {
		nodesByID[node.ID] = node
	}
	sort.Slice(handovers, func(i, j int) bool { return handovers[i].PreviousEpoch < handovers[j].PreviousEpoch })
	for _, sourcePeer := range sourcePeers.Items {
		if sourcePeer.State == "revoked" {
			continue
		}
		target, registered := nodesByID[sourcePeer.NodeID]
		if !registered {
			result.Pending = append(result.Pending, sourcePeer.NodeID)
			continue
		}
		var targetPeers struct {
			Items []nodePeer `json:"items"`
		}
		if err := s.callNodeJSON(ctx, target, http.MethodGet, "/api/v1/peers", nil,
			&targetPeers, correlationID); err != nil {
			result.Pending = append(result.Pending, sourcePeer.NodeID)
			continue
		}
		var trusted *nodePeer
		for index := range targetPeers.Items {
			if targetPeers.Items[index].NodeID == source.ID {
				trusted = &targetPeers.Items[index]
				break
			}
		}
		if trusted == nil || trusted.State == "revoked" {
			result.Pending = append(result.Pending, sourcePeer.NodeID)
			continue
		}
		delivered := true
		for _, handover := range handovers {
			if handover.NodeID != source.ID || handover.PreviousEpoch < trusted.IdentityEpoch {
				continue
			}
			if handover.PreviousEpoch != trusted.IdentityEpoch ||
				handover.PreviousFingerprint != trusted.Fingerprint {
				delivered = false
				break
			}
			if err := s.callNodeJSON(ctx, target, http.MethodPatch,
				"/api/v1/peers/"+url.PathEscape(source.ID)+"/identity/handover",
				handover, trusted, correlationID); err != nil {
				delivered = false
				break
			}
		}
		if delivered {
			result.Acknowledged = append(result.Acknowledged, sourcePeer.NodeID)
		} else {
			result.Pending = append(result.Pending, sourcePeer.NodeID)
		}
	}
	sort.Strings(result.Acknowledged)
	sort.Strings(result.Pending)
	result.Complete = true
	return result
}

func (s *Server) distributeNodeMTLSRotation(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	path := "nodes/" + nodeID + "/keys/mtls"
	if !s.authorize(w, r, path, "sudo", "sudo_required",
		"Esta operação exige a capability sudo.") ||
		!s.authorize(w, r, path, "execute", "permission_denied",
			"A policy atual não permite distribuir a rotação mTLS.") {
		return
	}
	source, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	correlationID := r.Header.Get("X-Correlation-ID")
	var envelope mtlsRolloutEnvelope
	if err := s.callNodeJSON(r.Context(), source, http.MethodGet,
		"/api/v1/crypto/mtls/rollout", nil, &envelope, correlationID); err != nil {
		writeError(w, r, http.StatusConflict, "mtls_rotation_not_pending",
			"O node não possui um certificado mTLS preparado para distribuição.")
		return
	}
	if envelope.NodeID != source.ID || envelope.Certificate.Serial == "" ||
		envelope.Certificate.State != "next" || envelope.CertificatePEM == "" {
		writeError(w, r, http.StatusBadGateway, "invalid_mtls_rollout",
			"O node retornou um envelope de rotação mTLS inválido.")
		return
	}
	delivery := s.deliverMTLSRotation(r.Context(), source, envelope, correlationID)
	s.audit(r, "distribute", path, "allowed")
	writeJSON(w, http.StatusOK, delivery)
}

func (s *Server) deliverMTLSRotation(ctx context.Context, source store.Node,
	envelope mtlsRolloutEnvelope, correlationID string) mtlsRolloutDelivery {
	result := mtlsRolloutDelivery{
		Serial: envelope.Certificate.Serial, Acknowledged: []string{}, Pending: []string{},
	}
	var sourcePeers struct {
		Items []nodePeer `json:"items"`
	}
	if err := s.callNodeJSON(ctx, source, http.MethodGet, "/api/v1/peers", nil,
		&sourcePeers, correlationID); err != nil {
		return result
	}
	registered, err := s.store.ListNodes(ctx)
	if err != nil {
		return result
	}
	nodesByID := make(map[string]store.Node, len(registered))
	for _, node := range registered {
		nodesByID[node.ID] = node
	}
	record := func(peerNodeID, deliveryError string) bool {
		payload := map[string]any{
			"serial": envelope.Certificate.Serial, "peer_node_id": peerNodeID,
			"delivery_error": deliveryError,
		}
		return s.callNodeJSON(ctx, source, http.MethodPost,
			"/api/v1/crypto/mtls/rollout/deliveries", payload, nil, correlationID) == nil
	}
	for _, peer := range sourcePeers.Items {
		if peer.State == "revoked" {
			continue
		}
		target, exists := nodesByID[peer.NodeID]
		if !exists {
			_ = record(peer.NodeID, "peer is not registered in the Control Tower")
			result.Pending = append(result.Pending, peer.NodeID)
			continue
		}
		var acceptance map[string]any
		err := s.callNodeJSON(ctx, target, http.MethodPatch,
			"/api/v1/peers/"+url.PathEscape(source.ID)+"/mtls/rollout",
			envelope, &acceptance, correlationID)
		if err != nil {
			_ = record(peer.NodeID, "peer did not acknowledge the certificate")
			result.Pending = append(result.Pending, peer.NodeID)
			continue
		}
		if !record(peer.NodeID, "") {
			result.Pending = append(result.Pending, peer.NodeID)
			continue
		}
		result.Acknowledged = append(result.Acknowledged, peer.NodeID)
	}
	sort.Strings(result.Acknowledged)
	sort.Strings(result.Pending)
	result.Complete = true
	return result
}

type connectionRequest struct {
	IssuerNodeID  string `json:"issuer_node_id"`
	TargetNodeID  string `json:"target_node_id"`
	TransferMode  string `json:"transfer_mode"`
	IssuerRole    string `json:"issuer_role"`
	InviteeRole   string `json:"invitee_role"`
	Purpose       string `json:"purpose"`
	ClusterID     string `json:"cluster_id"`
	ExpiryMinutes int    `json:"expiry_minutes"`
}

type nodeMetadata struct {
	NodeID        string `json:"node_id"`
	Name          string `json:"name"`
	Fingerprint   string `json:"fingerprint"`
	IdentityEpoch int    `json:"identity_epoch"`
	MTLSEndpoint  string `json:"mtls_endpoint"`
}

type pairingInviteResult struct {
	Invite struct {
		ID            string    `json:"invite_id"`
		TransferMode  string    `json:"transfer_mode"`
		IssuerRole    string    `json:"issuer_role"`
		InviteeRole   string    `json:"invitee_role"`
		Purpose       string    `json:"purpose"`
		ClusterID     string    `json:"cluster_id"`
		ExpiresAt     time.Time `json:"expires_at"`
		CorrelationID string    `json:"correlation_id"`
	} `json:"invite"`
	InviteToken string `json:"invite_token"`
}

type pairingRequestResult struct {
	ID        string    `json:"request_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
}

func (s *Server) createConnectionRequest(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "create", "control-tower/connections") {
		return
	}
	var input connectionRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.IssuerNodeID == "" || input.TargetNodeID == "" || input.IssuerNodeID == input.TargetNodeID {
		writeError(w, r, http.StatusBadRequest, "invalid_connection", "Escolha dois nodes diferentes.")
		return
	}
	issuer, err := s.store.GetNode(r.Context(), input.IssuerNodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "issuer_not_found", "Node emissor não encontrado.")
		return
	}
	target, err := s.store.GetNode(r.Context(), input.TargetNodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "target_not_found", "Node alvo não encontrado.")
		return
	}
	issuerMetadata, err := s.nodeMetadata(r.Context(), issuer)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "issuer_unavailable", "O node emissor está indisponível ou não confia mais na Control Tower.")
		return
	}
	var inviteResult pairingInviteResult
	invitePayload := map[string]any{
		"target_node_id": target.ID, "transfer_mode": input.TransferMode,
		"issuer_role": input.IssuerRole, "invitee_role": input.InviteeRole,
		"purpose": input.Purpose, "cluster_id": input.ClusterID, "expiry_minutes": input.ExpiryMinutes,
	}
	if err := s.callNodeJSON(r.Context(), issuer, http.MethodPost, "/api/v1/pairing/invites", invitePayload, &inviteResult, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "invite_creation_failed", err.Error())
		return
	}
	requestPayload := map[string]any{
		"invite_id": inviteResult.Invite.ID, "invite_token": inviteResult.InviteToken,
		"issuer_node_id": issuerMetadata.NodeID, "issuer_name": issuerMetadata.Name,
		"issuer_fingerprint":    issuerMetadata.Fingerprint,
		"issuer_identity_epoch": issuerMetadata.IdentityEpoch, "issuer_endpoint": issuer.Endpoint,
		"issuer_mtls_endpoint": issuerMetadata.MTLSEndpoint,
		"transfer_mode":        inviteResult.Invite.TransferMode, "issuer_role": inviteResult.Invite.IssuerRole,
		"invitee_role": inviteResult.Invite.InviteeRole, "purpose": inviteResult.Invite.Purpose,
		"cluster_id": inviteResult.Invite.ClusterID, "expires_at": inviteResult.Invite.ExpiresAt,
	}
	var pairingRequest pairingRequestResult
	if err := s.callNodeJSON(r.Context(), target, http.MethodPost, "/api/v1/pairing/requests", requestPayload, &pairingRequest, r.Header.Get("X-Correlation-ID")); err != nil {
		_ = s.callNodeJSON(r.Context(), issuer, http.MethodDelete, "/api/v1/pairing/invites/"+url.PathEscape(inviteResult.Invite.ID), nil, nil, r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusBadGateway, "request_delivery_failed", "O convite foi revogado porque o node alvo não recebeu o pedido.")
		return
	}
	encryptedInviteToken, err := security.Encrypt(s.config.EncryptionKey, inviteResult.InviteToken)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "credential_encryption_failed", "Não foi possível proteger o convite.")
		return
	}
	now := time.Now().UTC()
	connection := store.Connection{
		RequestID: pairingRequest.ID, InviteID: inviteResult.Invite.ID,
		IssuerNodeID: issuer.ID, TargetNodeID: target.ID,
		InviteTokenEncrypted: encryptedInviteToken, IssuerFingerprint: issuerMetadata.Fingerprint,
		Status: "pending_review", ExpiresAt: pairingRequest.ExpiresAt, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.SaveConnection(r.Context(), connection); err != nil {
		_ = s.callNodeJSON(r.Context(), target, http.MethodPost, "/api/v1/pairing/requests/"+url.PathEscape(pairingRequest.ID)+"/reject", map[string]any{}, nil, r.Header.Get("X-Correlation-ID"))
		_ = s.callNodeJSON(r.Context(), issuer, http.MethodDelete, "/api/v1/pairing/invites/"+url.PathEscape(inviteResult.Invite.ID), nil, nil, r.Header.Get("X-Correlation-ID"))
		writeError(w, r, http.StatusInternalServerError, "connection_persistence_failed", "O pedido foi entregue, mas não pôde ser registrado pela Control Tower.")
		return
	}
	autoApproved := false
	connectionStatus := connection.Status
	if s.canAutoApproveConnection(r, target.ID) {
		var approvalErr *connectionApprovalError
		connectionStatus, approvalErr = s.establishConnection(
			r.Context(), connection, connection.IssuerFingerprint, r.Header.Get("X-Correlation-ID"),
		)
		if approvalErr == nil {
			autoApproved = true
			s.audit(r, "auto_approve", "connections/"+connection.RequestID, "allowed")
		} else {
			s.audit(r, "auto_approve", "connections/"+connection.RequestID, "denied")
		}
	}
	resource := "nodes/" + issuer.ID + "/connections/" + target.ID
	s.audit(r, "create", resource, "allowed")
	writeJSON(w, http.StatusCreated, map[string]any{
		"request": pairingRequest, "issuer_node_id": issuer.ID, "target_node_id": target.ID,
		"status": connectionStatus, "trust_established": autoApproved,
		"auto_approved": autoApproved, "grants_created": false,
	})
}

type approveConnectionInput struct {
	ConfirmedFingerprint string `json:"confirmed_fingerprint"`
}

type connectionApprovalError struct {
	status  int
	code    string
	message string
}

// canAutoApproveConnection is deliberately limited to human sessions. A
// service account can create a request through the API, but it must never
// silently establish trust on a second node.
func (s *Server) canAutoApproveConnection(r *http.Request, targetNodeID string) bool {
	if currentActorType(r) != "user" {
		return false
	}
	decision, err := s.evaluateAuthorization(
		r, "nodes/"+targetNodeID+"/admin/pairing", "sudo",
	)
	if err != nil {
		return false
	}
	s.auditAuthorizationDecision(r, decision)
	return decision.Allowed
}

// peerTrusted reports whether node already holds a usable peer row for
// peerNodeID. Each handshake step checks this first so establishConnection is
// safe to re-run: that is what makes reconciliation possible.
func (s *Server) peerTrusted(ctx context.Context, node store.Node,
	peerNodeID, correlationID string,
) (bool, error) {
	peers, err := s.nodePeers(ctx, node, correlationID)
	if err != nil {
		return false, err
	}
	for _, peer := range peers {
		if peer.NodeID == peerNodeID {
			return trustedPeerState(peer.State), nil
		}
	}
	return false, nil
}

// pairingStatus returns the status a node reports for one invite or request, or
// "" when the row is gone.
func (s *Server) pairingStatus(ctx context.Context, node store.Node,
	resource, idField, id, correlationID string,
) (string, error) {
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/pairing/"+resource, nil,
		&response, correlationID); err != nil {
		return "", err
	}
	for _, item := range response.Items {
		if value, ok := item[idField].(string); ok && value == id {
			status, _ := item["status"].(string)
			return status, nil
		}
	}
	return "", nil
}

// establishConnection drives the two-sided handshake to completion and is
// idempotent: every step inspects the node's current state before acting, so a
// retry after a partial failure finishes the missing half instead of replaying
// a consumed invite.
func (s *Server) establishConnection(ctx context.Context, connection store.Connection,
	confirmedFingerprint, correlationID string,
) (string, *connectionApprovalError) {
	issuer, issuerErr := s.store.GetNode(ctx, connection.IssuerNodeID)
	target, targetErr := s.store.GetNode(ctx, connection.TargetNodeID)
	if issuerErr != nil || targetErr != nil {
		return connection.Status, &connectionApprovalError{
			status: http.StatusNotFound, code: "node_not_found",
			message: "Um dos nodes do pedido não está mais cadastrado.",
		}
	}
	targetMetadata, err := s.nodeMetadata(ctx, target)
	if err != nil {
		return connection.Status, &connectionApprovalError{
			status: http.StatusBadGateway, code: "target_unavailable",
			message: "O node alvo está indisponível.",
		}
	}
	issuerDone, err := s.peerTrusted(ctx, issuer, targetMetadata.NodeID, correlationID)
	if err != nil {
		return connection.Status, &connectionApprovalError{
			status: http.StatusBadGateway, code: "issuer_unavailable",
			message: "O node emissor está indisponível.",
		}
	}
	issuerMetadata, err := s.nodeMetadata(ctx, issuer)
	if err != nil {
		return connection.Status, &connectionApprovalError{
			status: http.StatusBadGateway, code: "issuer_unavailable",
			message: "O node emissor está indisponível.",
		}
	}
	targetDone, err := s.peerTrusted(ctx, target, issuerMetadata.NodeID, correlationID)
	if err != nil {
		return connection.Status, &connectionApprovalError{
			status: http.StatusBadGateway, code: "target_unavailable",
			message: "O node alvo está indisponível.",
		}
	}
	if !issuerDone {
		status, statusErr := s.pairingStatus(ctx, issuer, "invites", "invite_id",
			connection.InviteID, correlationID)
		if statusErr != nil {
			return connection.Status, &connectionApprovalError{
				status: http.StatusBadGateway, code: "issuer_unavailable",
				message: "O node emissor está indisponível.",
			}
		}
		if status != "pending" {
			return s.persistConnectionStatus(ctx, connection, "partially_connected"),
				&connectionApprovalError{
					status: http.StatusConflict, code: "reconcile_requires_new_invite",
					message: "O convite já foi consumido ou expirou e o emissor não confia no alvo. " +
						"Remova a confiança nos dois nodes e crie uma nova conexão.",
				}
		}
		inviteToken, decryptErr := security.Decrypt(s.config.EncryptionKey, connection.InviteTokenEncrypted)
		if decryptErr != nil {
			return connection.Status, &connectionApprovalError{
				status: http.StatusInternalServerError, code: "invite_unavailable",
				message: "O segredo do convite não pôde ser recuperado.",
			}
		}
		approvePayload := map[string]any{
			"invite_token": inviteToken, "peer_node_id": targetMetadata.NodeID,
			"peer_name": targetMetadata.Name, "peer_fingerprint": targetMetadata.Fingerprint,
			"peer_identity_epoch": targetMetadata.IdentityEpoch,
			"peer_endpoint":       target.Endpoint, "peer_mtls_endpoint": targetMetadata.MTLSEndpoint,
		}
		if approveErr := s.callNodeJSON(ctx, issuer, http.MethodPost,
			"/api/v1/pairing/invites/"+url.PathEscape(connection.InviteID)+"/approve",
			approvePayload, nil, correlationID); approveErr != nil {
			return connection.Status, &connectionApprovalError{
				status: http.StatusBadGateway, code: "issuer_approval_failed", message: approveErr.Error(),
			}
		}
	}
	if !targetDone {
		status, statusErr := s.pairingStatus(ctx, target, "requests", "request_id",
			connection.RequestID, correlationID)
		if statusErr != nil {
			return connection.Status, &connectionApprovalError{
				status: http.StatusBadGateway, code: "target_unavailable",
				message: "O node alvo está indisponível.",
			}
		}
		if status != "pending_review" {
			return s.persistConnectionStatus(ctx, connection, "partially_connected"),
				&connectionApprovalError{
					status: http.StatusConflict, code: "reconcile_requires_new_invite",
					message: "O pedido no node alvo já não está pendente e o alvo não confia no emissor. " +
						"Remova a confiança nos dois nodes e crie uma nova conexão.",
				}
		}
		acceptPayload := map[string]any{"confirmed_fingerprint": confirmedFingerprint}
		if acceptErr := s.callNodeJSON(ctx, target, http.MethodPost,
			"/api/v1/pairing/requests/"+url.PathEscape(connection.RequestID)+"/accept",
			acceptPayload, nil, correlationID); acceptErr != nil {
			return s.persistConnectionStatus(ctx, connection, "partially_connected"),
				&connectionApprovalError{
					status: http.StatusBadGateway, code: "target_acceptance_failed",
					message: "O emissor confiou no alvo, mas o alvo não concluiu a conexão. O pedido requer reconciliação.",
				}
		}
	}
	return s.persistConnectionStatus(ctx, connection, "connected"), nil
}

// persistConnectionStatus logs a failed write instead of discarding it: a
// dropped update used to leave a fully paired connection reading
// "pending_review" forever.
func (s *Server) persistConnectionStatus(ctx context.Context, connection store.Connection, status string) string {
	if err := s.store.UpdateConnectionStatus(ctx, connection.RequestID, status); err != nil {
		s.log.Error("persist connection status", "request_id", connection.RequestID,
			"status", status, "error", err)
	}
	return status
}

func (s *Server) approveConnection(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "execute", "control-tower/connections/"+r.PathValue("requestID")) {
		return
	}
	var input approveConnectionInput
	if !decodeJSON(w, r, &input) {
		return
	}
	connection, err := s.store.GetConnection(r.Context(), r.PathValue("requestID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "connection_not_found", "Pedido de conexão não encontrado.")
		return
	}
	// partially_connected is approvable because establishConnection is now
	// idempotent: approving again finishes the half that failed.
	if !reconcilableStatuses[connection.Status] || connectionExpired(connection) {
		writeError(w, r, http.StatusConflict, "connection_not_pending", "O pedido não está mais disponível para aprovação.")
		return
	}
	if input.ConfirmedFingerprint != connection.IssuerFingerprint {
		s.audit(r, "approve", "connections/"+connection.RequestID, "denied")
		writeError(w, r, http.StatusConflict, "fingerprint_mismatch", "A fingerprint confirmada não corresponde ao node emissor.")
		return
	}
	status, approvalErr := s.establishConnection(
		r.Context(), connection, input.ConfirmedFingerprint, r.Header.Get("X-Correlation-ID"),
	)
	if approvalErr != nil {
		s.audit(r, "approve", "connections/"+connection.RequestID, "denied")
		writeError(w, r, approvalErr.status, approvalErr.code, approvalErr.message)
		return
	}
	s.audit(r, "approve", "connections/"+connection.RequestID, "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "trust_established": true, "grants_created": false})
}

func (s *Server) rejectConnection(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "execute", "control-tower/connections/"+r.PathValue("requestID")) {
		return
	}
	connection, err := s.store.GetConnection(r.Context(), r.PathValue("requestID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "connection_not_found", "Pedido de conexão não encontrado.")
		return
	}
	issuer, issuerErr := s.store.GetNode(r.Context(), connection.IssuerNodeID)
	target, targetErr := s.store.GetNode(r.Context(), connection.TargetNodeID)
	if issuerErr != nil || targetErr != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Um dos nodes do pedido não está mais cadastrado.")
		return
	}
	// Rejecting an already connected or revoked request used to be allowed and
	// tore down the target's state while leaving both peers trusted.
	if connection.Status != "pending_review" && connection.Status != "partially_connected" {
		writeError(w, r, http.StatusConflict, "connection_not_pending",
			"O pedido não está mais disponível para rejeição.")
		return
	}
	correlationID := r.Header.Get("X-Correlation-ID")
	targetStatus, statusErr := s.pairingStatus(r.Context(), target, "requests",
		"request_id", connection.RequestID, correlationID)
	if statusErr != nil {
		writeError(w, r, http.StatusBadGateway, "target_unavailable",
			"O node alvo está indisponível, então a rejeição não pode ser confirmada.")
		return
	}
	// Only a still-pending request can be rejected. A request that was already
	// resolved or is gone is nothing to undo, and must not block the issuer
	// cleanup below — that is exactly the partially_connected case.
	if targetStatus == "pending_review" {
		if err := s.callNodeJSON(r.Context(), target, http.MethodPost, "/api/v1/pairing/requests/"+url.PathEscape(connection.RequestID)+"/reject", map[string]any{}, nil, correlationID); err != nil {
			writeError(w, r, http.StatusBadGateway, "target_rejection_failed", err.Error())
			return
		}
	}
	_ = s.callNodeJSON(r.Context(), issuer, http.MethodDelete, "/api/v1/pairing/invites/"+url.PathEscape(connection.InviteID), nil, nil, correlationID)
	// A partially_connected rejection leaves the issuer trusting a peer that
	// never trusted it back, so the issuer's peer row has to go too.
	issuerSide := s.revokePeerOn(r.Context(), issuer, connection.TargetNodeID, correlationID)
	s.persistConnectionStatus(r.Context(), connection, "rejected")
	if !issuerSide.Done {
		s.audit(r, "reject", "connections/"+connection.RequestID, "denied")
		writeError(w, r, http.StatusBadGateway, "issuer_revoke_failed",
			"O pedido foi rejeitado, mas a confiança no node emissor não pôde ser removida.")
		return
	}
	s.audit(r, "reject", "connections/"+connection.RequestID, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

// fileTargetsFromRequest collects the mount-relative paths a file request acts
// on. Copy and move carry them in the JSON body, which is buffered and
// restored so the proxy can still forward it; everything else uses ?path=.
func fileTargetsFromRequest(r *http.Request) (fileTargets, error) {
	targets := fileTargets{}
	base := strings.TrimSpace(r.URL.Query().Get("path"))
	if base != "" {
		targets.Paths = append(targets.Paths, base)
	}
	// Each archive selection is a separate path being read, so each one is
	// authorized on its own instead of riding on the base path's decision.
	for _, name := range r.URL.Query()["name"] {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			targets.Paths = append(targets.Paths, path.Join(base, trimmed))
		}
	}
	if r.Method != http.MethodPost || r.Body == nil {
		return targets, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return targets, errors.New("invalid file operation body")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return targets, nil
	}
	var payload struct {
		Path            string `json:"path"`
		SourcePath      string `json:"source_path"`
		DestinationPath string `json:"destination_path"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return targets, errors.New("invalid file operation body")
	}
	if strings.TrimSpace(payload.Path) != "" {
		targets.Paths = append(targets.Paths, payload.Path)
	}
	targets.Source = payload.SourcePath
	targets.Destination = payload.DestinationPath
	return targets, nil
}

// subtreeReadResource reports whether a resource reads a whole subtree from a
// single named root, rather than one explicitly named path.
func subtreeReadResource(resource string) bool {
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	if len(segments) < 4 || segments[0] != "mounts" || segments[2] != "files" {
		return false
	}
	return segments[3] == "archive" || segments[3] == "search"
}

func mountIDFromResource(resource string) string {
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	if len(segments) < 2 {
		return ""
	}
	return segments[1]
}

// deniesWithinScope loads the subject's policies and asks whether any deny rule
// applies at or below scope. A service account outside the node's access group
// is already refused by the ordinary capability check.
func (s *Server) deniesWithinScope(r *http.Request, scope string) (bool, error) {
	policies, err := s.store.RBACPoliciesForSubject(r.Context(), currentActorType(r), currentUser(r).ID)
	if err != nil {
		return false, err
	}
	return rbac.DeniesWithin(rbac.ExpandCompatibilityRules(policies), scope), nil
}

// isMountFileResource reports whether resource addresses files inside a mount,
// which is the only family whose authorization is subpath-scoped.
func isMountFileResource(resource string) bool {
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	return len(segments) >= 3 && segments[0] == "mounts" && segments[2] == "files"
}

func (s *Server) proxyNode(w http.ResponseWriter, r *http.Request) {
	resource := strings.TrimPrefix(r.PathValue("resource"), "/")
	targets := fileTargets{}
	if isMountFileResource(resource) {
		parsed, err := fileTargetsFromRequest(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_file_request",
				"Não foi possível determinar os caminhos desta operação de arquivo.")
			return
		}
		targets = parsed
	}
	// Archive and search read an entire subtree from one named root, so
	// authorizing the root alone would let them reach descendants the subject
	// is denied. Refuse while any deny rule applies inside the requested
	// subtree; a narrower request on an allowed subfolder still works.
	if subtreeReadResource(resource) && r.Method == http.MethodGet {
		mountBase := "nodes/" + r.PathValue("nodeID") + "/files/mounts/" + mountIDFromResource(resource)
		for _, scope := range fileScopes(mountBase, targets.all()) {
			denied, err := s.deniesWithinScope(r, scope)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if denied {
				s.audit(r, "read", scope, "denied")
				writeError(w, r, http.StatusForbidden, "deny_rule_within_scope",
					"Há regras de negação dentro desta pasta. Baixe ou pesquise em uma subpasta permitida.")
				return
			}
		}
	}
	requirements := nodeAuthorizationRequirements(r.PathValue("nodeID"), resource, r.Method, targets)
	if len(requirements) == 0 {
		writeError(w, r, http.StatusNotFound, "resource_not_found", "Recurso do node não permitido.")
		return
	}
	if strings.HasPrefix(resource, "transfers/") && r.Method == http.MethodPost {
		for _, requirement := range requirements {
			if !s.authorize(w, r, requirement.Path, requirement.Capability, "permission_denied",
				"A policy atual não permite esta operação no node.") {
				return
			}
		}
		transfer, err := transferFromBody(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_transfer",
				"A transferência precisa informar peer_node_id e grants válidos.")
			return
		}
		mountRequirements, err := s.transferMountRequirements(r.Context(), r.PathValue("nodeID"), transfer)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_transfer_grants",
				"Não foi possível validar os grants e mounts exatos desta transferência.")
			return
		}
		requirements = mountRequirements
	}
	for _, requirement := range requirements {
		if !s.authorize(w, r, requirement.Path, requirement.Capability, "permission_denied",
			"A policy atual não permite esta operação no node.") {
			return
		}
	}
	node, err := s.store.GetNode(r.Context(), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_not_found", "Node não encontrado.")
		return
	}
	if !allowedNodeResource(resource) {
		writeError(w, r, http.StatusNotFound, "resource_not_found", "Recurso do node não permitido.")
		return
	}
	token, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	target := node.Endpoint + "/api/v1/" + resource
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Correlation-ID", r.Header.Get("X-Correlation-ID"))
	request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	for _, header := range []string{"Range", "If-Range", "If-Modified-Since", "If-None-Match",
		// Content-Range carries the offset of a resumable upload chunk.
		"Content-Range"} {
		if value := r.Header.Get(header); value != "" {
			request.Header.Set(header, value)
		}
	}
	// A chunk body has a known length; forwarding it avoids chunked encoding
	// for every upload segment.
	if r.ContentLength > 0 {
		request.ContentLength = r.ContentLength
	}
	if value := r.Header.Get("Idempotency-Key"); value != "" {
		request.Header.Set("Idempotency-Key", value)
	}
	response, err := s.client.Do(request)
	if err != nil {
		_ = s.store.UpdateNodeState(r.Context(), node.ID, "offline", node.LastSeenAt)
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node está indisponível.")
		return
	}
	defer response.Body.Close()
	for _, header := range []string{"Content-Type", "Content-Length", "Content-Disposition",
		"Accept-Ranges", "Content-Range", "Cache-Control", "X-Accel-Buffering",
		// Resumable uploads and archives report their state in these headers.
		"X-Jolt-Upload-Offset", "X-Jolt-Archive-Files", "X-Jolt-Archive-Bytes",
		"X-Jolt-Archive-Skipped-Symlinks"} {
		if value := response.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	if r.URL.Query().Get("disposition") == "inline" && response.StatusCode >= http.StatusOK &&
		response.StatusCode < http.StatusMultipleChoices && isInlineMediaType(response.Header.Get("Content-Type")) {
		w.Header().Set("Content-Disposition", "inline")
	}
	w.WriteHeader(response.StatusCode)
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		_, _ = io.Copy(flushingWriter{writer: w}, response.Body)
	} else {
		_, _ = io.Copy(w, response.Body)
	}
	action := strings.ToLower(r.Method)
	result := resultForStatus(response.StatusCode)
	s.registry.Inc("jolt_control_node_proxy_total", node.ID, result)
	s.audit(r, action, "nodes/"+node.ID+"/"+resource, result)
}

func isInlineMediaType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") ||
		strings.HasPrefix(mediaType, "image/")
}

type transferAuthorizationInput struct {
	PeerNodeID         string `json:"peer_node_id"`
	SourceGrantID      string `json:"source_grant_id"`
	DestinationGrantID string `json:"destination_grant_id"`
	Operation          string `json:"operation"`
}

type nodeTransferGrant struct {
	ID               string   `json:"grant_id"`
	PeerNodeID       string   `json:"peer_node_id"`
	MountID          string   `json:"mount_id"`
	Path             string   `json:"path"`
	Direction        string   `json:"direction"`
	Enabled          bool     `json:"enabled"`
	ConflictPolicies []string `json:"conflict_policies"`
	Permissions      struct {
		Read   bool `json:"read"`
		Write  bool `json:"write"`
		Delete bool `json:"delete"`
	} `json:"permissions"`
}

// logicalTransferRequest intentionally contains only mount-relative paths. The
// control tower resolves the node-local grants and never exposes their IDs to
// callers of the public transfer API.
type logicalTransferRequest struct {
	Operation string `json:"operation"`
	Source    struct {
		NodeID  string   `json:"node_id"`
		MountID string   `json:"mount_id"`
		Paths   []string `json:"paths"`
	} `json:"source"`
	Destination struct {
		MountID string `json:"mount_id"`
		Path    string `json:"path"`
	} `json:"destination"`
	ConflictPolicy    string `json:"conflict_policy"`
	VerifyChecksum    bool   `json:"verify_checksum"`
	BandwidthLimit    int64  `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles  int    `json:"max_parallel_files"`
	MaxParallelChunks int    `json:"max_parallel_chunks"`
}

type transferTargetsRequest struct {
	Operation     string   `json:"operation"`
	SourceMountID string   `json:"source_mount_id"`
	SourcePaths   []string `json:"source_paths"`
	Source        struct {
		NodeID  string   `json:"node_id"`
		MountID string   `json:"mount_id"`
		Paths   []string `json:"paths"`
	} `json:"source"`
}

type transferTargetMount struct {
	MountID          string   `json:"mount_id"`
	Name             string   `json:"name"`
	RootPath         string   `json:"root_path"`
	ConflictPolicies []string `json:"conflict_policies"`
	CanBrowse        bool     `json:"can_browse"`
	Available        bool     `json:"available"`
	State            string   `json:"state"`
}

type transferTargetNode struct {
	NodeID    string                `json:"node_id"`
	Name      string                `json:"name"`
	State     string                `json:"state"`
	Available bool                  `json:"available"`
	Mounts    []transferTargetMount `json:"mounts"`
}

type blockedTransferTarget struct {
	NodeID  string   `json:"node_id"`
	Name    string   `json:"name"`
	Reasons []string `json:"reasons"`
}

type nodeMount struct {
	ID       string `json:"mount_id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	State    string `json:"state"`
	Readable bool   `json:"readable"`
	Writable bool   `json:"writable"`
}

type resolvedLogicalTransfer struct {
	Request          logicalTransferRequest
	SourceNode       store.Node
	SourcePeerNodeID string
	DestinationNode  store.Node
	SourceGrant      nodeTransferGrant
	DestinationGrant nodeTransferGrant
	SourcePaths      []string
	DestinationPath  string
}

func (s *Server) transferTargets(w http.ResponseWriter, r *http.Request) {
	sourceNodeID := strings.TrimSpace(r.PathValue("nodeID"))
	var input transferTargetsRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Source.MountID != "" || len(input.Source.Paths) > 0 || input.Source.NodeID != "" {
		input.SourceMountID, input.SourcePaths = input.Source.MountID, input.Source.Paths
		if input.Source.NodeID != "" && input.Source.NodeID != sourceNodeID {
			writeError(w, r, http.StatusBadRequest, "invalid_selection", "O node de origem não confere com a URL.")
			return
		}
	}
	if len(input.SourcePaths) > s.transferMaxSourcePaths() {
		writeError(w, r, http.StatusBadRequest, "selection_limit_exceeded", "A seleção excede o limite configurado de raízes.")
		return
	}
	paths, operation, err := s.normalizeTransferSelection(input.SourcePaths, input.Operation)
	if err != nil || !validPathIdentifier(sourceNodeID) || !validPathIdentifier(input.SourceMountID) {
		writeError(w, r, http.StatusBadRequest, "invalid_selection", "A seleção de origem é inválida.")
		return
	}
	if !s.authorize(w, r, "nodes/"+sourceNodeID+"/files/mounts/"+input.SourceMountID,
		"read", "permission_denied", "Você não pode ler o mount de origem.") {
		return
	}
	if operation == "move" && !s.authorize(w, r, "nodes/"+sourceNodeID+"/files/mounts/"+input.SourceMountID,
		"delete", "permission_denied", "Você não pode remover itens do mount de origem.") {
		return
	}
	sourceNode, err := s.store.GetNode(r.Context(), sourceNodeID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "node_unavailable", "O node de origem não está disponível.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sourceGrants, err := s.nodeTransferGrants(r.Context(), sourceNode)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível consultar o node de origem.")
		return
	}
	sourceMetadata, err := s.nodeMetadata(r.Context(), sourceNode)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível consultar a identidade do node de origem.")
		return
	}
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	targets := make([]transferTargetNode, 0, len(nodes))
	blockedTargets := make([]blockedTransferTarget, 0)
	for _, candidate := range nodes {
		if candidate.ID == sourceNodeID || candidate.State == "untrusted" {
			continue
		}
		target := transferTargetNode{NodeID: candidate.ID, Name: candidate.Name, State: candidate.State,
			Available: candidate.State == "online"}
		if !target.Available {
			targets = append(targets, target)
			continue
		}
		if !s.transferCapabilityAllowed(r, "nodes/"+candidate.ID+"/transfers", "execute") {
			continue
		}
		destinationMetadata, metadataErr := s.nodeMetadata(r.Context(), candidate)
		if metadataErr != nil {
			target.State, target.Available = "offline", false
			targets = append(targets, target)
			continue
		}
		destinationGrants, grantsErr := s.nodeTransferGrants(r.Context(), candidate)
		if grantsErr != nil {
			target.State, target.Available = "offline", false
			targets = append(targets, target)
			continue
		}
		mounts, mountsErr := s.nodeMounts(r.Context(), candidate)
		if mountsErr != nil {
			target.State, target.Available = "offline", false
			targets = append(targets, target)
			continue
		}
		mountByID := make(map[string]nodeMount, len(mounts))
		for _, mount := range mounts {
			mountByID[mount.ID] = mount
		}
		sourceAllowed := hasCompatibleSourceGrant(sourceGrants, destinationMetadata.NodeID, input.SourceMountID, paths, operation)
		destinationAllowed := false
		for _, destinationGrant := range destinationGrants {
			if !destinationGrantAllows(destinationGrant, sourceMetadata.NodeID) ||
				!s.transferCapabilityAllowed(r, "nodes/"+candidate.ID+"/files/mounts/"+destinationGrant.MountID, "create") {
				continue
			}
			mount, exists := mountByID[destinationGrant.MountID]
			if !exists {
				continue
			}
			rootPath, rootErr := normalizeTransferPath(destinationGrant.Path, true)
			if rootErr != nil {
				continue
			}
			destinationAllowed = true
			if !sourceAllowed {
				continue
			}
			canBrowse := s.transferCapabilityAllowed(r, "nodes/"+candidate.ID+"/files/mounts/"+destinationGrant.MountID, "list")
			target.Mounts = append(target.Mounts, transferTargetMount{
				MountID: destinationGrant.MountID, Name: mount.Name, RootPath: rootPath,
				ConflictPolicies: append([]string(nil), destinationGrant.ConflictPolicies...), CanBrowse: canBrowse,
				Available: mount.Enabled && mount.State == "available" && mount.Writable, State: mount.State,
			})
		}
		if len(target.Mounts) > 0 {
			targets = append(targets, target)
		} else {
			blocked := blockedTransferTarget{NodeID: candidate.ID, Name: candidate.Name, Reasons: []string{}}
			if !sourceAllowed {
				blocked.Reasons = append(blocked.Reasons, "source_grant_missing")
			}
			if !destinationAllowed {
				blocked.Reasons = append(blocked.Reasons, "destination_grant_missing")
			}
			blockedTargets = append(blockedTargets, blocked)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"max_source_paths": s.transferMaxSourcePaths(), "targets": targets, "blocked_targets": blockedTargets,
	})
}

func (s *Server) planLogicalTransfer(w http.ResponseWriter, r *http.Request) {
	resolved, ok := s.resolveLogicalTransferRequest(w, r, "create")
	if !ok {
		return
	}
	var plan any
	if err := s.callNodeJSON(r.Context(), resolved.DestinationNode, http.MethodPost,
		"/api/v1/transfers/pull/batch/plan", resolved.nodeRequest(r.Header.Get("X-Correlation-ID")), &plan,
		r.Header.Get("X-Correlation-ID")); err != nil {
		s.writeLogicalTransferNodeError(w, r, err)
		return
	}
	s.audit(r, "plan", "nodes/"+resolved.DestinationNode.ID+"/transfers", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "max_source_paths": s.transferMaxSourcePaths()})
}

func (s *Server) createLogicalTransfer(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key é obrigatório para criar a transferência.")
		return
	}
	resolved, ok := s.resolveLogicalTransferRequest(w, r, "execute")
	if !ok {
		return
	}
	payload := resolved.nodeRequest(r.Header.Get("X-Correlation-ID"))
	canonical, err := json.Marshal(struct {
		DestinationNodeID string                 `json:"destination_node_id"`
		Request           logicalTransferRequest `json:"request"`
	}{DestinationNodeID: resolved.DestinationNode.ID, Request: resolved.Request})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum := sha256.Sum256(canonical)
	var job any
	err = s.callNodeJSONWithHeaders(r.Context(), resolved.DestinationNode, http.MethodPost,
		"/api/v1/transfers/pull/batch", payload, &job, r.Header.Get("X-Correlation-ID"), http.Header{
			"Idempotency-Key":         []string{r.Header.Get("Idempotency-Key")},
			"X-Jolt-Idempotency-Hash": []string{hex.EncodeToString(sum[:])},
		})
	if err != nil {
		s.writeLogicalTransferNodeError(w, r, err)
		return
	}
	s.audit(r, "execute", "nodes/"+resolved.DestinationNode.ID+"/transfers", "allowed")
	if jobID, _ := job.(map[string]any)["job_id"].(string); jobID != "" {
		w.Header().Set("Location", "/api/v1/nodes/"+url.PathEscape(resolved.DestinationNode.ID)+"/jobs/"+url.PathEscape(jobID))
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) resolveLogicalTransferRequest(w http.ResponseWriter, r *http.Request, transferCapability string) (resolvedLogicalTransfer, bool) {
	destinationNodeID := strings.TrimSpace(r.PathValue("nodeID"))
	var request logicalTransferRequest
	if !decodeJSON(w, r, &request) {
		return resolvedLogicalTransfer{}, false
	}
	if len(request.Source.Paths) > s.transferMaxSourcePaths() {
		writeError(w, r, http.StatusBadRequest, "selection_limit_exceeded", "A seleção excede o limite configurado de raízes.")
		return resolvedLogicalTransfer{}, false
	}
	paths, operation, err := s.normalizeTransferSelection(request.Source.Paths, request.Operation)
	if err != nil || !validPathIdentifier(destinationNodeID) || !validPathIdentifier(request.Source.NodeID) ||
		!validPathIdentifier(request.Source.MountID) || !validPathIdentifier(request.Destination.MountID) ||
		request.Source.NodeID == destinationNodeID {
		writeError(w, r, http.StatusBadRequest, "invalid_selection", "A seleção ou o destino da transferência são inválidos.")
		return resolvedLogicalTransfer{}, false
	}
	destinationPath, err := normalizeTransferPath(request.Destination.Path, true)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "path_outside_grant", "A pasta de destino precisa ser relativa ao mount autorizado.")
		return resolvedLogicalTransfer{}, false
	}
	request.Operation = operation
	request.Source.Paths = paths
	request.Destination.Path = destinationPath
	request.ConflictPolicy = strings.ToLower(strings.TrimSpace(request.ConflictPolicy))
	if request.ConflictPolicy == "" {
		request.ConflictPolicy = "fail"
	}
	if !validConflictPolicy(request.ConflictPolicy) {
		writeError(w, r, http.StatusBadRequest, "invalid_selection", "A política de conflito é inválida.")
		return resolvedLogicalTransfer{}, false
	}
	sourceFilePath := "nodes/" + request.Source.NodeID + "/files/mounts/" + request.Source.MountID
	destinationFilePath := "nodes/" + destinationNodeID + "/files/mounts/" + request.Destination.MountID
	if !s.authorize(w, r, sourceFilePath, "read", "permission_denied", "Você não pode ler o mount de origem.") ||
		!s.authorize(w, r, destinationFilePath, "create", "permission_denied", "Você não pode gravar no mount de destino.") ||
		!s.authorize(w, r, "nodes/"+destinationNodeID+"/transfers", transferCapability,
			"permission_denied", "Você não pode executar transferências neste node.") {
		return resolvedLogicalTransfer{}, false
	}
	if operation == "move" && !s.authorize(w, r, sourceFilePath, "delete", "permission_denied", "Você não pode remover itens do mount de origem.") {
		return resolvedLogicalTransfer{}, false
	}
	sourceNode, err := s.store.GetNode(r.Context(), request.Source.NodeID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "node_unavailable", "O node de origem não está disponível.")
		return resolvedLogicalTransfer{}, false
	}
	destinationNode, err := s.store.GetNode(r.Context(), destinationNodeID)
	if err != nil || destinationNode.State == "untrusted" {
		writeError(w, r, http.StatusNotFound, "node_unavailable", "O node de destino não está disponível.")
		return resolvedLogicalTransfer{}, false
	}
	sourceMetadata, sourceIdentityErr := s.nodeMetadata(r.Context(), sourceNode)
	destinationMetadata, destinationIdentityErr := s.nodeMetadata(r.Context(), destinationNode)
	if sourceIdentityErr != nil || destinationIdentityErr != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Não foi possível consultar a identidade dos nodes da transferência.")
		return resolvedLogicalTransfer{}, false
	}
	sourceGrants, err := s.nodeTransferGrants(r.Context(), sourceNode)
	if err != nil {
		s.writeLogicalTransferNodeError(w, r, err)
		return resolvedLogicalTransfer{}, false
	}
	destinationGrants, err := s.nodeTransferGrants(r.Context(), destinationNode)
	if err != nil {
		s.writeLogicalTransferNodeError(w, r, err)
		return resolvedLogicalTransfer{}, false
	}
	sourceGrant, destinationGrant, found := selectLogicalTransferGrants(sourceGrants, destinationGrants,
		sourceMetadata.NodeID, destinationMetadata.NodeID, request.Source.MountID, request.Destination.MountID,
		paths, destinationPath, operation, request.ConflictPolicy)
	if !found {
		writeError(w, r, http.StatusUnprocessableEntity, "no_compatible_grant", "Não há um grant compatível para toda a seleção e o destino.")
		return resolvedLogicalTransfer{}, false
	}
	translatedPaths := make([]string, len(paths))
	for index, sourcePath := range paths {
		translatedPaths[index], _ = relativeTransferPath(sourcePath, sourceGrant.Path)
	}
	translatedDestination, _ := relativeTransferPath(destinationPath, destinationGrant.Path)
	return resolvedLogicalTransfer{Request: request, SourceNode: sourceNode, DestinationNode: destinationNode,
		SourcePeerNodeID: sourceMetadata.NodeID,
		SourceGrant:      sourceGrant, DestinationGrant: destinationGrant, SourcePaths: translatedPaths,
		DestinationPath: translatedDestination}, true
}

func (resolved resolvedLogicalTransfer) nodeRequest(_ string) map[string]any {
	sourceNames := make([]string, len(resolved.Request.Source.Paths))
	for index, sourcePath := range resolved.Request.Source.Paths {
		sourceNames[index] = path.Base(sourcePath)
	}
	return map[string]any{
		"peer_node_id": resolved.SourcePeerNodeID, "source_grant_id": resolved.SourceGrant.ID,
		"source_paths": resolved.SourcePaths, "source_names": sourceNames, "destination_grant_id": resolved.DestinationGrant.ID,
		"destination_path": resolved.DestinationPath, "operation": resolved.Request.Operation,
		"conflict_policy": resolved.Request.ConflictPolicy, "verify_checksum": resolved.Request.VerifyChecksum,
		"bandwidth_limit_bytes_per_second": resolved.Request.BandwidthLimit,
		"max_parallel_files":               resolved.Request.MaxParallelFiles, "max_parallel_chunks": resolved.Request.MaxParallelChunks,
	}
}

func (s *Server) normalizeTransferSelection(paths []string, operation string) ([]string, string, error) {
	operation = strings.ToLower(strings.TrimSpace(operation))
	if operation == "" {
		operation = "copy"
	}
	if operation != "copy" && operation != "move" {
		return nil, "", errors.New("invalid operation")
	}
	if len(paths) < 1 || len(paths) > s.transferMaxSourcePaths() {
		return nil, "", errors.New("selection limit exceeded")
	}
	normalized := make([]string, 0, len(paths))
	for _, value := range paths {
		clean, err := normalizeTransferPath(value, false)
		if err != nil {
			return nil, "", err
		}
		normalized = append(normalized, clean)
	}
	sort.Strings(normalized)
	for index := range normalized {
		if index > 0 && (normalized[index] == normalized[index-1] || strings.HasPrefix(normalized[index], normalized[index-1]+"/")) {
			return nil, "", errors.New("overlapping selection")
		}
	}
	return normalized, operation, nil
}

func (s *Server) transferMaxSourcePaths() int {
	if s.config.TransferMaxSourcePaths > 0 {
		return s.config.TransferMaxSourcePaths
	}
	return 1000
}

func normalizeTransferPath(value string, allowRoot bool) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		if allowRoot {
			return "", nil
		}
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(value, "/") {
		return "", errors.New("absolute path")
	}
	clean := path.Clean(value)
	if clean == "." {
		if allowRoot {
			return "", nil
		}
		return "", errors.New("root path")
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("path traversal")
	}
	return clean, nil
}

func validConflictPolicy(policy string) bool {
	switch policy {
	case "fail", "skip", "overwrite", "rename", "ask", "checksum":
		return true
	default:
		return false
	}
}

func sourceGrantAllows(grant nodeTransferGrant, destinationNodeID, mountID string, paths []string, operation string) bool {
	if !grant.Enabled || grant.PeerNodeID != destinationNodeID || grant.MountID != mountID || !grant.Permissions.Read ||
		(grant.Direction != "send" && grant.Direction != "send_receive") || (operation == "move" && !grant.Permissions.Delete) {
		return false
	}
	for _, sourcePath := range paths {
		if _, ok := relativeTransferPath(sourcePath, grant.Path); !ok {
			return false
		}
	}
	return true
}

func destinationGrantAllows(grant nodeTransferGrant, sourceNodeID string) bool {
	return grant.Enabled && grant.PeerNodeID == sourceNodeID && grant.Permissions.Write &&
		(grant.Direction == "receive" || grant.Direction == "send_receive")
}

func hasCompatibleSourceGrant(grants []nodeTransferGrant, destinationNodeID, mountID string, paths []string, operation string) bool {
	for _, grant := range grants {
		if sourceGrantAllows(grant, destinationNodeID, mountID, paths, operation) {
			return true
		}
	}
	return false
}

func selectLogicalTransferGrants(sourceGrants, destinationGrants []nodeTransferGrant, sourceNodeID, destinationNodeID,
	sourceMountID, destinationMountID string, paths []string, destinationPath, operation, conflictPolicy string) (nodeTransferGrant, nodeTransferGrant, bool) {
	var sourceGrant nodeTransferGrant
	sourceSpecificity := -1
	for _, candidate := range sourceGrants {
		if !sourceGrantAllows(candidate, destinationNodeID, sourceMountID, paths, operation) {
			continue
		}
		root, err := normalizeTransferPath(candidate.Path, true)
		if err != nil {
			continue
		}
		if len(root) > sourceSpecificity {
			sourceGrant, sourceSpecificity = candidate, len(root)
		}
	}
	if sourceSpecificity < 0 {
		return nodeTransferGrant{}, nodeTransferGrant{}, false
	}
	var destinationGrant nodeTransferGrant
	destinationSpecificity := -1
	for _, candidate := range destinationGrants {
		if !destinationGrantAllows(candidate, sourceNodeID) || candidate.MountID != destinationMountID ||
			!containsString(candidate.ConflictPolicies, conflictPolicy) {
			continue
		}
		if _, ok := relativeTransferPath(destinationPath, candidate.Path); !ok {
			continue
		}
		root, err := normalizeTransferPath(candidate.Path, true)
		if err != nil {
			continue
		}
		if len(root) > destinationSpecificity {
			destinationGrant, destinationSpecificity = candidate, len(root)
		}
	}
	return sourceGrant, destinationGrant, destinationSpecificity >= 0
}

func relativeTransferPath(candidate, grantPath string) (string, bool) {
	candidate, candidateErr := normalizeTransferPath(candidate, true)
	grantPath, grantErr := normalizeTransferPath(grantPath, true)
	if candidateErr != nil || grantErr != nil {
		return "", false
	}
	if grantPath == "" {
		return candidate, true
	}
	if candidate == grantPath {
		return "", true
	}
	if strings.HasPrefix(candidate, grantPath+"/") {
		return strings.TrimPrefix(candidate, grantPath+"/"), true
	}
	return "", false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func (s *Server) nodeTransferGrants(ctx context.Context, node store.Node) ([]nodeTransferGrant, error) {
	var response struct {
		Items []nodeTransferGrant `json:"items"`
	}
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/grants", nil, &response, ""); err != nil {
		return nil, err
	}
	return response.Items, nil
}

func (s *Server) nodeMounts(ctx context.Context, node store.Node) ([]nodeMount, error) {
	var response struct {
		Items []nodeMount `json:"items"`
	}
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/mounts", nil, &response, ""); err != nil {
		return nil, err
	}
	return response.Items, nil
}

func (s *Server) transferCapabilityAllowed(r *http.Request, resource, capability string) bool {
	decision, err := s.evaluateAuthorization(r, resource, capability)
	if err != nil {
		return false
	}
	return decision.Allowed
}

func transferFromBody(r *http.Request) (transferAuthorizationInput, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return transferAuthorizationInput{}, errors.New("invalid transfer body")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var payload transferAuthorizationInput
	if err := json.Unmarshal(body, &payload); err != nil ||
		!validPathIdentifier(payload.PeerNodeID) ||
		!validPathIdentifier(payload.SourceGrantID) ||
		!validPathIdentifier(payload.DestinationGrantID) {
		return transferAuthorizationInput{}, errors.New("invalid transfer identifiers")
	}
	payload.Operation = strings.ToLower(strings.TrimSpace(payload.Operation))
	if payload.Operation != "" && payload.Operation != "copy" && payload.Operation != "move" {
		return transferAuthorizationInput{}, errors.New("invalid transfer operation")
	}
	return payload, nil
}

func (s *Server) transferMountRequirements(ctx context.Context, destinationNodeID string,
	input transferAuthorizationInput) ([]authorizationRequirement, error) {
	destinationNode, err := s.store.GetNode(ctx, destinationNodeID)
	if err != nil {
		return nil, err
	}
	sourceNode, err := s.store.GetNode(ctx, input.PeerNodeID)
	if err != nil {
		return nil, err
	}
	sourceGrant, err := s.nodeTransferGrant(ctx, sourceNode, input.SourceGrantID)
	if err != nil || !sourceGrant.Enabled || sourceGrant.PeerNodeID != destinationNodeID ||
		(sourceGrant.Direction != "send" && sourceGrant.Direction != "send_receive") ||
		!sourceGrant.Permissions.Read || (input.Operation == "move" && !sourceGrant.Permissions.Delete) {
		return nil, errors.New("source grant does not authorize this transfer")
	}
	destinationGrant, err := s.nodeTransferGrant(ctx, destinationNode, input.DestinationGrantID)
	if err != nil || !destinationGrant.Enabled || destinationGrant.PeerNodeID != input.PeerNodeID ||
		(destinationGrant.Direction != "receive" && destinationGrant.Direction != "send_receive") ||
		!destinationGrant.Permissions.Write {
		return nil, errors.New("destination grant does not authorize this transfer")
	}
	requirements := []authorizationRequirement{
		{Path: "nodes/" + input.PeerNodeID + "/files/mounts/" + sourceGrant.MountID, Capability: "read"},
		{Path: "nodes/" + destinationNodeID + "/files/mounts/" + destinationGrant.MountID, Capability: "create"},
	}
	if input.Operation == "move" {
		requirements = append(requirements, authorizationRequirement{Path: "nodes/" + input.PeerNodeID + "/files/mounts/" + sourceGrant.MountID, Capability: "delete"})
	}
	return requirements, nil
}

func (s *Server) nodeTransferGrant(ctx context.Context, node store.Node, grantID string) (nodeTransferGrant, error) {
	grants, err := s.nodeTransferGrants(ctx, node)
	if err != nil {
		return nodeTransferGrant{}, err
	}
	for _, grant := range grants {
		if grant.ID == grantID && validPathIdentifier(grant.MountID) {
			return grant, nil
		}
	}
	return nodeTransferGrant{}, errors.New("grant not found")
}

func validPathIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.ContainsAny(value, "/\\?#")
}

type authorizationRequirement struct {
	Path       string
	Capability string
}

// fileScopes turns the mount-relative paths a request touches into RBAC paths.
// With no path it falls back to the mount itself, which is what a listing of
// the mount root or a mount-wide operation authorizes against.
func fileScopes(base string, relatives []string) []string {
	scopes := make([]string, 0, len(relatives))
	for _, relative := range relatives {
		if scope := fileScope(base, relative); scope != "" {
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		return []string{base}
	}
	return scopes
}

// fileScope appends a mount-relative path to the mount's RBAC path so policies
// can target a subtree. A path that escapes the mount yields an empty scope,
// which callers turn into a denial rather than silently widening to the mount.
func fileScope(base, relative string) string {
	relative = strings.Trim(strings.ReplaceAll(strings.TrimSpace(relative), "\\", "/"), "/")
	if relative == "" || relative == "." {
		return base
	}
	segments := make([]string, 0, 8)
	for _, segment := range strings.Split(relative, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			// The node rejects traversal too, but an RBAC path must never be
			// built from a path that walks upward: it would authorize the wrong
			// subtree.
			return ""
		default:
			segments = append(segments, segment)
		}
	}
	if len(segments) == 0 {
		return base
	}
	return base + "/" + strings.Join(segments, "/")
}

func requirementsFor(paths []string, capability string) []authorizationRequirement {
	requirements := make([]authorizationRequirement, 0, len(paths))
	for _, path := range paths {
		requirements = append(requirements, authorizationRequirement{Path: path, Capability: capability})
	}
	return requirements
}

// fileTargets carries the mount-relative paths a file request acts on, so
// authorization can be evaluated against the exact subtree instead of the
// whole mount. Source and Destination are set for copy and move, where the two
// sides need different capabilities.
type fileTargets struct {
	Paths       []string
	Source      string
	Destination string
}

func (t fileTargets) all() []string {
	all := make([]string, 0, len(t.Paths)+2)
	all = append(all, t.Paths...)
	if t.Source != "" {
		all = append(all, t.Source)
	}
	if t.Destination != "" {
		all = append(all, t.Destination)
	}
	return all
}

func nodeAuthorizationRequirements(nodeID, resource, method string, targets fileTargets) []authorizationRequirement {
	segments := strings.Split(strings.Trim(resource, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		return nil
	}
	prefix := "nodes/" + nodeID
	switch segments[0] {
	case "node":
		if method == http.MethodGet {
			return []authorizationRequirement{{Path: prefix, Capability: "read"}}
		}
	case "fs":
		if method == http.MethodGet {
			return []authorizationRequirement{{Path: prefix + "/mounts", Capability: "create"}}
		}
	case "mounts":
		if len(segments) == 1 {
			return []authorizationRequirement{{Path: prefix + "/mounts", Capability: capabilityForMethod(method, true)}}
		}
		mountID := segments[1]
		if len(segments) < 3 || segments[2] != "files" {
			return []authorizationRequirement{{Path: prefix + "/mounts/" + mountID, Capability: capabilityForMethod(method, false)}}
		}
		mountBase := prefix + "/files/mounts/" + mountID
		// A path that escaped the mount produces no scope, which must deny
		// instead of falling back to the mount-wide scope.
		for _, relative := range targets.all() {
			if fileScope(mountBase, relative) == "" {
				return nil
			}
		}
		scopes := fileScopes(mountBase, targets.Paths)
		source := fileScope(mountBase, targets.Source)
		destination := fileScope(mountBase, targets.Destination)
		switch method {
		case http.MethodGet:
			if len(segments) >= 4 && (segments[3] == "content" || segments[3] == "metadata" ||
				segments[3] == "archive") {
				return requirementsFor(scopes, "read")
			}
			return requirementsFor(scopes, "list")
		case http.MethodPut:
			return requirementsFor(scopes, "create")
		case http.MethodDelete:
			return requirementsFor(scopes, "delete")
		case http.MethodPost:
			// Copy and move keep their historical capabilities, now evaluated
			// on each side's own subtree: reading the source and writing the
			// destination are separate grants once policies can name subpaths.
			if len(segments) >= 5 && segments[3] == "copy" && segments[4] == "plan" {
				return []authorizationRequirement{
					{Path: source, Capability: "read"},
					{Path: destination, Capability: "create"},
				}
			}
			if len(segments) >= 4 && segments[3] == "copy" {
				return []authorizationRequirement{
					{Path: source, Capability: "read"},
					{Path: destination, Capability: "create"},
					{Path: prefix + "/jobs", Capability: "create"},
				}
			}
			if len(segments) >= 4 && segments[3] == "move" {
				return []authorizationRequirement{
					{Path: source, Capability: "update"},
					{Path: destination, Capability: "update"},
					{Path: prefix + "/jobs", Capability: "create"},
				}
			}
			return append(requirementsFor(scopes, "create"),
				authorizationRequirement{Path: prefix + "/jobs", Capability: "create"})
		}
	case "jobs":
		if method == http.MethodGet {
			if len(segments) == 1 || (len(segments) == 2 && segments[1] == "events") {
				return []authorizationRequirement{{Path: prefix + "/jobs", Capability: "list"}}
			}
			return []authorizationRequirement{{Path: prefix + "/jobs/" + segments[1], Capability: "read"}}
		}
		if method == http.MethodPost && len(segments) >= 2 {
			capability := "execute"
			if len(segments) >= 4 && segments[2] == "items" {
				capability = "update"
			}
			return []authorizationRequirement{{Path: prefix + "/jobs/" + segments[1], Capability: capability}}
		}
	case "transfers":
		capability := "execute"
		if slicesContain(segments, "plan") {
			capability = "create"
		}
		return []authorizationRequirement{{Path: prefix + "/transfers", Capability: capability}}
	case "grants":
		return []authorizationRequirement{{Path: prefix + "/grants", Capability: capabilityForMethod(method, true)}}
	case "peers":
		return []authorizationRequirement{{Path: prefix + "/peers", Capability: capabilityForMethod(method, true)}}
	case "pairing":
		return []authorizationRequirement{{Path: prefix + "/admin/pairing", Capability: "sudo"}}
	case "crypto":
		keyType := "mtls"
		if len(segments) > 1 && segments[1] == "identity" {
			keyType = "identity"
		}
		path := prefix + "/keys/" + keyType
		if method == http.MethodGet {
			return []authorizationRequirement{{Path: path, Capability: "read"}}
		}
		if keyType == "identity" {
			return []authorizationRequirement{{Path: path, Capability: "sudo"}}
		}
		return []authorizationRequirement{{Path: path, Capability: "sudo"}, {Path: path, Capability: "execute"}}
	}
	return nil
}

func capabilityForMethod(method string, collection bool) string {
	switch method {
	case http.MethodGet:
		if collection {
			return "list"
		}
		return "read"
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return ""
	}
}

func slicesContain(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type flushingWriter struct {
	writer http.ResponseWriter
}

func (w flushingWriter) Write(buffer []byte) (int, error) {
	written, err := w.writer.Write(buffer)
	if flusher, ok := w.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return written, err
}

func (s *Server) fetchNodeID(ctx context.Context, endpoint, token string) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/api/v1/node", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("node authentication failed")
	}
	var payload struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil || payload.NodeID == "" {
		return "", errors.New("invalid node response")
	}
	return payload.NodeID, nil
}

func (s *Server) nodeMetadata(ctx context.Context, node store.Node) (nodeMetadata, error) {
	var metadata nodeMetadata
	err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/node", nil, &metadata, "")
	if err != nil || metadata.NodeID == "" || metadata.Fingerprint == "" {
		return metadata, errors.New("invalid node metadata")
	}
	return metadata, nil
}

func (s *Server) callNodeJSON(ctx context.Context, node store.Node, method, path string, body any, output any, correlationID string) error {
	return s.callNodeJSONWithHeaders(ctx, node, method, path, body, output, correlationID, nil)
}

type nodeAPIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (err *nodeAPIError) Error() string {
	if err.Message != "" {
		return err.Message
	}
	return "node rejected the operation"
}

func (s *Server) callNodeJSONWithHeaders(ctx context.Context, node store.Node, method, path string, body any, output any, correlationID string, headers http.Header) error {
	token, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		return errors.New("cannot unlock node credential")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, node.Endpoint+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	if correlationID != "" {
		request.Header.Set("X-Correlation-ID", correlationID)
	}
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err := s.client.Do(request)
	if err != nil {
		return errors.New("node unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload)
		return &nodeAPIError{StatusCode: response.StatusCode, Code: payload.Error.Code, Message: payload.Error.Message}
	}
	if output != nil && response.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(output); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) writeLogicalTransferNodeError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *nodeAPIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "idempotency_conflict":
			writeError(w, r, http.StatusConflict, "idempotency_conflict", "A chave de idempotência já foi usada com outro payload.")
			return
		case "grant_forbidden", "permission_denied":
			writeError(w, r, http.StatusForbidden, "permission_denied", "A transferência não é permitida pelos grants atuais.")
			return
		case "mount_unavailable", "waiting_mount":
			writeError(w, r, http.StatusServiceUnavailable, "mount_unavailable", "O mount necessário não está disponível.")
			return
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "node unavailable") {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Um dos nodes necessários está indisponível.")
		return
	}
	writeError(w, r, http.StatusUnprocessableEntity, "invalid_selection", "A transferência não pôde ser planejada com a seleção informada.")
}

func (s *Server) refreshNodeState(ctx context.Context, node *store.Node) {
	checkContext, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	token, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		node.State = "degraded"
		return
	}
	request, _ := http.NewRequestWithContext(checkContext, http.MethodGet, node.Endpoint+"/api/v1/node", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := s.client.Do(request)
	if err != nil {
		node.State = "offline"
		_ = s.store.UpdateNodeState(ctx, node.ID, node.State, node.LastSeenAt)
		return
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		now := time.Now().UTC()
		node.State, node.LastSeenAt = "online", &now
	} else if response.StatusCode == http.StatusUnauthorized {
		node.State = "untrusted"
	} else {
		node.State = "degraded"
	}
	_ = s.store.UpdateNodeState(ctx, node.ID, node.State, node.LastSeenAt)
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, r, http.StatusNotFound, "not_found", "Rota não encontrada.")
		return
	}
	relative := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), string(filepath.Separator))
	path := filepath.Join(s.config.StaticDir, relative)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		if contentType := mime.TypeByExtension(filepath.Ext(path)); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		http.ServeFile(w, r, path)
		return
	}
	index := filepath.Join(s.config.StaticDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "frontend_unavailable", "A interface da Control Tower ainda não foi compilada.")
		return
	}
	http.ServeFile(w, r, index)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "error", err, "correlation_id", r.Header.Get("X-Correlation-ID"))
	writeError(w, r, http.StatusInternalServerError, "internal_error", "Erro interno.")
}

func allowedNodeResource(resource string) bool {
	root := strings.Split(resource, "/")[0]
	return root == "node" || root == "mounts" || root == "jobs" || root == "pairing" ||
		root == "peers" || root == "grants" || root == "transfers" || root == "crypto" ||
		root == "fs"
}

func currentUser(r *http.Request) store.User {
	user, _ := r.Context().Value(userKey).(store.User)
	return user
}

func currentActorType(r *http.Request) string {
	actorType, _ := r.Context().Value(actorTypeKey).(string)
	if actorType == "" {
		return "user"
	}
	return actorType
}

func publicUser(user store.User) map[string]any {
	return map[string]any{"user_id": user.ID, "username": user.Username, "role": user.Role, "enabled": user.Enabled}
}

func resultForStatus(status int) string {
	if status >= 200 && status < 400 {
		return "allowed"
	}
	return "denied"
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "Corpo JSON inválido.")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "correlation_id": r.Header.Get("X-Correlation-ID")}})
}

func randomID(prefix string) string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return prefix + "_" + hex.EncodeToString(value)
}
