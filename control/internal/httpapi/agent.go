package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

type agentTokenState struct {
	tokens    float64
	last      time.Time
	next      uint64
	accountID string
	active    map[uint64]context.CancelFunc
}

type agentContext struct {
	limits store.AgentLimits
	budget int64
}

func normalizeAgentLimits(input *store.AgentLimits) (store.AgentLimits, error) {
	limits := store.DefaultAgentLimits()
	if input != nil {
		limits = *input
	}
	if limits.RequestsPerMinute < 1 || limits.RequestsPerMinute > 60000 || limits.Burst < 1 || limits.Burst > 10000 ||
		limits.MaxConcurrent < 1 || limits.MaxConcurrent > 32 || limits.MaxResponseBytes < 1024 || limits.MaxResponseBytes > 1<<30 ||
		limits.DailyBytes < limits.MaxResponseBytes || limits.DailyBytes > 1<<50 || len(limits.AllowedCIDRs) > 64 || len(limits.ReadMediaTypes) > 64 {
		return limits, errors.New("invalid agent limits")
	}
	for i, raw := range limits.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return limits, errors.New("invalid allowed CIDR")
		}
		limits.AllowedCIDRs[i] = prefix.Masked().String()
	}
	seenTypes := make(map[string]bool, len(limits.ReadMediaTypes))
	for i, raw := range limits.ReadMediaTypes {
		value := strings.ToLower(strings.TrimSpace(raw))
		mediaType, params, err := mime.ParseMediaType(value)
		if err != nil || len(params) != 0 || strings.Contains(mediaType, "*") || !strings.Contains(mediaType, "/") || seenTypes[mediaType] {
			return limits, errors.New("invalid read media type")
		}
		limits.ReadMediaTypes[i] = mediaType
		seenTypes[mediaType] = true
	}
	if limits.Capabilities != nil {
		seen := map[string]bool{}
		for i, raw := range *limits.Capabilities {
			capability := strings.ToLower(strings.TrimSpace(raw))
			if (capability != "read" && capability != "list") || seen[capability] {
				return limits, errors.New("invalid agent capability ceiling")
			}
			(*limits.Capabilities)[i] = capability
			seen[capability] = true
		}
	}
	return limits, nil
}

func sourceAddress(r *http.Request, trusted []netip.Prefix) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, err
	}
	address = address.Unmap()
	contains := func(a netip.Addr) bool {
		for _, prefix := range trusted {
			if prefix.Contains(a) {
				return true
			}
		}
		return false
	}
	if !contains(address) {
		return address, nil
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(chain) - 1; i >= 0 && contains(address); i-- {
		part := strings.TrimSpace(chain[i])
		if part == "" {
			continue
		}
		next, err := netip.ParseAddr(part)
		if err != nil {
			return netip.Addr{}, err
		}
		address = next.Unmap()
	}
	return address, nil
}

func addressAllowed(r *http.Request, limits store.AgentLimits, trusted []netip.Prefix) bool {
	if len(limits.AllowedCIDRs) == 0 {
		return true
	}
	address, err := sourceAddress(r, trusted)
	if err != nil {
		return false
	}
	for _, raw := range limits.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) serveAgent(next http.Handler, w http.ResponseWriter, r *http.Request, digest string, account store.ServiceAccount, token store.ServiceAccountToken) {
	limits, err := normalizeAgentLimits(token.AgentLimits)
	if err != nil || token.ExpiresAt == nil || !token.ExpiresAt.After(time.Now().UTC()) || !addressAllowed(r, limits, s.config.TrustedProxies) {
		s.auditAgentDenial(r, account.ID, token.ID, "invalid_credential", http.StatusUnauthorized)
		writeError(w, r, http.StatusUnauthorized, "invalid_service_token", "Credencial de agente inválida, expirada ou fora da rede permitida.")
		return
	}
	now := time.Now().UTC()
	s.agentMu.Lock()
	// Serialize admission with revocation and disable, and recheck the token
	// after taking the lock so a stale authentication cannot start a stream.
	currentAccount, currentToken, err := s.store.AuthenticateServiceAccount(r.Context(), digest)
	if err != nil || currentAccount.ID != account.ID || currentToken.ID != token.ID || currentAccount.Kind != "agent" || currentToken.ExpiresAt == nil || !currentToken.ExpiresAt.After(now) {
		s.agentMu.Unlock()
		writeError(w, r, http.StatusUnauthorized, "invalid_service_token", "Credencial de agente inválida ou revogada.")
		return
	}
	limits, err = normalizeAgentLimits(currentToken.AgentLimits)
	if err != nil || !addressAllowed(r, limits, s.config.TrustedProxies) {
		s.agentMu.Unlock()
		writeError(w, r, http.StatusUnauthorized, "invalid_service_token", "Credencial de agente inválida ou fora da rede permitida.")
		return
	}
	state := s.agentTokens[token.ID]
	actorLabel := s.agentMetricLabelLocked(account.ID)
	if state == nil {
		for key, old := range s.agentTokens {
			if len(old.active) == 0 && now.Sub(old.last) > 5*time.Minute {
				delete(s.agentTokens, key)
			}
		}
		if len(s.agentTokens) >= 10000 {
			s.agentMu.Unlock()
			writeError(w, r, http.StatusServiceUnavailable, "agent_capacity", "Limite de credenciais ativas atingido.")
			return
		}
		state = &agentTokenState{tokens: float64(limits.Burst), last: now, accountID: account.ID, active: map[uint64]context.CancelFunc{}}
		s.agentTokens[token.ID] = state
	}
	state.tokens = math.Min(float64(limits.Burst), state.tokens+now.Sub(state.last).Seconds()*float64(limits.RequestsPerMinute)/60)
	state.last = now
	if state.tokens < 1 || len(state.active) >= limits.MaxConcurrent {
		retry := int(math.Ceil((1 - state.tokens) * 60 / float64(limits.RequestsPerMinute)))
		if retry < 1 {
			retry = 1
		}
		s.agentMu.Unlock()
		s.registry.Inc("jolt_control_agent_limited_total", actorLabel, "rate_or_concurrency")
		s.auditAgentDenial(r, account.ID, token.ID, "rate_or_concurrency", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeError(w, r, http.StatusTooManyRequests, "agent_rate_limited", "Limite de requisições do agente atingido.")
		return
	}
	day := now.Format("2006-01-02")
	budget, err := s.store.ReserveAgentBytes(r.Context(), token.ID, day, limits.MaxResponseBytes, limits.DailyBytes)
	if err != nil {
		s.agentMu.Unlock()
		if errors.Is(err, store.ErrAgentQuota) {
			s.registry.Inc("jolt_control_agent_limited_total", actorLabel, "daily_quota")
			s.auditAgentDenial(r, account.ID, token.ID, "daily_quota", http.StatusTooManyRequests)
			w.Header().Set("Retry-After", secondsUntilNextUTCDay(now))
			writeError(w, r, http.StatusTooManyRequests, "agent_daily_quota", "A cota diária de leitura foi atingida.")
		} else {
			s.fail(w, r, err)
		}
		return
	}
	state.tokens--
	state.next++
	id := state.next
	deadline := *currentToken.ExpiresAt
	if midnight := now.Truncate(24 * time.Hour).Add(24 * time.Hour); midnight.Before(deadline) {
		deadline = midnight
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	controller := http.NewResponseController(w)
	// A canceled upstream context alone does not unblock a response currently
	// stalled on a slow client. Apply a write deadline to the downstream too.
	_ = controller.SetWriteDeadline(deadline)
	state.active[id] = func() {
		cancel()
		_ = controller.SetWriteDeadline(time.Now())
	}
	s.agentMu.Unlock()
	limited := &agentWriter{ResponseWriter: w, ctx: ctx, limit: budget, status: http.StatusOK}
	started := time.Now()
	defer func() {
		s.agentMu.Lock()
		delete(state.active, id)
		wasCancelled := ctx.Err() != nil
		s.agentMu.Unlock()
		cancel()
		if !limited.aborted && !wasCancelled {
			_ = controller.SetWriteDeadline(time.Time{})
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := s.store.RefundAgentBytes(cleanup, token.ID, day, budget-limited.written); err != nil {
			s.log.Error("agent quota refund failed", "token_id", token.ID, "error", err)
		}
		result := "allowed"
		if limited.aborted || limited.status >= 400 {
			result = "denied"
		}
		s.registry.Inc("jolt_control_agent_requests_total", actorLabel, result)
		s.registry.Add("jolt_control_agent_bytes_out_total", limited.written, actorLabel)
		detail := map[string]any{"token_id": token.ID, "method": r.Method, "status": limited.status, "bytes_out": limited.written, "duration_ms": time.Since(started).Milliseconds()}
		if value := auditRange(r.Header.Get("Range")); value != "" {
			detail["range"] = value
		}
		if limited.aborted {
			reason := limited.abortReason
			if wasCancelled {
				reason = "cancelled"
			}
			if reason == "" {
				reason = "transport"
			}
			detail["aborted_by"] = reason
			if reason == "quota" {
				s.registry.Inc("jolt_control_agent_limited_total", actorLabel, "stream_quota")
			}
		}
		if s.config.AuditSearchQuery && strings.HasSuffix(r.URL.Path, "/files/search") {
			if query := []rune(r.URL.Query().Get("query")); len(query) > 0 {
				if len(query) > 128 {
					query = query[:128]
				}
				detail["query"] = string(query)
			}
		}
		source := ""
		if address, err := sourceAddress(r, s.config.TrustedProxies); err == nil {
			source = address.String()
		}
		if err := s.store.AuditAgentRequest(cleanup, account.ID, r.URL.Path, result, r.Header.Get("X-Correlation-ID"), source, detail); err != nil {
			s.log.Error("agent request audit failed", "error", err)
		}
	}()
	ctx = context.WithValue(ctx, agentKey, agentContext{limits: limits, budget: budget})
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(limited, r, http.StatusForbidden, "agent_read_only", "Esta conta de agente permite apenas leitura.")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/files") || strings.HasSuffix(r.URL.Path, "/files/search") {
		query := r.URL.Query()
		limit, err := strconv.Atoi(query.Get("limit"))
		if err != nil || limit <= 0 || limit > 200 {
			query.Set("limit", "200")
			r.URL.RawQuery = query.Encode()
		}
	}
	next.ServeHTTP(limited, r.WithContext(ctx))
	if limited.aborted || (ctx.Err() != nil && limited.wrote) {
		limited.aborted = true
		if ctx.Err() != nil {
			limited.abortReason = "cancelled"
		}
		panic(http.ErrAbortHandler)
	}
}

type agentWriter struct {
	http.ResponseWriter
	ctx            context.Context
	limit, written int64
	status         int
	abortReason    string
	wrote, aborted bool
}

func (w *agentWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
	}
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *agentWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		w.aborted = true
		w.abortReason = "cancelled"
		return 0, err
	}
	remaining := w.limit - w.written
	if int64(len(data)) > remaining {
		w.aborted = true
		w.abortReason = "quota"
		if remaining <= 0 {
			return 0, io.ErrShortWrite
		}
		data = data[:int(remaining)]
	}
	if !w.wrote {
		w.status = http.StatusOK
	}
	w.wrote = true
	n, err := w.ResponseWriter.Write(data)
	w.written += int64(n)
	if err != nil && !w.aborted {
		w.aborted = true
		w.abortReason = "transport"
	}
	if w.aborted && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}
func (w *agentWriter) Flush() {
	if w.ctx.Err() != nil {
		w.aborted = true
		w.abortReason = "cancelled"
		return
	}
	if !w.wrote {
		w.status = http.StatusOK
	}
	w.wrote = true
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Server) agentMetricLabelLocked(accountID string) string {
	if _, ok := s.agentActors[accountID]; ok {
		return accountID
	}
	if len(s.agentActors) >= 1024 {
		return "other"
	}
	s.agentActors[accountID] = struct{}{}
	return accountID
}

func (s *Server) auditCanary(r *http.Request, actorID, actorType, resource string, status int) {
	s.store.AuditActor(r.Context(), actorID, actorType, "canary", resource, resultForStatus(status), r.Header.Get("X-Correlation-ID"))
	s.agentMu.Lock()
	label := s.agentMetricLabelLocked(actorID)
	s.agentMu.Unlock()
	s.registry.Inc("jolt_control_canary_total", label)
}

func auditRange(value string) string {
	if len(value) > 128 || !strings.HasPrefix(value, "bytes=") {
		return ""
	}
	for _, ch := range value[len("bytes="):] {
		if (ch < '0' || ch > '9') && ch != '-' && ch != ',' && ch != ' ' {
			return ""
		}
	}
	return value
}

func (s *Server) auditAgentDenial(r *http.Request, actorID, tokenID, reason string, status int) {
	source := ""
	if address, err := sourceAddress(r, s.config.TrustedProxies); err == nil {
		source = address.String()
	}
	if err := s.store.AuditAgentRequest(r.Context(), actorID, r.URL.Path, "denied", r.Header.Get("X-Correlation-ID"), source, map[string]any{"token_id": tokenID, "status": status, "reason": reason, "bytes_out": 0}); err != nil {
		s.log.Error("agent denial audit failed", "error", err)
	}
}

// cancelAgentLocked is called under agentMu after the database mutation.
func (s *Server) cancelAgentLocked(accountID, tokenID string) {
	for id, state := range s.agentTokens {
		if (accountID == "" || state.accountID == accountID) && (tokenID == "" || id == tokenID) {
			for _, cancel := range state.active {
				cancel()
			}
		}
	}
}

func (s *Server) disableAgents(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "disable", "control-tower/service-accounts") {
		return
	}
	if kind := r.URL.Query().Get("kind"); kind != "" && kind != "agent" {
		writeError(w, r, http.StatusBadRequest, "invalid_kind", "O desligamento coletivo aceita apenas agentes.")
		return
	}
	s.agentMu.Lock()
	count, err := s.store.DisableAgents(r.Context(), time.Now().UTC())
	if err == nil {
		s.cancelAgentLocked("", "")
	}
	s.agentMu.Unlock()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "disable_agents", "control-tower/service-accounts", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"disabled": count})
}

func (s *Server) updateAgentToken(w http.ResponseWriter, r *http.Request) {
	accountID, tokenID := strings.TrimSpace(r.PathValue("serviceAccountID")), strings.TrimSpace(r.PathValue("tokenID"))
	resource := "control-tower/service-accounts/" + accountID + "/tokens/" + tokenID
	if !s.requireAdmin(w, r, "update", resource) {
		return
	}
	var input struct {
		AgentLimits *store.AgentLimits `json:"agent_limits"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.AgentLimits == nil {
		writeError(w, r, http.StatusBadRequest, "invalid_agent_settings", "Informe os limites da credencial.")
		return
	}
	limits, err := normalizeAgentLimits(input.AgentLimits)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_agent_settings", "Limites ou redes permitidas são inválidos.")
		return
	}
	s.agentMu.Lock()
	err = s.store.UpdateAgentTokenLimits(r.Context(), accountID, tokenID, limits)
	if err == nil {
		s.cancelAgentLocked(accountID, tokenID)
	}
	s.agentMu.Unlock()
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "service_token_not_found", "Credencial de agente ativa não encontrada.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "update_agent_limits", resource, "allowed")
	w.WriteHeader(http.StatusNoContent)
}

func validAgentExpiry(expiry *time.Time, now time.Time) bool {
	return expiry != nil && expiry.After(now) && !expiry.After(now.Add(30*24*time.Hour))
}

func secondsUntilNextUTCDay(now time.Time) string {
	now = now.UTC()
	return strconv.Itoa(int(math.Ceil(now.Truncate(24 * time.Hour).Add(24 * time.Hour).Sub(now).Seconds())))
}

func agentExpiryError() string {
	return fmt.Sprintf("A credencial de agente deve expirar em até %d dias.", 30)
}
