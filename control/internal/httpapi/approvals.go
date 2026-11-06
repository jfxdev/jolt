package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/store"
)

// Human approval. A policy rule may grant delete or update only with a
// person's approval. Where the Control Tower can keep the request (a small JSON
// delete, move or copy of files), it stores it and answers 202; an approver
// then replays it with their own permissions. Everywhere else a marked
// capability is refused, never granted, so no route can skip the approval.

const (
	maxApprovalBody       = 16 << 10
	maxPendingPerIdentity = 20
	approvalsResource     = "control-tower/approvals"
)

type approvalCollectorKey struct{}

// approvalCollector gathers the capabilities a request needed approval for,
// while the ordinary authorization loop runs.
type approvalCollector struct{ requirements []store.PendingRequirement }

func (c *approvalCollector) add(path, capability string) {
	for _, existing := range c.requirements {
		if existing.Path == path && existing.Capability == capability {
			return
		}
	}
	c.requirements = append(c.requirements, store.PendingRequirement{Path: path, Capability: capability})
}

type approvedKey struct{}

// approvedGrant lets exactly the stored requirements of one approved request
// through the approval gate while it is replayed.
type approvedGrant struct {
	id  string
	set map[string]bool
}

func requirementKey(path, capability string) string {
	return rbac.NormalizePath(path) + "\x00" + capability
}

func (g approvedGrant) covers(path, capability string) bool {
	return g.set[requirementKey(path, capability)]
}

// applyApproval turns a grant that needs approval into a denial unless this
// request is the replay of an approved one. With approvals off the mark still
// holds: the grant is refused, so turning the feature off never loosens it.
func (s *Server) applyApproval(r *http.Request, decision rbac.Decision) rbac.Decision {
	if !decision.NeedsApproval {
		return decision
	}
	if !s.config.Approvals {
		decision.Allowed, decision.NeedsApproval = false, false
		return decision
	}
	if grant, ok := r.Context().Value(approvedKey{}).(approvedGrant); ok && grant.covers(decision.Path, decision.Capability) {
		decision.NeedsApproval = false
		return decision
	}
	decision.Allowed = false
	return decision
}

// approvalRoute reports whether a request is one the Control Tower can keep for
// approval: a file delete, move or copy with a small JSON body.
func approvalRoute(resource, method string) (operation string, ok bool) {
	parts := strings.Split(resource, "/")
	if len(parts) < 3 || parts[0] != "mounts" || parts[2] != "files" {
		return "", false
	}
	switch {
	case len(parts) == 3 && method == http.MethodDelete:
		return "delete", true
	case len(parts) == 4 && method == http.MethodPost && parts[3] == "move":
		return "move", true
	case len(parts) == 4 && method == http.MethodPost && parts[3] == "copy":
		return "copy", true
	}
	return "", false
}

// withApprovalCollector arms the gate for a request that may be kept. Agents
// never get one: they have no write path to approve.
func (s *Server) withApprovalCollector(r *http.Request, resource string) (*http.Request, *approvalCollector) {
	if !s.config.Approvals || r.Context().Value(agentKey) != nil {
		return r, nil
	}
	// A replay is already approved: whatever it needs beyond what was approved
	// is refused, not queued again under the approver's name.
	if _, replay := r.Context().Value(approvedKey{}).(approvedGrant); replay {
		return r, nil
	}
	if _, ok := approvalRoute(resource, r.Method); !ok {
		return r, nil
	}
	return s.armApprovalCollector(r)
}

// armApprovalCollector makes the authorization checks that follow collect, not
// refuse, the grants that need a person's approval. Not for agents and not for
// the replay of a request that was approved already.
func (s *Server) armApprovalCollector(r *http.Request) (*http.Request, *approvalCollector) {
	if !s.config.Approvals || r.Context().Value(agentKey) != nil {
		return r, nil
	}
	if _, replay := r.Context().Value(approvedKey{}).(approvedGrant); replay {
		return r, nil
	}
	collector := &approvalCollector{}
	return r.WithContext(context.WithValue(r.Context(), approvalCollectorKey{}, collector)), collector
}

// keepForApproval stores the request that needed approval and answers 202.
func (s *Server) keepForApproval(w http.ResponseWriter, r *http.Request, resource string, targets fileTargets, collector *approvalCollector) {
	operation, _ := approvalRoute(resource, r.Method)
	body, err := io.ReadAll(io.LimitReader(r.Body, maxApprovalBody+1))
	if err != nil || len(body) > maxApprovalBody {
		writeError(w, r, http.StatusRequestEntityTooLarge, "approval_body_too_large", "O pedido é grande demais para ser guardado para aprovação.")
		return
	}
	mountID := mountIDFromResource(resource)
	summary, _ := json.Marshal(map[string]any{"operation": operation, "mount_id": mountID, "paths": targets.all()})
	op, existing, err := s.store.CreatePendingOperation(r.Context(), store.PendingOperation{
		RequesterType: currentActorType(r), RequesterID: currentUser(r).ID, Method: r.Method, NodeID: r.PathValue("nodeID"),
		Resource: resource, RawQuery: r.URL.RawQuery, Body: body, Summary: summary, Requirements: collector.requirements,
	}, maxPendingPerIdentity, time.Now())
	if errors.Is(err, store.ErrPendingTooMany) {
		writeError(w, r, http.StatusTooManyRequests, "too_many_pending_operations", "Há pedidos demais aguardando aprovação. Espere uma decisão antes de pedir outro.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !existing {
		s.notifyApproval(op, operation, mountID)
	}
	w.Header().Set("Location", "/api/v1/control-tower/pending-operations/"+op.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"pending_operation_id": op.ID, "state": "pending_approval", "expires_at": op.ExpiresAt, "operation": operation,
	})
}

type planCounts struct {
	Files       int64 `json:"files"`
	Directories int64 `json:"directories"`
	Bytes       int64 `json:"bytes"`
}

// keepPlanForApproval stores the request for a tree operation whose grant needs
// a person's approval. The plan the node made is only a count of what the
// approver will be asked about; its token is dropped, and the approver plans
// and confirms again as themselves.
func (s *Server) keepPlanForApproval(w http.ResponseWriter, r *http.Request, node store.Node, mountID, operation, source, destination string, overwrite bool, plan json.RawMessage, collector *approvalCollector) {
	var counts planCounts
	if json.Unmarshal(plan, &counts) != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node.")
		return
	}
	body, _ := json.Marshal(map[string]any{"operation": operation, "source_path": source, "destination_path": destination, "overwrite": overwrite})
	paths := []string{source}
	if operation == "move" {
		paths = append(paths, destination)
	}
	summary, _ := json.Marshal(map[string]any{"operation": operation, "mount_id": mountID, "paths": paths, "tree": true,
		"files": counts.Files, "directories": counts.Directories, "bytes": counts.Bytes})
	op, existing, err := s.store.CreatePendingOperation(r.Context(), store.PendingOperation{
		Kind: store.PendingKindPlan, RequesterType: currentActorType(r), RequesterID: currentUser(r).ID, Method: http.MethodPost,
		NodeID: node.ID, Resource: "mounts/" + mountID + "/files/destructive-plans", Body: body, Summary: summary, Requirements: collector.requirements,
	}, maxPendingPerIdentity, time.Now())
	if errors.Is(err, store.ErrPendingTooMany) {
		writeError(w, r, http.StatusTooManyRequests, "too_many_pending_operations", "Há pedidos demais aguardando aprovação. Espere uma decisão antes de pedir outro.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !existing {
		s.notifyApproval(op, operation, mountID)
	}
	w.Header().Set("Location", "/api/v1/control-tower/pending-operations/"+op.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"pending_operation_id": op.ID, "state": "pending_approval", "expires_at": op.ExpiresAt, "operation": operation,
		"files": counts.Files, "directories": counts.Directories, "bytes": counts.Bytes,
	})
}

// executePlanApproval runs an approved tree operation as the approver: plan it
// again, require the tree to be what the requester was shown, and confirm it
// at once. The job is the approver's, so its authorization renews under their
// permissions.
func (s *Server) executePlanApproval(r *http.Request, op store.PendingOperation) (int, string) {
	writer := &captureWriter{header: make(http.Header)}
	finish := func() (int, string) {
		if writer.status == 0 {
			writer.status = http.StatusOK
		}
		return writer.status, writer.body.String()
	}
	var request struct {
		Operation       string `json:"operation"`
		SourcePath      string `json:"source_path"`
		DestinationPath string `json:"destination_path"`
		Overwrite       bool   `json:"overwrite"`
	}
	var summary planCounts
	decoder := json.NewDecoder(bytes.NewReader(op.Body))
	decoder.DisallowUnknownFields()
	mountID := mountIDFromResource(op.Resource)
	node, nodeErr := s.store.GetNode(r.Context(), op.NodeID)
	if decoder.Decode(&request) != nil || json.Unmarshal(op.Summary, &summary) != nil || nodeErr != nil || !validPathIdentifier(mountID) {
		writeError(writer, r, http.StatusConflict, "invalid_pending_operation", "O pedido guardado não pôde ser lido.")
		return finish()
	}
	grant := approvedGrant{id: op.ID, set: map[string]bool{}}
	for _, requirement := range op.Requirements {
		grant.set[requirementKey(requirement.Path, requirement.Capability)] = true
	}
	r = r.WithContext(context.WithValue(r.Context(), approvedKey{}, grant))
	if s.config.TypedPolicies {
		r = markNodeFiltered(r)
	}
	if !s.authorizeDestructive(writer, r, node.ID, mountID, request.Operation, request.SourcePath, request.DestinationPath, request.Overwrite) {
		return finish()
	}
	if !s.nodeHasCapabilities(r, node, "destructive_plans_v1", "signed_local_copy_execution_v1") {
		writeError(writer, r, http.StatusConflict, "node_upgrade_required", "Atualize o node para usar planos de operações destrutivas.")
		return finish()
	}
	planned, ok := s.createPlanOnNode(writer, r, node, mountID, request.Operation, request.SourcePath, request.DestinationPath, request.Overwrite)
	if !ok {
		return finish()
	}
	var plan struct {
		planCounts
		ID    string `json:"plan_id"`
		Token string `json:"token"`
	}
	if json.Unmarshal(planned, &plan) != nil || !validPathIdentifier(plan.ID) || plan.Token == "" {
		writeError(writer, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node.")
		return finish()
	}
	if plan.planCounts != summary {
		// The approver approved what the requester was shown. The tree is
		// something else now: nothing runs, and the request must be made again.
		writeError(writer, r, http.StatusConflict, "tree_changed", "A pasta mudou depois do pedido ("+
			describeTreeChange(summary, plan.planCounts)+"). Nada foi executado; peça de novo.")
		return finish()
	}
	s.confirmPlanInto(writer, r, node, mountID, plan.ID, plan.Token, "approval-"+op.ID)
	return finish()
}

func describeTreeChange(before, after planCounts) string {
	return fmt.Sprintf("era %d arquivos, %d pastas, %d bytes; agora %d, %d, %d", before.Files, before.Directories, before.Bytes, after.Files, after.Directories, after.Bytes)
}

// notifyApproval tells an optional webhook that a request is waiting. It is a
// notification only: it carries no paths, body or credentials, and a failure
// changes nothing.
func (s *Server) notifyApproval(op store.PendingOperation, operation, mountID string) {
	if s.config.ApprovalWebhookURL == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"event": "pending_operation", "pending_operation_id": op.ID, "operation": operation, "node_id": op.NodeID,
		"mount_id": mountID, "requester_type": op.RequesterType, "requester_id": op.RequesterID, "expires_at": op.ExpiresAt,
	})
	go func() {
		defer func() { _ = recover() }()
		request, err := http.NewRequest(http.MethodPost, s.config.ApprovalWebhookURL, bytes.NewReader(payload))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(request)
		if err != nil {
			s.log.Warn("approval webhook failed", "error", err)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
	}()
}

type pendingView struct {
	store.PendingOperation
	RequesterName string `json:"requester_name,omitempty"`
	DecidedByName string `json:"decided_by_name,omitempty"`
}

func (s *Server) subjectName(ctx context.Context, actorType, id string) string {
	switch actorType {
	case "user":
		if user, err := s.store.GetUser(ctx, id); err == nil {
			return user.Username
		}
	case "service_account":
		if account, err := s.store.GetServiceAccount(ctx, id); err == nil {
			return account.Name
		}
	}
	return ""
}

func (s *Server) pendingView(ctx context.Context, op store.PendingOperation) pendingView {
	view := pendingView{PendingOperation: op, RequesterName: s.subjectName(ctx, op.RequesterType, op.RequesterID)}
	if op.DecidedByID != "" {
		view.DecidedByName = s.subjectName(ctx, op.DecidedByType, op.DecidedByID)
	}
	return view
}

func (s *Server) approvalsEnabled(w http.ResponseWriter, r *http.Request) bool {
	if s.config.Approvals {
		return true
	}
	writeError(w, r, http.StatusNotFound, "approvals_disabled", "As aprovações humanas não estão habilitadas.")
	return false
}

func (s *Server) listPendingOperations(w http.ResponseWriter, r *http.Request) {
	if !s.approvalsEnabled(w, r) {
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	requesterType, requesterID := "", ""
	if r.URL.Query().Get("mine") == "true" {
		requesterType, requesterID = currentActorType(r), currentUser(r).ID
	} else if !s.authorize(w, r, approvalsResource, "list", "permission_denied", "A policy atual não permite listar aprovações.") {
		return
	}
	items, err := s.store.ListPendingOperations(r.Context(), state, requesterType, requesterID, 100, time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	views := make([]pendingView, 0, len(items))
	for _, item := range items {
		views = append(views, s.pendingView(r.Context(), item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (s *Server) getPendingOperation(w http.ResponseWriter, r *http.Request) {
	if !s.approvalsEnabled(w, r) {
		return
	}
	op, err := s.store.GetPendingOperation(r.Context(), r.PathValue("operationID"), time.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "pending_operation_not_found", "Pedido não encontrado.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	own := op.RequesterType == currentActorType(r) && op.RequesterID == currentUser(r).ID
	if !own && !s.authorize(w, r, approvalsResource, "list", "permission_denied", "A policy atual não permite ver este pedido.") {
		return
	}
	writeJSON(w, http.StatusOK, s.pendingView(r.Context(), op))
}

// approver checks that the caller is a person allowed to decide.
func (s *Server) approver(w http.ResponseWriter, r *http.Request) bool {
	if currentActorType(r) != "user" || r.Context().Value(agentKey) != nil {
		writeError(w, r, http.StatusForbidden, "approval_requires_a_person", "Somente uma pessoa autenticada pode decidir um pedido.")
		return false
	}
	return s.requireAdmin(w, r, "sudo", approvalsResource)
}

type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}
func (c *captureWriter) Write(data []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if room := 16<<10 - c.body.Len(); room > 0 {
		c.body.Write(data[:min(len(data), room)])
	}
	return len(data), nil
}

type approveRequest struct {
	AcknowledgeSelfApproval bool `json:"acknowledge_self_approval"`
}

func (s *Server) approvePendingOperation(w http.ResponseWriter, r *http.Request) {
	if !s.approvalsEnabled(w, r) || !s.approver(w, r) {
		return
	}
	var input approveRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &input) {
		return
	}
	id, now := r.PathValue("operationID"), time.Now()
	op, err := s.store.GetPendingOperation(r.Context(), id, now)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "pending_operation_not_found", "Pedido não encontrado.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A decided request answers again with what happened, so a retry of the
	// approval never runs the operation twice.
	switch op.State {
	case store.PendingExecuted, store.PendingFailed:
		writeJSON(w, http.StatusOK, map[string]any{"pending_operation": s.pendingView(r.Context(), op), "result": resultView(op.ResultStatus, op.ResultBody), "replayed": true})
		return
	case store.PendingExecuting:
		writeError(w, r, http.StatusConflict, "operation_in_progress", "Este pedido já está sendo executado.")
		return
	case store.PendingExpired:
		writeError(w, r, http.StatusGone, "pending_operation_expired", "O pedido expirou. Peça novamente.")
		return
	case store.PendingIndeterminate:
		writeError(w, r, http.StatusConflict, "pending_operation_indeterminate", "O servidor reiniciou durante a execução: não se sabe se o pedido chegou ao node. Confira o resultado e peça novamente se preciso.")
		return
	case store.PendingRejected:
		writeError(w, r, http.StatusConflict, "pending_operation_rejected", "O pedido já foi rejeitado.")
		return
	}
	self := op.RequesterType == currentActorType(r) && op.RequesterID == currentUser(r).ID
	if self && !input.AcknowledgeSelfApproval {
		writeError(w, r, http.StatusConflict, "self_approval_requires_acknowledgement", "Você pediu esta operação. Confirme que aprova o seu próprio pedido.")
		return
	}
	if ok, err := s.requesterStillAllowed(r.Context(), op); err != nil {
		s.fail(w, r, err)
		return
	} else if !ok {
		_, _ = s.store.RejectPendingOperation(r.Context(), id, "system", "approvals", "requester no longer allowed", now)
		writeError(w, r, http.StatusConflict, "requester_not_allowed", "Quem pediu não tem mais permissão para esta operação. O pedido foi encerrado.")
		return
	}
	claimed, err := s.store.ClaimPendingOperation(r.Context(), id, currentActorType(r), currentUser(r).ID, now)
	switch {
	case errors.Is(err, store.ErrPendingExpired):
		writeError(w, r, http.StatusGone, "pending_operation_expired", "O pedido expirou. Peça novamente.")
		return
	case errors.Is(err, store.ErrPendingCorrupt):
		writeError(w, r, http.StatusConflict, "pending_operation_corrupt", "O pedido guardado não confere com o original e não será executado.")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "operation_in_progress", "Outro aprovador decidiu este pedido primeiro.")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	var status int
	var body string
	if claimed.Kind == store.PendingKindPlan {
		status, body = s.executePlanApproval(r, claimed)
	} else {
		status, body = s.replayApproved(r, claimed)
	}
	if err := s.store.FinishPendingOperation(r.Context(), id, status, body, time.Now()); err != nil {
		s.log.Error("could not record the result of an approved operation", "error", err, "pending_operation_id", id)
	}
	done, err := s.store.GetPendingOperation(r.Context(), id, time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "pending_operation_execute", "nodes/"+claimed.NodeID+"/"+claimed.Resource, resultForStatus(status))
	writeJSON(w, http.StatusOK, map[string]any{"pending_operation": s.pendingView(r.Context(), done), "result": resultView(status, body)})
}

func resultView(status int, body string) map[string]any {
	view := map[string]any{"status": status}
	if json.Valid([]byte(body)) {
		view["body"] = json.RawMessage(body)
	} else if body != "" {
		view["body"] = body
	}
	return view
}

// requesterStillAllowed re-evaluates, with the requester's current policies,
// every capability the request needed. Approval never adds to what the
// requester is allowed: it only supplies the person the policy asked for.
func (s *Server) requesterStillAllowed(ctx context.Context, op store.PendingOperation) (bool, error) {
	var groupIDs []string
	switch op.RequesterType {
	case "user":
		user, err := s.store.GetUser(ctx, op.RequesterID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !user.Enabled {
			return false, nil
		}
		if user.Role == "admin" {
			return true, nil
		}
	case "service_account":
		account, err := s.store.GetServiceAccount(ctx, op.RequesterID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !account.Enabled || account.Kind == "agent" {
			return false, nil
		}
		if groupIDs, err = s.store.ServiceAccountGroupIDs(ctx, account.ID, true); err != nil {
			return false, err
		}
	default:
		return false, nil
	}
	policies, err := s.store.RBACPoliciesForSubject(ctx, op.RequesterType, op.RequesterID)
	if err != nil {
		return false, err
	}
	policies = rbac.ExpandCompatibilityRules(policies)
	for _, requirement := range op.Requirements {
		if op.RequesterType == "service_account" {
			segments := strings.Split(rbac.NormalizePath(requirement.Path), "/")
			if len(segments) >= 2 && segments[0] == "nodes" {
				member := false
				for _, groupID := range groupIDs {
					in, err := s.store.NodeInAccessGroup(ctx, groupID, segments[1])
					if err != nil {
						return false, err
					}
					member = member || in
				}
				if !member {
					return false, nil
				}
			}
		}
		var decision rbac.Decision
		if s.config.TypedPolicies {
			decision = rbac.EvaluateTyped(policies, requirement.Path, requirement.Capability, rbac.EveryEntry)
		} else {
			decision = rbac.Evaluate(policies, requirement.Path, requirement.Capability)
		}
		if !decision.Allowed {
			return false, nil
		}
	}
	return true, nil
}

// replayApproved runs the stored request through the same pipeline as a fresh
// one, as the approver, with only its own requirements let past the gate.
func (s *Server) replayApproved(r *http.Request, op store.PendingOperation) (int, string) {
	grant := approvedGrant{id: op.ID, set: map[string]bool{}}
	for _, requirement := range op.Requirements {
		grant.set[requirementKey(requirement.Path, requirement.Capability)] = true
	}
	replay := r.Clone(context.WithValue(r.Context(), approvedKey{}, grant))
	replay.Method = op.Method
	replay.URL = &url.URL{Path: "/api/v1/nodes/" + op.NodeID + "/" + op.Resource, RawQuery: op.RawQuery}
	replay.RequestURI = replay.URL.RequestURI()
	replay.Body = io.NopCloser(bytes.NewReader(op.Body))
	replay.ContentLength = int64(len(op.Body))
	replay.Header = make(http.Header)
	replay.Header.Set("X-Correlation-ID", r.Header.Get("X-Correlation-ID"))
	// The same key on every replay of this request, so a node that creates
	// jobs by key cannot create two.
	replay.Header.Set("Idempotency-Key", "approval-"+op.ID)
	if len(op.Body) > 0 {
		replay.Header.Set("Content-Type", "application/json")
	}
	replay.SetPathValue("nodeID", op.NodeID)
	replay.SetPathValue("resource", op.Resource)
	writer := &captureWriter{header: make(http.Header)}
	s.proxyNode(writer, replay)
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.status, writer.body.String()
}

type rejectRequest struct {
	Note string `json:"note"`
}

func (s *Server) rejectPendingOperation(w http.ResponseWriter, r *http.Request) {
	if !s.approvalsEnabled(w, r) || !s.approver(w, r) {
		return
	}
	var input rejectRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &input) {
		return
	}
	input.Note = strings.TrimSpace(input.Note)
	if len([]rune(input.Note)) > 256 {
		writeError(w, r, http.StatusBadRequest, "invalid_note", "A nota deve ter até 256 caracteres.")
		return
	}
	op, err := s.store.RejectPendingOperation(r.Context(), r.PathValue("operationID"), currentActorType(r), currentUser(r).ID, input.Note, time.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "pending_operation_not_found", "Pedido não encontrado.")
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "pending_operation_decided", "Este pedido já foi decidido ou expirou.")
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, http.StatusOK, s.pendingView(r.Context(), op))
	}
}
