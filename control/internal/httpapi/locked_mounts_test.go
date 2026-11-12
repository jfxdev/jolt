package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// lockedShareNode answers like a node with a locked mount "l" and a mount "u"
// that tests can lock later.
type lockedShareNode struct {
	uLocked      atomic.Bool
	mountsStatus atomic.Int32
}

func newLockedShareHarness(t *testing.T) (*typedHarness, *lockedShareNode) {
	t.Helper()
	node := &lockedShareNode{}
	node.mountsStatus.Store(http.StatusOK)
	h := newTypedHarness(t, false, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/mounts" {
			if status := int(node.mountsStatus.Load()); status != http.StatusOK {
				return status, header, `{"error":{"code":"unavailable"}}`
			}
			u, _ := json.Marshal(map[string]any{"mount_id": "u", "name": "Open", "enabled": true, "state": "available", "locked": node.uLocked.Load()})
			return 200, header, `{"items":[{"mount_id":"l","name":"Locked","enabled":true,"state":"available","locked":true},` + string(u) + `]}`
		}
		return 200, header, `{"items":[]}`
	})
	return h, node
}

const sharesURL = "/api/v1/control-tower/shares"

func TestShareCannotBeCreatedOnALockedMount(t *testing.T) {
	h, _ := newLockedShareHarness(t)
	locked := h.do("admin", http.MethodPost, sharesURL, map[string]any{"node_id": "n1", "mount_id": "l", "path": "a.txt", "kind": "file"})
	if locked.Code != http.StatusForbidden || !strings.Contains(locked.Body.String(), "mount_locked") {
		t.Fatalf("locked mount: %d %s", locked.Code, locked.Body)
	}
	open := h.do("admin", http.MethodPost, sharesURL, map[string]any{"node_id": "n1", "mount_id": "u", "path": "a.txt", "kind": "file"})
	if open.Code != http.StatusCreated {
		t.Fatalf("regular mount: %d %s", open.Code, open.Body)
	}
}

func TestLockedMountLookupFailureLeavesTheDecisionToTheNode(t *testing.T) {
	h, node := newLockedShareHarness(t)
	node.mountsStatus.Store(http.StatusBadGateway)
	w := h.do("admin", http.MethodPost, sharesURL, map[string]any{"node_id": "n1", "mount_id": "l", "path": "a.txt", "kind": "file"})
	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "mount_locked") {
		t.Fatalf("the Control Tower must not invent a refusal it cannot confirm: %d %s", w.Code, w.Body)
	}
}
