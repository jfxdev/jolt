package httpapi

import (
	"context"
)

// A mount configured with locked: true exposes metadata only. The node is the
// authority: it refuses every content or movement operation with 403
// mount_locked, for every caller (administrators, signed leases, public links and
// its own mTLS peers), and the Control Tower relays that answer. The one thing
// the node cannot know is that a public link would never be served, so link
// creation checks the mount first. File proxying deliberately does not: it would
// add a round trip to every request for a check the node repeats anyway.

const lockedMountMessage = "Este mount está bloqueado: apenas metadados estão disponíveis."

// mountLockedByID asks the node whether a mount is locked. It fails open: when
// the node cannot be asked, the caller continues and the node refuses by itself.
func (s *Server) mountLockedByID(ctx context.Context, nodeID, mountID string) bool {
	if mountID == "" {
		return false
	}
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return false
	}
	mounts, err := s.nodeMounts(ctx, node)
	if err != nil {
		if s.log != nil {
			s.log.Warn("could not check whether a mount is locked", "node_id", node.ID, "mount_id", mountID, "error", err)
		}
		return false
	}
	for _, mount := range mounts {
		if mount.ID == mountID {
			return mount.Locked
		}
	}
	return false
}
