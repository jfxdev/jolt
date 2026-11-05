package httpapi

import (
	"context"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
)

// signedPolicySnapshot serializes temporary grant changes with the policy
// snapshot, so a newly granted policy cannot appear without its expiry.
// All temporary policies for the subject are included in the deadline: an
// expiring deny can affect the result just as an expiring allow can.
func (s *Server) signedPolicySnapshot(ctx context.Context, subjectType, subjectID string) ([]rbac.Policy, *time.Time, error) {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	return s.signedPolicySnapshotLocked(ctx, subjectType, subjectID)
}

// signedPolicySnapshotLocked requires agentMu. It is used when credential,
// group and policy validation must share the same admission boundary.
func (s *Server) signedPolicySnapshotLocked(ctx context.Context, subjectType, subjectID string) ([]rbac.Policy, *time.Time, error) {
	assignments, err := s.store.TemporaryPolicies(ctx, subjectType, subjectID)
	if err != nil {
		return nil, nil, err
	}
	policies, err := s.store.RBACPoliciesForSubject(ctx, subjectType, subjectID)
	if err != nil {
		return nil, nil, err
	}
	var earliest *time.Time
	for _, assignment := range assignments {
		if earliest == nil || assignment.ExpiresAt.Before(*earliest) {
			expiry := assignment.ExpiresAt
			earliest = &expiry
		}
	}
	return policies, earliest, nil
}
