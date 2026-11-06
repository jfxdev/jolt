package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

var (
	ErrJobAuthorizationUnavailable = contracts.ErrJobAuthorizationUnavailable
	ErrJobAuthorizationChanged     = contracts.ErrJobAuthorizationChanged
)

// GuardJobAuthorization returns a cancellation-aware context and a verified
// filter. It watches persisted renewals and cancels on expiry, revocation,
// inconsistent state or a changed policy context. Consumers must apply the
// filter to every operation and preserve checkpoints when the context is
// canceled.
func (s *Store) GuardJobAuthorization(parent context.Context, jobID, nodeID string, keys map[string]ed25519.PublicKey) (context.Context, *filetypes.Filter, context.CancelFunc, error) {
	return s.guardJobAuthorization(parent, jobID, nodeID, keys, 250*time.Millisecond)
}

func (s *Store) guardJobAuthorization(parent context.Context, jobID, nodeID string, keys map[string]ed25519.PublicKey, interval time.Duration) (context.Context, *filetypes.Filter, context.CancelFunc, error) {
	if interval <= 0 || interval > time.Second {
		return nil, nil, nil, ErrJobAuthorizationUnavailable
	}
	keySnapshot := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		keySnapshot[id] = append(ed25519.PublicKey(nil), key...)
	}
	now := time.Now().UTC()
	current, filter, err := s.ValidateJobAuthorization(parent, jobID, nodeID, keySnapshot, now)
	if err != nil {
		return nil, nil, nil, ErrJobAuthorizationUnavailable
	}
	claims, _, err := signedauth.VerifyJobLease(current.Envelope, keySnapshot, current.Binding, nodeID, current.Revision, now)
	if err != nil {
		return nil, nil, nil, ErrJobAuthorizationUnavailable
	}
	policy := append([]byte(nil), claims.Context...)
	guarded, cancel := context.WithCancelCause(parent)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		timer := time.NewTimer(time.Until(current.ExpiresAt))
		defer timer.Stop()
		for {
			select {
			case <-guarded.Done():
				return
			case <-ticker.C:
			case <-timer.C:
			}
			now := time.Now().UTC()
			next, _, err := s.ValidateJobAuthorization(guarded, jobID, nodeID, keySnapshot, now)
			if err != nil || next.Revision < current.Revision || next.Binding != current.Binding || next.Revision == current.Revision && next.Envelope != current.Envelope {
				cancel(ErrJobAuthorizationUnavailable)
				return
			}
			if next.Revision != current.Revision {
				claims, _, err := signedauth.VerifyJobLease(next.Envelope, keySnapshot, next.Binding, nodeID, next.Revision, now)
				if err != nil {
					cancel(ErrJobAuthorizationUnavailable)
					return
				}
				if !bytes.Equal(policy, claims.Context) {
					cancel(ErrJobAuthorizationChanged)
					return
				}
				current = next
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(time.Until(current.ExpiresAt))
			} else if !now.Before(current.ExpiresAt) {
				cancel(ErrJobAuthorizationUnavailable)
				return
			}
		}
	}()
	return guarded, filter, func() { cancel(context.Canceled) }, nil
}
