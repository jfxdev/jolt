package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

// DestructivePlan is an internal persistence contract. The caller must derive
// the subject from verified authorization and independently inspect both the
// source tree and any existing destination. No HTTP endpoint uses it yet.
type DestructivePlan struct {
	ID                string    `yaml:"id" json:"-"`
	TokenHash         string    `yaml:"token_hash" json:"-"`
	SubjectType       string    `yaml:"subject_type" json:"-"`
	SubjectID         string    `yaml:"subject_id" json:"-"`
	Operation         string    `yaml:"operation" json:"-"`
	MountID           string    `yaml:"mount_id" json:"-"`
	Source            string    `yaml:"source" json:"-"`
	Destination       string    `yaml:"destination,omitempty" json:"-"`
	Overwrite         bool      `yaml:"overwrite,omitempty" json:"-"`
	DestinationExists bool      `yaml:"destination_exists,omitempty" json:"-"`
	TreeDigest        string    `yaml:"tree_digest" json:"-"`
	DestinationDigest string    `yaml:"destination_digest,omitempty" json:"-"`
	CreatedAt         time.Time `yaml:"created_at" json:"-"`
	ExpiresAt         time.Time `yaml:"expires_at" json:"-"`
	ConsumedJobID     string    `yaml:"consumed_job_id,omitempty" json:"-"`
	IdempotencyKey    string    `yaml:"idempotency_key,omitempty" json:"-"`
	RequestHash       string    `yaml:"request_hash,omitempty" json:"-"`
}

func planDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func planPath(value string) bool {
	return value != "" && len(value) <= 2048 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\\\x00") && !strings.HasPrefix(value, "/") && value != "." && value != ".." && !strings.HasPrefix(value, "../") && path.Clean(value) == value
}

func destructiveIdempotencyKey(subjectType, subjectID, key string) string {
	sum := sha256.Sum256([]byte(subjectType + "\x00" + subjectID + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

// CreateDestructivePlan writes the security-version header before recording a
// plan, so an older node cannot silently ignore the new persisted contract.
func (s *Store) CreateDestructivePlan(ctx context.Context, plan DestructivePlan, now time.Time) error {
	if !signedauth.ValidKeyID(plan.ID) || !signedauth.ValidKeyID(plan.SubjectID) || !signedauth.ValidKeyID(plan.MountID) ||
		(plan.SubjectType != "user" && plan.SubjectType != "service_account") || !planDigest(plan.TokenHash) || !planDigest(plan.TreeDigest) || !planPath(plan.Source) || now.IsZero() ||
		plan.ConsumedJobID != "" || plan.IdempotencyKey != "" || plan.RequestHash != "" {
		return errors.New("invalid destructive plan")
	}
	switch plan.Operation {
	case "delete":
		if plan.Destination != "" || plan.Overwrite || plan.DestinationExists || plan.DestinationDigest != "" {
			return errors.New("invalid delete plan")
		}
	case "move":
		if !planPath(plan.Destination) || plan.Destination == plan.Source || strings.HasPrefix(plan.Destination, plan.Source+"/") ||
			plan.DestinationExists && (!plan.Overwrite || !planDigest(plan.DestinationDigest)) || !plan.DestinationExists && plan.DestinationDigest != "" {
			return errors.New("invalid move plan")
		}
	default:
		return errors.New("invalid destructive operation")
	}
	plan.CreatedAt, plan.ExpiresAt = now.UTC(), now.UTC().Add(5*time.Minute)
	return s.update(ctx, func(tx *transaction) error {
		if _, exists := s.index["destructive_plans"][plan.ID]; exists {
			return ErrInUse
		}
		if err := s.ensureSecurityVersion(4); err != nil {
			return err
		}
		return tx.put("destructive_plans", plan.ID, plan.SubjectID, order(plan.CreatedAt), plan)
	})
}

// GetDestructivePlan permits only the bound subject and token to load a plan.
// Consumed plans remain available for idempotent retries after their deadline.
func (s *Store) GetDestructivePlan(ctx context.Context, id, subjectType, subjectID, tokenHash string, now time.Time) (plan DestructivePlan, err error) {
	if !signedauth.ValidKeyID(id) || !signedauth.ValidKeyID(subjectID) || !planDigest(tokenHash) || now.IsZero() {
		return DestructivePlan{}, ErrInUse
	}
	err = s.view(ctx, func() error {
		current, err := get[DestructivePlan](s, "destructive_plans", id)
		if err != nil {
			return err
		}
		if current.SubjectType != subjectType || current.SubjectID != subjectID || subtle.ConstantTimeCompare([]byte(current.TokenHash), []byte(tokenHash)) != 1 ||
			current.ConsumedJobID == "" && (!now.Before(current.ExpiresAt) || now.Before(current.CreatedAt)) {
			return ErrInUse
		}
		plan = current
		return nil
	})
	return plan, err
}

// PurgeExpiredDestructivePlans removes only unused expired plans. Consumed
// records remain available to return the same job after a lost response.
func (s *Store) PurgeExpiredDestructivePlans(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, ErrInUse
	}
	removed := 0
	err := s.update(ctx, func(tx *transaction) error {
		for _, id := range keys(s, "destructive_plans", "") {
			if removed == 1000 {
				break
			}
			plan, err := get[DestructivePlan](s, "destructive_plans", id)
			if err != nil {
				return err
			}
			if plan.ConsumedJobID == "" && !now.Before(plan.ExpiresAt) {
				tx.remove("destructive_plans", id)
				removed++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// AcceptDestructivePlan atomically consumes a matching confirmation and
// creates its job. Snapshot digests must come from a fresh server-side scan;
// requestHash must be calculated server-side from the validated request. This
// method does not inspect the filesystem or establish subject identity.
func (s *Store) AcceptDestructivePlan(ctx context.Context, id, subjectType, subjectID, tokenHash, treeDigest string, destinationExists bool, destinationDigest string, job entities.Job, idempotencyKey, requestHash string, now time.Time) (entities.Job, bool, error) {
	if !signedauth.ValidKeyID(id) || !signedauth.ValidKeyID(subjectID) || !planDigest(tokenHash) || !planDigest(treeDigest) ||
		idempotencyKey == "" || len(idempotencyKey) > 256 || !planDigest(requestHash) || now.IsZero() {
		return entities.Job{}, false, ErrInUse
	}
	var accepted entities.Job
	var repeated bool
	err := s.update(ctx, func(tx *transaction) error {
		plan, err := get[DestructivePlan](s, "destructive_plans", id)
		if err != nil {
			return err
		}
		if plan.SubjectType != subjectType || plan.SubjectID != subjectID || subtle.ConstantTimeCompare([]byte(plan.TokenHash), []byte(tokenHash)) != 1 ||
			job.MountID != plan.MountID || job.SourcePath != plan.Source || job.Destination != plan.Destination || job.Overwrite != plan.Overwrite ||
			(plan.Operation == "delete" && (job.Type != "delete" || !job.Recursive)) || (plan.Operation == "move" && job.Type != "move_local") {
			return ErrInUse
		}
		if plan.ConsumedJobID != "" {
			if plan.IdempotencyKey != idempotencyKey || plan.RequestHash != requestHash {
				return ErrInUse
			}
			accepted, err = get[entities.Job](s, "jobs", plan.ConsumedJobID)
			repeated = err == nil
			return err
		}
		if !now.Before(plan.ExpiresAt) || now.Before(plan.CreatedAt) || subtle.ConstantTimeCompare([]byte(plan.TreeDigest), []byte(treeDigest)) != 1 ||
			plan.DestinationExists != destinationExists || plan.DestinationDigest != destinationDigest || !signedauth.ValidKeyID(job.ID) || job.State != "queued" {
			return ErrInUse
		}
		if _, exists := s.index["jobs"][job.ID]; exists {
			return ErrInUse
		}
		key := destructiveIdempotencyKey(subjectType, subjectID, idempotencyKey)
		if _, err := get[idempotencyRecord](s, "destructive_idempotency", key); err == nil {
			return ErrIdempotencyConflict
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		plan.ConsumedJobID, plan.IdempotencyKey, plan.RequestHash = job.ID, idempotencyKey, requestHash
		if err := tx.put("destructive_plans", plan.ID, plan.SubjectID, order(plan.CreatedAt), plan); err != nil {
			return err
		}
		if err := tx.put("jobs", job.ID, job.PeerNodeID, order(job.CreatedAt), job); err != nil {
			return err
		}
		if err := tx.put("destructive_idempotency", key, "", "", idempotencyRecord{job.ID, requestHash}); err != nil {
			return err
		}
		accepted = job
		return nil
	})
	return accepted, repeated, err
}
