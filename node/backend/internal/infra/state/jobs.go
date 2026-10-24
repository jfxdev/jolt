package state

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"sort"
	"time"
)

type idempotencyRecord struct {
	JobID       string `yaml:"job_id"`
	RequestHash string `yaml:"request_hash"`
}

func order(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }
func (s *Store) CreateJob(ctx context.Context, j entities.Job, key string) (entities.Job, bool, error) {
	return s.CreateJobWithItemsHashed(ctx, j, nil, key, "")
}
func (s *Store) CreateJobWithItems(ctx context.Context, j entities.Job, items []entities.JobItem, key string) (entities.Job, bool, error) {
	return s.CreateJobWithItemsHashed(ctx, j, items, key, "")
}
func (s *Store) CreateJobWithItemsHashed(ctx context.Context, j entities.Job, items []entities.JobItem, key, hash string) (entities.Job, bool, error) {
	reused := false
	err := s.update(ctx, func(tx *transaction) error {
		if key != "" {
			v, err := get[idempotencyRecord](s, "idempotency", key)
			if err == nil {
				if hash != "" && hash != v.RequestHash {
					return ErrIdempotencyConflict
				}
				j, err = get[entities.Job](s, "jobs", v.JobID)
				reused = err == nil
				return err
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if _, ok := s.index["jobs"][j.ID]; ok {
			return errors.New("job already exists")
		}
		if err := tx.put("jobs", j.ID, j.PeerNodeID, order(j.CreatedAt), j); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, item := range items {
			item.JobID = j.ID
			k := itemKey(item)
			if seen[k] {
				return errors.New("duplicate job item")
			}
			seen[k] = true
			if err := tx.put("items", k, j.ID, fmt.Sprintf("%012d", item.Ordinal), item); err != nil {
				return err
			}
		}
		if key != "" {
			return tx.put("idempotency", key, "", "", idempotencyRecord{j.ID, hash})
		}
		return nil
	})
	return j, reused, err
}
func (s *Store) FindJobByIdempotency(ctx context.Context, key string) (j entities.Job, hash string, found bool, err error) {
	err = s.view(ctx, func() error {
		v, e := get[idempotencyRecord](s, "idempotency", key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		j, e = get[entities.Job](s, "jobs", v.JobID)
		hash = v.RequestHash
		found = e == nil
		return e
	})
	return
}
func (s *Store) UpdateJob(ctx context.Context, j entities.Job) error {
	return s.update(ctx, func(tx *transaction) error {
		old, e := get[entities.Job](s, "jobs", j.ID)
		if e != nil {
			return e
		}
		j.CreatedAt = old.CreatedAt
		return tx.put("jobs", j.ID, j.PeerNodeID, order(j.CreatedAt), j)
	})
}
func (s *Store) GetJob(ctx context.Context, id string) (v entities.Job, err error) {
	err = s.view(ctx, func() error { v, err = get[entities.Job](s, "jobs", id); return err })
	return
}
func (s *Store) ListJobs(ctx context.Context, limit int) (out []entities.Job, err error) {
	err = s.view(ctx, func() error {
		ids := keys(s, "jobs", "")
		for i := len(ids) - 1; i >= 0 && (limit < 0 || len(out) < limit); i-- {
			v, e := get[entities.Job](s, "jobs", ids[i])
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}
func (s *Store) ListJobsByPeer(ctx context.Context, peer string) (out []entities.Job, err error) {
	err = s.view(ctx, func() error {
		ids := keys(s, "jobs", peer)
		for i := len(ids) - 1; i >= 0; i-- {
			v, e := get[entities.Job](s, "jobs", ids[i])
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}
func (s *Store) ClaimNextJob(ctx context.Context, now time.Time) (job entities.Job, err error) {
	err = s.update(ctx, func(tx *transaction) error {
		for _, id := range s.ordered[indexSelection{"jobs", "state", "queued"}] {
			j, e := get[entities.Job](s, "jobs", id)
			if e != nil {
				return e
			}
			if j.State != "queued" || (j.NextAttemptAt != nil && j.NextAttemptAt.After(now)) {
				continue
			}
			j.State, j.Phase, j.UpdatedAt, j.NextAttemptAt = "running", "validation", now, nil
			j.Attempt++
			if j.StartedAt == nil {
				j.StartedAt = &now
			}
			job = j
			return tx.put("jobs", id, j.PeerNodeID, order(j.CreatedAt), j)
		}
		return ErrNotFound
	})
	return
}
func (s *Store) changeJobs(ctx context.Context, now time.Time, states map[string]bool, match func(entities.Job) bool, recovery bool) (out []entities.Job, err error) {
	err = s.update(ctx, func(tx *transaction) error {
		for _, id := range keys(s, "jobs", "") {
			if !states[s.index["jobs"][id].State] {
				continue
			}
			j, e := get[entities.Job](s, "jobs", id)
			if e != nil {
				return e
			}
			if !match(j) {
				continue
			}
			j.State, j.Phase, j.Error, j.UpdatedAt, j.NextAttemptAt = "queued", "validation", "", now, nil
			if recovery {
				j.State, j.Phase = "waiting_validation", "waiting_validation"
				j.Error = "node stopped before the operation completed; explicit validation is required"
				j.ETASeconds, j.ETAConfidence = nil, ""
			}
			if e = tx.put("jobs", id, j.PeerNodeID, order(j.CreatedAt), j); e != nil {
				return e
			}
			out = append(out, j)
		}
		return nil
	})
	return
}
func (s *Store) RecoverRunningJobs(ctx context.Context, now time.Time) ([]entities.Job, error) {
	return s.changeJobs(ctx, now, map[string]bool{"running": true, "pause_requested": true, "cancel_requested": true}, func(j entities.Job) bool {
		return j.State == "running" || j.State == "pause_requested" || j.State == "cancel_requested"
	}, true)
}
func (s *Store) WakeWaitingPeerJobs(ctx context.Context, id string, now time.Time) ([]entities.Job, error) {
	return s.changeJobs(ctx, now, map[string]bool{"waiting_peer": true}, func(j entities.Job) bool { return j.PeerNodeID == id }, false)
}
func (s *Store) WakeWaitingMountJobs(ctx context.Context, id string, now time.Time) ([]entities.Job, error) {
	return s.changeJobs(ctx, now, map[string]bool{"waiting_mount": true}, func(j entities.Job) bool { return j.MountID == id }, false)
}
func itemKey(item entities.JobItem) string { return item.JobID + "\x00" + item.RelativePath }
func (s *Store) ReplaceJobItems(ctx context.Context, id string, items []entities.JobItem) error {
	return s.update(ctx, func(tx *transaction) error {
		if _, err := get[entities.Job](s, "jobs", id); err != nil {
			return err
		}
		for _, key := range keys(s, "items", id) {
			tx.remove("items", key)
		}
		seen := map[string]bool{}
		for _, item := range items {
			item.JobID = id
			k := itemKey(item)
			if seen[k] {
				return errors.New("duplicate job item")
			}
			seen[k] = true
			if err := tx.put("items", k, id, fmt.Sprintf("%012d", item.Ordinal), item); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Store) ListJobItems(ctx context.Context, id string) (out []entities.JobItem, err error) {
	err = s.view(ctx, func() error {
		for _, key := range keys(s, "items", id) {
			v, e := get[entities.JobItem](s, "items", key)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}
func (s *Store) UpdateJobItem(ctx context.Context, item entities.JobItem) error {
	return s.update(ctx, func(tx *transaction) error {
		k := itemKey(item)
		if _, ok := s.index["items"][k]; !ok {
			return ErrNotFound
		}
		return tx.put("items", k, item.JobID, fmt.Sprintf("%012d", item.Ordinal), item)
	})
}
func (s *Store) RecordJobEvent(ctx context.Context, event entities.JobEvent) (entities.JobEvent, error) {
	err := s.update(ctx, func(tx *transaction) error {
		if _, ok := s.index["jobs"][event.JobID]; !ok {
			return ErrNotFound
		}
		event.ID = int64(s.sequence + 1)
		key := fmt.Sprintf("%020d", event.ID)
		return tx.put("events", key, event.JobID, key, event)
	})
	return event, err
}
func (s *Store) ListJobEvents(ctx context.Context, after int64, id string, limit int) (out []entities.JobEvent, err error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	err = s.view(ctx, func() error {
		afterKey := fmt.Sprintf("%020d", after)
		ids := keys(s, "events", id)
		start := sort.Search(len(ids), func(i int) bool { return ids[i] > afterKey })
		for _, key := range ids[start:] {
			v, e := get[entities.JobEvent](s, "events", key)
			if e != nil {
				return e
			}
			out = append(out, v)
			if len(out) >= limit {
				break
			}
		}
		return nil
	})
	return
}

// ListJobItemsPage decodes only the requested page, using the ordered index.
func (s *Store) ListJobItemsPage(ctx context.Context, id string, after, limit int) (out []entities.JobItem, next int, err error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	out = []entities.JobItem{}
	err = s.view(ctx, func() error {
		if _, ok := s.index["jobs"][id]; !ok {
			return ErrNotFound
		}
		ids := keys(s, "items", id)
		start := sort.Search(len(ids), func(i int) bool { return s.index["items"][ids[i]].Order >= fmt.Sprintf("%012d", max(after, 0)) })
		for _, key := range ids[start:] {
			if len(out) == limit {
				_, e := fmt.Sscanf(s.index["items"][key].Order, "%d", &next)
				return e
			}
			v, e := get[entities.JobItem](s, "items", key)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}

func (s *Store) JobSummary(ctx context.Context) (summary entities.JobSummary, err error) {
	summary.Counts = map[string]int{}
	err = s.view(ctx, func() error {
		for _, ref := range s.index["jobs"] {
			summary.Counts[ref.State]++
		}
		summary.ObservedAt = time.Now().UTC()
		return nil
	})
	return
}
