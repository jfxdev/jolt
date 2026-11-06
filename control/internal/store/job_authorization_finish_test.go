package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFinishedJobAuthorizationLinksLeaveTheActiveList(t *testing.T) {
	s, _, link, _, now := newJobLinkFixture(t)
	ctx := context.Background()
	if err := s.CreateJobAuthorizationLink(ctx, link, now); err != nil {
		t.Fatal(err)
	}
	active, err := s.ListActiveJobAuthorizationLinks(ctx, 10)
	if err != nil || len(active) != 1 || active[0].JobID != link.JobID || active[0].CredentialDigest != link.CredentialDigest {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	if _, err := s.ListActiveJobAuthorizationLinks(ctx, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("zero limit accepted: %v", err)
	}
	if err := s.FinishJobAuthorizationLink(ctx, link.NodeID, "other", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown link finished: %v", err)
	}
	for range 2 { // idempotent
		if err := s.FinishJobAuthorizationLink(ctx, link.NodeID, link.JobID, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if active, err := s.ListActiveJobAuthorizationLinks(ctx, 10); err != nil || len(active) != 0 {
		t.Fatalf("finished link still active: %+v %v", active, err)
	}
	// The link itself, and so its confirmed lease history, is kept.
	if kept, err := s.GetJobAuthorizationLink(ctx, link.NodeID, link.JobID); err != nil || kept.JobID != link.JobID {
		t.Fatalf("link lost: %+v %v", kept, err)
	}
}
