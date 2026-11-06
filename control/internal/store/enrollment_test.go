package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func token(id, secret, name string) JoinToken {
	return JoinToken{ID: id, SecretHash: "hash-of-" + secret, NodeName: name, Approval: "auto", CreatedBy: "admin", CreatedAt: t0, ExpiresAt: t0.Add(15 * time.Minute)}
}

func enrollment(id, name, state string) Enrollment {
	return Enrollment{ID: id, State: state, NodeName: name, NodeID: "node-" + id, NodeFingerprint: "AB", APIEndpoint: "https://n.lan:8080", RemoteAddr: "10.0.0.9",
		CSRPEM: "CSR", CSRHash: "csr-" + id, OperationalEncrypted: "sealed", PollHash: "poll-" + id, CreatedAt: t0, ExpiresAt: t0.Add(EnrollmentLifetime)}
}

func TestAJoinTokenIsSpentOnceAndEveryOtherFailureLooksTheSame(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	if _, err := s.Metadata(ctx, "minimum_security_version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version set before any token: %v", err)
	}
	if err := s.CreateJoinToken(ctx, token("t1", "s1", "alpha")); err != nil {
		t.Fatal(err)
	}
	if version, _ := s.Metadata(ctx, "minimum_security_version"); version != "10" {
		t.Fatalf("security version %q", version)
	}
	if err := s.CreateJoinToken(ctx, token("t2", "s1", "beta")); !errors.Is(err, ErrConflict) {
		t.Fatalf("the same secret twice: %v", err)
	}

	// Every wrong way to present a token answers the same thing.
	for name, attempt := range map[string]struct {
		hash, node string
		at         time.Time
	}{
		"unknown secret": {"hash-of-nope", "alpha", t0},
		"other node":     {"hash-of-s1", "beta", t0},
		"expired":        {"hash-of-s1", "alpha", t0.Add(15 * time.Minute)},
	} {
		if _, err := s.StartEnrollment(ctx, attempt.hash, enrollment("e0", attempt.node, EnrollmentIssued), attempt.at); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// None of those spent it.
	spent, err := s.StartEnrollment(ctx, "hash-of-s1", enrollment("e1", "alpha", EnrollmentIssued), t0.Add(time.Minute))
	if err != nil || spent.EnrollmentID != "e1" || spent.UsedAt == nil {
		t.Fatalf("first use: %+v %v", spent, err)
	}
	again, err := s.StartEnrollment(ctx, "hash-of-s1", enrollment("e2", "alpha", EnrollmentIssued), t0.Add(2*time.Minute))
	if !errors.Is(err, ErrTokenUsed) || again.EnrollmentID != "e1" {
		t.Fatalf("second use: %+v %v", again, err)
	}
	if _, err := s.GetEnrollment(ctx, "e2", t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("a second enrollment was recorded for a spent token")
	}
	// A spent token is evidence and stays; an unused one can be taken back.
	if err := s.RevokeJoinToken(ctx, "t1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking a spent token: %v", err)
	}
	if err := s.CreateJoinToken(ctx, token("t3", "s3", "gamma")); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeJoinToken(ctx, "t3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartEnrollment(ctx, "hash-of-s3", enrollment("e3", "gamma", EnrollmentIssued), t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revoked token worked: %v", err)
	}
}

func TestOnlyOneOfManyConcurrentUsesOfATokenWins(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	if err := s.CreateJoinToken(ctx, token("t1", "s1", "alpha")); err != nil {
		t.Fatal(err)
	}
	var wins, used int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.StartEnrollment(ctx, "hash-of-s1", enrollment(fmt.Sprintf("e%d", i), "alpha", EnrollmentIssued), t0)
			switch {
			case err == nil:
				atomic.AddInt32(&wins, 1)
			case errors.Is(err, ErrTokenUsed):
				atomic.AddInt32(&used, 1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || used != 11 {
		t.Fatalf("wins=%d used=%d", wins, used)
	}
}

func TestPendingEnrollmentsAreCapped(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	for i := 0; i < maxPendingEnroll+1; i++ {
		secret := fmt.Sprintf("s%d", i)
		if err := s.CreateJoinToken(ctx, token(fmt.Sprintf("t%d", i), secret, fmt.Sprintf("n%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxPendingEnroll; i++ {
		if _, err := s.StartEnrollment(ctx, fmt.Sprintf("hash-of-s%d", i), enrollment(fmt.Sprintf("e%d", i), fmt.Sprintf("n%d", i), EnrollmentPending), t0); err != nil {
			t.Fatalf("enrollment %d: %v", i, err)
		}
	}
	last := maxPendingEnroll
	if _, err := s.StartEnrollment(ctx, fmt.Sprintf("hash-of-s%d", last), enrollment("elast", fmt.Sprintf("n%d", last), EnrollmentPending), t0); !errors.Is(err, ErrTooManyEnrollments) {
		t.Fatalf("over the cap: %v", err)
	}
	// The refused attempt did not spend its token.
	if _, err := s.StartEnrollment(ctx, fmt.Sprintf("hash-of-s%d", last), enrollment("elast", fmt.Sprintf("n%d", last), EnrollmentIssued), t0); err != nil {
		t.Fatalf("the token was spent by a refused attempt: %v", err)
	}
}

func TestADecisionHappensOnceAndOnlyBeforeTheTimeRunsOut(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	for _, name := range []string{"a", "b", "c"} {
		if err := s.CreateJoinToken(ctx, token("t"+name, "s"+name, name)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.StartEnrollment(ctx, "hash-of-s"+name, enrollment("e"+name, name, EnrollmentPending), t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DecideEnrollment(ctx, "ea", EnrollmentIssued, "admin", "", `{"status":"issued"}`, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEnrollment(ctx, "ea", t0.Add(time.Minute))
	if err != nil || got.State != EnrollmentIssued || got.DecidedBy != "admin" || got.Response != `{"status":"issued"}` || got.DecidedAt == nil {
		t.Fatalf("decided: %+v %v", got, err)
	}
	if got.CSRPEM != "" {
		t.Fatal("the request is kept after it was answered")
	}
	if err := s.DecideEnrollment(ctx, "ea", EnrollmentRejected, "admin", "late", "", t0.Add(2*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second decision: %v", err)
	}
	if err := s.DecideEnrollment(ctx, "eb", EnrollmentRejected, "admin", "no", "", t0.Add(EnrollmentLifetime)); !errors.Is(err, ErrConflict) {
		t.Fatalf("a decision after the time ran out: %v", err)
	}
	// Reading it already says expired, before the sweep runs.
	if late, _ := s.GetEnrollment(ctx, "eb", t0.Add(EnrollmentLifetime)); late.State != EnrollmentExpired {
		t.Fatalf("lazy expiry: %s", late.State)
	}
	if count, err := s.ExpireEnrollments(ctx, t0.Add(EnrollmentLifetime)); err != nil || count != 2 {
		t.Fatalf("sweep: %d %v", count, err)
	}
	swept, _ := s.GetEnrollment(ctx, "ec", t0.Add(time.Hour))
	if swept.State != EnrollmentExpired || swept.CSRPEM != "" || swept.OperationalEncrypted != "" {
		t.Fatalf("the sweep kept what the request held: %+v", swept)
	}
	if issued, _ := s.GetEnrollment(ctx, "ea", t0); issued.State != EnrollmentIssued {
		t.Fatal("the sweep touched a decided enrollment")
	}
	pending, _ := s.ListEnrollments(ctx, EnrollmentPending, 10, t0.Add(time.Hour))
	all, _ := s.ListEnrollments(ctx, "", 10, t0.Add(time.Hour))
	if len(pending) != 0 || len(all) != 3 {
		t.Fatalf("lists: %d pending, %d all", len(pending), len(all))
	}
}

func TestAPollSecretCanBeReplacedWhileTheRequestIsPending(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	_ = s.CreateJoinToken(ctx, token("t1", "s1", "alpha"))
	_, _ = s.StartEnrollment(ctx, "hash-of-s1", enrollment("e1", "alpha", EnrollmentPending), t0)
	if err := s.ReplacePollSecret(ctx, "e1", "new"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetEnrollment(ctx, "e1", t0); got.PollHash != "new" {
		t.Fatal("not replaced")
	}
	_ = s.DecideEnrollment(ctx, "e1", EnrollmentIssued, "admin", "", "{}", t0)
	_ = s.ReplacePollSecret(ctx, "e1", "later")
	if got, _ := s.GetEnrollment(ctx, "e1", t0); got.PollHash != "new" {
		t.Fatal("a decided enrollment's secret changed")
	}
}

func TestManagedNodesRoundTripAndGoWithTheirNode(t *testing.T) {
	ctx := context.Background()
	s, _ := openPendingStore(t)
	if err := s.SaveNode(ctx, Node{ID: "n1", Name: "alpha", Endpoint: "https://n1", TokenEncrypted: "x", State: "online", CreatedAt: t0, UpdatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	failedAt := t0.Add(time.Hour)
	node := ManagedNode{NodeID: "n1", EnrolledAt: t0, BundleVersion: 3, CertSerial: "abc", CertNotBefore: t0, CertNotAfter: t0.Add(90 * 24 * time.Hour), LastError: "boom", LastErrorAt: &failedAt}
	if err := s.SaveManagedNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	node.BundleVersion, node.LastError, node.LastErrorAt = 4, "", nil
	if err := s.SaveManagedNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.ListManagedNodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].BundleVersion != 4 || nodes[0].CertSerial != "abc" || nodes[0].LastError != "" || nodes[0].LastErrorAt != nil || !nodes[0].CertNotAfter.Equal(node.CertNotAfter) {
		t.Fatalf("round trip: %+v %v", nodes, err)
	}
	if err := s.DeleteNode(ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := s.ListManagedNodes(ctx); len(nodes) != 0 {
		t.Fatal("a deleted node is still listed as enrolled")
	}
}
