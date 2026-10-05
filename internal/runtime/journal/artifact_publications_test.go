package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func seedArtifactPublicationWorkflow(t *testing.T, j *Journal, id, slug, tenant, digest string) {
	t.Helper()
	ctx := context.Background()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenant}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenantWithArtifactDisabled(ctx, id, slug,
		"codehash", "0.1.0", digest, json.RawMessage(`{}`), tenant, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactPublicationTenantVersionClaimAndBoundedRetry(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const slug = "shared-publication"
	digestA, digestB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	seedArtifactPublicationWorkflow(t, j, "wf_pub_a", slug, "tenant-a", digestA)
	seedArtifactPublicationWorkflow(t, j, "wf_pub_b", slug, "tenant-b", digestB)

	a, err := j.EnqueueArtifactPublication(ctx, "tenant-a", "wf_pub_a", 1, digestA)
	if err != nil || a.Status != ArtifactPublicationPending || a.Slug != slug || a.Attempts != 0 {
		t.Fatalf("enqueue A = %+v, %v", a, err)
	}
	if same, err := j.EnqueueArtifactPublication(ctx, "tenant-a", "wf_pub_a", 1, digestA); err != nil || same.ID != a.ID {
		t.Fatalf("exact retry = %+v, %v", same, err)
	}
	if _, err := j.EnqueueArtifactPublication(ctx, "tenant-b", "wf_pub_a", 1, digestA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign workflow enqueue = %v", err)
	}
	if _, err := j.GetArtifactPublicationForTenant(ctx, a.ID, "tenant-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign receipt read = %v", err)
	}
	if _, err := j.EnqueueArtifactPublication(ctx, "tenant-a", "wf_pub_a", 1, digestB); !errors.Is(err, ErrWorkflowArtifactFence) {
		t.Fatalf("wrong digest enqueue = %v", err)
	}
	b, err := j.EnqueueArtifactPublication(ctx, "tenant-b", "wf_pub_b", 1, digestB)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimArtifactPublications(ctx, 2, time.Minute)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	byID := map[string]ArtifactPublication{}
	for _, publication := range claimed {
		byID[publication.ID] = publication
		if publication.ClaimToken == "" || publication.Status != ArtifactPublicationClaimed || publication.Attempts != 1 {
			t.Fatalf("invalid claim: %+v", publication)
		}
		encoded, _ := json.Marshal(publication)
		if strings.Contains(string(encoded), publication.ClaimToken) || strings.Contains(string(encoded), "claim_token") {
			t.Fatalf("claim token serialized: %s", encoded)
		}
	}
	claimA := byID[a.ID]
	if claimA.TenantID != "tenant-a" || claimA.ArtifactSHA256 != digestA {
		t.Fatalf("A claim was not tenant pinned: %+v", claimA)
	}
	if err := j.RenewArtifactPublicationClaim(ctx, a.ID, "stale", time.Minute); !errors.Is(err, ErrArtifactPublicationClaimLost) {
		t.Fatalf("wrong-token renewal = %v", err)
	}
	if err := j.CompleteArtifactPublication(ctx, a.ID, "stale"); !errors.Is(err, ErrArtifactPublicationClaimLost) {
		t.Fatalf("wrong-token completion = %v", err)
	}
	if err := j.RenewArtifactPublicationClaim(ctx, a.ID, claimA.ClaimToken, time.Minute); err != nil {
		t.Fatalf("renew A: %v", err)
	}
	if err := j.CompleteArtifactPublication(ctx, a.ID, claimA.ClaimToken); err != nil {
		t.Fatalf("complete A: %v", err)
	}
	if err := j.CompleteArtifactPublication(ctx, a.ID, claimA.ClaimToken); !errors.Is(err, ErrArtifactPublicationClaimLost) {
		t.Fatalf("duplicate completion = %v", err)
	}
	statusA, err := j.GetArtifactPublicationForTenant(ctx, a.ID, "tenant-a")
	if err != nil || statusA.Status != ArtifactPublicationPublished || statusA.PublishedAt == nil || statusA.ClaimUntil != nil {
		t.Fatalf("A status = %+v, %v", statusA, err)
	}
	claimB := byID[b.ID]
	if err := j.FailArtifactPublication(ctx, b.ID, claimB.ClaimToken, "copy_failed: /private/secret"); err == nil {
		t.Fatal("unbounded failure text was persisted")
	}
	for attempt := 1; attempt <= MaxArtifactPublicationAttempts; attempt++ {
		if attempt > 1 {
			if _, err := j.db.ExecContext(ctx, `UPDATE artifact_publications SET next_attempt_at = ? WHERE id = ?`,
				j.formatTime(time.Now().UTC().Add(-time.Minute)), b.ID); err != nil {
				t.Fatal(err)
			}
			claimed, err = j.ClaimArtifactPublications(ctx, 2, time.Minute)
			if err != nil || len(claimed) != 1 || claimed[0].ID != b.ID {
				t.Fatalf("claim attempt %d = %+v, %v", attempt, claimed, err)
			}
			if err := j.CompleteArtifactPublication(ctx, b.ID, claimB.ClaimToken); !errors.Is(err, ErrArtifactPublicationClaimLost) {
				t.Fatalf("stale claim completion = %v", err)
			}
			claimB = claimed[0]
		}
		if claimB.Attempts != attempt {
			t.Fatalf("attempt %d reported %d", attempt, claimB.Attempts)
		}
		if err := j.FailArtifactPublication(ctx, b.ID, claimB.ClaimToken, "copy_failed"); err != nil {
			t.Fatalf("fail attempt %d: %v", attempt, err)
		}
	}
	statusB, err := j.GetArtifactPublicationForTenant(ctx, b.ID, "tenant-b")
	if err != nil || statusB.Status != ArtifactPublicationFailed || statusB.Attempts != MaxArtifactPublicationAttempts || statusB.LastFailureCode != "copy_failed" {
		t.Fatalf("B terminal status = %+v, %v", statusB, err)
	}
	if again, err := j.EnqueueArtifactPublication(ctx, "tenant-b", "wf_pub_b", 1, digestB); err != nil || again.ID != b.ID || again.Status != ArtifactPublicationFailed {
		t.Fatalf("terminal enqueue retry = %+v, %v", again, err)
	}
	if claimed, err := j.ClaimArtifactPublications(ctx, 2, time.Minute); err != nil || len(claimed) != 0 {
		t.Fatalf("terminal receipt was reclaimed: %+v, %v", claimed, err)
	}
	if _, err := j.RequeueFailedArtifactPublication(ctx, "tenant-a", b.ID, digestB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign recovery = %v", err)
	}
	if _, err := j.RequeueFailedArtifactPublication(ctx, "tenant-b", b.ID, digestA); !errors.Is(err, ErrWorkflowArtifactFence) {
		t.Fatalf("wrong-digest recovery = %v", err)
	}
	requeued, err := j.RequeueFailedArtifactPublication(ctx, "tenant-b", b.ID, digestB)
	if err != nil || requeued.ID != b.ID || requeued.Status != ArtifactPublicationPending ||
		requeued.Attempts != 0 || requeued.LastFailureCode != "" || !requeued.RequestedAt.Equal(statusB.RequestedAt) {
		t.Fatalf("requeued receipt = %+v, %v", requeued, err)
	}
	if _, err := j.RequeueFailedArtifactPublication(ctx, "tenant-b", b.ID, digestB); !errors.Is(err, ErrArtifactPublicationNotFailed) {
		t.Fatalf("nonterminal recovery = %v", err)
	}
	claimed, err = j.ClaimArtifactPublications(ctx, 2, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].ID != b.ID || claimed[0].Attempts != 1 {
		t.Fatalf("recovered claim = %+v, %v", claimed, err)
	}
	if err := j.CompleteArtifactPublication(ctx, b.ID, claimed[0].ClaimToken); err != nil {
		t.Fatalf("complete recovered claim: %v", err)
	}
}

func TestArtifactPublicationCurrentVersionAndExpiredLeaseFence(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digest := strings.Repeat("d", 64)
	seedArtifactPublicationWorkflow(t, j, "wf_pub_version", "versioned-publication", "tenant-version", digest)
	first, err := j.EnqueueArtifactPublication(ctx, "tenant-version", "wf_pub_version", 1, digest)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimArtifactPublications(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim first = %+v, %v", claimed, err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE artifact_publications SET claim_until = ? WHERE id = ?`,
		j.formatTime(time.Now().UTC().Add(-time.Minute)), first.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteArtifactPublication(ctx, first.ID, claimed[0].ClaimToken); !errors.Is(err, ErrArtifactPublicationClaimLost) {
		t.Fatalf("expired claim completion = %v", err)
	}
	reclaimed, err := j.ClaimArtifactPublications(ctx, 1, time.Minute)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != first.ID || reclaimed[0].Attempts != 2 {
		t.Fatalf("reclaim = %+v, %v", reclaimed, err)
	}
	if err := j.CompleteArtifactPublication(ctx, first.ID, reclaimed[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx, "wf_pub_version", "0.1.0", "newhash", strings.Repeat("e", 64), json.RawMessage(`{}`), 1, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.EnqueueArtifactPublication(ctx, "tenant-version", "wf_pub_version", 1, digest); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale version enqueue = %v", err)
	}
}

func TestArtifactPublicationExhaustedExpiredClaimBecomesTerminal(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	digest := strings.Repeat("9", 64)
	seedArtifactPublicationWorkflow(t, j, "wf_pub_expired", "expired-publication", "tenant-expired", digest)
	publication, err := j.EnqueueArtifactPublication(ctx, "tenant-expired", "wf_pub_expired", 1, digest)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimArtifactPublications(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE artifact_publications
		SET attempts = ?, claim_until = ? WHERE id = ?`, MaxArtifactPublicationAttempts,
		j.formatTime(time.Now().UTC().Add(-time.Minute)), publication.ID); err != nil {
		t.Fatal(err)
	}
	if reclaimed, err := j.ClaimArtifactPublications(ctx, 1, time.Minute); err != nil || len(reclaimed) != 0 {
		t.Fatalf("exhausted expired claim = %+v, %v", reclaimed, err)
	}
	status, err := j.GetArtifactPublicationForTenant(ctx, publication.ID, "tenant-expired")
	if err != nil || status.Status != ArtifactPublicationFailed || status.LastFailureCode != "lease_expired" {
		t.Fatalf("exhausted status = %+v, %v", status, err)
	}
	if err := j.CompleteArtifactPublication(ctx, publication.ID, claimed[0].ClaimToken); !errors.Is(err, ErrArtifactPublicationClaimLost) {
		t.Fatalf("expired publisher completion = %v", err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifactIfDisabledExpected(ctx, "wf_pub_expired", "0.1.0", "newhash", strings.Repeat("8", 64), json.RawMessage(`{}`), 1, strings.Repeat("7", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RequeueFailedArtifactPublication(ctx, "tenant-expired", publication.ID, digest); !errors.Is(err, ErrWorkflowVersionConflict) {
		t.Fatalf("stale-current-version recovery = %v", err)
	}
}
