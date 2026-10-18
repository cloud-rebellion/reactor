// Package flare provides bounded incident evidence for Reactor workflows
// triggered by Flare automation notices. It never writes source, approves
// human review, or advances CI, merge, deployment or synthetic stages.
package flare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxNoticeBytes  = 2048
	maxIssueBytes   = 64 << 10
	maxTriageBytes  = 16 << 10
	maxReceiptBytes = 16 << 10
	maxOriginBytes  = 512
)

var (
	ErrInvalidNotice    = errors.New("invalid Flare automation notice")
	ErrIssueScope       = errors.New("Flare issue is outside the configured project")
	ErrFreshTriage      = errors.New("Flare did not return a fresh evidence digest and AI receipt ID")
	ErrReceiptPending   = errors.New("completed Flare AI evidence receipt is not available")
	ErrReceiptMismatch  = errors.New("Flare AI receipt does not confirm the exact fresh incident evidence")
	ErrResponseTooLarge = errors.New("Flare response exceeds the evidence handoff limit")
	ErrNoIssue          = errors.New("Flare notice has no incident issue")
)

// Notice contains only the six fields authenticated by the flare-v1 webhook
// receiver. DecodeNotice revalidates them because a workflow can also be run
// manually with an input that did not pass through that receiver.
type Notice struct {
	Schema     string `json:"schema"`
	Event      string `json:"event"`
	ProjectID  string `json:"project_id"`
	IssueID    string `json:"issue_id"`
	EventCount int64  `json:"event_count"`
	ObservedAt string `json:"observed_at"`
}

var noticeEvents = map[string]bool{
	"new_issue": true, "regression": true, "anomaly": true,
	"silence": true, "monitor_missing": true, "deploy_failure": true,
	"deploy_acceptance": true, "rollback": true, "spike": true,
	"connector": true, "release": true, "service": true,
	"log": true, "usage": true, "ai": true, "alert": true, "test": true,
}

// DecodeNotice accepts exactly the Flare v1 fields and one configured project.
// No issue text, stack, or future schema extension reaches a workflow step.
func DecodeNotice(raw []byte, projectID string) (Notice, error) {
	var n Notice
	if len(raw) == 0 || len(raw) > maxNoticeBytes || !utf8.Valid(raw) || !validID(projectID, true) {
		return n, ErrInvalidNotice
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return n, ErrInvalidNotice
	}
	allowed := map[string]bool{"schema": true, "event": true, "project_id": true,
		"issue_id": true, "event_count": true, "observed_at": true}
	seen := make(map[string]bool, len(allowed))
	for dec.More() {
		keyToken, err := dec.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return n, ErrInvalidNotice
		}
		seen[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return n, ErrInvalidNotice
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) ||
		dec.Decode(&struct{}{}) != io.EOF || json.Unmarshal(raw, &n) != nil {
		return Notice{}, ErrInvalidNotice
	}
	if !n.validFor(projectID) {
		return Notice{}, ErrInvalidNotice
	}
	return n, nil
}

func (n Notice) validFor(projectID string) bool {
	if n.Schema != "flare.automation.v1" || !noticeEvents[n.Event] ||
		!validID(n.ProjectID, true) || n.ProjectID != projectID ||
		!validID(n.IssueID, false) || n.EventCount < 0 || n.EventCount > 1_000_000_000 {
		return false
	}
	observed, err := time.Parse(time.RFC3339Nano, n.ObservedAt)
	return err == nil && observed.UTC().Format(time.RFC3339Nano) == n.ObservedAt
}

func validID(value string, required bool) bool {
	if len(value) > 128 || (required && value == "") || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

// DeliveryKey is a bounded stable key for Reactor step replay. The webhook
// receiver separately deduplicates signed notices before it creates a run.
func (n Notice) DeliveryKey() string {
	canonical, _ := json.Marshal(n)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Draft is the only incident data persisted in Reactor's step journal and
// shown on its authenticated run page. Raw issue text and AI output stay in
// Flare. This is a review handoff, not a passed patch or Stage receipt.
type Draft struct {
	Status         string `json:"status"`
	ProjectID      string `json:"project_id"`
	IssueID        string `json:"issue_id"`
	Event          string `json:"event"`
	ObservedAt     string `json:"observed_at"`
	EvidenceDigest string `json:"evidence_digest"`
	AIReceiptID    string `json:"ai_receipt_id"`
	IssueURL       string `json:"issue_url"`
}

// Client is pinned to an operator-reviewed Flare origin and project. Neither
// the notice nor a Flare response can choose an outbound URL or credential.
type Client struct {
	baseURL   string
	projectID string
	bearer    string
	http      *http.Client
}

func trustedOrigin(baseURL, projectID string) (string, error) {
	u, err := url.Parse(baseURL)
	if len(baseURL) > maxOriginBytes || err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") ||
		(u.Port() != "" && u.Port() != "443") || !validID(projectID, true) {
		return "", errors.New("invalid trusted Flare client configuration")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func NewClient(baseURL, projectID, bearer string, supplied *http.Client) (*Client, error) {
	origin, err := trustedOrigin(baseURL, projectID)
	if err != nil || len(bearer) == 0 || len(bearer) > 4096 {
		return nil, errors.New("invalid trusted Flare client configuration")
	}
	for _, char := range bearer {
		if char < 33 || char > 126 {
			return nil, errors.New("invalid trusted Flare client configuration")
		}
	}
	client := &http.Client{Timeout: 65 * time.Second}
	if supplied != nil {
		copyClient := *supplied
		client = &copyClient
	}
	if client.Timeout <= 0 || client.Timeout > 65*time.Second {
		client.Timeout = 65 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("Flare redirects are disabled") }
	return &Client{baseURL: origin, projectID: projectID, bearer: bearer, http: client}, nil
}

// Prevent accidental formatting or journal encoding of a client from exposing
// its member credential. Only the bounded Draft/FreshTriage outputs are useful.
func (Client) String() string               { return "[Flare client: REDACTED]" }
func (c Client) GoString() string           { return c.String() }
func (Client) MarshalJSON() ([]byte, error) { return []byte(`"[Flare client: REDACTED]"`), nil }

// FreshTriage is the bounded result of one fresh provider call. The returned
// receipt ID identifies that exact call; Reactor journals it with the digest
// so a replay does not start another provider call.
type FreshTriage struct {
	EvidenceDigest string `json:"evidence_digest"`
	AIReceiptID    string `json:"ai_receipt_id"`
}

// TriageFresh checks the current issue's project before asking Flare for a
// provider call. It returns only the digest and receipt ID, never model text.
func (c *Client) TriageFresh(ctx context.Context, issueID string) (FreshTriage, error) {
	if err := c.verifyIssue(ctx, issueID); err != nil {
		return FreshTriage{}, err
	}
	var answer struct {
		Cached *bool `json:"cached"`
		FreshTriage
	}
	if err := c.requestJSON(ctx, http.MethodPost, "/api/issues/"+url.PathEscape(issueID)+"/triage?refresh=true", maxTriageBytes, &answer); err != nil {
		return FreshTriage{}, err
	}
	if answer.Cached == nil || *answer.Cached || !validDigest(answer.EvidenceDigest) || !validID(answer.AIReceiptID, true) {
		return FreshTriage{}, ErrFreshTriage
	}
	return answer.FreshTriage, nil
}

// ConfirmDraft rechecks scope and requires Flare's completed receipt for the
// exact fresh triage call. An older receipt with the same digest cannot create
// a draft if the new call's completion write is still pending or failed.
func (c *Client) ConfirmDraft(ctx context.Context, notice Notice, fresh FreshTriage) (Draft, error) {
	if c == nil || !notice.validFor(c.projectID) || !validID(notice.IssueID, true) || notice.Event == "test" ||
		!validDigest(fresh.EvidenceDigest) || !validID(fresh.AIReceiptID, true) {
		return Draft{}, ErrInvalidNotice
	}
	if err := c.verifyIssue(ctx, notice.IssueID); err != nil {
		return Draft{}, err
	}
	var receipt struct {
		ID             string     `json:"id"`
		IssueID        string     `json:"issue_id"`
		Operation      string     `json:"operation"`
		Status         string     `json:"status"`
		EvidenceDigest string     `json:"evidence_digest"`
		CompletedAt    *time.Time `json:"completed_at"`
	}
	path := "/api/projects/" + url.PathEscape(c.projectID) + "/ai-receipts/" + url.PathEscape(fresh.AIReceiptID)
	if err := c.requestJSON(ctx, http.MethodGet, path, maxReceiptBytes, &receipt); err != nil {
		var status responseStatusError
		if errors.As(err, &status) && status == http.StatusNotFound {
			return Draft{}, ErrReceiptPending
		}
		return Draft{}, err
	}
	if receipt.ID != fresh.AIReceiptID || receipt.IssueID != notice.IssueID || receipt.Operation != "triage" {
		return Draft{}, ErrReceiptMismatch
	}
	if receipt.Status == "started" && (receipt.EvidenceDigest == "" || receipt.EvidenceDigest == fresh.EvidenceDigest) {
		return Draft{}, ErrReceiptPending
	}
	if receipt.Status != "succeeded" || receipt.EvidenceDigest != fresh.EvidenceDigest || receipt.CompletedAt == nil || receipt.CompletedAt.IsZero() {
		return Draft{}, ErrReceiptMismatch
	}
	return c.draft(notice, fresh), nil
}

func (c *Client) draft(notice Notice, fresh FreshTriage) Draft {
	return Draft{Status: "draft", ProjectID: c.projectID, IssueID: notice.IssueID,
		Event: notice.Event, ObservedAt: notice.ObservedAt, EvidenceDigest: fresh.EvidenceDigest,
		AIReceiptID: fresh.AIReceiptID, IssueURL: c.baseURL + "/issues/" + url.PathEscape(notice.IssueID)}
}

func (c *Client) verifyIssue(ctx context.Context, issueID string) error {
	if c == nil || !validID(issueID, true) {
		return ErrInvalidNotice
	}
	var issue struct {
		ID        string `json:"id"`
		ProjectID string `json:"project_id"`
	}
	if err := c.requestJSON(ctx, http.MethodGet, "/api/issues/"+url.PathEscape(issueID), maxIssueBytes, &issue); err != nil {
		return err
	}
	if issue.ID != issueID || issue.ProjectID != c.projectID {
		return ErrIssueScope
	}
	return nil
}

type responseStatusError int

func (status responseStatusError) Error() string {
	return fmt.Sprintf("Flare returned HTTP %d", status)
}

func (c *Client) requestJSON(ctx context.Context, method, path string, limit int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, http.NoBody)
	if err != nil {
		return errors.New("cannot build Flare request")
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("Flare request unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return responseStatusError(resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return errors.New("cannot read Flare response")
	}
	if int64(len(raw)) > limit {
		return ErrResponseTooLarge
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("invalid Flare JSON response")
	}
	return nil
}
