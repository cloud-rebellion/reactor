package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	flareV1Schema        = "flare.automation.v1"
	flareV1Skew          = 5 * time.Minute
	maxFlareV1BodyBytes  = 2048
	maxFlareV1EventCount = int64(1_000_000_000)
)

var flareV1Events = map[string]bool{
	"new_issue": true, "regression": true, "anomaly": true,
	"silence": true, "monitor_missing": true, "deploy_failure": true,
	"deploy_acceptance": true, "rollback": true, "spike": true,
	"connector": true, "release": true, "service": true,
	"log": true, "usage": true, "ai": true, "alert": true,
	"test": true,
}

type flareV1Notice struct {
	Schema     string `json:"schema"`
	Event      string `json:"event"`
	ProjectID  string `json:"project_id"`
	IssueID    string `json:"issue_id"`
	EventCount int64  `json:"event_count"`
	ObservedAt string `json:"observed_at"`
}

// verifyFlareV1 authenticates the exact Flare wire bytes before the receiver
// parses their JSON. It is intentionally not Reactor's automation-v1 protocol:
// Flare signs timestamp + "." + body and has no delivery-id header.
func verifyFlareV1(h http.Header, body, key []byte, now time.Time) error {
	if len(key) == 0 {
		return errors.New("Flare signing key is empty")
	}
	timestamp, err := singleRequiredHeader(h, "X-Flare-Automation-Timestamp")
	if err != nil {
		return err
	}
	if timestamp == "" || timestamp[0] == '0' || timestamp != strings.TrimSpace(timestamp) {
		return errors.New("malformed Flare timestamp")
	}
	for _, char := range timestamp {
		if char < '0' || char > '9' {
			return errors.New("malformed Flare timestamp")
		}
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != timestamp {
		return errors.New("malformed Flare timestamp")
	}
	signedAt := time.Unix(seconds, 0)
	if signedAt.Before(now.Add(-flareV1Skew)) || signedAt.After(now.Add(flareV1Skew)) {
		return errors.New("Flare timestamp outside replay window")
	}
	signature, err := singleRequiredHeader(h, "X-Flare-Automation-Signature")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(signature, "sha256=") || !isLowerHexDigest(strings.TrimPrefix(signature, "sha256=")) {
		return errors.New("malformed Flare signature")
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return errors.New("malformed Flare signature")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return errors.New("Flare signature mismatch")
	}
	return nil
}

// validateFlareV1Notice keeps telemetry and future schema extensions out of
// Reactor's workflow journal. The trigger is pinned to one Flare project: a
// shared org API key or a different Flare channel cannot route another project
// into this workflow merely by naming it in an otherwise valid notice.
func validateFlareV1Notice(body []byte, h http.Header, config []byte) error {
	if len(body) == 0 || len(body) > maxFlareV1BodyBytes || !utf8.Valid(body) {
		return errors.New("Flare body is empty, oversized, or invalid UTF-8")
	}
	var cfg struct {
		ProjectID string `json:"flare_project_id"`
	}
	if err := json.Unmarshal(config, &cfg); err != nil || !validFlareV1ID(cfg.ProjectID, true) {
		return errors.New("Flare trigger has no valid project binding")
	}
	var notice flareV1Notice
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("Flare body must be one JSON object")
	}
	allowed := map[string]bool{
		"schema": true, "event": true, "project_id": true,
		"issue_id": true, "event_count": true, "observed_at": true,
	}
	seen := make(map[string]bool, len(allowed))
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return errors.New("malformed Flare JSON object")
		}
		key, ok := keyToken.(string)
		if !ok || !allowed[key] || seen[key] {
			return errors.New("unknown or duplicate Flare field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("malformed Flare field")
		}
	}
	if len(seen) != len(allowed) {
		return errors.New("missing Flare field")
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return errors.New("malformed Flare JSON object")
	}
	if dec.Decode(&struct{}{}) != io.EOF || json.Unmarshal(body, &notice) != nil {
		return errors.New("Flare body must contain one valid notice")
	}
	if notice.Schema != flareV1Schema || !flareV1Events[notice.Event] {
		return errors.New("unsupported Flare schema or event")
	}
	if !validFlareV1ID(notice.ProjectID, true) || notice.ProjectID != cfg.ProjectID ||
		!validFlareV1ID(notice.IssueID, false) {
		return errors.New("Flare project or issue is outside trigger binding")
	}
	if notice.EventCount < 0 || notice.EventCount > maxFlareV1EventCount {
		return errors.New("Flare event count is out of range")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, notice.ObservedAt)
	if err != nil || observedAt.UTC().Format(time.RFC3339Nano) != notice.ObservedAt {
		return errors.New("Flare observed_at is not a UTC RFC3339 timestamp")
	}
	eventHeader, err := singleRequiredHeader(h, "X-Flare-Automation-Event")
	if err != nil || eventHeader != notice.Event {
		return errors.New("Flare event header does not match signed event")
	}
	return nil
}

func validFlareV1ID(value string, required bool) bool {
	if len(value) > 128 || (required && value == "") {
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

// ValidFlareProjectID is shared with trigger creation so an invalid project
// binding is refused before Reactor mints a credential or creates a trigger.
func ValidFlareProjectID(value string) bool { return validFlareV1ID(value, true) }
