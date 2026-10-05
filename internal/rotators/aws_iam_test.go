package rotators

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// formValue parses a x-www-form-urlencoded body and returns the named param.
func formValue(body, name string) string {
	v, err := url.ParseQuery(body)
	if err != nil {
		return ""
	}
	return v.Get(name)
}

func TestAWSIAMRotateHappyPath(t *testing.T) {
	t.Parallel()

	const oldKeyID = "AKIAOLDOLDOLD"
	const newKeyID = "AKIANEWNEWNEW"
	const newSecret = "newsecretvaluexxxxxxxxxxxxxxxxxxxxxxxxxx"

	var createHits, deleteHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		action := formValue(string(body), "Action")

		auth := r.Header.Get("Authorization")
		if !strings.Contains(auth, "AWS4-HMAC-SHA256") {
			t.Errorf("missing SigV4 authorization: %q", auth)
		}
		if r.Header.Get("X-Amz-Date") == "" {
			t.Errorf("missing X-Amz-Date header")
		}

		switch action {
		case "CreateAccessKey":
			createHits.Add(1)
			if formValue(string(body), "UserName") != "deploy-bot" {
				t.Errorf("CreateAccessKey UserName mismatch: %s", body)
			}
			if !strings.Contains(auth, "Credential="+oldKeyID+"/") {
				t.Errorf("CreateAccessKey signed with wrong key: %q", auth)
			}
			fmt.Fprintf(w, `<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
<CreateAccessKeyResult><AccessKey>
<UserName>deploy-bot</UserName>
<AccessKeyId>%s</AccessKeyId>
<SecretAccessKey>%s</SecretAccessKey>
<Status>Active</Status>
</AccessKey></CreateAccessKeyResult>
</CreateAccessKeyResponse>`, newKeyID, newSecret)
		case "DeleteAccessKey":
			deleteHits.Add(1)
			if formValue(string(body), "UserName") != "deploy-bot" {
				t.Errorf("DeleteAccessKey UserName mismatch: %s", body)
			}
			if formValue(string(body), "AccessKeyId") != oldKeyID {
				t.Errorf("DeleteAccessKey AccessKeyId mismatch: %s", body)
			}
			if !strings.Contains(auth, "Credential="+newKeyID+"/") {
				t.Errorf("DeleteAccessKey should be signed with the NEW key, got %q", auth)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected Action: %s", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	p := &AWSIAMProvider{APIBase: srv.URL}
	current, _ := json.Marshal(awsAccessKeyPair{
		AccessKeyID:     oldKeyID,
		SecretAccessKey: "oldsecretvaluexxxxxxxxxxxxxxxxxxxxxxxxxx",
	})
	got, err := p.Rotate(context.Background(), string(current), map[string]string{
		"iam_user_name": "deploy-bot",
		"region":        "eu-north-1",
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	var newPair awsAccessKeyPair
	if err := json.Unmarshal([]byte(got), &newPair); err != nil {
		t.Fatalf("unmarshal new pair: %v", err)
	}
	if newPair.AccessKeyID != newKeyID || newPair.SecretAccessKey != newSecret {
		t.Fatalf("new pair mismatch: %+v", newPair)
	}
	if createHits.Load() != 1 {
		t.Fatalf("CreateAccessKey hits = %d, want 1", createHits.Load())
	}
	if deleteHits.Load() != 1 {
		t.Fatalf("DeleteAccessKey hits = %d, want 1", deleteHits.Load())
	}
}

func TestAWSIAMRotateSkipsDeleteWhenDisabled(t *testing.T) {
	t.Parallel()

	var createHits, deleteHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch formValue(string(body), "Action") {
		case "CreateAccessKey":
			createHits.Add(1)
			fmt.Fprint(w, `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey>
<AccessKeyId>AKIANEW</AccessKeyId>
<SecretAccessKey>secretval</SecretAccessKey>
</AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`)
		case "DeleteAccessKey":
			deleteHits.Add(1)
		}
	}))
	defer srv.Close()

	p := &AWSIAMProvider{APIBase: srv.URL}
	current, _ := json.Marshal(awsAccessKeyPair{
		AccessKeyID:     "AKIAOLD",
		SecretAccessKey: "oldsecret",
	})
	_, err := p.Rotate(context.Background(), string(current), map[string]string{
		"iam_user_name": "deploy-bot",
		"delete_old":    "false",
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if createHits.Load() != 1 {
		t.Fatalf("CreateAccessKey hits = %d, want 1", createHits.Load())
	}
	if deleteHits.Load() != 0 {
		t.Fatalf("DeleteAccessKey hits = %d, want 0 (delete_old=false)", deleteHits.Load())
	}
}

func TestAWSIAMRotateMissingUserFails(t *testing.T) {
	t.Parallel()

	p := &AWSIAMProvider{}
	current, _ := json.Marshal(awsAccessKeyPair{AccessKeyID: "AKIA", SecretAccessKey: "s"})
	_, err := p.Rotate(context.Background(), string(current), map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "iam_user_name") {
		t.Fatalf("want iam_user_name error, got %v", err)
	}
}

func TestAWSIAMRotateBadCurrentKeyFails(t *testing.T) {
	t.Parallel()

	p := &AWSIAMProvider{}
	_, err := p.Rotate(context.Background(), "not-json", map[string]string{
		"iam_user_name": "u",
	})
	if err == nil || !strings.Contains(err.Error(), "parse current key") {
		t.Fatalf("want parse error, got %v", err)
	}
}

func TestAWSIAMProviderRejectsLinkLocalAPIBase(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	current, _ := json.Marshal(awsAccessKeyPair{AccessKeyID: "AKIA", SecretAccessKey: "secret"})
	_, err := (&AWSIAMProvider{APIBase: "http://169.254.169.254"}).Rotate(ctx, string(current), map[string]string{"iam_user_name": "u"})
	if err == nil || !strings.Contains(err.Error(), "ssrf") {
		t.Fatalf("metadata API base error = %v, want SSRF refusal", err)
	}
}

func TestAWSIAMRotateCreateAccessKeyHTTPErrorFails(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
	}))
	defer srv.Close()

	p := &AWSIAMProvider{APIBase: srv.URL}
	current, _ := json.Marshal(awsAccessKeyPair{AccessKeyID: "AKIA", SecretAccessKey: "s"})
	_, err := p.Rotate(context.Background(), string(current), map[string]string{
		"iam_user_name": "u",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error, got %v", err)
	}
}

func TestDeriveSigV4KeyMatchesAWSReference(t *testing.T) {
	t.Parallel()

	// Reference vector from the AWS SigV4 docs.
	got := deriveSigV4Key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830", "us-east-1", "iam")
	want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if hex.EncodeToString(got) != want {
		t.Fatalf("signing key mismatch:\n got %s\nwant %s", hex.EncodeToString(got), want)
	}
}
