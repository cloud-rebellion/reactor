package rotators

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/safehttp"
)

// awsIAMHTTPClient is the shared client; bounded timeout prevents a stuck
// IAM endpoint from holding up the rotation runner.
// APIBase is configurable for private IAM-compatible gateways and tests, so
// use the shared connect-time SSRF policy. Link-local/metadata destinations
// remain blocked even when private RFC1918 endpoints are allowed.
var awsIAMHTTPClient = safehttp.Client(true)

// defaultAWSIAMEndpoint is the global IAM endpoint. Tests inject a custom
// endpoint via APIBase so concurrent tests never share-mutate state.
const defaultAWSIAMEndpoint = "https://iam.amazonaws.com"

// AWSIAMProvider rotates an AWS IAM user access key pair self-referentially:
// the currently stored pair signs a CreateAccessKey call against its own
// IAM user, then signs a DeleteAccessKey for the old key using the NEW
// pair (which both proves the new key works and frees up the user's
// two-key limit). The vault value is JSON {"access_key_id","secret_access_key"}.
//
// Required meta:
//   - "iam_user_name": the IAM user owning the key pair
//
// Optional meta:
//   - "region": signing region (IAM is global; "us-east-1" by default)
//   - "delete_old": "false" disables the post-create cleanup
//
// No AWS SDK dependency; stdlib SigV4 keeps the binary small.
type AWSIAMProvider struct {
	APIBase string
}

func (p *AWSIAMProvider) endpoint() string {
	if p.APIBase != "" {
		return p.APIBase
	}
	return defaultAWSIAMEndpoint
}

func (p *AWSIAMProvider) Name() string        { return "aws-iam" }
func (p *AWSIAMProvider) CanAutoRotate() bool { return true }

type awsAccessKeyPair struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// Rotate parses currentKey as a JSON access key pair, calls IAM
// CreateAccessKey for the configured user, optionally deletes the old
// key (signed with the new pair), and returns the new pair as JSON.
func (p *AWSIAMProvider) Rotate(ctx context.Context, currentKey string, meta map[string]string) (string, error) {
	user := meta["iam_user_name"]
	if user == "" {
		return "", fmt.Errorf("aws-iam: missing meta.iam_user_name")
	}
	region := meta["region"]
	if region == "" {
		region = "us-east-1"
	}

	var current awsAccessKeyPair
	if err := json.Unmarshal([]byte(currentKey), &current); err != nil {
		return "", fmt.Errorf("aws-iam: parse current key: %w", err)
	}
	if current.AccessKeyID == "" || current.SecretAccessKey == "" {
		return "", fmt.Errorf("aws-iam: current key missing access_key_id or secret_access_key")
	}

	newPair, err := p.createAccessKey(ctx, current, user, region)
	if err != nil {
		return "", fmt.Errorf("aws-iam: create access key: %w", err)
	}

	if meta["delete_old"] != "false" {
		if err := p.deleteAccessKey(ctx, newPair, user, current.AccessKeyID, region); err != nil {
			return "", fmt.Errorf("aws-iam: delete old key %s: %w", current.AccessKeyID, err)
		}
	}

	out, err := json.Marshal(newPair)
	if err != nil {
		return "", fmt.Errorf("aws-iam: marshal new key: %w", err)
	}
	return string(out), nil
}

// Validate signs a GetUser call with the given key and reports success.
// Cheap upstream check used by callers before attempting a Rotate.
func (p *AWSIAMProvider) Validate(ctx context.Context, key string, meta map[string]string) (bool, error) {
	var pair awsAccessKeyPair
	if err := json.Unmarshal([]byte(key), &pair); err != nil {
		return false, err
	}
	region := meta["region"]
	if region == "" {
		region = "us-east-1"
	}
	body := url.Values{"Action": {"GetUser"}, "Version": {"2010-05-08"}}
	resp, err := p.signedPOST(ctx, pair, region, body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == 200, nil
}

func (p *AWSIAMProvider) createAccessKey(ctx context.Context, signer awsAccessKeyPair, user, region string) (awsAccessKeyPair, error) {
	body := url.Values{
		"Action":   {"CreateAccessKey"},
		"UserName": {user},
		"Version":  {"2010-05-08"},
	}
	resp, err := p.signedPOST(ctx, signer, region, body)
	if err != nil {
		return awsAccessKeyPair{}, err
	}
	defer resp.Body.Close()
	raw, err := readBoundedProviderResponse(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return awsAccessKeyPair{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 200 {
		return awsAccessKeyPair{}, fmt.Errorf("status %d: %s", resp.StatusCode, trim(raw))
	}
	var parsed struct {
		XMLName xml.Name `xml:"CreateAccessKeyResponse"`
		Result  struct {
			AccessKey struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				Status          string `xml:"Status"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return awsAccessKeyPair{}, fmt.Errorf("parse response: %w (body %s)", err, trim(raw))
	}
	if parsed.Result.AccessKey.AccessKeyID == "" || parsed.Result.AccessKey.SecretAccessKey == "" {
		return awsAccessKeyPair{}, fmt.Errorf("response missing access key fields: %s", trim(raw))
	}
	return awsAccessKeyPair{
		AccessKeyID:     parsed.Result.AccessKey.AccessKeyID,
		SecretAccessKey: parsed.Result.AccessKey.SecretAccessKey,
	}, nil
}

func (p *AWSIAMProvider) deleteAccessKey(ctx context.Context, signer awsAccessKeyPair, user, oldKeyID, region string) error {
	body := url.Values{
		"Action":      {"DeleteAccessKey"},
		"UserName":    {user},
		"AccessKeyId": {oldKeyID},
		"Version":     {"2010-05-08"},
	}
	resp, err := p.signedPOST(ctx, signer, region, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := readBoundedProviderResponse(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, trim(raw))
	}
	return nil
}

// signedPOST signs a form-encoded IAM Query API request with SigV4 and
// dispatches it. IAM only accepts POST for state-changing actions in v0
// API, and POST with x-www-form-urlencoded is universal across actions.
func (p *AWSIAMProvider) signedPOST(ctx context.Context, signer awsAccessKeyPair, region string, body url.Values) (*http.Response, error) {
	endpoint := p.endpoint()
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}

	payload := body.Encode()
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	host := u.Host
	canonicalURI := "/"
	if u.Path != "" {
		canonicalURI = u.Path
	}

	payloadHash := sha256Hex([]byte(payload))
	canonicalHeaders := "content-type:application/x-www-form-urlencoded\n" +
		"host:" + host + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-date"

	canonicalRequest := strings.Join([]string{
		"POST",
		canonicalURI,
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credScope := dateStamp + "/" + region + "/iam/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigV4Key(signer.SecretAccessKey, dateStamp, region, "iam")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authorization := "AWS4-HMAC-SHA256 Credential=" + signer.AccessKeyID + "/" + credScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", authorization)
	return awsIAMHTTPClient.Do(req)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func deriveSigV4Key(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
