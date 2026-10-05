package oauth

import (
	"net/url"
	"strings"
)

// legacyEmailRawException is deliberately narrow: the currently shipped
// Gmail/Outlook POST adapters still use raw tokens, but an operator cannot
// obtain that exception by assigning their provider IDs to arbitrary OAuth
// endpoints. Existing pre-0062 connections retain their grandfathered mode.
func legacyEmailRawException(providerID, authRaw, tokenRaw string) bool {
	auth, err := url.Parse(authRaw)
	if err != nil || !canonicalLegacyEmailURL(auth) {
		return false
	}
	token, err := url.Parse(tokenRaw)
	if err != nil || !canonicalLegacyEmailURL(token) {
		return false
	}
	switch providerID {
	case "google":
		return auth.Hostname() == "accounts.google.com" && auth.Path == "/o/oauth2/v2/auth" &&
			token.Hostname() == "oauth2.googleapis.com" && token.Path == "/token"
	case "microsoft":
		if auth.Hostname() != "login.microsoftonline.com" || token.Hostname() != "login.microsoftonline.com" {
			return false
		}
		authParts := strings.Split(auth.Path, "/")
		tokenParts := strings.Split(token.Path, "/")
		if len(authParts) != 5 || len(tokenParts) != 5 || authParts[1] != tokenParts[1] ||
			authParts[2] != "oauth2" || tokenParts[2] != "oauth2" ||
			authParts[3] != "v2.0" || tokenParts[3] != "v2.0" ||
			authParts[4] != "authorize" || tokenParts[4] != "token" {
			return false
		}
		tenant := authParts[1]
		if tenant == "" || len(tenant) > 64 {
			return false
		}
		for _, c := range tenant {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
		return true
	}
	return false
}

func canonicalLegacyEmailURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil && u.Opaque == "" &&
		u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" &&
		(u.Port() == "" || u.Port() == "443") && u.Hostname() == strings.ToLower(u.Hostname())
}

// legacyEmailScopesAllowed limits the temporary raw-token exception to the
// send adapter's least-privilege delegated grant. Both configured requested
// scopes and the persisted effective grant must be safe; a provider scope
// expansion or an admin edit closes the raw path at its next use.
func legacyEmailScopesAllowed(providerID, requested, granted string) bool {
	if requested == "" || granted == "" {
		return false
	}
	allowed := map[string]bool{"openid": true, "email": true, "profile": true}
	required := ""
	switch providerID {
	case "google":
		required = "https://www.googleapis.com/auth/gmail.send"
	case "microsoft":
		allowed["offline_access"] = true
		required = "https://graph.microsoft.com/Mail.Send"
		allowed["Mail.Send"] = true // Microsoft may return the short granted form.
	default:
		return false
	}
	allowed[required] = true
	valid := func(raw string) bool {
		seenSend := false
		for _, scope := range strings.Fields(raw) {
			if !allowed[scope] {
				return false
			}
			if scope == required || (providerID == "microsoft" && scope == "Mail.Send") {
				seenSend = true
			}
		}
		return seenSend
	}
	return valid(requested) && valid(granted)
}
