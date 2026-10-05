package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// registerNotificationTools exposes routing metadata and lets an explicitly
// scoped MCP client attach existing channels. Channel configuration is kept in
// the journal/vault boundary and is never accepted or returned here.
func (s *Server) registerNotificationTools() {
	if s.Journal == nil {
		return
	}
	s.tools["reactor_list_notification_routes"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_notification_routes",
			Description: "List alert channels attached to a workflow in the active MCP tenant. Channel configuration and secrets are never returned.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug"},
				"properties": map[string]any{
					"slug":   map[string]any{"type": "string"},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPNotificationPage, "default": 100},
					"offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug   string `json:"slug"`
				Limit  int    `json:"limit"`
				Offset int    `json:"offset"`
			}
			if err := decodeMCPArgs(args, &a); err != nil || strings.TrimSpace(a.Slug) == "" {
				return nil, fmt.Errorf("%w: slug required", errInvalidParamsErr)
			}
			if a.Limit == 0 {
				a.Limit = 100
			}
			if a.Limit < 1 || a.Limit > maxMCPNotificationPage || a.Offset < 0 || a.Offset > 10000 {
				return nil, fmt.Errorf("%w: limit must be 1..%d and offset 0..10000", errInvalidParamsErr, maxMCPNotificationPage)
			}
			a.Slug = strings.TrimSpace(a.Slug)
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			routes, err := s.Journal.ListNotificationRoutesForWorkflowPageBounded(ctx, workflowID, a.Limit+1, a.Offset, maxMCPNotificationNameBytes, maxMCPNotificationStatusBytes)
			if err != nil {
				return nil, err
			}
			hasMore := len(routes) > a.Limit
			if hasMore {
				routes = routes[:a.Limit]
			}
			out := make([]map[string]any, 0, len(routes))
			for _, route := range routes {
				out = append(out, map[string]any{
					"workflow_id": route.WorkflowID, "channel_id": route.ChannelID,
					"channel_name": route.ChannelName, "channel_kind": route.ChannelKind,
					"on_statuses": route.OnStatuses, "created_at": route.CreatedAt,
				})
				if route.ChannelNameTruncated {
					out[len(out)-1]["channel_name_truncated"] = true
					out[len(out)-1]["channel_name_bytes"] = route.ChannelNameBytes
				}
				if route.OnStatusesTruncated {
					out[len(out)-1]["on_statuses_truncated"] = true
					out[len(out)-1]["on_status_bytes"] = route.OnStatusesBytes
				}
			}
			result := map[string]any{"routes": out, "limit": a.Limit, "offset": a.Offset, "has_more": hasMore}
			if hasMore {
				result["next_offset"] = a.Offset + a.Limit
			}
			return result, nil
		},
	}

	if !s.writeEnabled(s.Scopes == nil || s.Scopes.Notifications) {
		return
	}

	s.tools["reactor_create_notification_channel"] = toolDef{
		tool: Tool{
			Name:        "reactor_create_notification_channel",
			Description: "Create a tenant-owned notification channel from non-secret configuration. Webhook and SMTP secrets, including Slack webhook URLs, must be existing same-tenant vault credential IDs; plaintext secrets are rejected. Requires the notifications MCP scope (--mcp-allow-notifications on reactor serve; --allow-notifications on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"name", "kind", "config"},
				"properties": map[string]any{
					"name":   map[string]any{"type": "string"},
					"kind":   map[string]any{"type": "string", "enum": []string{journal.ChannelKindSlackWebhook, journal.ChannelKindGenericWebhook, journal.ChannelKindEmailSMTP}},
					"config": map[string]any{"type": "object", "description": "Non-secret channel settings; use *_credential_id for secret values"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Name   string          `json:"name"`
				Kind   string          `json:"kind"`
				Config json.RawMessage `json:"config"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.Name, a.Kind = strings.TrimSpace(a.Name), strings.TrimSpace(a.Kind)
			if a.Name == "" || len(a.Name) > 128 {
				return nil, fmt.Errorf("%w: name is required and must be at most 128 characters", errInvalidParamsErr)
			}
			config, err := s.normalizeNotificationConfig(ctx, a.Kind, a.Config)
			if err != nil {
				return nil, err
			}
			id, err := s.Journal.CreateNotificationChannelInTenant(ctx, s.tenantID(ctx), a.Name, a.Kind, config)
			if err != nil {
				return nil, err
			}
			return map[string]any{"channel_id": id, "name": a.Name, "kind": a.Kind, "created": true}, nil
		},
	}

	s.tools["reactor_delete_notification_channel"] = toolDef{
		tool: Tool{
			Name:        "reactor_delete_notification_channel",
			Description: "Delete a same-tenant notification channel after exact id confirmation. Active workflow routes must be detached first. Requires the notifications MCP scope (--mcp-allow-notifications on reactor serve; --allow-notifications on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"channel_id", "confirm_channel_id"},
				"properties": map[string]any{
					"channel_id":         map[string]any{"type": "string"},
					"confirm_channel_id": map[string]any{"type": "string"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				ChannelID        string `json:"channel_id"`
				ConfirmChannelID string `json:"confirm_channel_id"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.ChannelID, a.ConfirmChannelID = strings.TrimSpace(a.ChannelID), strings.TrimSpace(a.ConfirmChannelID)
			if a.ChannelID == "" || a.ChannelID != a.ConfirmChannelID {
				return nil, fmt.Errorf("%w: channel_id and matching confirm_channel_id are required", errInvalidParamsErr)
			}
			_, err := s.Journal.GetNotificationChannelMetadataForTenant(ctx, a.ChannelID, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			if err := s.Journal.DeleteNotificationChannel(ctx, a.ChannelID); err != nil {
				return nil, err
			}
			return map[string]any{"channel_id": a.ChannelID, "deleted": true}, nil
		},
	}

	s.tools["reactor_attach_notification_channel"] = toolDef{
		tool: Tool{
			Name:        "reactor_attach_notification_channel",
			Description: "Attach an existing same-tenant notification channel to a workflow. Defaults to failed and failed_dlq alerts; channel secrets remain in the daemon. Requires the notifications MCP scope (--mcp-allow-notifications on reactor serve; --allow-notifications on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "channel_id"},
				"properties": map[string]any{
					"slug":        map[string]any{"type": "string"},
					"channel_id":  map[string]any{"type": "string"},
					"on_statuses": map[string]any{"type": "string", "description": "comma-separated succeeded, failed, failed_dlq, or cancelled"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug       string `json:"slug"`
				ChannelID  string `json:"channel_id"`
				OnStatuses string `json:"on_statuses"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.Slug, a.ChannelID, a.OnStatuses = strings.TrimSpace(a.Slug), strings.TrimSpace(a.ChannelID), strings.TrimSpace(a.OnStatuses)
			if a.Slug == "" || a.ChannelID == "" {
				return nil, fmt.Errorf("%w: slug and channel_id are required", errInvalidParamsErr)
			}
			statuses, err := normalizeMCPNotificationStatuses(a.OnStatuses)
			if err != nil {
				return nil, err
			}
			tenantID := s.tenantID(ctx)
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, tenantID)
			if err != nil {
				return nil, err
			}
			channel, err := s.Journal.GetNotificationChannelMetadataForTenant(ctx, a.ChannelID, tenantID)
			if err != nil {
				return nil, err
			}
			if err := s.Journal.AddNotificationRoute(ctx, workflowID, channel.ID, statuses); err != nil {
				return nil, err
			}
			return map[string]any{"slug": a.Slug, "workflow_id": workflowID, "channel_id": channel.ID, "on_statuses": statuses, "attached": true}, nil
		},
	}

	s.tools["reactor_detach_notification_channel"] = toolDef{
		tool: Tool{
			Name:        "reactor_detach_notification_channel",
			Description: "Detach an existing notification channel from a workflow in the active MCP tenant. The channel itself is preserved. Requires the notifications MCP scope (--mcp-allow-notifications on reactor serve; --allow-notifications on the explicit stdio compatibility command).",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"slug", "channel_id"},
				"properties": map[string]any{
					"slug":       map[string]any{"type": "string"},
					"channel_id": map[string]any{"type": "string"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Slug      string `json:"slug"`
				ChannelID string `json:"channel_id"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
			}
			a.Slug, a.ChannelID = strings.TrimSpace(a.Slug), strings.TrimSpace(a.ChannelID)
			if a.Slug == "" || a.ChannelID == "" {
				return nil, fmt.Errorf("%w: slug and channel_id are required", errInvalidParamsErr)
			}
			tenantID := s.tenantID(ctx)
			workflowID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, tenantID)
			if err != nil {
				return nil, err
			}
			channel, err := s.Journal.GetNotificationChannelMetadataForTenant(ctx, a.ChannelID, tenantID)
			if err != nil {
				return nil, err
			}
			if err := s.Journal.DeleteNotificationRoute(ctx, workflowID, channel.ID); err != nil {
				return nil, err
			}
			return map[string]any{"slug": a.Slug, "workflow_id": workflowID, "channel_id": channel.ID, "detached": true}, nil
		},
	}
}

// normalizeNotificationConfig accepts only the non-secret fields needed by
// the notifier. MCP never accepts plaintext passwords or header values; those
// values must already exist in the tenant vault and are referenced by ID.
func (s *Server) normalizeNotificationConfig(ctx context.Context, kind string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxMCPNotificationConfig {
		return nil, fmt.Errorf("%w: config must be a JSON object no larger than %d bytes", errInvalidParamsErr, maxMCPNotificationConfig)
	}
	// Config is a nested JSON value, so the outer MCP argument decoder cannot
	// reject duplicate keys inside it. encoding/json applies last-wins
	// semantics, which would let an audit/proxy inspect one endpoint or
	// credential reference while the notifier persists another. Keep the
	// nested authoring boundary deterministic just like top-level arguments.
	if duplicateJSONKey(raw) {
		return nil, fmt.Errorf("%w: config contains duplicate fields", errInvalidParamsErr)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("%w: config must be a JSON object", errInvalidParamsErr)
	}
	readString := func(key string, required bool, max int) (string, error) {
		value, ok := fields[key]
		if !ok {
			if required {
				return "", fmt.Errorf("%w: config.%s is required", errInvalidParamsErr, key)
			}
			return "", nil
		}
		var out string
		if json.Unmarshal(value, &out) != nil || strings.TrimSpace(out) == "" || len(out) > max {
			return "", fmt.Errorf("%w: config.%s must be a non-empty string of at most %d bytes", errInvalidParamsErr, key, max)
		}
		return strings.TrimSpace(out), nil
	}
	ensureKeys := func(allowed ...string) error {
		ok := make(map[string]bool, len(allowed))
		for _, key := range allowed {
			ok[key] = true
		}
		for key := range fields {
			if !ok[key] {
				return fmt.Errorf("%w: config field %q is not allowed", errInvalidParamsErr, key)
			}
		}
		return nil
	}
	credentialRef := func(key string) (string, error) {
		id, err := readString(key, false, 256)
		if err != nil || id == "" {
			return id, err
		}
		if s.Credentials == nil {
			return "", fmt.Errorf("%w: credential repository unavailable", errInvalidParamsErr)
		}
		_, err = s.Credentials.GetMetadataByTenant(ctx, id, s.tenantID(ctx))
		if err != nil {
			return "", fmt.Errorf("%w: %s must reference an existing same-tenant credential", errInvalidParamsErr, key)
		}
		return id, nil
	}

	switch kind {
	case journal.ChannelKindSlackWebhook:
		if err := ensureKeys("url_credential_id"); err != nil {
			return nil, err
		}
		credentialID, err := credentialRef("url_credential_id")
		if err != nil || credentialID == "" {
			return nil, fmt.Errorf("%w: config.url_credential_id must reference a same-tenant vault credential", errInvalidParamsErr)
		}
		return json.Marshal(map[string]string{"url_credential_id": credentialID})
	case journal.ChannelKindGenericWebhook:
		if err := ensureKeys("url", "header_name", "header_credential_id"); err != nil {
			return nil, err
		}
		endpoint, err := readString("url", true, 2048)
		if err != nil {
			return nil, err
		}
		u, parseErr := url.Parse(endpoint)
		if parseErr != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%w: generic webhook url must be an absolute http(s) URL without userinfo", errInvalidParamsErr)
		}
		headerName, err := readString("header_name", false, 128)
		if err != nil {
			return nil, err
		}
		headerID, err := credentialRef("header_credential_id")
		if err != nil {
			return nil, err
		}
		if (headerName == "") != (headerID == "") {
			return nil, fmt.Errorf("%w: header_name and header_credential_id must be supplied together", errInvalidParamsErr)
		}
		out := map[string]string{"url": endpoint}
		if headerName != "" {
			out["header_name"], out["header_credential_id"] = headerName, headerID
		}
		return json.Marshal(out)
	case journal.ChannelKindEmailSMTP:
		if err := ensureKeys("host", "port", "username", "from", "to", "starttls", "password_credential_id"); err != nil {
			return nil, err
		}
		host, err := readString("host", true, 255)
		if err != nil {
			return nil, err
		}
		username, err := readString("username", false, 320)
		if err != nil {
			return nil, err
		}
		from, err := readString("from", true, 320)
		if err != nil {
			return nil, err
		}
		to, err := readString("to", true, 4096)
		if err != nil {
			return nil, err
		}
		port := 587
		if value, ok := fields["port"]; ok {
			if json.Unmarshal(value, &port) != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("%w: config.port must be an integer between 1 and 65535", errInvalidParamsErr)
			}
		}
		// Port 465 starts TLS before the SMTP greeting; STARTTLS is a
		// separate upgrade and cannot be requested on that connection. Keep
		// the existing required STARTTLS default for other MCP-created
		// channels, including port 25.
		startTLS := port != 465
		if value, ok := fields["starttls"]; ok && json.Unmarshal(value, &startTLS) != nil {
			return nil, fmt.Errorf("%w: config.starttls must be boolean", errInvalidParamsErr)
		}
		if port == 465 && startTLS {
			return nil, fmt.Errorf("%w: config.starttls must be false on port 465, which uses implicit TLS", errInvalidParamsErr)
		}
		passwordID, err := credentialRef("password_credential_id")
		if err != nil {
			return nil, err
		}
		out := map[string]any{"host": host, "port": port, "username": username, "from": from, "to": to, "starttls": startTLS}
		if passwordID != "" {
			out["password_credential_id"] = passwordID
		} else {
			return nil, fmt.Errorf("%w: config.password_credential_id is required; plaintext password is never accepted", errInvalidParamsErr)
		}
		return json.Marshal(out)
	default:
		return nil, fmt.Errorf("%w: unsupported notification channel kind %q", errInvalidParamsErr, kind)
	}
}

func normalizeMCPNotificationStatuses(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "failed,failed_dlq"
	}
	if len(raw) > 256 {
		return "", fmt.Errorf("%w: on_statuses exceeds 256 bytes", errInvalidParamsErr)
	}
	allowed := map[string]bool{"succeeded": true, "failed": true, "failed_dlq": true, "cancelled": true}
	seen := map[string]bool{}
	statuses := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		status := strings.ToLower(strings.TrimSpace(part))
		if status == "" {
			continue
		}
		if !allowed[status] {
			return "", fmt.Errorf("%w: unsupported notification status %q", errInvalidParamsErr, status)
		}
		if !seen[status] {
			seen[status] = true
			statuses = append(statuses, status)
		}
	}
	if len(statuses) == 0 {
		return "", fmt.Errorf("%w: on_statuses must list at least one terminal status", errInvalidParamsErr)
	}
	sort.Strings(statuses)
	return strings.Join(statuses, ","), nil
}
