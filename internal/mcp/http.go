package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// MCPProtocolVersionHeader is the transport-level version marker used by
	// Streamable HTTP clients after initialize. Reactor is stateless, so the
	// header is optional for backwards compatibility; when present it must
	// name the one version this server actually implements.
	MCPProtocolVersionHeader = "MCP-Protocol-Version"
	maxMCPHTTPResponseBytes  = 4 << 20
	// Bound the complete execution of one HTTP request, including all members
	// of a JSON-RPC batch. Individual tools have their own limits, but without
	// one cumulative deadline a batch of long waits could retain a handler for
	// batch-size times the per-tool timeout. Keep this above the longest
	// advertised reactor_wait_for_run timeout (120s), with enough margin for
	// the final read and JSON response to be produced as the tool deadline
	// expires. This is a cumulative batch deadline, not a per-member budget.
	maxMCPHTTPExecution = 150 * time.Second
)

// ServeHTTP implements the Streamable HTTP MCP transport (single-shot
// request/response variant). The full spec also supports SSE streams
// for incremental notifications; v0.1 only ships the synchronous JSON
// shape because every existing tool handler is already synchronous
// and an SSE stream would just wrap a single payload anyway.
//
// Contract:
//
//	POST /mcp
//	Content-Type: application/json
//	Accept: application/json, text/event-stream
//	Body: a single JSON-RPC 2.0 request, notification, or response OR a
//	      JSON array of those messages (batch). Notifications and responses
//	      get no response slot in the batch.
//
//	-> 200 OK
//	   Content-Type: application/json
//	   Body: the matching response object, or an array when the request
//	         was a batch.
//
// Auth: this handler does not enforce auth on its own. The caller is
// expected to wrap it in the daemon's existing BasicAuth + rate-limit
// middleware (or in a remote-MCP gateway that does its own bearer
// auth). The Server's tool gating still applies to the explicit
// authoring/dispatch/secrets/knowledge/diagnostics scopes configured at
// construction time.
//
// The Server's tools are registered lazily on first call.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.serveHTTPWithTimeout(w, r, maxMCPHTTPExecution)
}

// serveHTTPWithTimeout is the transport implementation with an injectable
// cumulative execution budget. Production callers use ServeHTTP, while the
// bounded budget hook lets tests exercise long-polling tools without waiting
// for the full production deadline.
func (s *Server) serveHTTPWithTimeout(w http.ResponseWriter, r *http.Request, executionTimeout time.Duration) {
	setMCPNoStoreResponseHeaders(w)
	if executionTimeout <= 0 {
		executionTimeout = maxMCPHTTPExecution
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Keep the response marker on every POST, including transport errors, so a
	// client can distinguish an unsupported server version from an auth or
	// application failure without parsing the body. Older native clients do not
	// send this header, which remains valid for Reactor's stateless transport.
	w.Header().Set(MCPProtocolVersionHeader, ProtocolVersion)
	if !s.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if version := strings.TrimSpace(r.Header.Get(MCPProtocolVersionHeader)); version != "" && version != ProtocolVersion {
		writeRPCResponseHTTPStatus(w, http.StatusBadRequest, invalidRPCResponse(rpcRequest{}, &rpcError{
			Code: errInvalidRequest, Message: "unsupported MCP protocol version " + version,
		}))
		return
	}
	// Streamable HTTP clients must identify JSON request bodies explicitly.
	// Requiring the header (rather than accepting an omitted value) keeps this
	// endpoint aligned with Stage/Mesh and preserves the browser CSRF boundary:
	// a cross-origin form post cannot submit application/json without a CORS
	// preflight, while a form-compatible request is refused before parsing.
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct == "" || !isJSONContentType(ct) {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	if accept := r.Header.Get("Accept"); !acceptsJSONResponse(accept) {
		w.Header().Set("Accept", "application/json, text/event-stream")
		http.Error(w, "client must accept application/json", http.StatusNotAcceptable)
		return
	}

	s.ensureRegistered()

	const maxBody = 1 << 20 // shared Stage/Hephaestus/Mesh MCP request cap
	const maxBatchRequests = 128
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Distinguish batch [...] from single {...}; the JSON-RPC spec
	// allows either at this endpoint.
	trimmed := trimLeadingSpace(body)
	if len(trimmed) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	execCtx, cancel := context.WithTimeout(r.Context(), executionTimeout)
	defer cancel()

	if trimmed[0] == '[' {
		var rawReqs []json.RawMessage
		if err := json.Unmarshal(body, &rawReqs); err != nil {
			writeRPCResponseHTTP(w, invalidRPCResponse(rpcRequest{}, &rpcError{Code: errParseError, Message: err.Error()}))
			return
		}
		// JSON-RPC explicitly rejects an empty batch. A batch containing only
		// notifications is valid and returns 202, but [] has no request at all
		// and must produce the invalid-request envelope.
		if len(rawReqs) == 0 {
			writeRPCResponseHTTP(w, invalidRPCResponse(rpcRequest{}, &rpcError{Code: errInvalidRequest, Message: "empty batch"}))
			return
		}
		if len(rawReqs) > maxBatchRequests {
			writeRPCResponseHTTP(w, invalidRPCResponse(rpcRequest{}, &rpcError{Code: errInvalidRequest, Message: "batch exceeds 128 requests"}))
			return
		}
		responses := make([]rpcResponse, 0, len(rawReqs))
		for _, rawReq := range rawReqs {
			req, decodeErr := decodeRPCRequest(rawReq)
			if decodeErr != nil {
				responses = append(responses, invalidRPCResponse(req, decodeErr))
				continue
			}
			// A server may have issued a request on another transport stream.
			// JSON-RPC responses are valid POST input, but they are not requests
			// for this stateless dispatcher. If a batch contains only responses
			// and notifications, the transport returns 202 with no body below.
			if req.Response {
				continue
			}
			if resp, ok := s.handleHTTPOne(execCtx, req); ok {
				resp.JSONRPC = "2.0"
				responses = append(responses, resp)
			}
		}
		// Empty batch (all notifications) is HTTP 202 with no body per
		// the streamable HTTP transport spec.
		if len(responses) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeRPCResponsesHTTP(w, responses)
		return
	}

	req, decodeErr := decodeRPCRequest(body)
	if decodeErr != nil {
		writeRPCResponseHTTP(w, invalidRPCResponse(req, decodeErr))
		return
	}
	if req.Response {
		// A lone JSON-RPC response is accepted as transport input but has no
		// response of its own, matching the Streamable HTTP 202 contract for
		// response/notification-only POST bodies.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	resp, ok := s.handleHTTPOne(execCtx, req)
	if !ok {
		// Notification -> 202 Accepted with no body.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeRPCResponseHTTP(w, resp)
}

// setMCPNoStoreResponseHeaders prevents browser and intermediary caches from
// retaining authenticated tool results, which may include tenant metadata or
// bounded command output. MCP POST responses are not generally cacheable, but
// an explicit directive keeps that guarantee across permissive gateways.
func setMCPNoStoreResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// invalidRPCResponse preserves a request ID only when it is a valid JSON-RPC
// string, number, or null. When the request cannot provide a correlatable ID,
// JSON-RPC requires an explicit id:null member instead of omitting the member
// or echoing an invalid boolean/object ID.
func invalidRPCResponse(req rpcRequest, err *rpcError) rpcResponse {
	id := req.ID
	if !validHTTPRPCID(id) {
		id = json.RawMessage("null")
	}
	return rpcResponse{ID: id, Error: err}
}

// decodeRPCRequest validates a JSON-RPC request or response envelope before
// dispatch. Tool argument decoders are strict, but accepting an empty method,
// a boolean/object request id, duplicate top-level keys, or an ambiguous
// request/response envelope here would leave the transport's interpretation
// different from a proxy or MCP client inspecting the same bytes. Unknown
// extension fields remain valid.
func decodeRPCRequest(raw []byte) (rpcRequest, *rpcError) {
	raw = bytes.TrimSpace(raw)
	var req rpcRequest
	if len(raw) == 0 || !json.Valid(raw) {
		return req, &rpcError{Code: errParseError, Message: "invalid JSON"}
	}
	if raw[0] != '{' {
		return req, &rpcError{Code: errInvalidRequest, Message: "JSON-RPC request must be an object"}
	}
	if duplicateJSONKey(raw) {
		return req, &rpcError{Code: errInvalidRequest, Message: "duplicate keys in JSON-RPC request"}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return req, &rpcError{Code: errInvalidRequest, Message: "JSON-RPC request must be an object"}
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, &rpcError{Code: errInvalidRequest, Message: "invalid JSON-RPC request envelope"}
	}
	if req.JSONRPC != "2.0" {
		return req, &rpcError{Code: errInvalidRequest, Message: "jsonrpc must be 2.0"}
	}
	if id, ok := fields["id"]; ok && !validHTTPRPCID(id) {
		return req, &rpcError{Code: errInvalidRequest, Message: "id must be a string, number, or null"}
	}
	_, hasMethod := fields["method"]
	_, hasResult := fields["result"]
	_, hasError := fields["error"]
	if !hasMethod {
		// JSON-RPC responses have exactly one of result or error. They are
		// accepted as transport messages and consumed by the caller without
		// entering the server's request dispatcher.
		if hasResult == hasError {
			return req, &rpcError{Code: errInvalidRequest, Message: "response must contain exactly one of result or error"}
		}
		if _, ok := fields["id"]; !ok {
			return req, &rpcError{Code: errInvalidRequest, Message: "response id is required"}
		}
		req.Response = true
		return req, nil
	}
	if req.Method == "" {
		return req, &rpcError{Code: errInvalidRequest, Message: "method is required"}
	}
	if hasResult {
		return req, &rpcError{Code: errInvalidRequest, Message: "request cannot include result"}
	}
	if hasError {
		return req, &rpcError{Code: errInvalidRequest, Message: "request cannot include error"}
	}
	return req, nil
}

func validHTTPRPCID(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case '"', 'n':
		return raw[0] == 'n' && bytes.Equal(raw, []byte("null")) || raw[0] == '"'
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		// The outer json.Valid check already validated JSON number grammar.
		return true
	default:
		return false
	}
}

// duplicateJSONKey rejects duplicate keys at any object depth. encoding/json
// silently applies last-wins semantics; refusing ambiguity prevents a policy
// layer that inspects the first value from disagreeing with the dispatcher.
func duplicateJSONKey(raw []byte) bool {
	return hasDuplicateJSONKey(json.NewDecoder(bytes.NewReader(raw)))
}

func hasDuplicateJSONKey(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok {
				return false
			}
			if _, exists := seen[name]; exists {
				return true
			}
			seen[name] = struct{}{}
			if hasDuplicateJSONKey(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	case '[':
		for dec.More() {
			if hasDuplicateJSONKey(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	}
	return false
}

// originAllowed applies the MCP transport's DNS-rebinding boundary. Native
// clients generally omit Origin and remain compatible. When a browser sends
// Origin, it must either match an explicitly configured origin or a loopback
// request host. We intentionally do not trust an arbitrary Host header as a
// same-origin allowlist: a DNS-rebinding page can make that header and Origin
// agree while reaching a loopback listener that holds a dashboard session.
// Deployments behind a TLS terminator or on a named host must configure
// REACTOR_MCP_ALLOWED_ORIGINS with the public HTTPS origin.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if strings.Contains(origin, ",") {
		return false
	}
	canonical, ok := canonicalOrigin(origin)
	if !ok {
		return false
	}
	for _, allowed := range s.AllowedOrigins {
		if configured, valid := canonicalOrigin(allowed); valid && configured == canonical {
			return true
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host, ok := canonicalHost(r.Host, scheme)
	return ok && isLoopbackCanonicalHost(host) && canonical == scheme+"://"+host
}

// isLoopbackCanonicalHost identifies the only Host-derived origin that is
// safe to trust without operator configuration. A remote/named Host is
// attacker-controlled under DNS rebinding and therefore requires the explicit
// origin allowlist above.
func isLoopbackCanonicalHost(host string) bool {
	u, err := url.Parse("//" + host)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if hostname == "localhost" {
		return true
	}
	if zone := strings.LastIndexByte(hostname, '%'); zone >= 0 {
		hostname = hostname[:zone]
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// canonicalOrigin strips paths, query strings, fragments, and default ports
// so comparison follows the browser's origin tuple rather than raw text.
func canonicalOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host, ok := canonicalHost(u.Host, scheme)
	if !ok {
		return "", false
	}
	return scheme + "://" + host, true
}

func canonicalHost(raw, scheme string) (string, bool) {
	u, err := url.Parse("//" + strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", false
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port != "" {
		return hostname + ":" + port, true
	}
	return hostname, true
}

// handleHTTPOne dispatches a single JSON-RPC request and returns the
// response. ok=false signals a notification (no id) where no response
// should be written.
func (s *Server) handleHTTPOne(ctx context.Context, req rpcRequest) (rpcResponse, bool) {
	// Reactor has no server-side notification handlers. In particular, an
	// id-less tools/call must never run: the client would receive only 202 and
	// could not tell whether a workflow was created or dispatched. Consume
	// lifecycle and unknown notifications without invoking request handlers.
	if req.ID == nil {
		return rpcResponse{}, false
	}
	if req.JSONRPC != "2.0" {
		return rpcResponse{ID: req.ID, Error: &rpcError{Code: errInvalidRequest, Message: "jsonrpc must be 2.0"}}, true
	}
	result, err := s.handle(ctx, req.Method, req.Params)
	if err != nil {
		code := errInternalError
		if errors.Is(err, errMethodNotFoundErr) {
			code = errMethodNotFound
		} else if errors.Is(err, errInvalidParamsErr) {
			code = errInvalidParams
		}
		return rpcResponse{ID: req.ID, Error: &rpcError{Code: code, Message: err.Error()}}, true
	}
	return rpcResponse{ID: req.ID, Result: result}, true
}

// writeRPCResponseHTTP encodes a single rpcResponse with JSONRPC 2.0
// version preset. A tool result is untrusted data, so cap the serialized
// response even when a future handler forgets to bound one of its fields.
func writeRPCResponseHTTP(w http.ResponseWriter, resp rpcResponse) {
	writeRPCResponseHTTPStatus(w, http.StatusOK, resp)
}

func writeRPCResponseHTTPStatus(w http.ResponseWriter, status int, resp rpcResponse) {
	resp.JSONRPC = "2.0"
	raw, err := json.Marshal(resp)
	if err != nil {
		raw, _ = json.Marshal(rpcResponse{
			JSONRPC: "2.0", ID: resp.ID,
			Error: &rpcError{Code: errInternalError, Message: "MCP response could not be serialized"},
		})
	}
	if len(raw)+1 > maxMCPHTTPResponseBytes {
		raw, _ = json.Marshal(rpcResponse{
			JSONRPC: "2.0", ID: resp.ID,
			Error: &rpcError{Code: errInternalError, Message: "MCP response exceeds the 4 MiB transport limit"},
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

func writeRPCResponsesHTTP(w http.ResponseWriter, responses []rpcResponse) {
	raw, err := json.Marshal(responses)
	if err == nil && len(raw)+1 <= maxMCPHTTPResponseBytes {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(raw, '\n'))
		return
	}
	// A batch is correlated by each member's id. Returning one id:null error
	// when the aggregate response exceeds the transport cap loses the outcome
	// for every request in the batch and can make an AI retry successful
	// mutations blindly. Replace only members that cannot fit, preserving their
	// ids; if the aggregate is still too large, replace every member with a
	// bounded, id-correlated error envelope.
	const message = "MCP batch response exceeds the 4 MiB transport limit"
	bounded := make([]rpcResponse, len(responses))
	for i, response := range responses {
		member, memberErr := json.Marshal(response)
		if memberErr != nil || len(member) > maxMCPHTTPResponseBytes {
			id := response.ID
			if !validHTTPRPCID(id) {
				id = json.RawMessage("null")
			}
			bounded[i] = rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: errInternalError, Message: message}}
			continue
		}
		bounded[i] = response
	}
	raw, err = json.Marshal(bounded)
	if err != nil || len(raw)+1 > maxMCPHTTPResponseBytes {
		for i, response := range responses {
			id := response.ID
			if !validHTTPRPCID(id) {
				id = json.RawMessage("null")
			}
			bounded[i] = rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: errInternalError, Message: message}}
		}
		raw, _ = json.Marshal(bounded)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(raw, '\n'))
}

// ensureRegistered registers tools once. Stdio path calls registerTools
// at Serve start; the HTTP path needs an idempotent equivalent because
// ServeHTTP gets called per-request.
func (s *Server) ensureRegistered() {
	s.registerOnce.Do(func() {
		// The stdio compatibility path historically supplied this default before
		// registration. HTTP callers construct the same Server directly, and a
		// zero-value/embedded server must still return a valid MCP server identity
		// during initialize so connection probes do not reject a healthy endpoint.
		if strings.TrimSpace(s.Info.Name) == "" {
			s.Info.Name = "reactor"
		}
		s.registerTools()
	})
}

// isJSONContentType returns true when the Content-Type is application/json
// (with optional charset). Mirrors the stdlib's permissive content-type
// matching for JSON bodies.
func isJSONContentType(ct string) bool {
	media, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(media, "application/json")
}

// acceptsJSONResponse reports whether an HTTP Accept header permits the JSON
// response mode implemented by this handler. An omitted header is accepted
// for compatibility with older clients. q=0 explicitly excludes a media type.
func acceptsJSONResponse(header string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return true
	}
	for _, item := range strings.Split(header, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		media, params, err := mime.ParseMediaType(item)
		if err != nil {
			continue
		}
		if rawQ, ok := params["q"]; ok {
			q, err := strconv.ParseFloat(strings.TrimSpace(rawQ), 64)
			if err != nil || q <= 0 {
				continue
			}
		}
		if strings.EqualFold(media, "application/json") || media == "*/*" {
			return true
		}
	}
	return false
}

// trimLeadingSpace returns the slice with ASCII whitespace stripped from
// the front. Avoids pulling in strings/bytes just for the first-byte peek.
func trimLeadingSpace(b []byte) []byte {
	for len(b) > 0 {
		switch b[0] {
		case ' ', '\t', '\n', '\r':
			b = b[1:]
		default:
			return b
		}
	}
	return b
}
