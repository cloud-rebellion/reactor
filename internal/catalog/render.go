package catalog

import (
	"fmt"
	"sort"
	"strings"
)

// RenderForAI emits the catalog as Markdown for the codegen Environment Lens.
// For every service it states the base URL, auth scheme, suggested credential
// reference, and example operations, so the generator has documented starting
// points instead of inventing endpoints. Prefer an SDK package when one is
// listed; catalog metadata alone does not verify a provider contract.
func RenderForAI() string {
	var b strings.Builder
	b.WriteString("These services have catalog starting points. Use sdk/http inside a Step closure unless an SDK package is noted. ")
	b.WriteString("Fetch credentials at run time: API-key services use vault.MustGet(\"<key-name>\"); ordinary OAuth services use vault.MustGet(\"oauth:<connection-id>\"). ")
	b.WriteString("Credential-bearing sdk/http.Client calls require CredentialOrigin set to the reviewed provider scheme and authority; never derive it or the destination from workflow input or provider data. Query-parameter credentials also need this pin. ")
	b.WriteString("For REST writes use sdk/http.Client.PostJSON, PutJSON, PatchJSON, or Delete according to the documented method; use Put for a documented bodyless PUT. Direct net/http imports are not available to workflows. ")
	b.WriteString("A brokered OAuth service is different: use its listed host connector and never fetch or pass its raw token. ")
	b.WriteString("For collection reads, use sdk/http.FetchPages with a provider-specific decoder and bounded page/item/byte limits after confirming its pagination contract. ")
	b.WriteString("Before enabling a client integration, confirm the operation, pagination, throttling, and write idempotency against the linked provider docs.\n")

	byCat := map[string][]Service{}
	for _, s := range All() {
		byCat[s.Category] = append(byCat[s.Category], s)
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	for _, cat := range cats {
		fmt.Fprintf(&b, "\n### %s\n", catTitle(cat))
		for _, s := range byCat[cat] {
			b.WriteString(renderService(s))
		}
	}
	return b.String()
}

func renderService(s Service) string {
	var b strings.Builder
	cred := "vault key \"" + s.KeyName + "\" via vault.MustGet(\"" + s.KeyName + "\")"
	if s.Auth == OAuth {
		cred = "OAuth connection via vault.MustGet(\"oauth:<connection-id>\")"
	}
	if s.CredentialAccess == BrokeredGET {
		cred = "brokered OAuth connection (oauth:<connection-id>); never use vault.MustGet or a raw token"
	}
	fmt.Fprintf(&b, "\n**%s** (`%s`) -- auth: %s; %s\n", s.Name, s.ID, cred, s.AuthScheme)
	fmt.Fprintf(&b, "- base URL: `%s`\n", s.BaseURL)
	if s.CredentialAccess == BrokeredGET {
		fmt.Fprintf(&b, "- execution: GET only via sdk/http.ConnectorGet(ctx, \"oauth:<connection-id>\", \"%s<operation-path>\", &out); the path is relative to the validated account origin and the host attaches the token\n", s.BrokerPathPrefix)
	} else {
		b.WriteString("- execution: set sdk/http.Client.CredentialOrigin to the exact reviewed base-URL scheme and authority before sending credentials\n")
	}
	if s.SDK != "" {
		fmt.Fprintf(&b, "- SDK available: `%s` (prefer it)\n", s.SDK)
	}
	for _, op := range s.Ops {
		path := op.Path
		if path == "" {
			path = "(base)"
		}
		fmt.Fprintf(&b, "- %s `%s` -- %s\n", op.Method, path, op.Summary)
	}
	fmt.Fprintf(&b, "- docs: %s\n", s.Docs)
	return b.String()
}

func catTitle(cat string) string {
	switch cat {
	case "crm":
		return "CRM"
	case "project-management":
		return "Project management"
	case "cms":
		return "CMS"
	case "email":
		return "Email"
	case "payments":
		return "Payments"
	case "dev":
		return "Developer tools"
	default:
		return cat
	}
}
