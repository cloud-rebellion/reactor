// Package catalog is the service catalog behind Reactor's connectors: an
// extensive, data-driven list of CRMs, project-management tools, and the
// providers that already have first-class SDK packages. It is the single
// source of truth for three things:
//
//  1. The operator "auto-add" UI: OAuth services become one-click providers,
//     API-key services become one-click vault credentials, both pre-filled.
//  2. The codegen Environment Lens: RenderForAI emits the base URL, auth
//     scheme, and example operations for every service, so the AI has a
//     documented starting point for sdk/http calls.
//  3. Tests that keep the catalog well-formed as it grows.
//
// Catalog entries are authoring templates, not provider contract tests or
// production-certified adapters. Every entry carries a Docs link so the AI
// and operators can confirm details that drift. An integration is client-ready
// only after its auth, pagination, throttling, and write semantics are tested.
package catalog

import "sort"

// Auth is how a service authenticates.
type Auth string

const (
	// OAuth is the authorization-code flow (connected on the Connections page;
	// referenced in code as oauth:<connection-id>).
	OAuth Auth = "oauth"
	// APIKey is a static secret stored in the vault (referenced by name).
	APIKey Auth = "api_key"
)

// CredentialAccess describes how workflow code can use a connected OAuth
// account. An empty value means the ordinary vault-backed path. A brokered
// account never releases its raw token to workflow code.
type CredentialAccess string

const BrokeredGET CredentialAccess = "brokered_get"

// Op is one canonical operation: an HTTP method + path (relative to BaseURL)
// plus a one-line summary. These are starting points the AI adapts.
type Op struct {
	Method  string
	Path    string
	Summary string
}

// Service is one catalog entry.
type Service struct {
	ID       string // stable slug, e.g. "hubspot"
	Name     string // display name, e.g. "HubSpot"
	Category string // crm | project-management | email | payments | dev
	Auth     Auth
	BaseURL  string // API base; "" or a note when instance/region specific
	// AuthScheme is how the credential is presented, in plain words, e.g.
	// `Authorization: Bearer <token>` or `?api_token=<token>`.
	AuthScheme string
	// KeyName is the suggested vault credential id for API-key services.
	KeyName string
	// KeyHint is where to get the key / how to create the token.
	KeyHint string
	Docs    string // docs URL
	Ops     []Op
	SDK     string // non-empty when a first-class sdk/<pkg> already exists
	// CredentialAccess overrides the default vault-backed OAuth path when the
	// host owns the request and token. BrokerPathPrefix is relative to the
	// validated account origin and precedes each listed operation path.
	CredentialAccess CredentialAccess
	BrokerPathPrefix string
	// OAuth-only:
	AuthURL  string
	TokenURL string
	Scopes   string
	// TokenAuthStyle == "basic" makes the OAuth flow send the client id/secret
	// as an HTTP Basic header on the token request (Pipedrive, Notion). Empty
	// puts them in the body (the default).
	TokenAuthStyle string
	// AuthParams are extra authorize-URL query params (e.g. Notion owner=user).
	AuthParams map[string]string
}

// services is the catalog. Base URLs + auth schemes are the providers'
// documented values; confirm anything version-specific against Docs.
var services = []Service{
	// --- OAuth identity / mail / dev (also drive the OAuth quick-add) ---
	{
		ID: "google", Name: "Google", Category: "email", Auth: OAuth,
		BaseURL: "https://www.googleapis.com", AuthScheme: "Authorization: Bearer <token>",
		Docs:     "https://developers.google.com/identity/protocols/oauth2",
		SDK:      "sdk/email (Gmail)",
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		Scopes:   "openid email profile https://www.googleapis.com/auth/gmail.send",
		Ops: []Op{
			{"POST", "/gmail/v1/users/me/messages/send", "send an email (prefer sdk/email)"},
		},
	},
	{
		ID: "microsoft", Name: "Microsoft", Category: "email", Auth: OAuth,
		BaseURL: "https://graph.microsoft.com/v1.0", AuthScheme: "Authorization: Bearer <token>",
		Docs:     "https://learn.microsoft.com/en-us/graph/use-the-api",
		SDK:      "sdk/email (Outlook)",
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		Scopes:   "openid email profile offline_access https://graph.microsoft.com/Mail.Send",
		Ops: []Op{
			{"POST", "/me/sendMail", "send mail (prefer sdk/email)"},
		},
	},
	{
		ID: "github", Name: "GitHub", Category: "dev", Auth: OAuth,
		BaseURL: "https://api.github.com", AuthScheme: "Authorization: Bearer <token>",
		Docs:     "https://docs.github.com/en/rest",
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
		Scopes:   "read:user user:email repo",
		Ops: []Op{
			{"POST", "/repos/{owner}/{repo}/issues", "create an issue"},
			{"GET", "/repos/{owner}/{repo}/issues/{n}", "read an issue"},
		},
	},

	// --- Payments (SDK-backed; listed so the AI knows they exist) ---
	{
		ID: "stripe", Name: "Stripe", Category: "payments", Auth: APIKey,
		BaseURL: "https://api.stripe.com/v1", AuthScheme: "Authorization: Bearer <key>; form-encoded bodies; Idempotency-Key header",
		KeyName: "stripe-key", KeyHint: "Dashboard -> Developers -> API keys (secret key sk_...)",
		Docs: "https://docs.stripe.com/api", SDK: "sdk/stripe",
		Ops: []Op{{"POST", "/checkout/sessions", "hosted checkout (prefer sdk/stripe)"}},
	},
	{
		ID: "mollie", Name: "Mollie", Category: "payments", Auth: APIKey,
		BaseURL: "https://api.mollie.com/v2", AuthScheme: "Authorization: Bearer <key>",
		KeyName: "mollie-key", KeyHint: "Dashboard -> Developers -> API keys (test_/live_)",
		Docs: "https://docs.mollie.com/reference", SDK: "sdk/mollie",
		Ops: []Op{{"POST", "/payments", "create a payment (prefer sdk/mollie)"}},
	},

	// --- CRM ---
	{
		ID: "hubspot", Name: "HubSpot", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.hubapi.com", AuthScheme: "Authorization: Bearer <token>; private-app token or OAuth",
		KeyName: "hubspot-key", KeyHint: "Settings -> Integrations -> Private Apps -> access token",
		Docs:     "https://developers.hubspot.com/docs/api/crm/contacts",
		AuthURL:  "https://app.hubspot.com/oauth/authorize",
		TokenURL: "https://api.hubapi.com/oauth/v1/token",
		Scopes:   "oauth crm.objects.contacts.read crm.objects.contacts.write crm.objects.deals.read crm.objects.deals.write crm.objects.companies.read crm.objects.companies.write",
		Ops: []Op{
			{"POST", "/crm/v3/objects/contacts", "create a contact (body: {properties:{...}})"},
			{"GET", "/crm/v3/objects/contacts/{id}", "read a contact"},
			{"PATCH", "/crm/v3/objects/contacts/{id}", "update a contact"},
			{"POST", "/crm/v3/objects/deals", "create a deal"},
		},
	},
	{
		ID: "salesforce", Name: "Salesforce", Category: "crm", Auth: OAuth,
		BaseURL: "<validated OAuth instance_url>/services/data", AuthScheme: "GET via sdk/http.ConnectorGet with oauth:<connection-id>; host attaches Bearer token only to validated Salesforce org origin; raw token fetch is denied",
		CredentialAccess: BrokeredGET, BrokerPathPrefix: "/services/data",
		Docs:     "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/",
		AuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
		TokenURL: "https://login.salesforce.com/services/oauth2/token",
		Scopes:   "api id refresh_token offline_access",
		Ops: []Op{
			{"GET", "/v60.0/query?q=...", "SOQL query (GET-only broker; review fields and pagination)"},
			{"GET", "/v60.0/sobjects/Account/{id}", "read one account (GET-only broker)"},
		},
	},
	{
		ID: "pipedrive", Name: "Pipedrive", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.pipedrive.com/v1", AuthScheme: "OAuth Bearer, or ?api_token=<token> query param",
		KeyName: "pipedrive-key", KeyHint: "Settings -> Personal preferences -> API -> token",
		Docs:           "https://developers.pipedrive.com/docs/api/v1",
		AuthURL:        "https://oauth.pipedrive.com/oauth/authorize",
		TokenURL:       "https://oauth.pipedrive.com/oauth/token",
		Scopes:         "base deals:full contacts:full",
		TokenAuthStyle: "basic",
		Ops: []Op{
			{"POST", "/persons", "create a person"},
			{"POST", "/deals", "create a deal"},
			{"POST", "/organizations", "create an organization"},
		},
	},
	{
		ID: "zoho-crm", Name: "Zoho CRM", Category: "crm", Auth: OAuth,
		BaseURL: "https://www.zohoapis.com/crm/v5", AuthScheme: "Authorization: Zoho-oauthtoken <token>; base is region specific (.eu/.in)",
		Docs:     "https://www.zoho.com/crm/developer/docs/api/v5/",
		AuthURL:  "https://accounts.zoho.com/oauth/v2/auth",
		TokenURL: "https://accounts.zoho.com/oauth/v2/token",
		Scopes:   "ZohoCRM.modules.ALL offline_access",
		Ops:      []Op{{"POST", "/Contacts", "create a contact"}, {"POST", "/Leads", "create a lead"}},
	},
	{
		ID: "airtable", Name: "Airtable", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.airtable.com/v0", AuthScheme: "Authorization: Bearer <personal-access-token>",
		KeyName: "airtable-key", KeyHint: "Account -> Developer hub -> Personal access tokens",
		Docs: "https://airtable.com/developers/web/api/introduction",
		Ops: []Op{
			{"POST", "/{baseId}/{table}", "create records (body: {records:[{fields:{...}}]})"},
			{"GET", "/{baseId}/{table}", "list records"},
			{"PATCH", "/{baseId}/{table}", "update records"},
		},
	},
	{
		ID: "attio", Name: "Attio", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.attio.com/v2", AuthScheme: "Authorization: Bearer <key>",
		KeyName: "attio-key", KeyHint: "Workspace settings -> Developers -> API keys",
		Docs: "https://developers.attio.com/reference",
		Ops:  []Op{{"POST", "/objects/people/records", "create a person record"}, {"POST", "/objects/companies/records", "create a company"}},
	},
	{
		ID: "close", Name: "Close", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.close.com/api/v1", AuthScheme: "HTTP Basic: API key as username, blank password",
		KeyName: "close-key", KeyHint: "Settings -> Developer -> API Keys",
		Docs: "https://developer.close.com/",
		Ops:  []Op{{"POST", "/lead/", "create a lead"}, {"POST", "/contact/", "create a contact"}},
	},
	{
		ID: "copper", Name: "Copper", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.copper.com/developer_api/v1", AuthScheme: "headers X-PW-AccessToken: <key>, X-PW-Application: developer_api, X-PW-UserEmail: <email>",
		KeyName: "copper-key", KeyHint: "Settings -> API Keys (also needs your account email)",
		Docs: "https://developer.copper.com/",
		Ops:  []Op{{"POST", "/people", "create a person"}, {"POST", "/leads", "create a lead"}},
	},
	{
		ID: "freshsales", Name: "Freshsales", Category: "crm", Auth: APIKey,
		BaseURL: "https://<domain>.myfreshworks.com/crm/sales/api", AuthScheme: "Authorization: Token token=<key>; base host is your domain",
		KeyName: "freshsales-key", KeyHint: "Settings -> API Settings",
		Docs: "https://developers.freshworks.com/crm/api/",
		Ops:  []Op{{"POST", "/contacts", "create a contact"}, {"POST", "/leads", "create a lead"}},
	},
	{
		ID: "dynamics365", Name: "Microsoft Dynamics 365", Category: "crm", Auth: OAuth,
		BaseURL: "https://<org>.api.crm.dynamics.com/api/data/v9.2", AuthScheme: "Authorization: Bearer <token>; base host is your org",
		Docs:     "https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/overview",
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		Scopes:   "openid offline_access https://<org>.api.crm.dynamics.com/.default",
		Ops:      []Op{{"POST", "/contacts", "create a contact"}, {"POST", "/leads", "create a lead"}},
	},
	{
		ID: "zendesk-sell", Name: "Zendesk Sell", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.getbase.com/v2", AuthScheme: "Authorization: Bearer <access-token>",
		KeyName: "zendesk-sell-key", KeyHint: "Settings -> OAuth -> Access Tokens",
		Docs: "https://developer.zendesk.com/api-reference/sales-crm/introduction/",
		Ops:  []Op{{"POST", "/contacts", "create a contact"}, {"POST", "/leads", "create a lead"}},
	},
	{
		ID: "insightly", Name: "Insightly", Category: "crm", Auth: APIKey,
		BaseURL: "https://api.{pod}.insightly.com/v3.1", AuthScheme: "HTTP Basic: API key as username; pod e.g. na1",
		KeyName: "insightly-key", KeyHint: "User Settings -> API key",
		Docs: "https://api.insightly.com/v3.1/Help",
		Ops:  []Op{{"POST", "/Contacts", "create a contact"}, {"POST", "/Leads", "create a lead"}},
	},

	// --- Project management ---
	{
		ID: "asana", Name: "Asana", Category: "project-management", Auth: APIKey,
		BaseURL: "https://app.asana.com/api/1.0", AuthScheme: "Authorization: Bearer <token>; PAT or OAuth",
		KeyName: "asana-key", KeyHint: "Settings -> Apps -> Manage Developer Apps -> Personal access token",
		Docs:     "https://developers.asana.com/reference/rest-api-reference",
		AuthURL:  "https://app.asana.com/-/oauth_authorize",
		TokenURL: "https://app.asana.com/-/oauth_token",
		Scopes:   "default",
		Ops: []Op{
			{"POST", "/tasks", "create a task (body: {data:{...}})"},
			{"GET", "/tasks/{id}", "read a task"},
			{"POST", "/projects", "create a project"},
		},
	},
	{
		ID: "trello", Name: "Trello", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.trello.com/1", AuthScheme: "?key=<key>&token=<token> query params",
		KeyName: "trello-key", KeyHint: "https://trello.com/app-key (key + token)",
		Docs: "https://developer.atlassian.com/cloud/trello/rest/",
		Ops:  []Op{{"POST", "/cards", "create a card"}, {"GET", "/cards/{id}", "read a card"}, {"POST", "/boards", "create a board"}},
	},
	{
		ID: "jira", Name: "Jira", Category: "project-management", Auth: APIKey,
		BaseURL: "https://<your-domain>.atlassian.net/rest/api/3", AuthScheme: "HTTP Basic: email as username, API token as password",
		KeyName: "jira-key", KeyHint: "id.atlassian.com -> Security -> API tokens (store as email:token)",
		Docs: "https://developer.atlassian.com/cloud/jira/platform/rest/v3/",
		Ops:  []Op{{"POST", "/issue", "create an issue"}, {"GET", "/issue/{key}", "read an issue"}},
	},
	{
		ID: "clickup", Name: "ClickUp", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.clickup.com/api/v2", AuthScheme: "Authorization: <personal-token> (no Bearer prefix)",
		KeyName: "clickup-key", KeyHint: "Settings -> Apps -> Personal API token (pk_...)",
		Docs: "https://clickup.com/api",
		Ops:  []Op{{"POST", "/list/{list_id}/task", "create a task"}, {"GET", "/task/{id}", "read a task"}},
	},
	{
		ID: "monday", Name: "monday.com", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.monday.com/v2", AuthScheme: "Authorization: <token>; GraphQL: POST {query, variables}",
		KeyName: "monday-key", KeyHint: "Profile -> Developers -> My access tokens",
		Docs: "https://developer.monday.com/api-reference/docs",
		Ops:  []Op{{"POST", "/", "GraphQL mutation create_item / query boards"}},
	},
	{
		ID: "linear", Name: "Linear", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.linear.app/graphql", AuthScheme: "Authorization: <api-key>; GraphQL: POST {query, variables}",
		KeyName: "linear-key", KeyHint: "Settings -> Security & access -> Personal API keys",
		Docs: "https://developers.linear.app/docs",
		Ops:  []Op{{"POST", "", "GraphQL mutation issueCreate / query issues"}},
	},
	{
		ID: "notion", Name: "Notion", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.notion.com/v1", AuthScheme: "Authorization: Bearer <token>; header Notion-Version: 2022-06-28",
		KeyName: "notion-key", KeyHint: "notion.so/my-integrations -> Internal Integration Secret",
		Docs:           "https://developers.notion.com/reference/intro",
		AuthURL:        "https://api.notion.com/v1/oauth/authorize",
		TokenURL:       "https://api.notion.com/v1/oauth/token",
		Scopes:         "",
		TokenAuthStyle: "basic",
		AuthParams:     map[string]string{"owner": "user"},
		Ops: []Op{
			{"POST", "/pages", "create a page (in a database)"},
			{"POST", "/databases/{id}/query", "query a database"},
			{"PATCH", "/blocks/{id}/children", "append content"},
		},
	},
	{
		ID: "todoist", Name: "Todoist", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.todoist.com/rest/v2", AuthScheme: "Authorization: Bearer <api-token>",
		KeyName: "todoist-key", KeyHint: "Settings -> Integrations -> Developer -> API token",
		Docs: "https://developer.todoist.com/rest/v2/",
		Ops:  []Op{{"POST", "/tasks", "create a task"}, {"GET", "/tasks", "list tasks"}},
	},
	{
		ID: "wrike", Name: "Wrike", Category: "project-management", Auth: APIKey,
		BaseURL: "https://www.wrike.com/api/v4", AuthScheme: "Authorization: Bearer <permanent-token>",
		KeyName: "wrike-key", KeyHint: "Apps & Integrations -> API -> Permanent access token",
		Docs: "https://developers.wrike.com/",
		Ops:  []Op{{"POST", "/folders/{id}/tasks", "create a task"}, {"GET", "/tasks/{id}", "read a task"}},
	},
	{
		ID: "shortcut", Name: "Shortcut", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.app.shortcut.com/api/v3", AuthScheme: "header Shortcut-Token: <token>",
		KeyName: "shortcut-key", KeyHint: "Settings -> API Tokens",
		Docs: "https://developer.shortcut.com/api/rest/v3",
		Ops:  []Op{{"POST", "/stories", "create a story"}, {"GET", "/stories/{id}", "read a story"}},
	},
	{
		ID: "height", Name: "Height", Category: "project-management", Auth: APIKey,
		BaseURL: "https://api.height.app", AuthScheme: "Authorization: api-key <key>",
		KeyName: "height-key", KeyHint: "Settings -> API -> Secret key",
		Docs: "https://height.notion.site/Height-API-docs",
		Ops:  []Op{{"POST", "/tasks", "create a task"}, {"GET", "/tasks", "list tasks"}},
	},
	{
		ID: "teamwork", Name: "Teamwork", Category: "project-management", Auth: APIKey,
		BaseURL: "https://<site>.teamwork.com", AuthScheme: "HTTP Basic: API key as username; base host is your site",
		KeyName: "teamwork-key", KeyHint: "Profile -> Edit -> API & Mobile -> API key",
		Docs: "https://apidocs.teamwork.com/",
		Ops:  []Op{{"POST", "/projects/{id}/tasks.json", "create a task"}},
	},
	{
		ID: "basecamp", Name: "Basecamp", Category: "project-management", Auth: OAuth,
		BaseURL: "https://3.basecampapi.com/<account-id>", AuthScheme: "Authorization: Bearer <token>; base includes your account id",
		Docs:     "https://github.com/basecamp/bc3-api",
		AuthURL:  "https://launchpad.37signals.com/authorization/new",
		TokenURL: "https://launchpad.37signals.com/authorization/token",
		Scopes:   "",
		Ops:      []Op{{"POST", "/buckets/{project}/todolists/{id}/todos.json", "create a to-do"}},
	},

	// --- CMS ---
	{
		ID: "wordpress", Name: "WordPress", Category: "cms", Auth: APIKey,
		BaseURL: "https://<your-site>/wp-json/wp/v2", AuthScheme: "HTTP Basic: WordPress username + Application Password; base host is your site",
		KeyName: "wordpress-key", KeyHint: "Users -> Profile -> Application Passwords (store as username:app-password)",
		Docs: "https://developer.wordpress.org/rest-api/reference/posts/",
		Ops: []Op{
			{"POST", "/posts", "create a post (body: {title, content, status})"},
			{"POST", "/media", "upload media (multipart)"},
			{"GET", "/posts/{id}", "read a post"},
		},
	},
	{
		ID: "webflow", Name: "Webflow", Category: "cms", Auth: APIKey,
		BaseURL: "https://api.webflow.com/v2", AuthScheme: "Authorization: Bearer <token>; API token or OAuth",
		KeyName: "webflow-key", KeyHint: "Site settings -> Apps & integrations -> API access",
		Docs:     "https://developers.webflow.com/data/reference",
		AuthURL:  "https://webflow.com/oauth/authorize",
		TokenURL: "https://api.webflow.com/oauth/access_token",
		Scopes:   "sites:read sites:write cms:read cms:write assets:read assets:write",
		Ops: []Op{
			{"POST", "/collections/{collection_id}/items", "create a CMS item"},
			{"POST", "/sites/{site_id}/publish", "publish the site"},
		},
	},
	{
		ID: "contentful", Name: "Contentful", Category: "cms", Auth: APIKey,
		BaseURL: "https://api.contentful.com", AuthScheme: "Authorization: Bearer <CMA token>; EU host api.eu.contentful.com",
		KeyName: "contentful-key", KeyHint: "Settings -> CMA tokens (Content Management API)",
		Docs: "https://www.contentful.com/developers/docs/references/content-management-api/",
		Ops: []Op{
			{"PUT", "/spaces/{space}/environments/{env}/entries/{id}", "create a draft entry (header X-Contentful-Content-Type)"},
			{"PUT", "/spaces/{space}/environments/{env}/entries/{id}/published", "publish (header X-Contentful-Version)"},
		},
	},
	{
		ID: "sanity", Name: "Sanity", Category: "cms", Auth: APIKey,
		BaseURL: "https://<projectId>.api.sanity.io", AuthScheme: "Authorization: Bearer <token>; base host is your projectId",
		KeyName: "sanity-key", KeyHint: "manage.sanity.io -> API -> Tokens (editor/write)",
		Docs: "https://www.sanity.io/docs/http-mutations",
		Ops:  []Op{{"POST", "/v2021-10-21/data/mutate/{dataset}", "create or patch documents (mutations)"}},
	},
	{
		ID: "strapi", Name: "Strapi", Category: "cms", Auth: APIKey,
		BaseURL: "https://<your-domain>/api", AuthScheme: "Authorization: Bearer <api-token>; base host is your self-hosted domain",
		KeyName: "strapi-key", KeyHint: "Settings -> API Tokens",
		Docs: "https://docs.strapi.io/dev-docs/api/rest",
		Ops:  []Op{{"POST", "/{collection}", "create an entry (body: {data:{...}})"}, {"GET", "/{collection}", "list entries"}},
	},
	{
		ID: "ghost", Name: "Ghost", Category: "cms", Auth: APIKey,
		BaseURL: "https://<your-site>/ghost/api/admin", AuthScheme: "Authorization: Ghost <JWT>; sign a short-lived HS256 JWT from the Admin API key id:secret",
		KeyName: "ghost-key", KeyHint: "Settings -> Integrations -> Custom integration -> Admin API Key (id:secret)",
		Docs: "https://docs.ghost.org/admin-api/",
		Ops:  []Op{{"POST", "/posts/", "create a post"}, {"PUT", "/posts/{id}/", "update a post"}},
	},
	{
		ID: "storyblok", Name: "Storyblok", Category: "cms", Auth: APIKey,
		BaseURL: "https://mapi.storyblok.com/v1", AuthScheme: "Authorization: <management-token>",
		KeyName: "storyblok-key", KeyHint: "Account -> Access tokens (Management API / personal)",
		Docs: "https://www.storyblok.com/docs/api/management",
		Ops:  []Op{{"POST", "/spaces/{space_id}/stories", "create a story"}, {"PUT", "/spaces/{space_id}/stories/{id}", "update a story"}},
	},
	{
		ID: "drupal", Name: "Drupal", Category: "cms", Auth: APIKey,
		BaseURL: "https://<your-site>/jsonapi", AuthScheme: "HTTP Basic or OAuth; JSON:API; headers Accept + Content-Type: application/vnd.api+json",
		KeyName: "drupal-key", KeyHint: "Enable the JSON:API + Basic Auth modules; store as username:password",
		Docs: "https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module",
		Ops:  []Op{{"POST", "/node/{bundle}", "create content"}, {"GET", "/node/{bundle}", "list content"}},
	},
	{
		ID: "datocms", Name: "DatoCMS", Category: "cms", Auth: APIKey,
		BaseURL: "https://site-api.datocms.com", AuthScheme: "Authorization: Bearer <api-token>; header X-Api-Version: 3",
		KeyName: "datocms-key", KeyHint: "Project settings -> API tokens",
		Docs: "https://www.datocms.com/docs/content-management-api",
		Ops:  []Op{{"POST", "/items", "create a record"}, {"PUT", "/items/{id}", "update a record"}},
	},
	{
		ID: "wix", Name: "Wix", Category: "cms", Auth: APIKey,
		BaseURL: "https://www.wixapis.com", AuthScheme: "Authorization: <api-key>; header wix-site-id: <site-id>",
		KeyName: "wix-key", KeyHint: "Wix dashboard -> Settings -> Headless / API keys",
		Docs: "https://dev.wix.com/docs/rest",
		Ops:  []Op{{"POST", "/blog/v3/draft-posts", "create a draft post"}, {"POST", "/blog/v3/draft-posts/{id}/publish", "publish a post"}},
	},
}

// All returns every service, sorted by category then name (stable for UI).
func All() []Service {
	out := make([]Service, len(services))
	for i, service := range services {
		out[i] = cloneService(service)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ByID returns the service with id, or false.
func ByID(id string) (Service, bool) {
	for _, s := range services {
		if s.ID == id {
			return cloneService(s), true
		}
	}
	return Service{}, false
}

// Catalog entries are shared source data for the UI, OAuth setup, and AI
// authoring lens. Never expose their nested slices or maps for caller mutation.
func cloneService(s Service) Service {
	s.Ops = append([]Op(nil), s.Ops...)
	if s.AuthParams != nil {
		params := make(map[string]string, len(s.AuthParams))
		for key, value := range s.AuthParams {
			params[key] = value
		}
		s.AuthParams = params
	}
	return s
}

// HasOAuth reports whether a service can be connected via OAuth (the
// click-Connect-consent flow), whether or not it also supports an API key.
func (s Service) HasOAuth() bool { return s.AuthURL != "" && s.TokenURL != "" }

// OAuthServices returns every service connectable via OAuth (the Connect
// button), including API-key-primary services that also offer OAuth.
func OAuthServices() []Service { return filter(func(s Service) bool { return s.HasOAuth() }) }

// APIKeyServices returns the services that accept a static API key (the
// credential quick-add). A service may appear in both lists when it supports
// either auth.
func APIKeyServices() []Service { return filter(func(s Service) bool { return s.Auth == APIKey }) }

// ByCategory returns services in one category, sorted by name.
func ByCategory(cat string) []Service {
	return filter(func(s Service) bool { return s.Category == cat })
}

func filter(keep func(Service) bool) []Service {
	var out []Service
	for _, s := range All() {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}
