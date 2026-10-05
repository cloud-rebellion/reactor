// Package templates contains the reviewed starter briefs shared by the
// dashboard and MCP authoring surfaces. A brief is guidance for an author;
// it is never executable source and must still pass validation and review.
package templates

// Template is a starter automation brief. The dashboard may feed Brief to
// the optional code generator, while MCP clients can use it as authoring
// context before calling reactor_validate_workflow.
type Template struct {
	ID          string
	Name        string
	Category    string
	Description string
	Brief       string
}

var catalog = []Template{
	{
		ID: "webhook-to-slack", Name: "Webhook to Slack alert", Category: "Notify",
		Description: "Receive a webhook and post a formatted message to a Slack channel.",
		Brief:       "A webhook-triggered workflow that takes the incoming JSON payload and posts a concise, formatted summary message to a Slack channel via an incoming webhook URL stored as a credential. Include the key fields from the payload in the message.",
	},
	{
		ID: "daily-summary-email", Name: "Daily summary email", Category: "Report",
		Description: "On a schedule, gather data and email a summary.",
		Brief:       "A cron-triggered workflow that runs every morning at 8am, fetches a JSON report from an HTTP API endpoint, formats the results into a short readable summary, and sends it as an email via SMTP credentials. Use an idempotency key per day so a retry never sends twice.",
	},
	{
		ID: "form-to-crm", Name: "Form submission to CRM", Category: "Sales",
		Description: "Capture a form webhook, enrich the lead, and upsert it to a CRM.",
		Brief:       "A webhook-triggered workflow that receives a contact form submission (name, email, company), enriches it with an HTTP call to an enrichment API, scores the lead, and upserts the contact into a CRM via its REST API. Each external call is its own step with an idempotency key on the email.",
	},
	{
		ID: "url-health-check", Name: "Scheduled health check", Category: "Monitor",
		Description: "Poll a URL on a schedule and alert when it is down.",
		Brief:       "A cron-triggered workflow that runs every 5 minutes, does an HTTP GET to a configured URL, and if the response is not 2xx or takes longer than 3 seconds, sends an alert to a notification channel. Otherwise it records success and exits quietly.",
	},
	{
		ID: "stripe-receipt", Name: "Stripe payment to notification", Category: "Payments",
		Description: "On a Stripe payment webhook, notify the team.",
		Brief:       "A Stripe-webhook-triggered workflow (provider stripe) that fires on a successful payment event, extracts the amount, currency, and customer email, and posts a celebratory notification to a Slack channel. Verify it only acts on payment success events.",
	},
	{
		ID: "rss-to-webhook", Name: "RSS feed to webhook", Category: "Integrate",
		Description: "Poll an RSS feed to forward new items to a webhook.",
		Brief:       "A cron-triggered workflow that runs hourly, fetches an RSS/Atom feed over HTTP, parses the items, and for each item newer than the last run posts the title and link to an outbound webhook URL. Use an idempotency key per item GUID so an item is forwarded exactly once.",
	},
}

// All returns a copy so callers cannot mutate the shared catalog.
func All() []Template {
	out := make([]Template, len(catalog))
	copy(out, catalog)
	return out
}
