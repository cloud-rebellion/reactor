// cms-detect fingerprints a website to work out which CMS it runs, then (for
// WordPress) probes the REST API to confirm Reactor could actually talk to it.
// It is a great "test run" demo: give it a URL, hit Test run, and watch it
// detect live. It needs no credentials (detection + the public /wp-json probe
// are unauthenticated), so it runs out of the box.
//
// Detection covers the front-end-detectable CMSes (WordPress, Ghost, Webflow,
// Wix, Squarespace, Drupal, Joomla, Shopify) via the generator meta tag,
// response headers, and known markup markers. Headless CMSes (Contentful,
// Sanity, Strapi, DatoCMS, Storyblok) power custom front ends and cannot be
// fingerprinted from the rendered HTML, so the result says so and asks which
// backend the site uses.
//
// Build:    reactor workflow build --src examples/cms-detect --slug cms-detect
// Register: reactor workflow register --db ... --slug cms-detect
// Trigger:  POST /webhook/<token> with {"url":"https://example.com"}
package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/sdk"
	ahttp "github.com/bright-interaction/reactor/sdk/http"
	"github.com/bright-interaction/reactor/sdk/runtime"
)

//nolint:gochecknoglobals // SDK contract: package-level declarations.
var (
	Workflow = reactor.Workflow{Slug: "cms-detect", Version: "0.1.0"}
	Trigger  = reactor.WebhookTrigger{Path: "/webhook/cms-detect", Provider: "generic"}
)

// Payload is the webhook body.
type Payload struct {
	URL string `json:"url"`
}

// Page is the fetched homepage (body + a few headers we fingerprint on).
type Page struct {
	BodyLower string            `json:"-"`
	Headers   map[string]string `json:"-"`
}

// Result is the detection outcome, journaled so the run page shows it.
type Result struct {
	URL            string   `json:"url"`
	CMS            string   `json:"cms"`
	Confidence     string   `json:"confidence"` // high | medium | none
	Signals        []string `json:"signals"`
	ConnectorHint  string   `json:"connector_hint"`
	WPApiReachable bool     `json:"wp_api_reachable"`
}

func Run(ctx context.Context, flow reactor.Flow, in Payload) error {
	log := flow.Logger()
	url := strings.TrimSpace(in.URL)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return reactor.Permanent(errors.New("cms-detect: url must start with http:// or https://"))
	}
	url = strings.TrimRight(url, "/")
	log.Info("cms-detect: starting", "url", url)

	// Step 1: fetch the homepage (a read, so no idempotency key).
	page, err := reactor.Step(flow, ctx, "fetch-page", reactor.StepOpts{
		Timeout: 20 * time.Second,
	}, func(ctx context.Context) (Page, error) {
		return fetchPage(ctx, url)
	})
	if err != nil {
		return err
	}

	// Pure fingerprint (no IO), then classify the result.
	cms, signals := fingerprint(page)
	res := Result{
		URL:           url,
		CMS:           cms,
		Confidence:    confidence(signals),
		Signals:       signals,
		ConnectorHint: connectorHint(cms),
	}
	log.Info("cms-detect: fingerprinted", "cms", cms, "signals", len(signals))

	// Step 2: only for WordPress, confirm the REST API is reachable. This is the
	// "test run on it": proof Reactor's wordpress connector would work.
	if cms == "WordPress" {
		reachable, perr := reactor.Step(flow, ctx, "probe-wp-rest-api", reactor.StepOpts{
			Timeout: 15 * time.Second,
		}, func(ctx context.Context) (bool, error) {
			return probeWordPressAPI(ctx, url), nil
		})
		if perr != nil {
			return perr
		}
		res.WPApiReachable = reachable
		log.Info("cms-detect: wp rest api", "reachable", reachable)
	}

	// Surface the result on the run page (the last step's output is journaled).
	_, err = reactor.Step(flow, ctx, "report", reactor.StepOpts{}, func(_ context.Context) (Result, error) {
		return res, nil
	})
	return err
}

// fetchPage GETs the homepage and returns the lowercased body + key headers.
func fetchPage(ctx context.Context, url string) (Page, error) {
	c := &ahttp.Client{UserAgent: "reactor-cms-detect/0.1"}
	_, headers, body, err := c.GetRaw(ctx, url)
	if err != nil {
		return Page{}, err
	}
	h := map[string]string{}
	for _, k := range []string{"X-Powered-By", "X-Generator", "X-Pingback", "X-Drupal-Cache", "Server", "X-Shopid", "Set-Cookie", "Link"} {
		if v := headers[k]; v != "" {
			h[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
	if len(body) > 512*1024 {
		body = body[:512*1024]
	}
	return Page{BodyLower: strings.ToLower(string(body)), Headers: h}, nil
}

// detector is one CMS fingerprint: a name + the signals it looks for.
type detector struct {
	name string
	// body markers (any match counts) + header (key,substr) checks.
	body    []string
	headers [][2]string // {header-key-lower-substr-of-value}
}

var detectors = []detector{
	{"WordPress", []string{"/wp-content/", "/wp-includes/", `content="wordpress`, "api.w.org"}, [][2]string{{"x-pingback", ""}}},
	{"Ghost", []string{`content="ghost`, "/ghost/", "data-ghost", "ghost.io"}, nil},
	{"Webflow", []string{`content="webflow`, "data-wf-page", "data-wf-site", ".webflow.io"}, nil},
	{"Wix", []string{`content="wix.com website builder`, "static.wixstatic.com", "wix-warmup-data"}, [][2]string{{"x-wix-", ""}, {"server", "pepyaka"}}},
	{"Squarespace", []string{"this is squarespace", "static1.squarespace.com", `content="squarespace`}, nil},
	{"Drupal", []string{`content="drupal`, "/sites/default/files", "/core/misc/drupal.js", "drupal-settings-json"}, [][2]string{{"x-generator", "drupal"}, {"x-drupal-cache", ""}}},
	{"Joomla", []string{`content="joomla`, "/media/jui/", "option=com_content", "/templates/system/"}, nil},
	{"Shopify", []string{"cdn.shopify.com", "shopify.theme", "/cdn/shop/"}, [][2]string{{"x-shopid", ""}, {"x-powered-by", "shopify"}}},
}

// fingerprint returns the best-matching CMS name plus the signals that matched.
// It picks the detector with the most signals so a strong match beats a stray
// marker.
func fingerprint(p Page) (string, []string) {
	best := ""
	var bestSignals []string
	for _, d := range detectors {
		var sig []string
		for _, m := range d.body {
			if strings.Contains(p.BodyLower, m) {
				sig = append(sig, "body:"+m)
			}
		}
		for _, hc := range d.headers {
			if v, ok := p.Headers[hc[0]]; ok && (hc[1] == "" || strings.Contains(v, hc[1])) {
				sig = append(sig, "header:"+hc[0])
			}
		}
		if len(sig) > len(bestSignals) {
			best, bestSignals = d.name, sig
		}
	}
	if best == "" {
		return "Unknown / headless", nil
	}
	return best, bestSignals
}

func confidence(signals []string) string {
	switch {
	case len(signals) == 0:
		return "none"
	case len(signals) >= 2:
		return "high"
	default:
		return "medium"
	}
}

// probeWordPressAPI does a non-destructive GET of /wp-json/ to confirm the REST
// API (which the wordpress connector uses) is reachable.
func probeWordPressAPI(ctx context.Context, base string) bool {
	c := &ahttp.Client{UserAgent: "reactor-cms-detect/0.1"}
	status, _, body, err := c.GetRaw(ctx, base+"/wp-json/")
	if err != nil {
		return false
	}
	if status < 200 || status >= 300 {
		return false
	}
	if len(body) > 64*1024 {
		body = body[:64*1024]
	}
	b := strings.ToLower(string(body))
	return strings.Contains(b, "wp/v2") || strings.Contains(b, `"routes"`) || strings.Contains(b, "wp-json")
}

// connectorHint maps a detected CMS to Reactor's catalog connector advice.
func connectorHint(cms string) string {
	switch cms {
	case "WordPress":
		return "Use the wordpress connector: vault key wordpress-key (Basic auth username:app-password), base /wp-json/wp/v2."
	case "Webflow":
		return "Use the webflow connector: vault key webflow-key (Bearer), base https://api.webflow.com/v2."
	case "Ghost":
		return "Use the ghost connector: vault key ghost-key (signed JWT), base /ghost/api/admin."
	case "Drupal":
		return "Use the drupal connector: JSON:API at /jsonapi (Basic or OAuth)."
	case "Wix":
		return "Use the wix connector: vault key wix-key plus a wix-site-id header."
	case "Squarespace", "Joomla", "Shopify":
		return cms + " detected. Not yet a first-class Reactor connector; call its API via sdk/http with a vault key."
	default:
		return "No front-end CMS fingerprint. Likely a headless CMS (Contentful, Sanity, Strapi, DatoCMS, Storyblok) or a custom stack; ask which backend powers the site."
	}
}

func main() {
	runtime.Serve(Workflow, Trigger, Run)
}
