package server

import (
	"html/template"
	"net/http"
	"strings"
)

// This file holds the dashboard's presentation scaffolding (the page
// shell + base CSS + the render entry point), split out of server.go so
// the handler logic and the HTML layout don't share one 1,200-line file.

type page struct {
	Title   string
	Heading string
	Body    template.HTML
	Nav     template.HTML // role-aware nav, set by renderPage
}

// navItem is one nav link. section "" means it sits inline in the bar (primary,
// daily surfaces); a non-empty section groups it under the "More" dropdown.
// adminOnly links are hidden from members (the server-side requireAdmin gates
// are the real boundary; this just declutters the menu).
type navItem struct {
	href, label, section string
	adminOnly            bool
}

var navItems = []navItem{
	// Primary -- inline in the bar.
	{"/", "Home", "", false},
	{"/runs", "Runs", "", false},
	{"/errors", "Errors", "", false},
	{"/templates", "Templates", "", false},
	{"/integrations", "Integrations", "", false},
	{"/account", "Account", "", false},
	// Secondary -- grouped under "More".
	{"/connections", "Connections", "Workspace", false},
	{"/credentials", "Credentials", "Workspace", false},
	{"/knowledge", "Knowledge base", "Workspace", false},
	{"/notifications", "Notifications", "Workspace", true},
	{"/oauth-providers", "OAuth providers", "Workspace", true},
	{"/postmortems", "Post-mortems", "Monitor", true},
	{"/dlq", "Dead letters", "Monitor", true},
	{"/mail-sends", "Mail send reconciliation", "Monitor", true},
	{"/audit", "Audit", "Monitor", true},
	{"/tenants", "Tenants", "Billing & access", true},
	{"/plans", "Plans", "Billing & access", true},
	{"/users", "Users", "Billing & access", true},
	{"/tokens", "API tokens", "Billing & access", false},
	{"/security", "Security", "Billing & access", false},
	{"/docs", "Docs", "Help", false},
	{"/healthz", "Health", "Help", false},
}

var navSections = []string{"Workspace", "Monitor", "Billing & access", "Help"}

// themeGlyph is a monochrome half-circle (contrast) icon for the light/dark
// toggle -- no emoji, adapts via currentColor.
const themeGlyph = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" stroke="none"/></svg>`

// buildNav renders the bar: primary links inline, the rest under a sectioned
// "More" dropdown, then the theme toggle + Sign out.
func buildNav(admin bool) template.HTML {
	visible := func(it navItem) bool { return !it.adminOnly || admin }
	var b strings.Builder

	b.WriteString(`<div class="nav-main">`)
	for _, it := range navItems {
		if it.section == "" && visible(it) {
			b.WriteString(`<a href="` + it.href + `">` + it.label + `</a>`)
		}
	}
	b.WriteString(`</div><div class="nav-right">`)

	var more strings.Builder
	for _, sec := range navSections {
		var items strings.Builder
		for _, it := range navItems {
			if it.section == sec && visible(it) {
				items.WriteString(`<a href="` + it.href + `">` + it.label + `</a>`)
			}
		}
		if items.Len() > 0 {
			more.WriteString(`<div class="navdrop-sec">` + sec + `</div>` + items.String())
		}
	}
	if more.Len() > 0 {
		b.WriteString(`<details class="navdrop"><summary>More</summary><div class="navdrop-menu">` + more.String() + `</div></details>`)
	}
	b.WriteString(`<button type="button" id="theme-toggle" class="nav-icon" aria-label="Toggle light or dark" title="Toggle light or dark">` + themeGlyph + `</button>`)
	b.WriteString(`<form method="POST" action="/logout" class="nav-logout"><button type="submit">Sign out</button></form>`)
	b.WriteString(`</div>`)
	return template.HTML(b.String())
}

// navFor builds the nav for a request's viewer. Members see only the
// member-accessible links; admins (and no-auth / pre-login) see everything.
func navFor(r *http.Request) template.HTML {
	admin := true
	if u, ok := UserFromContext(r.Context()); ok {
		admin = u.IsAdmin()
	}
	return buildNav(admin)
}

// renderPage renders a page with a nav scoped to the request's viewer.
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, p page) {
	p.Nav = navFor(r)
	render(w, layout, p)
}

// fullNav is the complete operator menu, used as the default for render calls
// that have no request to scope by (the error + form-error helpers).
var fullNav = buildNav(true)

const layout = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
@font-face { font-family:'Inter'; font-style:normal; font-weight:300 700; font-display:swap; src:url(/assets/fonts/inter.woff2) format('woff2'); }
@font-face { font-family:'Geist'; font-style:normal; font-weight:300 700; font-display:swap; src:url(/assets/fonts/geist.woff2) format('woff2'); }
@font-face { font-family:'JetBrains Mono'; font-style:normal; font-weight:400 500; font-display:swap; src:url(/assets/fonts/jetbrains-mono.woff2) format('woff2'); }
:root {
  /* AtomicSite Swiss Minimal: monochrome, near-black accent (no chromatic accent). */
  --bg:#F7F7F7; --surface:#FFFFFF; --surface-2:#FAFAFA; --hover:#F0F0F0;
  --border:#E5E5E5; --border-strong:#D4D4D4;
  --fg:#0A0A0A; --muted:#525252; --faint:#A3A3A3;
  --accent:#171717; --accent-strong:#262626; --accent-fg:#FFFFFF; --accent-soft:#F5F5F5;
  --ok:#15803D; --ok-bg:#F0FDF4; --err:#DC2626; --err-bg:#FEF2F2;
  --warn:#D97706; --warn-bg:#FFFBEB; --info:#4F46E5; --info-bg:#EEF2FF;
  --shadow:0 1px 2px rgba(0,0,0,.04); --shadow-md:0 8px 24px -6px rgba(0,0,0,.10), 0 2px 6px -3px rgba(0,0,0,.05);
  --radius:12px; --radius-sm:8px; --radius-xs:6px;
  --ease:cubic-bezier(.32,.72,0,1);
  --mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,monospace;
  --sans:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --display:'Geist','Inter',system-ui,sans-serif;
}
/* Dark tokens: applied automatically when the OS prefers dark AND the user
   hasn't picked a theme, or explicitly via the header toggle (data-theme). */
@media (prefers-color-scheme:dark) {
  :root:not([data-theme]) {
    --bg:#0C0A09; --surface:#1C1917; --surface-2:#292524; --hover:#292524;
    --border:#2A2724; --border-strong:#3A3633;
    --fg:#FAFAF9; --muted:#A8A29E; --faint:#78716C;
    --accent:#FAFAF9; --accent-strong:#E7E5E4; --accent-fg:#0C0A09; --accent-soft:#292524;
    --ok:#4ADE80; --ok-bg:#14241A; --err:#F87171; --err-bg:#2A1717; --warn:#FBBF24; --warn-bg:#2A2012; --info:#A5B4FC; --info-bg:#1E1B33;
    --shadow:0 1px 2px rgba(0,0,0,.4); --shadow-md:0 8px 24px -6px rgba(0,0,0,.5);
  }
}
[data-theme="dark"] {
  --bg:#0C0A09; --surface:#1C1917; --surface-2:#292524; --hover:#292524;
  --border:#2A2724; --border-strong:#3A3633;
  --fg:#FAFAF9; --muted:#A8A29E; --faint:#78716C;
  --accent:#FAFAF9; --accent-strong:#E7E5E4; --accent-fg:#0C0A09; --accent-soft:#292524;
  --ok:#4ADE80; --ok-bg:#14241A; --err:#F87171; --err-bg:#2A1717; --warn:#FBBF24; --warn-bg:#2A2012; --info:#A5B4FC; --info-bg:#1E1B33;
  --shadow:0 1px 2px rgba(0,0,0,.4); --shadow-md:0 8px 24px -6px rgba(0,0,0,.5);
}
html { transition:background-color .2s var(--ease), color .2s var(--ease); }
* { box-sizing:border-box; }
html { -webkit-text-size-adjust:100%; }
body { margin:0; font:14px/1.6 var(--sans); color:var(--fg); background:var(--bg); -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; font-feature-settings:'cv11','ss01'; }
::selection { background:var(--accent); color:var(--accent-fg); }
header { position:sticky; top:0; z-index:20; background:color-mix(in srgb, var(--surface) 80%, transparent); backdrop-filter:saturate(1.6) blur(12px); -webkit-backdrop-filter:saturate(1.6) blur(12px); border-bottom:1px solid var(--border); padding:0 28px; }
.bar { max-width:1200px; margin:0 auto; display:flex; align-items:center; gap:28px; min-height:58px; flex-wrap:wrap; }
.brand { display:inline-flex; align-items:center; gap:9px; font-family:var(--display); font-weight:400; font-size:17px; letter-spacing:-.02em; color:var(--fg); text-decoration:none; }
.brand .dot { width:7px; height:7px; border-radius:50%; background:var(--accent); }
header nav { display:flex; flex:1; align-items:center; gap:10px; }
.nav-main { display:flex; flex-wrap:wrap; align-items:center; gap:1px; }
.nav-right { margin-left:auto; display:flex; align-items:center; gap:6px; }
header nav a { color:var(--muted); text-decoration:none; font-size:13px; font-weight:450; padding:6px 11px; border-radius:8px; transition:color .15s var(--ease),background .15s; }
header nav a:hover { color:var(--fg); background:var(--hover); text-decoration:none; }
.navdrop { position:relative; }
.navdrop summary { list-style:none; cursor:pointer; color:var(--muted); font-size:13px; font-weight:450; padding:6px 11px; border-radius:8px; user-select:none; white-space:nowrap; }
.navdrop summary::-webkit-details-marker { display:none; }
.navdrop summary::after { content:"\2304"; margin-left:5px; font-size:12px; opacity:.7; }
.navdrop summary:hover, .navdrop[open] summary { color:var(--fg); background:var(--hover); }
.navdrop-menu { position:absolute; right:0; top:calc(100% + 8px); background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); box-shadow:var(--shadow-md); padding:6px; min-width:208px; display:flex; flex-direction:column; z-index:40; }
.navdrop-menu a { color:var(--muted); font-size:13px; padding:7px 10px; border-radius:6px; text-decoration:none; transition:color .12s,background .12s; }
.navdrop-menu a:hover { color:var(--fg); background:var(--hover); text-decoration:none; }
.navdrop-sec { font-size:10px; text-transform:uppercase; letter-spacing:.07em; color:var(--faint); padding:10px 10px 3px; font-weight:600; }
.navdrop-sec:first-child { padding-top:2px; }
.nav-icon { background:none; border:1px solid transparent; color:var(--muted); padding:5px 6px; border-radius:8px; cursor:pointer; display:inline-flex; align-items:center; transition:color .15s,background .15s; box-shadow:none; }
.nav-icon:hover { color:var(--fg); background:var(--hover); border-color:transparent; box-shadow:none; transform:none; }
.nav-logout { display:inline-flex; margin:0; padding:0; background:none; border:none; box-shadow:none; }
.nav-logout button { background:none; border:1px solid var(--border); color:var(--muted); font-size:13px; font-weight:450; padding:6px 13px; border-radius:8px; box-shadow:none; }
.nav-logout button:hover { color:var(--fg); border-color:var(--border-strong); background:var(--hover); box-shadow:none; }
main { max-width:1200px; margin:0 auto; padding:34px 28px 72px; }
h1 { font-family:var(--display); font-size:27px; font-weight:300; letter-spacing:-.03em; margin:0 0 22px; }
h2 { font-size:11px; font-weight:600; margin:32px 0 13px; color:var(--faint); text-transform:uppercase; letter-spacing:.08em; }
p { margin:0 0 12px; }
table { width:100%; border-collapse:separate; border-spacing:0; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; box-shadow:var(--shadow); margin:0 0 8px; }
th, td { padding:11px 16px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
th { background:var(--surface-2); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--faint); }
tbody tr { transition:background .12s; }
tbody tr:hover { background:var(--surface-2); }
tr:last-child td { border-bottom:none; }
a { color:var(--accent); text-decoration:none; font-weight:500; }
a:hover { text-decoration:underline; text-underline-offset:2px; }
.empty { color:var(--muted); padding:32px; text-align:center; background:var(--surface); border:1px dashed var(--border-strong); border-radius:var(--radius); }
.tag { display:inline-flex; align-items:center; gap:5px; padding:3px 9px 3px 8px; border-radius:999px; font-size:11.5px; font-weight:600; line-height:1.45; letter-spacing:.01em; }
.tag::before { content:""; width:6px; height:6px; border-radius:50%; background:currentColor; }
.tag-succeeded, .tag-on { background:var(--ok-bg); color:var(--ok); }
.tag-failed, .tag-failed_dlq { background:var(--err-bg); color:var(--err); }
.tag-running { background:var(--warn-bg); color:var(--warn); }
.tag-suspended { background:var(--info-bg); color:var(--info); }
.tag-cancelled, .tag-off { background:color-mix(in srgb, var(--fg) 7%, transparent); color:var(--muted); }
.tag-queued { background:var(--accent-soft); color:var(--accent); }
.tag-warn { background:var(--warn-bg); color:var(--warn); }
.err { color:var(--err); }
.warn { color:var(--warn); }
.muted { color:var(--muted); }
.faint { color:var(--faint); }
code { font:12.5px var(--mono); background:color-mix(in srgb, var(--fg) 7%, transparent); color:var(--fg); padding:1.5px 6px; border-radius:5px; }
pre { background:var(--surface-2); color:var(--fg); border:1px solid var(--border); padding:14px 16px; overflow:auto; font:12px/1.55 var(--mono); border-radius:var(--radius-sm); }
button, .btn-primary, .btn-secondary { font:13.5px/1.4 var(--sans); font-weight:550; padding:8px 15px; border:1px solid var(--border-strong); background:var(--surface); color:var(--fg); border-radius:var(--radius-sm); cursor:pointer; text-decoration:none; display:inline-block; transition:transform .08s,box-shadow .15s,background .15s,border-color .15s,color .15s; }
button:hover, .btn-secondary:hover { border-color:var(--faint); box-shadow:var(--shadow); text-decoration:none; }
button:active, .btn-primary:active, .btn-secondary:active { transform:translateY(1px); }
button.btn-primary, .btn-primary { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); box-shadow:var(--shadow); }
button.btn-primary:hover, .btn-primary:hover { background:var(--accent-strong); border-color:var(--accent-strong); }
.btn-secondary { background:var(--surface); }
.btn-link { background:none; border:none; color:var(--accent); cursor:pointer; padding:0 3px; font:13px/1.4 var(--sans); font-weight:550; }
.btn-link:hover { text-decoration:underline; text-underline-offset:2px; }
:focus-visible { outline:2px solid var(--accent-strong); outline-offset:2px; border-radius:4px; }
form.form { background:var(--surface); border:1px solid var(--border); padding:22px 24px; max-width:560px; margin:10px 0 26px; border-radius:var(--radius); box-shadow:var(--shadow); }
form.form label { display:block; margin:0 0 14px; font-size:13px; font-weight:500; color:var(--muted); }
form.form label.inline, form.form label.form-inline { display:inline-flex; gap:8px; align-items:center; }
form.form input[type="text"], form.form input[type="password"], form.form input[type="number"], form.form select, form.form textarea { display:block; width:100%; padding:8px 11px; margin-top:5px; border:1px solid var(--border-strong); border-radius:var(--radius-xs); font:14px var(--sans); background:var(--surface); color:var(--fg); transition:border-color .15s,box-shadow .15s; }
form.form input:focus, form.form select:focus, form.form textarea:focus { outline:none; border-color:var(--accent-strong); box-shadow:0 0 0 3px var(--accent-soft); }
form.form textarea { font:12.5px/1.5 var(--mono); resize:vertical; }
form.form input[type="checkbox"] { width:auto; display:inline-block; margin:0 7px 0 0; accent-color:var(--accent-strong); }
form.form button { margin-right:8px; margin-top:4px; }
form.form-inline { display:inline-flex; gap:8px; align-items:center; margin:4px 8px 4px 0; }
form.form-inline input[type="text"], form.form-inline input[type="number"] { padding:6px 10px; border:1px solid var(--border-strong); border-radius:var(--radius-xs); font:inherit; background:var(--surface); min-width:240px; }
ul.grant-list { list-style:none; padding:0; margin:8px 0; }
ul.grant-list li { padding:8px 0; border-bottom:1px solid var(--border); display:flex; gap:12px; align-items:center; }
.callout { background:var(--warn-bg); border:1px solid color-mix(in srgb, var(--warn) 35%, transparent); color:var(--warn); padding:13px 16px; margin:14px 0; border-radius:var(--radius-sm); font-size:13.5px; }
.callout pre { background:var(--surface); }
/* Adapt legacy inline-styled banners (background:#fff / #fff8e1) to the theme. */
.err[style] { background:var(--surface) !important; border-radius:var(--radius-sm) !important; padding:13px 16px !important; }
#dag-canvas { background:var(--surface) !important; }
.callout[style] { background:var(--warn-bg) !important; border-color:color-mix(in srgb, var(--warn) 35%, transparent) !important; color:var(--warn) !important; border-radius:var(--radius-sm) !important; }
h3 { font-family:var(--display); font-size:15px; font-weight:400; letter-spacing:-.02em; margin:20px 0 8px; }
.flow { margin:8px 0 24px; }
.flow-row { display:flex; gap:16px; justify-content:center; flex-wrap:wrap; }
.flow-node { background:var(--surface); border:1px solid var(--border); border-left:3px solid var(--faint); border-radius:var(--radius-sm); min-width:244px; max-width:360px; box-shadow:var(--shadow); }
.flow-node-body { padding:12px 14px; }
.flow-node-head { display:flex; justify-content:space-between; align-items:baseline; gap:10px; }
.flow-name { font:12.5px var(--mono); font-weight:650; word-break:break-all; }
.flow-status { font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--faint); white-space:nowrap; font-weight:600; }
.flow-dur { font:11.5px var(--mono); color:var(--muted); margin-right:8px; }
.flow-meta { color:var(--muted); font-size:12px; margin-top:4px; }
.flow-note { color:var(--muted); font-size:12px; max-width:920px; }
.flow-data { margin-top:9px; }
.flow-data summary { cursor:pointer; font-size:12px; color:var(--accent); font-weight:500; }
.flow-data pre { margin:7px 0 0; max-height:260px; font-size:12px; }
.flow-err { color:var(--err); }
.flow-edges { display:flex; flex-wrap:wrap; justify-content:center; gap:5px 8px; margin:9px 0; }
.flow-edge { display:inline-flex; align-items:center; gap:4px; padding:3px 8px; border:1px solid var(--border-strong); border-radius:var(--radius-xs); color:var(--muted); background:var(--surface); font-size:11px; }
.flow-edge code { font-size:inherit; color:var(--fg); }
.flow-succeeded { border-left-color:var(--ok); }
.flow-failed, .flow-failed_dlq { border-left-color:var(--err); }
.flow-running { border-left-color:var(--warn); animation:flowpulse 1.6s ease-in-out infinite; }
.flow-suspended { border-left-color:var(--info); }
.flow-cancelled { border-left-color:var(--muted); }
.flow-pending { border-left-color:var(--border-strong); opacity:.62; }
.flow-word { display:none; }
.tpl-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:16px; margin:8px 0 24px; }
.tpl-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px 20px; display:flex; flex-direction:column; box-shadow:var(--shadow); transition:box-shadow .15s,transform .1s,border-color .15s; }
.tpl-card:hover { box-shadow:var(--shadow-md); border-color:var(--border-strong); transform:translateY(-1px); }
.tpl-cat { font-size:10.5px; text-transform:uppercase; letter-spacing:.07em; color:var(--accent); font-weight:650; }
.tpl-name { font-size:15px; font-weight:600; margin:5px 0 7px; color:var(--fg); text-transform:none; letter-spacing:-.01em; }
.tpl-desc { font-size:13px; color:var(--muted); margin:0 0 14px; flex:1; line-height:1.5; }
.tpl-use { margin:0 0 8px; background:none; border:none; padding:0; }
.tpl-brief summary { font-size:12px; color:var(--accent); cursor:pointer; font-weight:500; }
.tpl-brief p { font-size:12px; margin:6px 0 0; }
.analytics-detail { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:14px 18px; margin:0 0 16px; box-shadow:var(--shadow); }
.analytics-detail > summary { color:var(--faint); text-transform:uppercase; letter-spacing:.06em; font-size:11px; cursor:pointer; font-weight:600; }
@keyframes flowpulse { 0%,100% { box-shadow:var(--shadow); } 50% { box-shadow:0 0 0 3px rgba(180,83,9,.16); } }
/* --- workflow editor: visual/code toggle + node drawer --- */
.wf-toolbar { display:flex; align-items:center; gap:10px; margin:6px 0 14px; }
.wf-tab { background:var(--surface); border:1px solid var(--border); color:var(--muted); font-size:13px; font-weight:500; padding:6px 16px; border-radius:999px; cursor:pointer; box-shadow:none; transition:color .12s,background .12s,border-color .12s; }
.wf-tab:hover { color:var(--fg); border-color:var(--border-strong); background:var(--hover); }
.wf-tab.is-active { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
.wf-toolbar-hint { color:var(--faint); font-size:12px; margin-left:auto; }
.wf-canvas { width:100%; height:420px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); }
.wf-blockflow-canvas { width:100%; height:420px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); }
.wf-drawer-blockflow { border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px; background:var(--surface-2); }
.wf-drawer-blockflow[hidden] { display:none; }
.wf-block-list, .wf-block-edges { margin:8px 0 0; padding-left:22px; font-size:12px; line-height:1.65; }
.wf-block-list li, .wf-block-edges li { overflow-wrap:anywhere; }
.wf-block-step { margin-top:10px; }
.wf-block-step > summary { cursor:pointer; font-size:12px; color:var(--accent); }
.wf-block-flow-summary { margin:8px 0; }
.wf-block-flow-summary .flow-note { margin:0 0 8px; }
.wf-blockflow-list { margin-top:8px; max-height:180px; overflow:auto; }
.wf-steptable { margin-top:12px; }
.wf-steptable > summary { cursor:pointer; font-size:12px; color:var(--accent); font-weight:500; }
.wf-codearea { width:100%; font:12.5px/1.55 var(--mono); background:var(--surface); color:var(--fg); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px 14px; resize:vertical; tab-size:2; }
.wf-codearea:focus { outline:none; border-color:var(--border-strong); box-shadow:0 0 0 3px color-mix(in srgb,var(--info) 18%,transparent); }
.wf-drawer-backdrop { position:fixed; inset:0; background:color-mix(in srgb,var(--fg) 32%,transparent); z-index:60; }
.wf-drawer { position:fixed; top:0; right:0; height:100vh; width:min(620px,94vw); background:var(--bg); border-left:1px solid var(--border); box-shadow:-14px 0 44px color-mix(in srgb,var(--fg) 16%,transparent); z-index:70; display:flex; flex-direction:column; transform:translateX(100%); transition:transform .22s cubic-bezier(.4,0,.2,1); }
.wf-drawer.is-open { transform:none; }
.wf-drawer-head { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; padding:18px 22px 14px; border-bottom:1px solid var(--border); }
.wf-drawer-kicker { display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.07em; color:var(--faint); font-weight:650; }
.wf-drawer-head h3 { font:15px var(--mono); font-weight:600; margin:3px 0 0; word-break:break-all; letter-spacing:0; }
.wf-drawer-x { background:none; border:none; color:var(--muted); font-size:22px; line-height:1; cursor:pointer; padding:0 4px; box-shadow:none; }
.wf-drawer-x:hover { color:var(--fg); }
.wf-drawer-body { flex:1; overflow:auto; padding:16px 22px; display:flex; flex-direction:column; gap:12px; }
.wf-drawer-body .wf-codearea { flex:1; min-height:280px; }
.wf-drawer-status { font:12px/1.5 var(--mono); white-space:pre-wrap; word-break:break-word; max-height:220px; overflow:auto; }
.wf-drawer-status.is-err { color:var(--err); }
.wf-drawer-status.is-ok { color:var(--ok); }
.wf-drawer-status.is-busy { color:var(--muted); }
.wf-drawer-foot { display:flex; align-items:center; gap:14px; padding:14px 22px; border-top:1px solid var(--border); }
/* node dataflow panel (n8n-style "available data" + connections) */
.wf-dataflow { display:flex; flex-direction:column; gap:14px; }
.wf-df-sec { display:flex; flex-direction:column; gap:8px; }
.wf-df-hdr { font-size:10.5px; text-transform:uppercase; letter-spacing:.07em; color:var(--faint); font-weight:650; }
.wf-df-hdr .muted { text-transform:none; letter-spacing:0; font-weight:400; font-size:11.5px; margin-left:6px; }
.wf-df-empty, .wf-df-nodata { font-size:12.5px; margin:0; }
.wf-df-node { border:1px solid var(--border); border-radius:var(--radius-sm); padding:9px 11px; background:var(--surface-2); display:flex; flex-direction:column; gap:7px; }
.wf-df-noderow { display:flex; align-items:center; gap:8px; }
.wf-df-chip { display:inline-flex; align-items:center; gap:7px; font:12px var(--mono); font-weight:500; color:var(--fg); background:var(--surface); border:1px solid var(--border); border-radius:999px; padding:4px 11px; cursor:pointer; box-shadow:none; transition:border-color .12s,background .12s,transform .08s; }
.wf-df-chip:hover { border-color:var(--border-strong); background:var(--hover); }
.wf-df-chip:active { transform:translateY(1px); }
.wf-df-chip.is-static { cursor:default; }
.wf-df-chip.is-static:hover { border-color:var(--border); background:var(--surface); }
.wf-df-chips { display:flex; flex-wrap:wrap; gap:7px; }
.wf-df-dot { width:8px; height:8px; border-radius:2px; background:var(--muted); flex:none; }
.wf-k-step { background:#15803D; } .wf-k-side_effect { background:#4F46E5; }
.wf-k-await_signal { background:#D97706; } .wf-k-sleep { background:#A3A3A3; }
.wf-df-status { font-size:10px; text-transform:uppercase; letter-spacing:.04em; font-weight:650; padding:2px 7px; border-radius:999px; }
.wf-df-status.is-succeeded { color:var(--ok); background:var(--ok-bg,color-mix(in srgb,var(--ok) 12%,transparent)); }
.wf-df-status.is-failed, .wf-df-status.is-failed_dlq { color:var(--err); background:color-mix(in srgb,var(--err) 12%,transparent); }
.wf-df-status.is-running { color:var(--warn); background:color-mix(in srgb,var(--warn) 12%,transparent); }
.wf-df-data summary { cursor:pointer; font-size:11.5px; color:var(--accent); font-weight:500; }
.wf-df-data pre { margin:7px 0 0; max-height:200px; font-size:11.5px; }
.wf-drawer-sechdr { font-size:10.5px; text-transform:uppercase; letter-spacing:.07em; color:var(--faint); font-weight:650; margin-bottom:7px; }
.wf-drawer-sechdr .muted { text-transform:none; letter-spacing:0; font-weight:400; font-size:11.5px; margin-left:6px; }
.wf-drawer-codewrap { display:flex; flex-direction:column; }
.wf-drawer-codewrap .wf-codearea { min-height:240px; }
/* trigger picker (segmented, one form shown at a time, pure CSS) */
.trig-add { margin-top:8px; }
.trig-seg { display:inline-flex; gap:6px; margin:4px 0 14px; }
.trig-seg input { position:absolute; opacity:0; pointer-events:none; }
.trig-seg label { font-size:13px; font-weight:500; color:var(--muted); background:var(--surface); border:1px solid var(--border); border-radius:999px; padding:6px 16px; cursor:pointer; transition:color .12s,background .12s,border-color .12s; }
.trig-seg label:hover { color:var(--fg); border-color:var(--border-strong); background:var(--hover); }
.trig-panel { display:none; }
#trig-webhook:checked ~ .trig-seg label[for="trig-webhook"],
#trig-cron:checked ~ .trig-seg label[for="trig-cron"],
#trig-chain:checked ~ .trig-seg label[for="trig-chain"] { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
#trig-webhook:checked ~ .trig-panels #panel-webhook,
#trig-cron:checked ~ .trig-panels #panel-cron,
#trig-chain:checked ~ .trig-panels #panel-chain { display:block; }
/* cron builder (non-dev schedule) */
.cron-build { display:flex; flex-direction:column; gap:12px; background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:14px 16px; margin-bottom:12px; }
.cron-row { display:flex; flex-wrap:wrap; align-items:center; gap:10px; }
.cron-row > label { display:inline-flex; flex-direction:column; gap:4px; font-size:12px; color:var(--muted); font-weight:500; }
.cron-row select, .cron-row input { font:13px var(--body); }
.cron-field { display:none; }
.cron-field.is-on { display:inline-flex; }
.cron-dows { display:flex; flex-wrap:wrap; gap:6px; }
.cron-dow { display:inline-flex; align-items:center; gap:5px; font-size:12px; color:var(--muted); border:1px solid var(--border); border-radius:999px; padding:4px 10px; cursor:pointer; }
.cron-dow input { margin:0; }
.cron-dow:has(input:checked) { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
.cron-summary { font-size:13px; color:var(--fg); }
.cron-summary code { font-size:12px; }
.cron-summary .muted { display:block; margin-top:3px; }
.cron-advanced summary { font-size:12px; color:var(--accent); cursor:pointer; font-weight:500; }
.cron-advanced { margin-top:4px; }
/* OAuth provider presets (one-click fill) */
.oauth-presets { display:flex; flex-wrap:wrap; gap:8px; margin:4px 0 8px; }
.oauth-preset { font-size:13px; font-weight:500; color:var(--muted); background:var(--surface); border:1px solid var(--border); border-radius:999px; padding:7px 18px; cursor:pointer; box-shadow:none; transition:color .12s,background .12s,border-color .12s,transform .08s; }
.oauth-preset:hover { color:var(--fg); border-color:var(--border-strong); background:var(--hover); }
.oauth-preset:active { transform:translateY(1px); }
.oauth-preset.is-active { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
.oauth-preset-note { min-height:1.2em; font-size:12.5px; margin:0 0 10px; }
/* Service catalog quick-add (credential form) */
.svc-presets { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin:4px 0 8px; }
.svc-cat { width:100%; font-size:10.5px; text-transform:uppercase; letter-spacing:.07em; color:var(--faint); font-weight:650; margin-top:8px; }
.svc-cat:first-child { margin-top:0; }
.svc-preset { font-size:12.5px; font-weight:500; color:var(--muted); background:var(--surface); border:1px solid var(--border); border-radius:999px; padding:6px 14px; cursor:pointer; box-shadow:none; transition:color .12s,background .12s,border-color .12s,transform .08s; }
.svc-preset:hover { color:var(--fg); border-color:var(--border-strong); background:var(--hover); }
.svc-preset:active { transform:translateY(1px); }
.svc-preset.is-active { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
/* live run streaming indicator */
.live-dot { display:inline-block; width:9px; height:9px; border-radius:50%; background:var(--ok); margin-left:8px; vertical-align:middle; animation:livepulse 1.4s ease-in-out infinite; }
@keyframes livepulse { 0%,100% { opacity:1; box-shadow:0 0 0 0 color-mix(in srgb,var(--ok) 55%,transparent); } 50% { opacity:.55; box-shadow:0 0 0 5px color-mix(in srgb,var(--ok) 0%,transparent); } }
pre.runlog { max-height:420px; overflow:auto; }
/* integrations grid (Make-style connect) */
.intg-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; margin:8px 0 22px; }
.intg-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); padding:14px 15px; display:flex; flex-direction:column; gap:11px; box-shadow:var(--shadow); }
.intg-head { display:flex; align-items:baseline; justify-content:space-between; gap:8px; }
.intg-name { font-size:14px; font-weight:600; color:var(--fg); }
.intg-method { font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--faint); font-weight:600; white-space:nowrap; }
.intg-action { margin-top:auto; }
.intg-action .btn-primary, .intg-action .btn-secondary { padding:5px 14px; font-size:13px; }
.intg-connect { margin:0; }
a.btn-secondary { display:inline-block; background:var(--surface); border:1px solid var(--border-strong); color:var(--fg); border-radius:8px; padding:5px 14px; font-size:13px; font-weight:500; text-decoration:none; transition:background .12s,border-color .12s; }
a.btn-secondary:hover { background:var(--hover); border-color:var(--fg); text-decoration:none; }
</style>
<script src="/assets/theme.js"></script>
<script src="/assets/ui.js"></script>
</head>
<body>
<header>
<div class="bar">
<a href="/" class="brand"><span class="dot"></span>Reactor</a>
<nav>{{.Nav}}</nav>
</div>
</header>
<main>
<h1>{{.Heading}}</h1>
{{.Body}}
</main>
</body>
</html>`

func render(w http.ResponseWriter, tmplStr string, data any) {
	// Pages rendered outside renderPage (the error + form-error helpers, which
	// have no request to scope by) get the full operator nav by default.
	if p, ok := data.(page); ok && p.Nav == "" {
		p.Nav = fullNav
		data = p
	}
	t, err := template.New("p").Parse(tmplStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.Execute(w, data)
}
