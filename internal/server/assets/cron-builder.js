// cron-builder.js: the non-dev schedule builder. Served from /assets (CSP).
// For each [data-cron-build] block it reads the friendly controls (every N
// minutes, daily at HH:MM, weekly on days, monthly on a date, yearly), computes
// a standard 5-field cron expression, writes it into the named spec input, and
// shows a plain-language summary. Power users can still type raw cron under
// "Advanced" -- typing there wins until they touch a builder control again.
(function () {
  var DOW = { 0: "Sun", 1: "Mon", 2: "Tue", 3: "Wed", 4: "Thu", 5: "Fri", 6: "Sat" };
  var MONTH = ["", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"];

  function build(root) {
    function q(sel) { return root.querySelector(sel); }
    var freq = q('[data-cron="freq"]');
    var interval = q('[data-cron="interval"]');
    var unit = q('[data-cron="unit"]');
    var timeEl = q('[data-cron="time"]');
    var domEl = q('[data-cron="dom"]');
    var monthEl = q('[data-cron="month"]');
    var dows = root.querySelectorAll('[data-dow]');
    var summary = q('[data-cron="summary"]');
    var spec = q('[data-cron="spec"]');
    if (!freq || !spec) return;

    function showFields() {
      var f = freq.value;
      root.querySelectorAll(".cron-field").forEach(function (el) {
        var when = (el.getAttribute("data-when") || "").split(",");
        el.classList.toggle("is-on", when.indexOf(f) !== -1);
      });
      if (unit) unit.textContent = f === "hourly" ? "hours" : "minutes";
      if (interval) interval.setAttribute("max", f === "hourly" ? "23" : "59");
    }

    function hhmm() {
      var v = (timeEl && timeEl.value) || "09:00";
      var p = v.split(":");
      return { h: parseInt(p[0], 10) || 0, m: parseInt(p[1], 10) || 0 };
    }
    function selectedDows() {
      var out = [];
      dows.forEach(function (c) { if (c.checked) out.push(parseInt(c.getAttribute("data-dow"), 10)); });
      out.sort(function (a, b) { return a - b; });
      return out;
    }

    function compute() {
      var f = freq.value, t = hhmm();
      var n = Math.max(1, parseInt(interval && interval.value, 10) || 1);
      var dom = Math.min(31, Math.max(1, parseInt(domEl && domEl.value, 10) || 1));
      var mon = parseInt(monthEl && monthEl.value, 10) || 1;
      var ds = selectedDows();
      var cron = "", text = "";
      if (f === "minutes") {
        cron = "*/" + n + " * * * *";
        text = "Every " + (n === 1 ? "minute" : n + " minutes");
      } else if (f === "hourly") {
        cron = "0 */" + n + " * * *";
        text = "Every " + (n === 1 ? "hour" : n + " hours") + " (on the hour)";
      } else if (f === "daily") {
        cron = t.m + " " + t.h + " * * *";
        text = "Every day at " + fmtTime(t);
      } else if (f === "weekly") {
        var dl = ds.length ? ds.join(",") : "*";
        cron = t.m + " " + t.h + " * * " + dl;
        text = "Every week on " + (ds.length ? ds.map(function (d) { return DOW[d]; }).join(", ") : "every day") + " at " + fmtTime(t);
      } else if (f === "monthly") {
        cron = t.m + " " + t.h + " " + dom + " * *";
        text = "Every month on day " + dom + " at " + fmtTime(t);
      } else if (f === "yearly") {
        cron = t.m + " " + t.h + " " + dom + " " + mon + " *";
        text = "Every year on " + MONTH[mon] + " " + dom + " at " + fmtTime(t);
      }
      spec.value = cron;
      renderSummary(text, cron, false);
    }

    // Keep operator-entered cron text out of an HTML parser.  The advanced
    // field is intentionally free-form, so even an internal operator can
    // paste markup-like text here.
    function renderSummary(label, cron, custom) {
      if (!summary) return;
      summary.textContent = "";
      summary.appendChild(document.createTextNode(label + (custom ? "" : " ")));
      if (!custom) {
        var muted = document.createElement("span");
        muted.className = "muted";
        muted.appendChild(document.createTextNode("cron: "));
        var code = document.createElement("code");
        code.textContent = cron;
        muted.appendChild(code);
        summary.appendChild(muted);
        return;
      }
      var customCode = document.createElement("code");
      customCode.textContent = cron;
      summary.appendChild(customCode);
    }

    function fmtTime(t) {
      return (t.h < 10 ? "0" : "") + t.h + ":" + (t.m < 10 ? "0" : "") + t.m;
    }

    showFields();
    compute();
    freq.addEventListener("change", function () { showFields(); compute(); });
    [interval, timeEl, domEl, monthEl].forEach(function (el) {
      if (el) el.addEventListener("input", compute);
    });
    dows.forEach(function (c) { c.addEventListener("change", compute); });
    // If the operator types raw cron under Advanced, respect it: stop letting
    // the summary overwrite, but keep showing what they typed.
    spec.addEventListener("input", function (e) {
      if (e.isTrusted) renderSummary("Custom cron: ", spec.value || "", true);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-cron-build]").forEach(build);
  });
})();
