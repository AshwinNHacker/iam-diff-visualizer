"""
report.py
=========
Renders a DiffResult as a single, self-contained, offline-viewable HTML
report -- no external JS/CSS CDNs, no network calls, no dependencies
beyond the Python standard library. This matters for a security tool:
you should be able to open the report on an air-gapped machine.
"""
from __future__ import annotations

import datetime as _dt
import html
from typing import List, Optional

from .differ import ActionDiffEntry, DiffResult
from .risk_rules import RiskFinding

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _esc(s: object) -> str:
    return html.escape(str(s), quote=True)


def _badge(text: str, css_class: str) -> str:
    return f'<span class="badge {css_class}">{_esc(text)}</span>'


def _resource_list_html(resources: List[str]) -> str:
    if not resources:
        return '<span class="muted">—</span>'
    items = "".join(f"<li><code>{_esc(r)}</code></li>" for r in resources)
    return f'<ul class="resource-list">{items}</ul>'


def _condition_icon(conditioned: bool) -> str:
    return '<span title="This grant has a Condition; effect depends on runtime context" class="cond-flag">⚠ conditioned</span>' if conditioned else ""


def _entry_row(e: ActionDiffEntry) -> str:
    service = e.action.split(":", 1)[0]
    row_class = {
        "added": "row-added",
        "removed": "row-removed",
        "effect_changed": "row-effect",
        "scope_changed": "row-scope",
        "condition_changed": "row-condition",
    }.get(e.change_type, "")

    change_badges = {
        "added": _badge("ADDED", "badge-added"),
        "removed": _badge("REMOVED", "badge-removed"),
        "effect_changed": _badge("EFFECT CHANGED", "badge-effect"),
        "scope_changed": _badge("SCOPE CHANGED", "badge-scope"),
        "condition_changed": _badge("CONDITION CHANGED", "badge-condition"),
    }
    badge = change_badges.get(e.change_type, "")

    widened = ' <span class="widened-flag" title="Resource scope was broadened">⬈ widened</span>' if e.resource_widened else ""
    unresolved = ' <span class="unresolved-flag" title="Could not be fully expanded against the action catalogue">? unresolved</span>' if e.unresolved else ""

    old_col = f'{_badge(e.old_effect, "eff-" + (e.old_effect or "").lower())}{_condition_icon(e.old_conditioned)}<br>{_resource_list_html(e.old_resources)}' if e.old_effect else '<span class="muted">not granted</span>'
    new_col = f'{_badge(e.new_effect, "eff-" + (e.new_effect or "").lower())}{_condition_icon(e.new_conditioned)}<br>{_resource_list_html(e.new_resources)}' if e.new_effect else '<span class="muted">not granted</span>'

    return f"""
    <tr class="diff-row {row_class}" data-service="{_esc(service)}" data-action="{_esc(e.action)}">
      <td class="col-change">{badge}{widened}{unresolved}</td>
      <td class="col-action"><code>{_esc(e.action)}</code></td>
      <td class="col-old">{old_col}</td>
      <td class="col-new">{new_col}</td>
    </tr>"""


def _risk_card(r: RiskFinding, tone: str) -> str:
    actions_html = " ".join(f"<code>{_esc(a)}</code>" for a in r.actions)
    return f"""
    <div class="risk-card risk-{tone} sev-{r.severity.lower()}">
      <div class="risk-head">
        <span class="badge sev-badge sev-{r.severity.lower()}">{_esc(r.severity)}</span>
        <span class="risk-title">{_esc(r.title)}</span>
      </div>
      <p class="risk-detail">{_esc(r.detail)}</p>
      <p class="risk-actions">{actions_html}</p>
    </div>"""


def _service_bar_chart(old_summary: dict, new_summary: dict) -> str:
    services = sorted(set(old_summary) | set(new_summary), key=lambda s: -max(old_summary.get(s, 0), new_summary.get(s, 0)))[:15]
    if not services:
        return "<p class='muted'>No allowed actions to summarize.</p>"
    max_val = max([old_summary.get(s, 0) for s in services] + [new_summary.get(s, 0) for s in services] + [1])
    rows = []
    for s in services:
        old_v, new_v = old_summary.get(s, 0), new_summary.get(s, 0)
        old_w = round(old_v / max_val * 100, 1)
        new_w = round(new_v / max_val * 100, 1)
        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label"><code>{_esc(s)}</code></div>
          <div class="bar-track">
            <div class="bar old-bar" style="width:{old_w}%"><span>{old_v}</span></div>
            <div class="bar new-bar" style="width:{new_w}%"><span>{new_v}</span></div>
          </div>
        </div>""")
    return "\n".join(rows)


def render_html(
    result: DiffResult,
    old_label: str = "Old policy",
    new_label: str = "New policy",
    old_raw: Optional[str] = None,
    new_raw: Optional[str] = None,
) -> str:
    generated_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sections = []
    for group_title, group_id, entries in [
        ("Added permissions", "added", result.added),
        ("Removed permissions", "removed", result.removed),
        ("Modified permissions", "modified", result.modified),
    ]:
        if not entries:
            rows_html = f'<tr><td colspan="4" class="empty-row">No {group_title.lower()}.</td></tr>'
        else:
            rows_html = "\n".join(_entry_row(e) for e in entries)
        sections.append(f"""
        <section id="{group_id}">
          <h2>{_esc(group_title)} <span class="count-pill">{len(entries)}</span></h2>
          <table class="diff-table">
            <thead><tr><th>Change</th><th>Action</th><th>{_esc(old_label)}</th><th>{_esc(new_label)}</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </section>""")

    sorted_introduced = sorted(result.introduced_risks, key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))
    sorted_resolved = sorted(result.resolved_risks, key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))
    sorted_current = sorted(result.new_risks, key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))

    introduced_html = "".join(_risk_card(r, "introduced") for r in sorted_introduced) or "<p class='muted'>None. No new risk findings were introduced by this change.</p>"
    resolved_html = "".join(_risk_card(r, "resolved") for r in sorted_resolved) or "<p class='muted'>None.</p>"
    current_html = "".join(_risk_card(r, "current") for r in sorted_current) or "<p class='muted'>No risk findings against the new policy.</p>"

    unresolved_html = ""
    if result.unresolved_actions:
        items = "".join(f"<li><code>{_esc(a)}</code></li>" for a in result.unresolved_actions)
        unresolved_html = f"""
        <section id="unresolved">
          <h2>Unresolved action patterns <span class="count-pill warn">{len(result.unresolved_actions)}</span></h2>
          <p class="muted">These action patterns reference a service or action not present in the bundled catalogue
             (possibly a very new AWS service, or a typo). They were treated literally rather than expanded, and are
             excluded from wildcard-expansion-based comparisons. Verify them manually.</p>
          <ul class="resource-list">{items}</ul>
        </section>"""

    services_touched = sorted({e.action.split(":", 1)[0] for e in (result.added + result.removed + result.modified)})
    service_filter_options = "".join(f'<option value="{_esc(s)}">{_esc(s)}</option>' for s in services_touched)

    verdict = "NO EFFECTIVE CHANGE" if not result.has_changes() else (
        "⚠ RISK INTRODUCED" if result.introduced_risks else (
            "✓ RISK REDUCED" if result.resolved_risks and not result.added else "CHANGED"
        )
    )
    verdict_class = {
        "NO EFFECTIVE CHANGE": "verdict-neutral",
        "⚠ RISK INTRODUCED": "verdict-danger",
        "✓ RISK REDUCED": "verdict-good",
        "CHANGED": "verdict-neutral",
    }[verdict]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IAM Policy Diff Report — {_esc(old_label)} → {_esc(new_label)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<header class="page-header">
  <div class="header-inner">
    <div>
      <h1>IAM Policy Diff Visualizer</h1>
      <p class="subtitle">Effective permission change, not just a JSON diff</p>
    </div>
    <div class="header-meta">
      <div><strong>{_esc(old_label)}</strong> → <strong>{_esc(new_label)}</strong></div>
      <div class="muted">Generated {_esc(generated_at)}</div>
    </div>
  </div>
</header>

<main>
  <section id="summary">
    <div class="verdict-banner {verdict_class}">{_esc(verdict)}</div>
    <div class="summary-grid">
      <div class="summary-card added"><span class="summary-num">{len(result.added)}</span><span>Added</span></div>
      <div class="summary-card removed"><span class="summary-num">{len(result.removed)}</span><span>Removed</span></div>
      <div class="summary-card modified"><span class="summary-num">{len(result.modified)}</span><span>Modified</span></div>
      <div class="summary-card unchanged"><span class="summary-num">{result.unchanged_count}</span><span>Unchanged</span></div>
      <div class="summary-card risk-new"><span class="summary-num">{len(result.introduced_risks)}</span><span>New risk findings</span></div>
      <div class="summary-card risk-resolved"><span class="summary-num">{len(result.resolved_risks)}</span><span>Resolved risk findings</span></div>
    </div>
  </section>

  <section id="service-summary">
    <h2>Allowed actions by service (top 15)</h2>
    <div class="legend"><span class="legend-swatch old-bar"></span> {_esc(old_label)} &nbsp; <span class="legend-swatch new-bar"></span> {_esc(new_label)}</div>
    <div class="bar-chart">
      {_service_bar_chart(result.old_service_summary, result.new_service_summary)}
    </div>
  </section>

  <section id="risks">
    <h2>Security risk analysis</h2>
    <div class="risk-columns">
      <div>
        <h3>🆕 Newly introduced ({len(result.introduced_risks)})</h3>
        {introduced_html}
      </div>
      <div>
        <h3>✅ Resolved by this change ({len(result.resolved_risks)})</h3>
        {resolved_html}
      </div>
    </div>
    <details class="all-risks-details">
      <summary>All risk findings against {_esc(new_label)} ({len(result.new_risks)})</summary>
      {current_html}
    </details>
  </section>

  <section id="filters">
    <input type="text" id="search-box" placeholder="Filter by action name…" onkeyup="filterRows()">
    <select id="service-select" onchange="filterRows()">
      <option value="">All services</option>
      {service_filter_options}
    </select>
  </section>

  {''.join(sections)}

  {unresolved_html}

  <footer>
    <p>Generated by <strong>iamdiff</strong> — IAM Policy Diff Visualizer. Static analysis only;
       conditions (⚠ conditioned) are not evaluated against a live request context. Review flagged
       items manually before approving a policy change.</p>
  </footer>
</main>

<script>
function filterRows() {{
  const q = document.getElementById('search-box').value.toLowerCase();
  const svc = document.getElementById('service-select').value;
  document.querySelectorAll('tr.diff-row').forEach(row => {{
    const action = row.getAttribute('data-action').toLowerCase();
    const service = row.getAttribute('data-service');
    const matchesText = action.includes(q);
    const matchesService = !svc || service === svc;
    row.style.display = (matchesText && matchesService) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


_CSS = """
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --panel-2: #1c2128;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --green: #3fb950;
  --red: #f85149;
  --amber: #d29922;
  --blue: #58a6ff;
  --purple: #bc8cff;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); margin: 0; line-height: 1.5; }
code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 0.85em; background: rgba(110,118,129,0.15); padding: 1px 5px; border-radius: 4px; }
.muted { color: var(--muted); }

.page-header { background: linear-gradient(135deg,#161b22,#0d1117); border-bottom: 1px solid var(--border); padding: 28px 32px; }
.header-inner { display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:12px; max-width:1200px; margin:0 auto; }
.page-header h1 { margin:0; font-size: 1.6rem; }
.subtitle { margin:4px 0 0; color: var(--muted); }
.header-meta { text-align:right; font-size:0.9rem; }

main { max-width:1200px; margin: 0 auto; padding: 24px 32px 60px; }
section { margin-bottom: 40px; }
h2 { border-bottom:1px solid var(--border); padding-bottom:8px; font-size:1.2rem; }
h3 { font-size:1rem; color: var(--muted); text-transform:uppercase; letter-spacing:0.04em;}

.verdict-banner { display:inline-block; font-weight:700; letter-spacing:0.03em; padding:8px 18px; border-radius:8px; margin-bottom:18px; font-size:1rem;}
.verdict-danger { background: rgba(248,81,73,0.15); color: var(--red); border:1px solid var(--red); }
.verdict-good { background: rgba(63,185,80,0.15); color: var(--green); border:1px solid var(--green); }
.verdict-neutral { background: rgba(139,148,158,0.15); color: var(--muted); border:1px solid var(--border); }

.summary-grid { display:grid; grid-template-columns: repeat(6, minmax(120px,1fr)); gap:12px; }
.summary-card { background: var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; text-align:center; display:flex; flex-direction:column; gap:4px; }
.summary-num { font-size:1.8rem; font-weight:700; }
.summary-card.added .summary-num { color: var(--green); }
.summary-card.removed .summary-num { color: var(--red); }
.summary-card.modified .summary-num { color: var(--amber); }
.summary-card.risk-new .summary-num { color: var(--red); }
.summary-card.risk-resolved .summary-num { color: var(--green); }

.legend { color: var(--muted); font-size:0.85rem; margin-bottom:10px;}
.legend-swatch { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:4px; vertical-align:middle;}
.bar-chart { background: var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }
.bar-row { display:grid; grid-template-columns: 140px 1fr; gap:10px; align-items:center; margin-bottom:8px; }
.bar-track { display:flex; flex-direction:column; gap:2px; }
.bar { height:12px; border-radius:3px; display:flex; align-items:center; padding-left:4px; min-width: 18px;}
.bar span { font-size:0.65rem; color:#0d1117; font-weight:700; }
.old-bar { background: var(--blue); }
.new-bar { background: var(--purple); }

.risk-columns { display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-top:12px;}
.risk-card { border-radius:10px; padding:14px 16px; margin-bottom:12px; border:1px solid var(--border); background: var(--panel); }
.risk-card.risk-introduced { border-left:4px solid var(--red); }
.risk-card.risk-resolved { border-left:4px solid var(--green); }
.risk-head { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
.risk-title { font-weight:600; }
.risk-detail { color: var(--muted); font-size:0.9rem; margin:4px 0; }
.risk-actions { margin:0; }
.all-risks-details { margin-top:18px; background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 16px; }
.all-risks-details summary { cursor:pointer; font-weight:600; }

#filters { display:flex; gap:10px; margin-bottom: 16px; }
#search-box, #service-select { background: var(--panel-2); border:1px solid var(--border); color:var(--text); padding:8px 12px; border-radius:8px; font-size:0.9rem; }
#search-box { flex:1; }

.diff-table { width:100%; border-collapse: collapse; background: var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden;}
.diff-table th, .diff-table td { padding:10px 14px; border-bottom:1px solid var(--border); vertical-align:top; text-align:left; font-size:0.88rem;}
.diff-table th { background: var(--panel-2); color: var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.04em; }
.diff-table tr:last-child td { border-bottom:none; }
.col-action { white-space:nowrap; }
.empty-row { text-align:center; color: var(--muted); padding:18px; }

.badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:0.72rem; font-weight:700; letter-spacing:0.03em; }
.badge-added { background: rgba(63,185,80,0.18); color: var(--green); }
.badge-removed { background: rgba(248,81,73,0.18); color: var(--red); }
.badge-effect { background: rgba(248,81,73,0.18); color: var(--red); }
.badge-scope { background: rgba(210,153,34,0.18); color: var(--amber); }
.badge-condition { background: rgba(88,166,255,0.18); color: var(--blue); }
.eff-allow { background: rgba(63,185,80,0.18); color: var(--green); }
.eff-deny { background: rgba(248,81,73,0.18); color: var(--red); }
.sev-badge.sev-high { background: rgba(248,81,73,0.2); color: var(--red);}
.sev-badge.sev-medium { background: rgba(210,153,34,0.2); color: var(--amber);}
.sev-badge.sev-low { background: rgba(139,148,158,0.2); color: var(--muted);}
.count-pill { display:inline-block; background: var(--panel-2); border:1px solid var(--border); border-radius:20px; padding:1px 10px; font-size:0.75rem; color: var(--muted); margin-left:8px; }
.count-pill.warn { color: var(--amber); border-color: var(--amber); }
.cond-flag { color: var(--blue); font-size:0.72rem; margin-left:6px;}
.widened-flag { color: var(--amber); font-size:0.72rem; }
.unresolved-flag { color: var(--muted); font-size:0.72rem; }

.resource-list { list-style:none; margin:4px 0 0; padding:0; }
.resource-list li { margin-bottom:2px; }

footer { color: var(--muted); font-size:0.8rem; border-top:1px solid var(--border); padding-top:16px; margin-top:40px; }

@media (max-width: 900px) {
  .summary-grid { grid-template-columns: repeat(2, 1fr); }
  .risk-columns { grid-template-columns: 1fr; }
}
"""
