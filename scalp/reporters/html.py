"""Modern responsive HTML5 reporter for Scalp."""
import html
import time
from scalp.core.engine import ScanResult
from scalp.core.rules import ATTACK_NAMES
from scalp.reporters.base import BaseReporter

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scalp Report — {source_name}</title>
<style>
  :root {{
    --bg: #0f172a;
    --card: #1e293b;
    --card-border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --danger: #ef4444;
    --warning: #f59e0b;
    --success: #10b981;
    --code-bg: #090d16;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{
    border-bottom: 1px solid var(--card-border);
    padding-bottom: 20px;
    margin-bottom: 24px;
  }}
  h1 {{ margin: 0 0 8px 0; font-size: 1.8rem; color: var(--accent); }}
  .meta {{ color: var(--text-muted); font-size: 0.9rem; }}
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 16px;
  }}
  .stat-val {{ font-size: 1.6rem; font-weight: bold; color: var(--text); }}
  .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .attack-group {{
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    margin-bottom: 24px;
    overflow: hidden;
  }}
  .attack-header {{
    background: rgba(56, 189, 248, 0.1);
    padding: 12px 20px;
    font-weight: 600;
    font-size: 1.1rem;
    border-bottom: 1px solid var(--card-border);
    display: flex;
    justify-content: space-between;
  }}
  .match-item {{
    padding: 16px 20px;
    border-bottom: 1px solid var(--card-border);
  }}
  .match-item:last-child {{ border-bottom: none; }}
  .match-top {{
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: bold;
  }}
  .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
  .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
  .badge-info {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}
  .log-line {{
    background: var(--code-bg);
    border: 1px solid var(--card-border);
    border-radius: 4px;
    padding: 8px 12px;
    font-family: monospace;
    font-size: 0.85rem;
    overflow-x: auto;
    color: #e2e8f0;
  }}
  .reason {{ color: var(--text-muted); font-size: 0.9rem; margin-bottom: 6px; }}
  footer {{ text-align: center; margin-top: 40px; color: var(--text-muted); font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Scalp! Attack Analysis Report</h1>
    <div class="meta">Target Log: <b>{source_name}</b> | Generated on: {curtime}</div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val">{total_matches}</div>
      <div class="stat-label">Attacks Detected</div>
    </div>
    <div class="stat-card">
      <div class="stat-val">{processed_lines}</div>
      <div class="stat-label">Lines Analyzed</div>
    </div>
    <div class="stat-card">
      <div class="stat-val">{attack_classes_count}</div>
      <div class="stat-label">Attack Classes</div>
    </div>
    <div class="stat-card">
      <div class="stat-val">{elapsed:.2f}s</div>
      <div class="stat-label">Scan Duration</div>
    </div>
  </div>

  {attack_sections}

  <footer>
    Scalp! Modernized Edition — Maintained by DragonJAR SAS
  </footer>
</div>
</body>
</html>
"""


class HtmlReporter(BaseReporter):
    @classmethod
    def generate(cls, result: ScanResult, output_path: str, source_name: str = "") -> None:
        curtime = time.strftime("%a-%d-%b-%Y %H:%M:%S", time.localtime())

        # Group matches: tag -> impact -> list of matches
        grouped = {}
        for match in result.matches:
            tag = match.tag
            impact = match.rule.impact
            if tag not in grouped:
                grouped[tag] = {}
            if impact not in grouped[tag]:
                grouped[tag][impact] = []
            grouped[tag][impact].append(match)

        sections = []
        for tag, impacts_dict in grouped.items():
            tag_name = ATTACK_NAMES.get(tag.lower(), tag.upper())
            total_tag_hits = sum(len(m_list) for m_list in impacts_dict.values())

            section_html = [
                f'<div class="attack-group">',
                f'  <div class="attack-header">',
                f'    <span>{html.escape(tag_name)} ({html.escape(tag)})</span>',
                f'    <span>{total_tag_hits} hit(s)</span>',
                f'  </div>',
            ]

            for impact in sorted(impacts_dict.keys(), reverse=True):
                badge_class = (
                    "badge-danger" if impact >= 7 else ("badge-warning" if impact >= 4 else "badge-info")
                )
                for m in impacts_dict[impact]:
                    section_html.append(f'  <div class="match-item">')
                    status_badge = (
                        f'<span class="badge badge-danger">HTTP {m.entry.status_code}</span>'
                        if m.entry.status_code in (200, 201, 204, 500)
                        else f'<span class="badge badge-info">HTTP {m.entry.status_code}</span>'
                    )
                    section_html.append(
                        f'      <span class="meta"><b>IP:</b> {html.escape(m.entry.ip)} &nbsp;|&nbsp; <b>Method:</b> {html.escape(m.entry.method)} &nbsp;|&nbsp; {status_badge}</span>'
                    )
                    section_html.append(f'      <span class="badge {badge_class}">Impact {impact}</span>')
                    section_html.append(f'    </div>')
                    section_html.append(
                        f'    <div class="reason"><b>Rule [{html.escape(m.rule.rule_id)}]:</b> {html.escape(m.rule.description)}</div>'
                    )
                    matched_field = getattr(m, "matched_field", "url")
                    section_html.append(
                        f'    <div class="log-line"><b>Vector:</b> {html.escape(matched_field)} &nbsp;|&nbsp; <b>Target:</b> {html.escape(m.entry.url)}<br><b>Matched:</b> {html.escape(m.matched_string)}</div>'
                    )
                    section_html.append(f'  </div>')

            section_html.append("</div>")
            sections.append("\n".join(section_html))

        html_content = HTML_TEMPLATE.format(
            source_name=html.escape(source_name or "access.log"),
            curtime=curtime,
            total_matches=len(result.matches),
            processed_lines=result.processed_lines,
            attack_classes_count=len(grouped),
            elapsed=result.elapsed_seconds,
            attack_sections="\n".join(sections) if sections else "<p style='color: var(--success); font-weight: bold;'>No attack patterns detected. The analyzed log is clean.</p>",
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
