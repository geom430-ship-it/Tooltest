"""
Report Generator Module
Generate HTML and JSON security assessment reports
"""
import json
from datetime import datetime


def generate_html_report(scan_data, title="Security Assessment Report"):
    """Generate a comprehensive HTML security report"""

    findings_html = ""
    summary_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Build findings sections
    for section_name, section_data in scan_data.get("sections", {}).items():
        findings_html += f"""
        <div class="section">
            <h2 class="section-title">
                <span class="section-icon">🔍</span>
                {section_name}
            </h2>
            <div class="section-content">
        """

        if isinstance(section_data, list):
            for item in section_data:
                if isinstance(item, dict):
                    severity = item.get("severity", "info")
                    summary_counts[severity] = summary_counts.get(severity, 0) + 1
                    findings_html += f"""
                    <div class="finding finding-{severity}">
                        <span class="severity-badge badge-{severity}">{severity.upper()}</span>
                        <strong>{item.get('type', item.get('name', 'Finding'))}</strong>
                        <p>{item.get('description', item.get('detail', ''))}</p>
                        {f"<code>{item.get('payload', '')}</code>" if item.get('payload') else ''}
                    </div>
                    """
                else:
                    findings_html += f"<p class='finding-item'>{item}</p>"
        elif isinstance(section_data, dict):
            for k, v in section_data.items():
                if v:
                    findings_html += f"<p><strong>{k}:</strong> {v}</p>"
        else:
            findings_html += f"<p>{section_data}</p>"

        findings_html += "</div></div>"

    total_findings = sum(summary_counts.values())
    risk_score = (
        summary_counts["critical"] * 10 +
        summary_counts["high"] * 7 +
        summary_counts["medium"] * 4 +
        summary_counts["low"] * 1
    )

    overall_risk = "CRITICAL" if risk_score >= 30 else "HIGH" if risk_score >= 15 else "MEDIUM" if risk_score >= 5 else "LOW"
    risk_color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}[overall_risk]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = scan_data.get("target", "Unknown")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1a2035;
            --text-primary: #e2e8f0;
            --text-muted: #94a3b8;
            --accent: #00d4ff;
            --border: #2d3748;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 2rem;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #0a0e1a 0%, #1a2035 50%, #0d1b2a 100%);
            border: 1px solid var(--border);
            border-top: 4px solid var(--accent);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2rem;
            color: var(--accent);
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }}
        .header .meta {{
            color: var(--text-muted);
            margin-top: 0.5rem;
            font-size: 0.9rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 2.5rem;
            font-weight: bold;
            display: block;
        }}
        .summary-card .label {{
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: var(--accent); }}
        .risk-score {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-left: 4px solid {risk_color};
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .risk-badge {{
            background: {risk_color};
            color: white;
            padding: 0.5rem 1.5rem;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1rem;
        }}
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .section-title {{
            background: #1e2a3a;
            padding: 1rem 1.5rem;
            font-size: 1.1rem;
            border-bottom: 1px solid var(--border);
            color: var(--accent);
        }}
        .section-content {{
            padding: 1.5rem;
        }}
        .finding {{
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 6px;
            border-left: 3px solid;
        }}
        .finding-critical {{ background: rgba(220,53,69,0.1); border-color: #dc3545; }}
        .finding-high {{ background: rgba(253,126,20,0.1); border-color: #fd7e14; }}
        .finding-medium {{ background: rgba(255,193,7,0.1); border-color: #ffc107; }}
        .finding-low {{ background: rgba(40,167,69,0.1); border-color: #28a745; }}
        .finding-info {{ background: rgba(0,212,255,0.05); border-color: var(--accent); }}
        .severity-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: bold;
            margin-right: 8px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: var(--accent); color: black; }}
        code {{
            background: #0a0e1a;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85em;
            color: #ff6b6b;
        }}
        .footer {{
            text-align: center;
            color: var(--text-muted);
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            font-size: 0.85rem;
        }}
        p {{ margin-bottom: 0.5rem; }}
        strong {{ color: var(--accent); }}
        .finding-item {{ padding: 0.25rem 0; border-bottom: 1px solid var(--border); }}
        @media print {{
            body {{ background: white; color: black; }}
            .header, .section {{ border: 1px solid #ccc; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ {title}</h1>
        <div class="meta">
            Target: <strong style="color: #e2e8f0;">{target}</strong> &nbsp;|&nbsp;
            Date: {timestamp} &nbsp;|&nbsp;
            Tool: PentestKit v1.0
        </div>
    </div>

    <div class="risk-score">
        <div>
            <h3>Overall Risk Assessment</h3>
            <p style="color: var(--text-muted);">Based on {total_findings} findings | Risk Score: {risk_score}</p>
        </div>
        <div class="risk-badge">{overall_risk}</div>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <span class="count critical">{summary_counts['critical']}</span>
            <span class="label">Critical</span>
        </div>
        <div class="summary-card">
            <span class="count high">{summary_counts['high']}</span>
            <span class="label">High</span>
        </div>
        <div class="summary-card">
            <span class="count medium">{summary_counts['medium']}</span>
            <span class="label">Medium</span>
        </div>
        <div class="summary-card">
            <span class="count low">{summary_counts['low']}</span>
            <span class="label">Low</span>
        </div>
        <div class="summary-card">
            <span class="count info">{summary_counts['info']}</span>
            <span class="label">Info</span>
        </div>
    </div>

    {findings_html}

    <div class="footer">
        <p>Generated by PentestKit v1.0 | {timestamp}</p>
        <p>⚠️ This report is confidential and for authorized use only</p>
    </div>
</body>
</html>"""

    return html


def save_report(html_content, filename=None):
    """Save HTML report to file"""
    import os
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/pentest_report_{timestamp}.html"

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return filename
