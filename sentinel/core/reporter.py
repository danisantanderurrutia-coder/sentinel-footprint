"""
Reporting engine: Console (Rich), Markdown, Standalone HTML, and JSON.
"""
from __future__ import annotations
import json
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from sentinel.core.models import Finding, ScanSummary, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}

SEVERITY_BADGES = {
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
    Severity.HIGH: "[red]HIGH[/red]",
    Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    Severity.LOW: "[cyan]LOW[/cyan]",
    Severity.INFO: "[blue]INFO[/blue]",
}


def print_findings_table(title: str, findings: List[Finding]) -> None:
    """Print an interactive table of findings to console."""
    if not findings:
        console.print(f"[bold green]✔ No se detectaron vulnerabilidades en: {title}[/bold green]\n")
        return

    table = Table(title=title, show_lines=True)
    table.add_column("Severidad", justify="center", width=12)
    table.add_column("Categoría", style="magenta", width=15)
    table.add_column("Hallazgo / Nombre", style="bold")
    table.add_column("Detalles", style="dim")

    for f in findings:
        badge = SEVERITY_BADGES.get(f.severity, f.severity.value)
        table.add_row(badge, f.category, f.name, f.details[:90] + ("..." if len(f.details) > 90 else ""))

    console.print(table)


def print_educational_cards(findings: List[Finding]) -> None:
    """Print pedagogical cards for findings."""
    cards_printed = 0
    console.print("\n[bold yellow]══════ FICHAS PEDAGÓGICAS Y GUÍAS DE REMEDIACIÓN ══════[/bold yellow]\n")
    for f in findings:
        if f.educational_card:
            card = f.educational_card
            content_md = [
                f"### {card.title}",
                f"**Concepto:** {card.concept}\n",
                f"**¿Por qué es peligroso? (Escenario de Ataque):**\n{card.danger_scenario}\n",
                f"**¿Cómo se remedia?:**\n{card.remediation}\n"
            ]
            if card.code_before and card.code_after:
                content_md.append(f"**Antes (Inseguro):**\n```\n{card.code_before}\n```")
                content_md.append(f"**Después (Seguro):**\n```\n{card.code_after}\n```")
            if card.references:
                refs = "\n".join([f"- {ref}" for ref in card.references])
                content_md.append(f"**Referencias & Estándares:**\n{refs}")

            sev_color = SEVERITY_COLORS.get(f.severity, "white")
            panel = Panel(
                Markdown("\n".join(content_md)),
                title=f"[{sev_color}][{f.severity.value}] {f.name}[/{sev_color}]",
                border_style=sev_color.split()[-1],
                expand=False
            )
            console.print(panel)
            cards_printed += 1

    if cards_printed == 0:
        console.print("[dim]No hay fichas pedagógicas adicionales para mostrar.[/dim]")


def export_markdown_report(summary: ScanSummary, filepath: str) -> None:
    """Generate a clean Markdown report."""
    lines = [
        f"# Informe de Seguridad - Sentinel & Footprint",
        f"**Objetivo:** `{summary.target}`  ",
        f"**Tipo de Escaneo:** {summary.scan_type}  ",
        f"**Fecha:** {summary.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        "",
        "## Resumen Ejecutivo",
        f"- **Total de Hallazgos:** {summary.total_findings}",
        f"- **Críticos:** {summary.critical_count}",
        f"- **Altos:** {summary.high_count}",
        f"- **Medios:** {summary.medium_count}",
        f"- **Bajos:** {summary.low_count}",
        f"- **Informativos:** {summary.info_count}",
        "",
        "## Detalle de Hallazgos y Fichas Didácticas",
        ""
    ]

    for idx, f in enumerate(summary.findings, start=1):
        lines.append(f"### {idx}. [{f.severity.value}] {f.name}")
        lines.append(f"- **Categoría:** {f.category}")
        lines.append(f"- **Objetivo / Recurso:** `{f.target}`")
        lines.append(f"- **Detalle:** {f.details}")
        lines.append("")

        if f.educational_card:
            card = f.educational_card
            lines.append("#### Guía Pedagógica")
            lines.append(f"**Concepto:** {card.concept}\n")
            lines.append(f"**Escenario de Riesgo:** {card.danger_scenario}\n")
            lines.append(f"**Solución Recomendada:** {card.remediation}\n")
            if card.code_before and card.code_after:
                lines.append("**Ejemplo de Código Vulnerable:**")
                lines.append(f"```\n{card.code_before}\n```")
                lines.append("**Ejemplo de Código Corregido:**")
                lines.append(f"```\n{card.code_after}\n```")
            if card.references:
                lines.append("**Referencias:**")
                for ref in card.references:
                    lines.append(f"- {ref}")
            lines.append("")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def export_html_report(summary: ScanSummary, filepath: str) -> None:
    """Generate a modern, self-contained HTML report with styling."""
    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel & Footprint - Security Report: {summary.target}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    header {{ border-bottom: 1px solid #334155; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    h1 {{ color: #38bdf8; margin: 0 0 0.5rem 0; font-size: 2rem; }}
    .meta {{ color: #94a3b8; font-size: 0.9rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; border: 1px solid #334155; }}
    .stat-val {{ font-size: 1.8rem; font-weight: bold; margin-bottom: 0.25rem; }}
    .CRITICAL {{ color: #ef4444; }}
    .HIGH {{ color: #f97316; }}
    .MEDIUM {{ color: #eab308; }}
    .LOW {{ color: #06b6d4; }}
    .INFO {{ color: #3b82f6; }}
    .finding-card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border-left: 5px solid #64748b; }}
    .finding-card.CRITICAL {{ border-left-color: #ef4444; }}
    .finding-card.HIGH {{ border-left-color: #f97316; }}
    .finding-card.MEDIUM {{ border-left-color: #eab308; }}
    .finding-card.LOW {{ border-left-color: #06b6d4; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }}
    .badge.CRITICAL {{ background: #7f1d1d; color: #fca5a5; }}
    .badge.HIGH {{ background: #7c2d12; color: #fdba74; }}
    .badge.MEDIUM {{ background: #713f12; color: #fde047; }}
    .badge.LOW {{ background: #164e63; color: #67e8f9; }}
    .badge.INFO {{ background: #1e3a8a; color: #93c5fd; }}
    pre {{ background: #0b1120; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-size: 0.85rem; border: 1px solid #1e293b; }}
    .edu-section {{ margin-top: 1rem; padding-top: 1rem; border-top: 1px dashed #334155; }}
    .edu-title {{ color: #38bdf8; font-weight: 600; margin-bottom: 0.5rem; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>🛡️ Sentinel & Footprint Report</h1>
        <div class="meta">
            Target: <strong>{summary.target}</strong> | Tipo: <strong>{summary.scan_type}</strong> | Fecha: <strong>{summary.scan_date.strftime('%Y-%m-%d %H:%M:%S')}</strong>
        </div>
    </header>

    <div class="stats-grid">
        <div class="stat-card"><div class="stat-val">{summary.total_findings}</div>Total</div>
        <div class="stat-card"><div class="stat-val CRITICAL">{summary.critical_count}</div>Críticos</div>
        <div class="stat-card"><div class="stat-val HIGH">{summary.high_count}</div>Altos</div>
        <div class="stat-card"><div class="stat-val MEDIUM">{summary.medium_count}</div>Medios</div>
        <div class="stat-card"><div class="stat-val LOW">{summary.low_count}</div>Bajos</div>
    </div>

    <h2>Hallazgos y Guías de Remediación</h2>
"""
    for f in summary.findings:
        sev_class = f.severity.value
        edu_html = ""
        if f.educational_card:
            card = f.educational_card
            code_diff = ""
            if card.code_before and card.code_after:
                code_diff = f"""
                <p><strong>Antes (Vulnerable):</strong></p>
                <pre>{card.code_before}</pre>
                <p><strong>Después (Remediado):</strong></p>
                <pre>{card.code_after}</pre>
                """
            refs_html = "".join([f"<li>{r}</li>" for r in card.references])
            edu_html = f"""
            <div class="edu-section">
                <div class="edu-title">📖 Ficha Didáctica: {card.title}</div>
                <p><strong>Concepto:</strong> {card.concept}</p>
                <p><strong>Escenario de Ataque:</strong> {card.danger_scenario}</p>
                <p><strong>Remediación:</strong> {card.remediation}</p>
                {code_diff}
                <p><strong>Referencias:</strong></p>
                <ul>{refs_html}</ul>
            </div>
            """

        html_content += f"""
        <div class="finding-card {sev_class}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0; color:#f8fafc;">{f.name}</h3>
                <span class="badge {sev_class}">{sev_class}</span>
            </div>
            <p style="color:#94a3b8; font-size:0.85rem; margin:0.3rem 0;">Categoría: <strong>{f.category}</strong> | Objetivo: <code>{f.target}</code></p>
            <p>{f.details}</p>
            {edu_html}
        </div>
        """

    html_content += """
</div>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)


def export_json_report(summary: ScanSummary, filepath: str) -> None:
    """Generate structured JSON report."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(summary.model_dump(mode="json"), f, indent=2, ensure_ascii=False)
