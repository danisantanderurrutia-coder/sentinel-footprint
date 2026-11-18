"""
Sentinel & Footprint - Unified CLI Interface.
Provides command-line operations for AppSec Auditing and Digital Footprint Sanitization.
"""
from __future__ import annotations
import os
import sys
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from sentinel.core.config import settings
from sentinel.core.models import Finding, ScanSummary, Severity
from sentinel.core.reporter import (
    print_findings_table,
    print_educational_cards,
    export_markdown_report,
    export_html_report,
    export_json_report,
)
from sentinel.modules.auditor.headers import analyze_security_headers
from sentinel.modules.auditor.secrets import scan_local_secrets
from sentinel.modules.auditor.owasp_checks import check_sensitive_endpoints
from sentinel.modules.auditor.compliance import audit_privacy_compliance
from sentinel.modules.auditor.dependencies import audit_dependencies
from sentinel.modules.footprint.hibp import check_password_leak_k_anonymity, explain_k_anonymity
from sentinel.modules.footprint.metadata import (
    get_image_exif_metadata,
    strip_image_metadata,
    get_pdf_metadata,
    strip_pdf_metadata,
)
from sentinel.modules.footprint.gdpr_engine import (
    generate_erasure_request_es,
    generate_erasure_request_en,
)
from sentinel.modules.footprint.tracker import (
    add_account_to_tracker,
    list_tracked_accounts,
    update_account_status,
    remove_tracked_account,
)
from sentinel.modules.footprint.guides import get_guide

app = typer.Typer(
    name="sentinel",
    help="🛡️ Sentinel & Footprint: Web Security Auditor (DevSecOps) & Privacy Cleaner",
    add_completion=False
)
privacy_app = typer.Typer(help="Herramientas de huella digital, borrado y privacidad personal.")
metadata_app = typer.Typer(help="Auditoría y limpieza de metadatos (EXIF, PDF).")

app.add_typer(privacy_app, name="privacy")
app.add_typer(metadata_app, name="metadata")

console = Console()


def _build_summary(target: str, scan_type: str, findings: list[Finding]) -> ScanSummary:
    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)
    info = sum(1 for f in findings if f.severity == Severity.INFO)
    return ScanSummary(
        target=target,
        scan_type=scan_type,
        total_findings=len(findings),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        info_count=info,
        findings=findings
    )


def _handle_reports(summary: ScanSummary, report_md: Optional[str], report_html: Optional[str], report_json: Optional[str]):
    if report_md:
        export_markdown_report(summary, report_md)
        console.print(f"[bold green]✔ Informe Markdown guardado en:[/bold green] {report_md}")
    if report_html:
        export_html_report(summary, report_html)
        console.print(f"[bold green]✔ Informe HTML interactivo guardado en:[/bold green] {report_html}")
    if report_json:
        export_json_report(summary, report_json)
        console.print(f"[bold green]✔ Informe JSON exportado en:[/bold green] {report_json}")


# ==========================================
# MÓDULO 1: Web & App Security Auditor
# ==========================================

@app.command(name="web")
def web_audit(
    url: str = typer.Argument(..., help="URL del sitio o API web a auditar"),
    active_probes: bool = typer.Option(True, "--active/--no-active", help="Ejecutar escaneo de rutas sensibles expuestas (.git, .env)"),
    compliance: bool = typer.Option(True, "--compliance/--no-compliance", help="Verificar avisos de privacidad y cookies RGPD"),
    report_md: Optional[str] = typer.Option(None, "--report-md", help="Ruta para exportar informe en Markdown"),
    report_html: Optional[str] = typer.Option(None, "--report-html", help="Ruta para exportar informe en HTML"),
    report_json: Optional[str] = typer.Option(None, "--report-json", help="Ruta para exportar informe en JSON"),
):
    """
    Audita cabeceras HTTP, transporte TLS, cookies, rutas sensibles (OWASP) y cumplimiento RGPD.
    """
    console.print(Panel(f"[bold cyan]Sentinel Security Auditor[/bold cyan]\nObjetivo: [bold white]{url}[/bold white]", expand=False))
    
    findings: list[Finding] = []
    
    with console.status("[bold green]Analizando cabeceras y transporte seguro..."):
        hdr_findings, _ = analyze_security_headers(url)
        findings.extend(hdr_findings)

    if active_probes:
        with console.status("[bold green]Comprobando exposición de rutas sensibles (.git, .env, backups)..."):
            active_findings = check_sensitive_endpoints(url)
            findings.extend(active_findings)

    if compliance:
        with console.status("[bold green]Evaluando transparencia y cumplimiento RGPD/Cookies..."):
            comp_findings = audit_privacy_compliance(url)
            findings.extend(comp_findings)

    print_findings_table(f"Resultados de Auditoría Web: {url}", findings)
    print_educational_cards(findings)

    summary = _build_summary(url, "Web & Transport Security Audit", findings)
    _handle_reports(summary, report_md, report_html, report_json)


@app.command(name="secrets")
def secrets_audit(
    path: str = typer.Argument(".", help="Directorio o archivo de código fuente a escanear"),
    report_md: Optional[str] = typer.Option(None, "--report-md", help="Ruta para exportar informe en Markdown"),
    report_html: Optional[str] = typer.Option(None, "--report-html", help="Ruta para exportar informe en HTML"),
    report_json: Optional[str] = typer.Option(None, "--report-json", help="Ruta para exportar informe en JSON"),
):
    """
    Escanea archivos locales y repositorios en busca de credenciales, API Keys y tokens hardcodeados.
    """
    console.print(Panel(f"[bold cyan]Sentinel Secret Scanner[/bold cyan]\nRuta objetivo: [bold white]{os.path.abspath(path)}[/bold white]", expand=False))
    with console.status("[bold yellow]Escaneando archivos en busca de credenciales..."):
        findings = scan_local_secrets(path)

    print_findings_table(f"Resultados de Secretos: {path}", findings)
    print_educational_cards(findings)

    summary = _build_summary(path, "Local Secrets Scan", findings)
    _handle_reports(summary, report_md, report_html, report_json)


@app.command(name="dependencies")
def dependencies_audit(
    path: str = typer.Argument(".", help="Directorio del proyecto o archivo de dependencias (requirements.txt)"),
    report_md: Optional[str] = typer.Option(None, "--report-md", help="Ruta para exportar informe en Markdown"),
):
    """
    Analiza dependencias de software en busca de vulnerabilidades conocidas (CVEs / SCA).
    """
    console.print(Panel(f"[bold cyan]Sentinel SCA Dependency Auditor[/bold cyan]\nObjetivo: [bold white]{path}[/bold white]", expand=False))
    with console.status("[bold green]Analizando dependencias contra bases de datos de vulnerabilidades..."):
        findings = audit_dependencies(path)

    print_findings_table(f"Vulnerabilidades en Dependencias: {path}", findings)
    print_educational_cards(findings)
    if report_md:
        summary = _build_summary(path, "SCA Dependency Audit", findings)
        export_markdown_report(summary, report_md)
        console.print(f"[bold green]✔ Informe Markdown guardado en:[/bold green] {report_md}")


# ==========================================
# MÓDULO 2: Digital Footprint & Privacy Cleaner
# ==========================================

@app.command(name="pwned")
def pwned_check(
    password: Optional[str] = typer.Argument(None, help="Contraseña a verificar (si se omite, se pedirá de forma segura sin eco)"),
    explain: bool = typer.Option(True, "--explain/--no-explain", help="Mostrar explicación pedagógica del modelo k-Anonymity")
):
    """
    Verifica si una contraseña ha sido filtrada en brechas usando el modelo k-Anonymity (HIBP).
    """
    if not password:
        password = typer.prompt("Introduce la contraseña a comprobar (no se mostrará en pantalla)", hide_input=True)

    with console.status("[bold green]Consultando prefijo criptográfico en base de datos de brechas..."):
        is_leaked, count, prefix = check_password_leak_k_anonymity(password)

    if is_leaked:
        console.print(Panel(
            f"[bold red]⚠️ CONTRASEÑA COMPROMETIDA EN BRECHAS PÚBLICAS[/bold red]\n\n"
            f"Apariciones registradas: [bold yellow]{count:,}[/bold yellow] veces.\n"
            f"Prefijo SHA-1 consultado: [cyan]{prefix}[/cyan]\n\n"
            f"[bold]Recomendación:[/bold] Cambia inmediatamente esta contraseña en cualquier servicio donde la utilices. Nunca reutilices credenciales.",
            title="[red]Alerta de Seguridad Crítica[/red]",
            border_style="red"
        ))
    else:
        console.print(Panel(
            f"[bold green]✔ Contraseña NO detectada en brechas públicas conocidas.[/bold green]\n"
            f"Prefijo SHA-1 consultado: [cyan]{prefix}[/cyan]\n"
            f"[dim]Recuerda seguir utilizando contraseñas de al menos 14 caracteres y gestor de contraseñas.[/dim]",
            title="[green]Buen Estado[/green]",
            border_style="green"
        ))

    if explain:
        console.print(Panel(Markdown(explain_k_anonymity()), title="[blue]¿Cómo se preservó tu privacidad en esta consulta?[/blue]"))


# --- Subcomandos de Metadatos ---

@metadata_app.command(name="scan")
def metadata_scan(
    file_path: str = typer.Argument(..., help="Ruta de la imagen (.jpg, .png) o documento (.pdf) a analizar")
):
    """
    Extrae y analiza metadatos sensibles (geolocalización GPS, cámara, autor) en fotos o PDFs.
    """
    if not os.path.exists(file_path):
        console.print(f"[bold red]El archivo no existe:[/bold red] {file_path}")
        return

    ext = os.path.splitext(file_path)[1].lower()
    table = Table(title=f"Metadatos extraídos: {os.path.basename(file_path)}")
    table.add_column("Propiedad / Tag", style="cyan")
    table.add_column("Valor Detectado", style="magenta")

    if ext in [".jpg", ".jpeg", ".tiff", ".png"]:
        data = get_image_exif_metadata(file_path)
        if not data:
            console.print("[green]✔ La imagen no contiene metadatos EXIF o ya han sido eliminados.[/green]")
            return
        for k, v in data.items():
            if k == "GPSInfo" and isinstance(v, dict):
                gps_str = "\n".join([f"  {gk}: {gv}" for gk, gv in v.items()])
                table.add_row("[bold red]GPSInfo (Coordenadas)[/bold red]", f"[red]{gps_str}[/red]")
            else:
                table.add_row(str(k), str(v))
        console.print(table)
        if "GPSInfo" in data:
            console.print("[bold red]⚠️ ATENCIÓN: Esta imagen revela la ubicación geográfica exacta donde fue tomada.[/bold red]")

    elif ext == ".pdf":
        data = get_pdf_metadata(file_path)
        if not data:
            console.print("[green]✔ El PDF no contiene metadatos significativos.[/green]")
            return
        for k, v in data.items():
            table.add_row(str(k), str(v))
        console.print(table)
    else:
        console.print(f"[yellow]Formato no soportado para análisis directo: {ext}. Soporta imágenes y PDFs.[/yellow]")


@metadata_app.command(name="clean")
def metadata_clean(
    source_path: str = typer.Argument(..., help="Archivo original con metadatos"),
    output_path: str = typer.Argument(..., help="Ruta donde guardar el archivo saneado sin metadatos")
):
    """
    Elimina y purga por completo todos los metadatos EXIF / PDF, generando un archivo limpio.
    """
    if not os.path.exists(source_path):
        console.print(f"[bold red]Archivo no encontrado:[/bold red] {source_path}")
        return

    ext = os.path.splitext(source_path)[1].lower()
    success = False
    if ext in [".jpg", ".jpeg", ".png", ".tiff"]:
        success = strip_image_metadata(source_path, output_path)
    elif ext == ".pdf":
        success = strip_pdf_metadata(source_path, output_path)
    else:
        console.print(f"[yellow]Extensión no soportada para limpieza: {ext}[/yellow]")
        return

    if success:
        console.print(f"[bold green]✔ Archivo saneado y desinfectado guardado exitosamente en:[/bold green] {output_path}")
    else:
        console.print("[bold red]✖ Ocurrió un error al intentar limpiar los metadatos.[/bold red]")


# --- Subcomandos de Privacidad, RGPD y Tracker ---

@privacy_app.command(name="gdpr-request")
def privacy_gdpr(
    lang: str = typer.Option("es", "--lang", help="Idioma de la plantilla ('es' o 'en')"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Guardar la carta generada en un archivo de texto")
):
    """
    Generador interactivo de cartas legales de Derecho al Olvido / Supresión de Datos (Art. 17 RGPD).
    """
    console.print(Panel("[bold cyan]Generador de Solicitud de Supresión RGPD / Derecho al Olvido[/bold cyan]", expand=False))
    
    full_name = typer.prompt("Nombre completo")
    id_number = typer.prompt("Número de DNI / NIE / Pasaporte")
    email = typer.prompt("Correo electrónico registrado en la plataforma")
    service_name = typer.prompt("Nombre de la plataforma o empresa (ej. Twitter, Experian, DataBroker X)")
    username = typer.prompt("Nombre de usuario o ID en la plataforma (opcional, presiona Enter si no aplica)", default="")
    
    if lang.lower() == "en":
        letter = generate_erasure_request_en(full_name, id_number, email, service_name, username)
    else:
        letter = generate_erasure_request_es(full_name, id_number, email, service_name, username)

    console.print("\n[bold yellow]══════ CARTA GENERADA (LISTA PARA ENVIAR) ══════[/bold yellow]\n")
    console.print(Panel(letter, border_style="green"))

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(letter)
        console.print(f"[bold green]✔ Carta guardada en:[/bold green] {output_file}")
    else:
        save = typer.confirm("¿Deseas guardar la carta en un archivo de texto?")
        if save:
            filename = f"solicitud_supresion_{service_name.lower().replace(' ', '_')}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(letter)
            console.print(f"[bold green]✔ Guardada en {filename}[/bold green]")


@privacy_app.command(name="tracker-add")
def privacy_tracker_add(
    platform: str = typer.Argument(..., help="Nombre del servicio o data broker"),
    username: str = typer.Argument(..., help="Email o nombre de usuario registrado"),
    notes: str = typer.Option("", "--notes", "-n", help="Notas adicionales o fecha límite")
):
    """Añade un servicio o cuenta a la lista de tareas de eliminación / derecho al olvido."""
    item = add_account_to_tracker(platform, username, notes)
    console.print(f"[bold green]✔ Cuenta añadida a la lista de supresión:[/bold green] [{item.id}] {platform} ({username})")


@privacy_app.command(name="tracker-list")
def privacy_tracker_list():
    """Muestra el checklist interactivo de cuentas pendientes o eliminadas."""
    items = list_tracked_accounts()
    if not items:
        console.print("[dim]No hay cuentas registradas en el tracker aún. Usa `sentinel privacy tracker-add`.[/dim]")
        return

    table = Table(title="Checklist de Desinfección de Cuentas y Huella Digital")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Plataforma", style="cyan")
    table.add_column("Usuario / Email", style="magenta")
    table.add_column("Estado", justify="center")
    table.add_column("Fecha Solicitud", style="dim")
    table.add_column("Notas")

    for it in items:
        status_color = "green" if "borrado" in it.status.lower() or "eliminado" in it.status.lower() else "yellow"
        table.add_row(
            it.id,
            it.platform_name,
            it.email_or_username,
            f"[{status_color}]{it.status}[/{status_color}]",
            it.request_date or "-",
            it.notes or ""
        )
    console.print(table)


@privacy_app.command(name="tracker-update")
def privacy_tracker_update(
    account_id: str = typer.Argument(..., help="ID o nombre de la plataforma"),
    status: str = typer.Argument(..., help="Nuevo estado: 'Solicitado', 'En Proceso', 'Confirmado Borrado'")
):
    """Actualiza el estado de una solicitud de borrado en el tracker."""
    ok = update_account_status(account_id, status)
    if ok:
        console.print(f"[bold green]✔ Estado actualizado para '{account_id}' -> '{status}'[/bold green]")
    else:
        console.print(f"[bold red]✖ No se encontró ninguna cuenta con identificador:[/bold red] {account_id}")


@privacy_app.command(name="tracker-remove")
def privacy_tracker_remove(
    account_id: str = typer.Argument(..., help="ID o nombre de la plataforma a eliminar de la lista")
):
    """Elimina una entrada de la lista de seguimiento."""
    ok = remove_tracked_account(account_id)
    if ok:
        console.print(f"[bold green]✔ Entrada '{account_id}' eliminada del tracker.[/bold green]")
    else:
        console.print(f"[bold red]✖ No se encontró la entrada:[/bold red] {account_id}")


@privacy_app.command(name="guides")
def privacy_guides(
    provider: Optional[str] = typer.Argument(None, help="Proveedor: google, github, apple, meta, databrokers")
):
    """Muestra guías paso a paso de revocación de permisos OAuth y auditoría de sesiones activas."""
    guide_text = get_guide(provider or "all")
    console.print(Panel(Markdown(guide_text), title=f"[bold cyan]Guía de Privacidad y Revocación[/bold cyan]"))


# ==========================================
# MÓDULO 3: Web Dashboard Server
# ==========================================

@app.command(name="ui")
def start_dashboard(
    port: int = typer.Option(8000, "--port", "-p", help="Puerto local para el servidor web"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host de escucha"),
    no_open: bool = typer.Option(False, "--no-open", help="No abrir automáticamente el navegador")
):
    """
    Inicia el Dashboard Web interactivo y lo abre automáticamente en tu navegador.
    """
    import webbrowser
    import uvicorn
    from sentinel.ui.server import app as fastapi_app

    url = f"http://{host}:{port}"
    console.print(Panel(
        f"[bold cyan]🚀 Iniciando Dashboard Visual de Sentinel & Footprint[/bold cyan]\n\n"
        f"Acceso Web: [bold green]{url}[/bold green]\n"
        f"[dim]Presiona Ctrl+C en la terminal para detener el servidor.[/dim]",
        border_style="cyan"
    ))

    if not no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    uvicorn.run(fastapi_app, host=host, port=port, log_level="warning")



# ==========================================
# Main runner
# ==========================================

def main():
    app()

if __name__ == "__main__":
    main()
