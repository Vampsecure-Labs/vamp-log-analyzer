# © VampSecure Studios — VampSecure Labs Security Research Division
from __future__ import annotations
import argparse
import base64
import datetime
import json
import os
import pathlib
import ssl
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional
try:
    from rich.console import Console
    from rich.panel import Panel
    _RICH_OK = True
except ImportError:
    _RICH_OK = False
    class Console:
        def print(self, *a, **kw): print(*a)
    class Panel:
        def __init__(self, *a, **kw): pass
console = Console()
from ._models import (
    VERSION, TOOL, BANNER, ScopeConfig, Report,
    _ANSI_BOLD_MAGENTA, _ANSI_RESET, _severity_rank,
)
from ._core import (
    analyze_files, SigmaLoader, SigmaRule,
    StreamingAnalyzer, BaselineProfiler, NarrativeGenerator,
)
from ._report import (
    to_json, to_forensic_txt, to_ioc_csv, to_stix,
    to_baseline_delta_txt, to_html, EvidencePackager,
)

def print_banner() -> None:
    """Imprime la cabecera ASCII del toolkit VampSecure Labs."""
    try:
        print(f"{_ANSI_BOLD_MAGENTA}{BANNER}{_ANSI_RESET}", file=sys.stderr)
    except UnicodeEncodeError:
        # Fallback para terminales con encoding limitado
        print(BANNER, file=sys.stderr)

# ============================================================
# PATRONES DE DETECCIÓN
# ============================================================

# --- Ataques web ---

def resolve_paths(inputs: List[str]) -> List[str]:
    """Expande directorios en ficheros de log individuales."""
    LOG_EXTENSIONS = {".log", ".gz", ".xml", ".json", ".csv", ".txt", ""}
    out = []
    for p in inputs:
        path = pathlib.Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix.lower() in LOG_EXTENSIONS and f.stat().st_size > 0:
                    out.append(str(f))
        elif path.is_file():
            out.append(str(path))
        else:
            print(f"[!] No encontrado: {p}", file=sys.stderr)
    return out


def build_config(args, scope: Optional[ScopeConfig] = None) -> dict:
    night_from = args.night_from
    night_to = args.night_to
    # El scope sobrescribe el horario nocturno si está definido
    if scope:
        # "horario anómalo" = fuera del horario laboral del scope
        night_from = scope.business_end % 24
        night_to = scope.business_start
    return {
        "large_response":       args.large_response_mb * 1024 * 1024,
        "brute_window_sec":     args.brute_window,
        "brute_threshold_ssh":  args.brute_ssh,
        "brute_threshold_web":  args.brute_web,
        "spray_users_min":      args.spray_min_users,
        "dir_enum_threshold":   args.dir_enum,
        "unusual_hours":        (night_from, night_to),
        "top_n":                args.top_n,
    }


def print_summary(report: Report) -> None:
    s = report.summary
    print(f"\n{'═' * 60}")
    print(f"  {TOOL} v{VERSION}")
    print("  © VampSecure Studios — VampSecure Labs")
    print(f"{'═' * 60}")
    print(f"  Eventos procesados : {report.total_events_parsed:>8,}")
    print(f"  Período analizado  : {report.time_range_start or '?'[:19]} → {report.time_range_end or '?'[:19]}")
    print(f"{'─' * 60}")
    print(f"  CRÍTICO  : {s['critical']:>4}")
    print(f"  ALTO     : {s['high']:>4}")
    print(f"  MEDIO    : {s['medium']:>4}")
    print(f"  BAJO     : {s['low']:>4}")
    print(f"{'─' * 60}")
    if report.findings:
        print("  Hallazgos principales:")
        for f in report.findings[:10]:
            ts = f.first_seen.strftime("%Y-%m-%d %H:%M") if f.first_seen else "—"
            print(f"    [{f.severity:<8}] {f.fid}  {f.title[:55]}")
            print(f"             {ts}  IPs: {', '.join(f.ips[:3]) or '—'}")
    else:
        print("  Sin hallazgos detectados.")

    if report.ip_profiles:
        top_n = min(10, len(report.ip_profiles))
        print(f"{'─' * 60}")
        print(f"  IPs más activas (top {top_n} de {len(report.ip_profiles)} únicas):")
        for ip, p in list(report.ip_profiles.items())[:top_n]:
            dias = p['num_dias']
            ev = p['total_eventos']
            auth_str = f"  ✓{p['exitos_auth']}/✗{p['fallos_auth']}" if (p['exitos_auth'] or p['fallos_auth']) else ""
            pico = max(p["distribucion_hora_utc"].items(), key=lambda x: x[1])
            print(f"    {ip:<18} {ev:>5} eventos · {dias} día(s){auth_str}  [pico: {pico[0]}h UTC]")

    # Distribución de reglas Wazuh (solo si hay datos)
    if report.wazuh_rule_counts:
        print(f"{'─' * 60}")
        top_rules = sorted(report.wazuh_rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        print(f"  Top {len(top_rules)} reglas Wazuh más frecuentes (de {len(report.wazuh_rule_counts)} únicas):")
        for rule_id, count in top_rules:
            print(f"    [{count:>5}x]  Regla {rule_id}")

    print(f"{'═' * 60}\n")


# ---------------------------------------------------------------------------
# Modo --watch-wazuh-api (VampPurple P7 — loop purple sin ingesta manual)
# ---------------------------------------------------------------------------

def _wazuh_api_request(
    base_url: str,
    path: str,
    token: str,
    params: Optional[dict] = None,
    verify_ssl: bool = True,
) -> dict:
    """Realiza una petición GET autenticada a la API REST de Wazuh."""
    url = base_url.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    ctx = ssl.create_default_context() if verify_ssl else ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.loads(resp.read().decode())


def _wazuh_api_auth(base_url: str, user: str, password: str, verify_ssl: bool) -> str:
    """Autentica contra la API Wazuh y devuelve el JWT token."""
    url = base_url.rstrip("/") + "/security/user/authenticate"
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    ctx = ssl.create_default_context() if verify_ssl else ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, method="POST",
        headers={"Authorization": f"Basic {creds}"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data["data"]["token"]
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"Autenticación Wazuh fallida ({e.code}): {body}") from e


def _modo_watch_wazuh_api(args: argparse.Namespace) -> int:
    """
    Modo de vigilancia en tiempo real contra la API REST de Wazuh.

    Conecta a la API Wazuh (puerto 55000), obtiene un JWT, y sondea
    el endpoint /alerts periódicamente para recuperar alertas nuevas.
    Las alertas se muestran en consola y se escriben en NDJSON si se
    especifica --wazuh-output, listas para ser consumidas por VampPurple.

    Ctrl+C para detener el bucle.
    """
    console = Console()
    base_url = args.watch_wazuh_api.rstrip("/")
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    user     = getattr(args, "wazuh_user", None) or os.environ.get("WAZUH_USER", "wazuh")
    password = getattr(args, "wazuh_password", None) or os.environ.get("WAZUH_PASSWORD", "")
    if not password:
        import getpass
        password = getpass.getpass(f"  Contraseña Wazuh [{user}]: ")
    intervalo   = int(getattr(args, "wazuh_interval", 30) or 30)
    min_level   = int(getattr(args, "wazuh_min_level", 7) or 7)
    salida_path = getattr(args, "wazuh_output", None)
    verify_ssl  = not getattr(args, "wazuh_no_verify", False)

    console.print(Panel(
        f"[bold]API:[/bold] {base_url}  ·  "
        f"[bold]Nivel mínimo:[/bold] {min_level}  ·  "
        f"[bold]Intervalo:[/bold] {intervalo}s"
        + (f"\n[bold]Salida NDJSON:[/bold] {salida_path}" if salida_path else ""),
        title=f"[bold magenta]{TOOL} v{VERSION} — Modo watch-wazuh-api[/bold magenta]",
        border_style="magenta",
    ))

    try:
        token = _wazuh_api_auth(base_url, user, password, verify_ssl)
    except Exception as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        return 2

    token_ts          = time.time()
    TOKEN_TTL_S       = 3600 - 60  # refrescar antes de la expiración del JWT (1h por defecto)
    ya_vistos: set    = set()
    salida_fp         = open(salida_path, "a", encoding="utf-8") if salida_path else None  # noqa: WPS515

    console.print(f"[green]✓ Autenticado. Sondeando cada {intervalo}s (Ctrl+C para salir)…[/green]")

    try:
        while True:
            # Refrescar token si está cerca de expirar
            if time.time() - token_ts > TOKEN_TTL_S:
                try:
                    token    = _wazuh_api_auth(base_url, user, password, verify_ssl)
                    token_ts = time.time()
                    console.print("[dim]→ Token JWT renovado[/dim]")
                except Exception as e:
                    console.print(f"[yellow][!] No se pudo renovar el token: {e}[/yellow]")

            try:
                resp = _wazuh_api_request(
                    base_url, "/alerts",
                    token,
                    params={"q": f"rule.level>={min_level}", "sort": "-timestamp", "limit": 100},
                    verify_ssl=verify_ssl,
                )
            except Exception as e:
                console.print(f"[yellow][!] Error al consultar /alerts: {e}[/yellow]")
                time.sleep(intervalo)
                continue

            alertas = (resp.get("data") or {}).get("affected_items") or []
            nuevas  = [a for a in alertas if a.get("id") not in ya_vistos]

            for alerta in reversed(nuevas):  # cronológico
                a_id = alerta.get("id", "")
                ya_vistos.add(a_id)
                regla     = alerta.get("rule", {})
                nivel     = regla.get("level", 0)
                descr     = regla.get("description", "")
                agente    = alerta.get("agent", {}).get("name", "?")
                timestamp = alerta.get("timestamp", "")
                color     = "red" if nivel >= 12 else ("yellow" if nivel >= 7 else "dim")
                console.print(
                    f"[{color}][Nivel {nivel:>2}][/{color}]  "
                    f"[bold]{agente}[/bold]  {timestamp[:19]}  {descr}"
                )
                if salida_fp:
                    salida_fp.write(json.dumps(alerta, ensure_ascii=False) + "\n")
                    salida_fp.flush()

            if nuevas:
                console.print(f"[dim]  → {len(nuevas)} alerta(s) nueva(s). Total vistas: {len(ya_vistos)}[/dim]")

            time.sleep(intervalo)

    except KeyboardInterrupt:
        console.print("\n[yellow]Detenido por el usuario.[/yellow]")
    finally:
        if salida_fp:
            salida_fp.close()

    return 0


def main() -> int:
    print_banner()
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Analizador forense de logs multiplataforma — VampSecure Labs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Ejemplos:
          %(prog)s /var/log/nginx/access.log
          %(prog)s /logs/ --type auto --report-html forense.html
          %(prog)s auth.log nginx.log --from 2026-01-01 --to 2026-01-31
          %(prog)s /var/log/ --report-json findings.json --report-html forense.html
          %(prog)s security.xml --type windows --report-html windows_audit.html
        """),
    )
    parser.add_argument("paths", nargs="*", help="Ficheros o directorios de log a analizar")
    parser.add_argument("--type", default="auto",
                        choices=["auto","web","iis","db_mysql","db_postgres","db_mongo",
                                 "linux_auth","linux_sys","windows","macos",
                                 "wazuh","ossec","generic"],
                        help="Tipo de log (default: auto-detectar). "
                             "wazuh: JSON de Wazuh/OSSEC con campos agent/rule/data. "
                             "ossec: texto OSSEC legacy (** Alert …).")
    parser.add_argument("--from", dest="time_from", metavar="YYYY-MM-DD",
                        help="Analizar solo eventos desde esta fecha UTC")
    parser.add_argument("--to", dest="time_to", metavar="YYYY-MM-DD",
                        help="Analizar solo eventos hasta esta fecha UTC")
    parser.add_argument("--report-html", metavar="FICHERO", help="Guardar informe HTML")
    parser.add_argument("--report-json", metavar="FICHERO", help="Guardar informe JSON")
    parser.add_argument("--report-forensic", metavar="FICHERO", dest="report_forensic",
                        help="Guardar informe forense completo en texto plano (cadena de custodia, timeline, IOCs, ATT&CK)")
    parser.add_argument("--ioc-csv", metavar="FICHERO", dest="ioc_csv",
                        help="Exportar IOCs (IPs, rutas, UAs, usuarios) en formato CSV para SIEM")
    parser.add_argument("--min-severity", default="LOW",
                        choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
                        help="Severidad mínima a reportar (default: LOW)")
    # Análisis forense
    parser.add_argument("--chain-of-custody", action="store_true", dest="chain_of_custody",
                        help="Incluir hashes SHA-256 de ficheros + metadatos forenses")
    parser.add_argument("--analyst", metavar="NOMBRE", default="",
                        help="Nombre del perito para el informe forense")
    parser.add_argument("--case", metavar="REF", default="",
                        help="Referencia del caso para el informe forense")
    parser.add_argument("--geoip", action="store_true",
                        help="Enriquecer IPs atacantes con país/ASN (requiere conexión a internet)")
    parser.add_argument("--top-n", type=int, default=10, metavar="N", dest="top_n",
                        help="Número de elementos en rankings de IPs/rutas/UAs (default: 10)")
    parser.add_argument("--min-session-gap", type=int, default=30, metavar="MIN", dest="session_gap",
                        help="Minutos de silencio para separar sesiones de atacante (default: 30)")
    # Umbrales
    parser.add_argument("--brute-window",   type=int, default=300,  metavar="S",  help="Ventana en segundos para brute force (default: 300)")
    parser.add_argument("--brute-ssh",      type=int, default=5,    metavar="N",  help="Umbral fallos SSH para alertar (default: 5)")
    parser.add_argument("--brute-web",      type=int, default=20,   metavar="N",  help="Umbral fallos HTTP para alertar (default: 20)")
    parser.add_argument("--spray-min-users",type=int, default=5,    metavar="N",  help="Usuarios mínimos para detección de spray (default: 5)")
    parser.add_argument("--dir-enum",       type=int, default=30,   metavar="N",  help="Umbral 404s para detectar enumeración (default: 30)")
    parser.add_argument("--large-response-mb", type=int, default=10, metavar="MB", help="Tamaño de respuesta grande en MB (default: 10)")
    parser.add_argument("--night-from",     type=int, default=0,    metavar="H",  help="Inicio de horario nocturno anómalo UTC (default: 0)")
    parser.add_argument("--night-to",       type=int, default=6,    metavar="H",  help="Fin de horario nocturno anómalo UTC (default: 6)")
    parser.add_argument("--verbose", "-v",  action="store_true",    help="Modo detallado")
    # v2.1 — Diferenciación de mercado
    parser.add_argument("--scope", metavar="FICHERO.json",
                        help="Fichero de configuración del entorno (horas laborales, IPs de confianza, etc.)")
    parser.add_argument("--scope-example", action="store_true",
                        help="Mostrar ejemplo de fichero scope.json y salir")
    parser.add_argument("--stix", metavar="FICHERO.json", dest="stix_file",
                        help="Exportar hallazgos como bundle STIX 2.1 (para MISP/OpenCTI/TheHive)")
    parser.add_argument("--package", metavar="FICHERO.zip", dest="package_file",
                        help="Empaquetar evidencias + informes en ZIP sellado con SHA-256")
    parser.add_argument("--learn", metavar="BASELINE.json", dest="learn_file",
                        help="Generar perfil estadístico de comportamiento normal y guardarlo")
    parser.add_argument("--baseline", metavar="BASELINE.json", dest="baseline_file",
                        help="Comparar análisis actual contra un baseline previo (generado con --learn)")
    parser.add_argument("--narrative", choices=["ollama", "claude"], metavar="MOTOR",
                        help="Generar narrativa forense en español con LLM (ollama|claude)")
    parser.add_argument("--narrative-model", metavar="MODELO", default="llama3.2:3b",
                        help="Modelo LLM para la narrativa (default: llama3.2:3b con Ollama)")
    parser.add_argument("--narrative-host", metavar="URL", default="http://127.0.0.1:11434",
                        help="Host Ollama (default: http://127.0.0.1:11434)")
    parser.add_argument("--claude-api-key", metavar="KEY", default="",
                        help="API key de Anthropic para narrativa con Claude")
    parser.add_argument("--sigma-rules", metavar="RUTA", dest="sigma_rules",
                        help="Fichero .yml o directorio con reglas Sigma para detección adicional")
    parser.add_argument("--follow", metavar="FICHERO",
                        help="Modo streaming: monitorizar fichero en tiempo real (tail -f)")

    # Modo --watch-wazuh-api (VampPurple P7)
    parser.add_argument("--watch-wazuh-api", metavar="HOST[:PUERTO]", dest="watch_wazuh_api",
                        help="Vigilancia en tiempo real vía API REST Wazuh (puerto 55000). "
                             "Ejemplo: --watch-wazuh-api https://wazuh.empresa.local:55000")
    parser.add_argument("--wazuh-user", metavar="USUARIO", dest="wazuh_user", default="",
                        help="Usuario API Wazuh (default: var. entorno WAZUH_USER o 'wazuh')")
    parser.add_argument("--wazuh-password", metavar="CLAVE", dest="wazuh_password", default="",
                        help="Contraseña API Wazuh (default: var. entorno WAZUH_PASSWORD o prompt)")
    parser.add_argument("--wazuh-interval", metavar="S", dest="wazuh_interval", type=int, default=30,
                        help="Intervalo de sondeo en segundos (default: 30)")
    parser.add_argument("--wazuh-min-level", metavar="N", dest="wazuh_min_level", type=int, default=7,
                        help="Nivel mínimo de regla Wazuh a reportar (default: 7)")
    parser.add_argument("--wazuh-output", metavar="FICHERO", dest="wazuh_output",
                        help="Fichero NDJSON de salida para ingesta VampPurple (append)")
    parser.add_argument("--wazuh-no-verify", action="store_true", dest="wazuh_no_verify",
                        help="Deshabilitar verificación TLS del servidor Wazuh (no recomendado)")

    args = parser.parse_args()

    # --- Modo --scope-example ---
    if getattr(args, "scope_example", False):
        print(ScopeConfig.ejemplo())
        return 0

    # --- Sin argumentos ---
    if (not args.paths
            and not getattr(args, "follow", None)
            and not getattr(args, "watch_wazuh_api", None)):
        parser.print_help()
        return 0

    # --- Modo --watch-wazuh-api (VampPurple P7) ---
    if getattr(args, "watch_wazuh_api", None):
        return _modo_watch_wazuh_api(args)

    # --- Modo --follow (streaming, no necesita paths obligatorios) ---
    if getattr(args, "follow", None):
        scope: Optional[ScopeConfig] = None
        if getattr(args, "scope", None):
            try:
                scope = ScopeConfig(args.scope)
            except Exception as e:
                print(f"[!] Error cargando scope: {e}", file=sys.stderr)
                return 2
        cfg = build_config(args, scope)
        sa = StreamingAnalyzer(
            path=args.follow,
            log_type=args.type,
            config=cfg,
            min_severity=args.min_severity,
            interval=1.0,
        )
        sa.seguir()
        return 0

    # Resolución de fechas
    time_from = time_to = None
    try:
        if args.time_from:
            time_from = datetime.datetime.strptime(args.time_from, "%Y-%m-%d")
        if args.time_to:
            time_to = datetime.datetime.strptime(args.time_to, "%Y-%m-%d") + datetime.timedelta(days=1)
    except ValueError as e:
        print(f"[!] Fecha inválida: {e}", file=sys.stderr)
        return 2

    # Resolución de rutas
    paths = resolve_paths(args.paths)
    if not paths:
        print("[!] No se encontraron ficheros de log.", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"[*] Analizando {len(paths)} fichero(s)...", file=sys.stderr)

    # Carga de scope
    scope = None
    if getattr(args, "scope", None):
        try:
            scope = ScopeConfig(args.scope)
            print(f"[*] Scope cargado: {args.scope} "
                  f"(org: {scope.organization or 'N/D'}, "
                  f"horario: {scope.business_start}h-{scope.business_end}h, "
                  f"IPs de confianza: {len(scope.trusted_nets)})",
                  file=sys.stderr)
        except Exception as e:
            print(f"[!] Error cargando scope: {e}", file=sys.stderr)
            return 2

    # Cargar reglas Sigma si se especificaron
    sigma_rules: List[SigmaRule] = []
    if getattr(args, "sigma_rules", None):
        sigma_rules = SigmaLoader.load(args.sigma_rules)
        if sigma_rules:
            print(f"[*] {len(sigma_rules)} reglas Sigma cargadas desde: {args.sigma_rules}",
                  file=sys.stderr)
        else:
            print(f"[!] No se cargaron reglas Sigma desde: {args.sigma_rules}", file=sys.stderr)

    # Análisis
    config = build_config(args, scope)
    report = analyze_files(
        paths, args.type, time_from, time_to, config, args.verbose,
        chain_of_custody=args.chain_of_custody,
        analyst=(args.analyst or (scope.analyst_name if scope else "")),
        case=(args.case or (scope.case_name if scope else "")),
        enable_geoip=args.geoip,
        session_gap_min=args.session_gap,
        scope=scope,
        sigma_rules=sigma_rules or None,
    )

    # Filtrar por severidad mínima
    min_rank = _severity_rank(args.min_severity)
    report.findings = [f for f in report.findings if _severity_rank(f.severity) >= min_rank]

    # Mostrar resumen en consola
    print_summary(report)

    # Guardar informes
    alguno_guardado = False

    if args.report_json:
        out = pathlib.Path(args.report_json)
        out.write_text(to_json(report), encoding="utf-8")
        print(f"[✓] JSON guardado en: {out}", file=sys.stderr)
        alguno_guardado = True

    if args.report_html:
        out = pathlib.Path(args.report_html)
        out.write_text(to_html(report), encoding="utf-8")
        print(f"[✓] HTML guardado en: {out}", file=sys.stderr)
        alguno_guardado = True

    if getattr(args, "report_forensic", None):
        out = pathlib.Path(args.report_forensic)
        out.write_text(to_forensic_txt(report), encoding="utf-8")
        print(f"[✓] Informe forense TXT guardado en: {out}", file=sys.stderr)
        alguno_guardado = True

    if getattr(args, "ioc_csv", None):
        out = pathlib.Path(args.ioc_csv)
        out.write_text(to_ioc_csv(report), encoding="utf-8")
        print(f"[✓] IOCs CSV guardado en: {out}", file=sys.stderr)
        alguno_guardado = True

    # v2.1 — Comparativa baseline
    if getattr(args, "baseline_file", None):
        try:
            bl = json.loads(pathlib.Path(args.baseline_file).read_text(encoding="utf-8"))
            report.baseline_delta = BaselineProfiler.comparar(bl, report)
            print("\n" + to_baseline_delta_txt(report.baseline_delta))
        except Exception as e:
            print(f"[!] Error cargando baseline: {e}", file=sys.stderr)

    # v2.1 — Guardar baseline
    if getattr(args, "learn_file", None):
        bl_data = BaselineProfiler.generar(report)
        pathlib.Path(args.learn_file).write_text(
            json.dumps(bl_data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[✓] Baseline guardado en: {args.learn_file}", file=sys.stderr)
        alguno_guardado = True

    # v2.1 — Narrativa LLM
    if getattr(args, "narrative", None):
        print("[*] Generando narrativa forense con IA...", file=sys.stderr)
        if args.narrative == "ollama":
            report.narrative = NarrativeGenerator.ollama(
                report, model=args.narrative_model, host=args.narrative_host)
        else:
            api_key = args.claude_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                print("[!] --claude-api-key o variable ANTHROPIC_API_KEY requerida",
                      file=sys.stderr)
            else:
                report.narrative = NarrativeGenerator.claude(
                    report, api_key=api_key, model="claude-haiku-4-5-20251001")
        if report.narrative and not report.narrative.startswith("["):
            print(f"\n{'─' * 60}")
            print("  NARRATIVA DEL INCIDENTE:")
            print(f"{'─' * 60}")
            for linea in textwrap.wrap(report.narrative, width=72):
                print(f"  {linea}")
            print(f"{'─' * 60}\n")

    # v2.1 — Exportar STIX 2.1
    stix_content = ""
    if getattr(args, "stix_file", None):
        stix_content = to_stix(report)
        pathlib.Path(args.stix_file).write_text(stix_content, encoding="utf-8")
        print(f"[✓] STIX 2.1 bundle guardado en: {args.stix_file}", file=sys.stderr)
        alguno_guardado = True

    # v2.1 — Empaquetar evidencias
    if getattr(args, "package_file", None):
        print("[*] Generando paquete de evidencias...", file=sys.stderr)
        # Asegurar que tengamos el forense TXT y JSON para incluir
        forensic_content = to_forensic_txt(report)
        ioc_content = to_ioc_csv(report)
        json_content = to_json(report)
        if not stix_content:
            stix_content = to_stix(report)
        EvidencePackager.empaquetar(
            paths, report, args.package_file,
            forensic_txt=forensic_content,
            ioc_csv=ioc_content,
            stix_json=stix_content,
            analysis_json=json_content,
        )
        print(f"[✓] Paquete de evidencias guardado en: {args.package_file}", file=sys.stderr)
        alguno_guardado = True

    if not alguno_guardado:
        print(to_json(report))

    # Código de salida
    s = report.summary
    if s["critical"] > 0:
        return 2
    if s["high"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())
