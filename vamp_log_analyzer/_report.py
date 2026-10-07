# © VampSecure Studios — VampSecure Labs Security Research Division
from __future__ import annotations
import csv
import datetime
import hashlib
import io
import json
import pathlib
import textwrap
import uuid
import zipfile
from typing import Dict, List
from ._models import (
    VERSION, TOOL, _severity_rank,
    MITRE_MAPPING, _ip_is_private,
    Report,
)

class STIXExporter:
    """Exporta hallazgos como bundle STIX 2.1 para MISP / OpenCTI / TheHive."""

    @staticmethod
    def exportar(report: "Report") -> str:
        now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

        def new_id(t: str) -> str:
            return f"{t}--{uuid.uuid4()}"

        objs: List[dict] = []

        identity_id = new_id("identity")
        objs.append({
            "type": "identity", "spec_version": "2.1",
            "id": identity_id, "created": now_iso, "modified": now_iso,
            "name": "VampSecure Labs — vamp-log-analyzer",
            "identity_class": "system",
        })

        # Attack-pattern objects from MITRE_MAPPING
        fora_to_ap: Dict[str, str] = {}
        for rule_id, mapping in MITRE_MAPPING.items():
            ap_id = new_id("attack-pattern")
            fora_to_ap[rule_id] = ap_id
            tech = mapping["technique"]
            tech_id = tech.split("—")[0].strip().split()[0] if "—" in tech else ""
            objs.append({
                "type": "attack-pattern", "spec_version": "2.1",
                "id": ap_id, "created": now_iso, "modified": now_iso,
                "name": f"{mapping['tactic']} — {tech.split('—')[0].strip()}",
                "description": tech,
                "external_references": [{"source_name": "mitre-attack",
                                          "external_id": tech_id}],
                "created_by_ref": identity_id,
            })

        # Indicator objects for public IPs with findings
        ip_info: Dict[str, dict] = {}
        for f in report.findings:
            for ip in (f.ips or []):
                cur = ip_info.get(ip, {"sev": "LOW", "rules": set(),
                                        "internal": _ip_is_private(ip)})
                if _severity_rank(f.severity) > _severity_rank(cur["sev"]):
                    cur["sev"] = f.severity
                cur["rules"].add(f.fid)
                ip_info[ip] = cur

        ip_to_ind: Dict[str, str] = {}
        conf_map = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 50, "LOW": 30}
        for ip, info in ip_info.items():
            ind_id = new_id("indicator")
            ip_to_ind[ip] = ind_id
            valid_from = report.time_range_start or now_iso
            scope_note = " [IP interna/privada]" if info.get("internal") else ""
            objs.append({
                "type": "indicator", "spec_version": "2.1",
                "id": ind_id, "created": now_iso, "modified": now_iso,
                "name": f"IP sospechosa: {ip}{scope_note}",
                "description": (f"Severidad máxima: {info['sev']}. "
                                f"Detectores: {', '.join(sorted(info['rules']))}"),
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": valid_from,
                "indicator_types": ["malicious-activity"],
                "confidence": conf_map.get(info["sev"], 50),
                "created_by_ref": identity_id,
            })

        # Observed-data object
        obs_id = new_id("observed-data")
        objs.append({
            "type": "observed-data", "spec_version": "2.1",
            "id": obs_id, "created": now_iso, "modified": now_iso,
            "first_observed": report.time_range_start or now_iso,
            "last_observed": report.time_range_end or now_iso,
            "number_observed": report.total_events_parsed,
            "object_refs": list(ip_to_ind.values())[:200],
            "created_by_ref": identity_id,
        })

        # Relationships: indicator → attack-pattern (deduplicadas)
        seen_rels: set = set()
        for f in report.findings:
            if f.fid not in fora_to_ap:
                continue
            ap_id = fora_to_ap[f.fid]
            for ip in (f.ips or []):
                if ip not in ip_to_ind:
                    continue
                key = (ip_to_ind[ip], ap_id)
                if key in seen_rels:
                    continue
                seen_rels.add(key)
                objs.append({
                    "type": "relationship", "spec_version": "2.1",
                    "id": new_id("relationship"),
                    "created": now_iso, "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": ip_to_ind[ip],
                    "target_ref": ap_id,
                    "created_by_ref": identity_id,
                })

        bundle = {
            "type": "bundle",
            "id": new_id("bundle"),
            "spec_version": "2.1",
            "objects": objs,
        }
        return json.dumps(bundle, ensure_ascii=False, indent=2)


class EvidencePackager:
    """Empaqueta evidencias en un ZIP sellado con SHA-256 (apto para peritaje)."""

    @staticmethod
    def empaquetar(
        log_paths: List[str],
        report: "Report",
        output_zip: str,
        *,
        forensic_txt: str = "",
        ioc_csv: str = "",
        stix_json: str = "",
        analysis_json: str = "",
    ) -> str:
        manifest: List[str] = [
            "# MANIFEST SHA-256 — VampSecure Labs — vamp-log-analyzer",
            f"# Generado     : {datetime.datetime.utcnow().isoformat()}Z",
            f"# Herramienta  : vamp-log-analyzer v{VERSION}",
            f"# Caso         : {report.chain_of_custody.get('case', 'N/D')}",
            f"# Analista     : {report.chain_of_custody.get('analyst', 'N/D')}",
            "",
        ]

        def sha256b(data: bytes) -> str:
            return hashlib.sha256(data).hexdigest()

        with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Ficheros de log originales
            for path in log_paths:
                p = pathlib.Path(path)
                if not p.is_file():
                    continue
                data = p.read_bytes()
                arc = f"evidencias/{p.name}"
                zf.writestr(arc, data)
                manifest.append(f"{sha256b(data)}  {arc}")

            # Informes generados
            reports_to_add = [
                ("informes/informe_forense.txt", forensic_txt),
                ("informes/iocs.csv", ioc_csv),
                ("informes/hallazgos.stix.json", stix_json),
                ("informes/analisis.json", analysis_json),
            ]
            for arc, content in reports_to_add:
                if not content:
                    continue
                data = content.encode("utf-8")
                zf.writestr(arc, data)
                manifest.append(f"{sha256b(data)}  {arc}")

            # Cadena de custodia
            coc_data = json.dumps(
                report.chain_of_custody, ensure_ascii=False, indent=2
            ).encode("utf-8")
            zf.writestr("cadena_de_custodia.json", coc_data)
            manifest.append(f"{sha256b(coc_data)}  cadena_de_custodia.json")

            # Manifiesto final (auto-incluido)
            manifest_txt = "\n".join(manifest) + "\n"
            zf.writestr("MANIFEST.sha256", manifest_txt.encode("utf-8"))

        return output_zip

def to_json(report: Report) -> str:
    """Serializa el informe al esquema JSON unificado VSL."""
    def dt_str(dt):
        return dt.isoformat() if dt else None

    findings_out = []
    for f in report.findings:
        findings_out.append({
            "id": f.fid,
            "severity": f.severity,
            "title": f.title,
            "attack_phase": f.attack_phase,
            "description": f.description,
            "first_seen": dt_str(f.first_seen),
            "last_seen": dt_str(f.last_seen),
            "duration": f.duration_str,
            "affected_ips": f.ips,
            "affected_users": f.users,
            "evidence": f.evidence,
            "remediation": f.remediation,
        })

    obj = {
        "tool": report.tool,
        "version": report.version,
        "timestamp": report.generated,
        "sources": report.sources,
        "time_range": {
            "start": report.time_range_start,
            "end": report.time_range_end,
        },
        "total_events_parsed": report.total_events_parsed,
        "findings": findings_out,
        "summary": report.summary,
        "ip_profiles": list(report.ip_profiles.values())[:100],  # top 100 IPs
        "attack_chain": report.attack_chain,
        "iocs": report.iocs,
        "timeline_analysis": report.timeline_analysis,
        "chain_of_custody": report.chain_of_custody,
        "geoip_data": report.geoip_data,
        "timeline": report.timeline[:500],
    }
    return json.dumps(obj, ensure_ascii=False, indent=2)


def to_forensic_txt(report: Report) -> str:
    """Genera informe forense completo en texto plano apto para peritaje."""
    lineas: List[str] = []
    sep = "=" * 80
    sep2 = "-" * 80

    def sec(titulo: str) -> None:
        lineas.append("")
        lineas.append(sep)
        lineas.append(f"  {titulo}")
        lineas.append(sep)

    def subsec(titulo: str) -> None:
        lineas.append("")
        lineas.append(sep2)
        lineas.append(f"  {titulo}")
        lineas.append(sep2)

    # --- Cabecera ---
    lineas.append(sep)
    lineas.append("  INFORME FORENSE DE ANÁLISIS DE LOGS")
    lineas.append(f"  {TOOL} v{VERSION}  ·  © VampSecure Studios — VampSecure Labs")
    lineas.append(sep)

    # --- Cadena de custodia ---
    coc = report.chain_of_custody
    if coc:
        sec("1. CADENA DE CUSTODIA Y METADATOS DEL ANÁLISIS")
        lineas.append(f"  Perito/Analista     : {coc.get('perito_analizador', '—')}")
        lineas.append(f"  Referencia del caso : {coc.get('referencia_caso', '—')}")
        lineas.append(f"  Fecha de análisis   : {coc.get('fecha_analisis_utc', '—')}")
        lineas.append(f"  Herramienta         : {coc.get('herramienta', '—')}")
        lineas.append("")
        lineas.append("  Ficheros de evidencia analizados:")
        for fich in coc.get("ficheros_evidencia", []):
            lineas.append(f"    · {fich['nombre']}")
            lineas.append(f"        Ruta    : {fich['ruta']}")
            lineas.append(f"        SHA-256 : {fich['sha256']}")
            lineas.append(f"        Tamaño  : {fich['tamaño_bytes']:,} bytes")

    # --- Resumen ejecutivo ---
    sec("2. RESUMEN EJECUTIVO")
    s = report.summary
    lineas.append(f"  Fecha de generación    : {report.generated}")
    lineas.append(f"  Eventos procesados     : {report.total_events_parsed:,}")
    lineas.append(f"  Período analizado      : {report.time_range_start or '?'} → {report.time_range_end or '?'}")
    lineas.append(f"  Ficheros de log        : {len(report.sources)}")
    lineas.append("")
    lineas.append(f"  Hallazgos CRITICAL     : {s['critical']:>4}")
    lineas.append(f"  Hallazgos HIGH         : {s['high']:>4}")
    lineas.append(f"  Hallazgos MEDIUM       : {s['medium']:>4}")
    lineas.append(f"  Hallazgos LOW          : {s['low']:>4}")
    lineas.append(f"  TOTAL HALLAZGOS        : {s['total']:>4}")

    # --- Línea de tiempo ---
    ta = report.timeline_analysis
    if ta:
        sec("3. ANÁLISIS DE LÍNEA DE TIEMPO")
        lineas.append(f"  Primer evento    : {ta.get('primer_evento', '?')}")
        lineas.append(f"  Último evento    : {ta.get('ultimo_evento', '?')}")
        lineas.append(f"  Duración total   : {ta.get('duracion_total_h', 0):.1f} horas")
        lineas.append(f"  Eventos timeline : {ta.get('total_eventos_timeline', 0)}")
        gaps = ta.get("gaps_silencio", [])
        if gaps:
            lineas.append(f"\n  Períodos de silencio (gaps > 1h): {len(gaps)}")
            for g in gaps[:10]:
                lineas.append(f"    [{g['inicio']} → {g['fin']}]  ({g['duracion_h']}h)")
        bursts = ta.get("rafagas", [])
        if bursts:
            lineas.append(f"\n  Ráfagas de actividad detectadas: {len(bursts)}")
            for b in bursts[:10]:
                lineas.append(f"    [{b['inicio']}]  {b['eventos']} eventos en < 60s")
        dist = ta.get("distribucion_por_hora_utc", {})
        if dist:
            lineas.append("\n  Actividad por hora UTC (0h-23h):")
            max_c = max(int(v) for v in dist.values()) if dist else 1
            for h in range(24):
                c = int(dist.get(str(h), 0))
                bar = "█" * int(c * 30 / max_c) if max_c > 0 else ""
                lineas.append(f"    {h:02d}h  {bar:<30} {c}")

    # --- Cadena de ataque MITRE ---
    if report.attack_chain:
        sec("4. CADENA DE ATAQUE — MITRE ATT&CK")
        for tactica, hallazgos in report.attack_chain.items():
            lineas.append(f"\n  [{tactica}]")
            for h in hallazgos:
                lineas.append(f"    · {h['fid']} [{h['severidad']}]  {h['titulo'][:60]}")
                lineas.append(f"      Técnica: {h['tecnica_mitre']}")
                if h["ips"]:
                    lineas.append(f"      IPs   : {', '.join(h['ips'])}")

    # --- Sesiones reconstruidas ---
    if report.sessions:
        sec("5. SESIONES DE ATACANTE RECONSTRUIDAS")
        for i, ses in enumerate(report.sessions[:30], 1):
            lineas.append(f"\n  SESIÓN #{i}  IP: {ses['ip']}")
            lineas.append(f"    Período    : {ses['inicio']} → {ses['fin']}")
            lineas.append(f"    Eventos    : {ses['num_eventos']}")
            if ses["hallazgos_fid"]:
                lineas.append(f"    Hallazgos : {', '.join(ses['hallazgos_fid'][:8])}")
            if ses["acciones"]:
                lineas.append(f"    Acciones  : {', '.join(ses['acciones'][:8])}")
            if ses["rutas_accedidas"]:
                lineas.append("    Rutas:")
                for r in ses["rutas_accedidas"][:5]:
                    lineas.append(f"      · {r}")

    # --- IOCs ---
    iocs = report.iocs
    if iocs:
        sec("6. INDICADORES DE COMPROMISO (IOCs)")
        ips_ioc = iocs.get("ips_atacantes", [])
        if ips_ioc:
            lineas.append(f"\n  IPs atacantes ({len(ips_ioc)} únicas):")
            for entry in ips_ioc[:50]:
                geo = report.geoip_data.get(entry["ip"], {})
                geo_str = f"  [{geo.get('pais', '')} / {geo.get('isp', '')}]" if geo else ""
                lineas.append(f"    · {entry['ip']:<18} [{entry['severidad_max']:<8}]{geo_str}")
                lineas.append(f"      Hallazgos: {', '.join(entry['hallazgos'][:5])}")
        rutas_ioc = iocs.get("rutas_objetivo", [])
        if rutas_ioc:
            lineas.append("\n  Rutas objetivo más atacadas:")
            for entry in rutas_ioc[:20]:
                lineas.append(f"    · ({entry['ocurrencias']:>4}x)  {entry['ruta']}")
        ua_ioc = iocs.get("user_agents_sospechosos", [])
        if ua_ioc:
            lineas.append("\n  User-Agents de herramientas de ataque:")
            for entry in ua_ioc[:10]:
                lineas.append(f"    · ({entry['ocurrencias']:>3}x)  {entry['ua'][:100]}")
        usr_ioc = iocs.get("usuarios_objetivo", [])
        if usr_ioc:
            lineas.append("\n  Usuarios objetivo (cuentas atacadas):")
            for entry in usr_ioc[:20]:
                lineas.append(f"    · ({entry['ocurrencias']:>4}x)  {entry['usuario']}")

    # --- Perfiles de actividad por IP ---
    if report.ip_profiles:
        sec("7. PERFILES DE ACTIVIDAD POR IP")
        lineas.append(f"  Total IPs únicas detectadas: {len(report.ip_profiles)}")
        for ip, p in list(report.ip_profiles.items())[:50]:  # máximo 50 perfiles
            geo = report.geoip_data.get(ip, {})
            geo_str = f"  [{geo.get('pais','')} · {geo.get('isp','')}]" if geo else ""
            lineas.append("")
            lineas.append(sep2)
            lineas.append(f"  IP: {ip}{geo_str}")
            lineas.append(sep2)
            lineas.append(f"  Total eventos    : {p['total_eventos']:,}")
            lineas.append(f"  Período activo   : {p['primer_evento'] or '?'} → {p['ultimo_evento'] or '?'}")
            lineas.append(f"  Días activo      : {p['num_dias']}  ({', '.join(p['dias_activo'][:14])}{'…' if len(p['dias_activo'])>14 else ''})")
            if p["usuarios_cuentas"]:
                lineas.append(f"  Cuentas/usuarios : {', '.join(p['usuarios_cuentas'][:10])}")
            if p["fuentes_log"]:
                lineas.append(f"  Ficheros de log  : {', '.join(p['fuentes_log'][:5])}")
            # Franjas horarias
            lineas.append("  Franjas horarias (UTC):")
            lineas.append(f"    Madrugada 00-06h : {p['franja_madrugada_0_6h']:>5} eventos")
            lineas.append(f"    Mañana    06-12h : {p['franja_manana_6_12h']:>5} eventos")
            lineas.append(f"    Tarde     12-18h : {p['franja_tarde_12_18h']:>5} eventos")
            lineas.append(f"    Noche     18-24h : {p['franja_noche_18_24h']:>5} eventos")
            # Distribución por hora (gráfico ASCII)
            dist = p["distribucion_hora_utc"]
            max_h = max((v for v in dist.values()), default=1)
            lineas.append("  Distribución horaria UTC:")
            for h in range(24):
                c = dist.get(str(h), 0)
                bar = "█" * int(c * 25 / max_h) if max_h > 0 and c > 0 else ""
                marker = " ◄" if c == max_h and max_h > 0 else ""
                lineas.append(f"    {h:02d}h  {bar:<25} {c:>5}{marker}")
            # Días de la semana
            if p["distribucion_diasemana"]:
                diasem_str = "  ".join(
                    f"{d}:{c}" for d, c in p["distribucion_diasemana"].items()
                )
                lineas.append(f"  Actividad por día semana: {diasem_str}")
            # Acciones
            if p["acciones"]:
                acc_str = ", ".join(f"{a}×{c}" for a, c in list(p["acciones"].items())[:8])
                lineas.append(f"  Acciones         : {acc_str}")
            # Auth
            if p["exitos_auth"] or p["fallos_auth"]:
                lineas.append(f"  Auth             : ✓ {p['exitos_auth']} éxitos · ✗ {p['fallos_auth']} fallos")
            # HTTP
            if p["exitos_http"] or p["fallos_http"]:
                lineas.append(f"  HTTP             : 2xx={p['exitos_http']} · 4xx/5xx={p['fallos_http']}")
            if p["bytes_total"]:
                mb = p["bytes_total"] / 1_048_576
                lineas.append(f"  Bytes transferidos: {mb:.1f} MB ({p['bytes_total']:,} bytes)")
            # Rutas top
            if p["recursos_top"]:
                lineas.append("  Rutas más accedidas:")
                for entry in p["recursos_top"][:10]:
                    lineas.append(f"    ({entry['accesos']:>4}×)  {entry['ruta']}")

    # --- Baseline delta ---
    if report.baseline_delta:
        sec("8. ANÁLISIS DIFERENCIAL CONTRA BASELINE")
        lineas.append(to_baseline_delta_txt(report.baseline_delta))

    # --- Narrativa LLM ---
    if report.narrative:
        sec("9. NARRATIVA DEL INCIDENTE (GENERADA POR IA)")
        for linea in textwrap.wrap(report.narrative, width=72):
            lineas.append(f"  {linea}")
        lineas.append("")

    # --- Hallazgos detallados ---
    n_sec = 10 if (report.baseline_delta or report.narrative) else 8
    sec(f"{n_sec}. HALLAZGOS DETALLADOS")
    for f in report.findings:
        subsec(f"{f.fid} [{f.severity}] — {f.title}")
        lineas.append(f"  Descripción  : {f.description}")
        lineas.append(f"  Fase ATT&CK  : {f.attack_phase}")
        ts_ini = f.first_seen.strftime("%Y-%m-%d %H:%M:%S") if f.first_seen else "?"
        ts_fin = f.last_seen.strftime("%Y-%m-%d %H:%M:%S") if f.last_seen else "?"
        lineas.append(f"  Período      : {ts_ini} → {ts_fin} ({f.duration_str})")
        lineas.append(f"  IPs          : {', '.join(f.ips[:10]) or '—'}")
        lineas.append(f"  Usuarios     : {', '.join(f.users[:10]) or '—'}")
        lineas.append(f"  Remediación  : {f.remediation}")
        if f.evidence:
            lineas.append("  Evidencias (máx 10 líneas):")
            for ev in f.evidence[:10]:
                lineas.append(f"    > {ev[:200]}")

    # --- Pie de informe ---
    lineas.append("")
    lineas.append(sep)
    lineas.append(f"  FIN DEL INFORME  ·  {TOOL} v{VERSION}")
    lineas.append("  © VampSecure Studios — VampSecure Labs Security Research Division")
    lineas.append("  Uso exclusivo en entornos autorizados.")
    lineas.append(sep)

    return "\n".join(lineas)


def to_ioc_csv(report: Report) -> str:
    """Exporta los IOCs en formato CSV para importar en SIEM o plataformas de inteligencia."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow(["tipo", "valor", "severidad", "hallazgos", "pais", "isp", "notas"])

    iocs = report.iocs
    for entry in iocs.get("ips_atacantes", []):
        geo = report.geoip_data.get(entry["ip"], {})
        writer.writerow([
            "ip",
            entry["ip"],
            entry["severidad_max"],
            " | ".join(entry["hallazgos"][:10]),
            geo.get("pais", ""),
            geo.get("isp", ""),
            geo.get("asn", ""),
        ])
    for entry in iocs.get("rutas_objetivo", []):
        writer.writerow([
            "url_path",
            entry["ruta"],
            "HIGH",
            f"ocurrencias:{entry['ocurrencias']}",
            "", "", "",
        ])
    for entry in iocs.get("user_agents_sospechosos", []):
        writer.writerow([
            "user_agent",
            entry["ua"],
            "MEDIUM",
            f"ocurrencias:{entry['ocurrencias']}",
            "", "", "",
        ])
    for entry in iocs.get("usuarios_objetivo", []):
        writer.writerow([
            "username",
            entry["usuario"],
            "MEDIUM",
            f"ocurrencias:{entry['ocurrencias']}",
            "", "", "",
        ])

    return buf.getvalue()


def to_stix(report: Report) -> str:
    """Exporta hallazgos como STIX 2.1 bundle (delegado a STIXExporter)."""
    return STIXExporter.exportar(report)


def to_baseline_delta_txt(delta: dict) -> str:
    """Genera texto legible de la comparativa contra baseline."""
    lines = [
        "=" * 72,
        "ANÁLISIS DIFERENCIAL — COMPARATIVA CONTRA BASELINE",
        "=" * 72,
        f"Baseline creado : {delta.get('baseline_created', 'N/D')}",
        f"Fuentes baseline: {', '.join(delta.get('baseline_sources', []))}",
        "",
    ]
    def section(title: str, items: list, fmt=str):
        lines.append(f"  {title}:")
        if items:
            for it in items:
                lines.append(f"    • {fmt(it)}")
        else:
            lines.append("    (ninguno)")
        lines.append("")

    section("IPs NUEVAS (no vistas en baseline)",
            delta.get("nuevas_ips", []))
    section("IPs DESAPARECIDAS (presentes en baseline, no ahora)",
            delta.get("ips_desaparecidas", []))

    act = delta.get("ips_nuevas_alta_actividad", [])
    if act:
        lines.append("  IPs NUEVAS CON ALTA ACTIVIDAD:")
        for x in act:
            lines.append(
                f"    • {x['ip']:<18} {x['eventos']:>6} eventos "
                f"| {x['dias']} día(s) | pico {x.get('pico_hora', '?')}h UTC")
        lines.append("")

    section("DETECTORES NUEVOS (no disparados en baseline)",
            delta.get("nuevos_detectores", []))
    section("DETECTORES DESAPARECIDOS (presentes en baseline, no ahora)",
            delta.get("detectores_desaparecidos", []))

    anom = delta.get("anomalias_horarias", [])
    if anom:
        lines.append("  ANOMALÍAS HORARIAS (>3σ respecto baseline):")
        for a in anom[:15]:
            lines.append(
                f"    • {a['ip']:<18} hora {a['hora_utc']:02d}h UTC "
                f"→ {a['eventos']} ev  (media baseline: {a['media_baseline']}, "
                f"+{a['desviaciones_std']}σ)")
        lines.append("")

    lines += [
        "  RESUMEN COMPARATIVO:",
        "  " + "-" * 50,
    ]
    rb = delta.get("resumen_baseline", {})
    ra = delta.get("resumen_actual", {})
    for sev in ("critical", "high", "medium", "low"):
        b = rb.get(sev, 0)
        a = ra.get(sev, 0)
        diff = a - b
        arrow = ("▲" if diff > 0 else "▼" if diff < 0 else "═")
        lines.append(
            f"  {sev.upper():<8}  baseline: {b:>4}  actual: {a:>4}  "
            f"{arrow} {abs(diff):+d}")
    lines.append("")
    return "\n".join(lines)


def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": "#dc2626",
        "HIGH":     "#f97316",
        "MEDIUM":   "#eab308",
        "LOW":      "#3b82f6",
        "INFO":     "#6b7280",
    }.get(sev, "#6b7280")


def _sev_bg(sev: str) -> str:
    return {
        "CRITICAL": "rgba(220,38,38,.12)",
        "HIGH":     "rgba(249,115,22,.10)",
        "MEDIUM":   "rgba(234,179,8,.10)",
        "LOW":      "rgba(59,130,246,.10)",
        "INFO":     "rgba(107,114,128,.08)",
    }.get(sev, "rgba(107,114,128,.08)")


def to_html(report: Report) -> str:
    s = report.summary
    risk_score = min(100, s["critical"] * 25 + s["high"] * 10 + s["medium"] * 5 + s["low"] * 1)
    risk_color = "#dc2626" if risk_score >= 75 else "#f97316" if risk_score >= 40 else "#eab308" if risk_score >= 15 else "#3b82f6"
    risk_label = "CRÍTICO" if risk_score >= 75 else "ALTO" if risk_score >= 40 else "MODERADO" if risk_score >= 15 else "BAJO"

    # --- Findings HTML ---
    findings_html = ""
    for f in report.findings:
        evidence_lines = "\n".join(
            f"<div class='ev-line'><span class='ev-num'>{i+1}</span><code>{_esc(line)}</code></div>"
            for i, line in enumerate(f.evidence)
        )
        ips_html = " ".join(f"<span class='chip'>{_esc(ip)}</span>" for ip in f.ips[:8])
        users_html = " ".join(f"<span class='chip'>{_esc(u)}</span>" for u in f.users[:8])
        ts_html = (
            f"<span class='ts'>{f.first_seen.strftime('%Y-%m-%d %H:%M:%S')} UTC</span>"
            if f.first_seen else "<span class='ts'>—</span>"
        )
        dur_html = f" → {f.duration_str}" if f.duration_str != "—" else ""
        findings_html += f"""
        <div class="finding" id="{f.fid}">
          <div class="finding-header" onclick="toggle('{f.fid}-body')">
            <div class="finding-id">{f.fid}</div>
            <div class="finding-sev" style="background:{_sev_bg(f.severity)};color:{_sev_color(f.severity)}">{f.severity}</div>
            <div class="finding-title">{_esc(f.title)}</div>
            <div class="finding-phase">{_esc(f.attack_phase)}</div>
            <div class="finding-ts">{ts_html}{dur_html}</div>
            <div class="finding-toggle">▾</div>
          </div>
          <div class="finding-body" id="{f.fid}-body" style="display:none">
            <p class="finding-desc">{_esc(f.description)}</p>
            <div class="finding-meta-row">
              {f'<div class="meta-group"><span class="meta-label">IPs</span>{ips_html}</div>' if f.ips else ''}
              {f'<div class="meta-group"><span class="meta-label">Usuarios</span>{users_html}</div>' if f.users else ''}
            </div>
            <div class="evidence-block">
              <div class="evidence-title">Evidencias ({len(f.evidence)} entradas)</div>
              {evidence_lines}
            </div>
            <div class="remediation-block">
              <div class="remediation-title">Remediación</div>
              <p>{_esc(f.remediation)}</p>
            </div>
          </div>
        </div>"""

    # --- Timeline HTML ---
    timeline_html = ""
    for entry in report.timeline[:300]:
        sev = entry.get("severity", "INFO")
        ts_display = (entry.get("ts") or "")[:19].replace("T", " ")
        resource = _esc((entry.get("resource") or "")[:80])
        ip_display = _esc(entry.get("ip") or "")
        user_display = _esc(entry.get("user") or "")
        action_display = _esc(entry.get("action") or "")
        source_display = _esc(entry.get("source") or "")
        status = entry.get("status")
        fid = entry.get("finding") or ""
        timeline_html += f"""
        <tr class="tl-row" data-sev="{sev}">
          <td class="tl-ts">{ts_display}</td>
          <td><span class="tl-sev" style="color:{_sev_color(sev)}">{sev}</span></td>
          <td class="tl-source">{source_display}</td>
          <td class="tl-ip">{ip_display}</td>
          <td class="tl-user">{user_display}</td>
          <td class="tl-action">{action_display}</td>
          <td class="tl-resource">{resource}</td>
          <td>{status or '—'}</td>
          <td>{f'<a href="#{fid}" class="fid-link">{fid}</a>' if fid else ''}</td>
        </tr>"""

    # --- Summary bars ---
    max_count = max(s.values()) if any(s.values()) else 1
    bars_html = ""
    for sev, label, key in [
        ("CRITICAL", "Crítico", "critical"),
        ("HIGH",     "Alto",    "high"),
        ("MEDIUM",   "Medio",   "medium"),
        ("LOW",      "Bajo",    "low"),
    ]:
        count = s[key]
        pct = int(count / max_count * 100) if max_count else 0
        bars_html += f"""
        <div class="bar-row">
          <span class="bar-label" style="color:{_sev_color(sev)}">{label}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{_sev_color(sev)}"></div></div>
          <span class="bar-count">{count}</span>
        </div>"""

    sources_list = "\n".join(f"<li><code>{_esc(p)}</code></li>" for p in report.sources)
    ts_range = ""
    if report.time_range_start and report.time_range_end:
        ts_range = f"{report.time_range_start[:19]} UTC → {report.time_range_end[:19]} UTC"
    elif report.time_range_start:
        ts_range = f"desde {report.time_range_start[:19]} UTC"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe Forense — {TOOL} v{VERSION}</title>
<style>
:root {{
  --bg: #070b14; --bg2: #0d1220; --bg3: #111827;
  --border: #1e2a3a; --text: #e2e8f0; --muted: #64748b;
  --accent: #00d4ff; --mono: 'Cascadia Code','Fira Code','Consolas',monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: system-ui,sans-serif; font-size: 14px; line-height: 1.6; }}
a {{ color: var(--accent); }}
.wrap {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem; }}
/* Header */
.report-header {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 2rem; margin-bottom: 1.5rem; display: flex; gap: 2rem; align-items: flex-start; flex-wrap: wrap; }}
.rh-title {{ flex: 1; }}
.rh-badge {{ font-size: .7rem; font-family: var(--mono); color: var(--accent); text-transform: uppercase; letter-spacing: .15em; margin-bottom: .5rem; }}
.rh-title h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: .25rem; }}
.rh-meta {{ color: var(--muted); font-size: .8rem; line-height: 1.9; }}
.rh-meta code {{ font-family: var(--mono); font-size: .75rem; color: var(--accent); }}
/* Gauge */
.gauge-wrap {{ text-align: center; min-width: 140px; }}
.gauge-score {{ font-size: 2.5rem; font-weight: 800; font-variant-numeric: tabular-nums; }}
.gauge-label {{ font-size: .7rem; font-family: var(--mono); text-transform: uppercase; letter-spacing: .12em; margin-top: .2rem; }}
/* Cards */
.cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
.card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; }}
.card-n {{ font-size: 2rem; font-weight: 800; font-variant-numeric: tabular-nums; }}
.card-l {{ font-size: .7rem; color: var(--muted); text-transform: uppercase; letter-spacing: .1em; margin-top: .15rem; }}
/* Bars */
.bars {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }}
.bars h2 {{ font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .1em; margin-bottom: 1rem; }}
.bar-row {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .6rem; }}
.bar-label {{ width: 60px; font-size: .75rem; font-weight: 600; }}
.bar-track {{ flex: 1; background: var(--bg3); border-radius: 4px; height: 6px; overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 4px; transition: width .4s; }}
.bar-count {{ width: 30px; text-align: right; font-family: var(--mono); font-size: .75rem; color: var(--muted); }}
/* Section */
.section {{ margin-bottom: 2rem; }}
.section-title {{ font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .1em; margin-bottom: 1rem; padding-bottom: .5rem; border-bottom: 1px solid var(--border); }}
/* Findings */
.finding {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: .75rem; overflow: hidden; }}
.finding-header {{ display: flex; align-items: center; gap: .75rem; padding: .9rem 1.1rem; cursor: pointer; flex-wrap: wrap; transition: background .15s; }}
.finding-header:hover {{ background: var(--bg3); }}
.finding-id {{ font-family: var(--mono); font-size: .72rem; color: var(--muted); min-width: 72px; }}
.finding-sev {{ font-size: .68rem; font-family: var(--mono); text-transform: uppercase; letter-spacing: .1em; padding: .2rem .6rem; border-radius: 4px; font-weight: 700; white-space: nowrap; }}
.finding-title {{ flex: 1; font-weight: 600; font-size: .9rem; }}
.finding-phase {{ font-size: .72rem; color: var(--muted); font-family: var(--mono); }}
.finding-ts {{ font-size: .72rem; color: var(--muted); font-family: var(--mono); white-space: nowrap; }}
.finding-toggle {{ color: var(--muted); font-size: .8rem; }}
.finding-body {{ padding: 1.25rem 1.4rem; background: var(--bg3); border-top: 1px solid var(--border); }}
.finding-desc {{ color: #94a3b8; margin-bottom: 1rem; font-size: .88rem; }}
.finding-meta-row {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1rem; }}
.meta-group {{ display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }}
.meta-label {{ font-size: .68rem; font-family: var(--mono); color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }}
.chip {{ background: rgba(0,212,255,.08); border: 1px solid rgba(0,212,255,.2); color: var(--accent); font-family: var(--mono); font-size: .72rem; padding: .1rem .5rem; border-radius: 4px; }}
.evidence-block {{ background: #060910; border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 6px; padding: 1rem; margin-bottom: 1rem; overflow-x: auto; }}
.evidence-title {{ font-size: .7rem; font-family: var(--mono); color: var(--muted); text-transform: uppercase; letter-spacing: .1em; margin-bottom: .6rem; }}
.ev-line {{ display: flex; gap: .75rem; margin-bottom: .25rem; }}
.ev-num {{ color: var(--muted); font-family: var(--mono); font-size: .72rem; min-width: 22px; text-align: right; padding-top: .05em; }}
.ev-line code {{ font-family: var(--mono); font-size: .75rem; color: #a8d8ea; line-height: 1.6; word-break: break-all; }}
.remediation-block {{ background: rgba(74,222,128,.04); border: 1px solid rgba(74,222,128,.15); border-radius: 6px; padding: 1rem; }}
.remediation-title {{ font-size: .7rem; font-family: var(--mono); color: #4ade80; text-transform: uppercase; letter-spacing: .1em; margin-bottom: .4rem; }}
.remediation-block p {{ color: #94a3b8; font-size: .85rem; }}
.ts {{ font-family: var(--mono); font-size: .75rem; }}
/* Timeline */
.tl-controls {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: .75rem; }}
.tl-btn {{ background: var(--bg3); border: 1px solid var(--border); color: var(--muted); font-size: .72rem; font-family: var(--mono); padding: .25rem .7rem; border-radius: 4px; cursor: pointer; transition: all .15s; }}
.tl-btn:hover, .tl-btn.active {{ border-color: var(--accent); color: var(--accent); }}
.tl-search {{ background: var(--bg3); border: 1px solid var(--border); color: var(--text); font-size: .78rem; font-family: var(--mono); padding: .25rem .7rem; border-radius: 4px; outline: none; width: 220px; }}
.tl-search:focus {{ border-color: var(--accent); }}
.tl-table-wrap {{ overflow-x: auto; background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; }}
table {{ width: 100%; border-collapse: collapse; font-size: .78rem; }}
thead th {{ background: var(--bg3); color: var(--muted); font-family: var(--mono); font-size: .68rem; text-transform: uppercase; letter-spacing: .08em; padding: .6rem .75rem; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; position: sticky; top: 0; }}
.tl-row td {{ padding: .45rem .75rem; border-bottom: 1px solid rgba(30,42,58,.6); vertical-align: top; }}
.tl-row:last-child td {{ border-bottom: none; }}
.tl-row:hover td {{ background: var(--bg3); }}
.tl-ts {{ font-family: var(--mono); font-size: .72rem; color: var(--muted); white-space: nowrap; }}
.tl-sev {{ font-family: var(--mono); font-size: .68rem; font-weight: 700; }}
.tl-source {{ font-family: var(--mono); font-size: .72rem; color: var(--muted); }}
.tl-ip {{ font-family: var(--mono); font-size: .72rem; }}
.tl-user {{ font-family: var(--mono); font-size: .72rem; color: #c084fc; }}
.tl-action {{ font-family: var(--mono); font-size: .72rem; color: var(--accent); }}
.tl-resource {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); font-size: .72rem; color: #94a3b8; }}
.fid-link {{ font-family: var(--mono); font-size: .7rem; }}
/* Sources */
.sources-list {{ list-style: none; }}
.sources-list li {{ padding: .3rem 0; border-bottom: 1px solid var(--border); }}
.sources-list li:last-child {{ border-bottom: none; }}
.sources-list code {{ font-family: var(--mono); font-size: .8rem; color: var(--accent); }}
/* Footer */
.footer {{ text-align: center; color: var(--muted); font-size: .75rem; padding: 2rem 0 1rem; border-top: 1px solid var(--border); margin-top: 3rem; }}
</style>
</head>
<body>
<div class="wrap">

  <!-- CABECERA -->
  <div class="report-header">
    <div class="rh-title">
      <div class="rh-badge">© VampSecure Studios — VampSecure Labs Security Research Division</div>
      <h1>Informe Forense de Logs</h1>
      <div class="rh-meta">
        Herramienta: <code>{TOOL} v{VERSION}</code><br>
        Generado: <code>{report.generated}</code><br>
        {f'Período analizado: <code>{ts_range}</code><br>' if ts_range else ''}
        Eventos procesados: <code>{report.total_events_parsed:,}</code> &nbsp;·&nbsp;
        Hallazgos: <code>{len(report.findings)}</code><br>
        Fuentes: <code>{len(report.sources)}</code> fichero(s) de log
      </div>
    </div>
    <div class="gauge-wrap">
      <div class="gauge-score" style="color:{risk_color}">{risk_score}</div>
      <div class="gauge-label" style="color:{risk_color}">Riesgo {risk_label}</div>
    </div>
  </div>

  <!-- TARJETAS RESUMEN -->
  <div class="cards">
    <div class="card"><div class="card-n" style="color:#dc2626">{s["critical"]}</div><div class="card-l">Críticos</div></div>
    <div class="card"><div class="card-n" style="color:#f97316">{s["high"]}</div><div class="card-l">Altos</div></div>
    <div class="card"><div class="card-n" style="color:#eab308">{s["medium"]}</div><div class="card-l">Medios</div></div>
    <div class="card"><div class="card-n" style="color:#3b82f6">{s["low"]}</div><div class="card-l">Bajos</div></div>
    <div class="card"><div class="card-n">{report.total_events_parsed:,}</div><div class="card-l">Eventos</div></div>
    <div class="card"><div class="card-n">{len(report.timeline):,}</div><div class="card-l">En timeline</div></div>
  </div>

  <!-- BARRAS -->
  <div class="bars">
    <h2>Distribución de hallazgos</h2>
    {bars_html}
  </div>

  <!-- HALLAZGOS -->
  <div class="section">
    <div class="section-title">Hallazgos de seguridad ({len(report.findings)})</div>
    {findings_html if findings_html else '<p style="color:var(--muted);padding:.5rem 0">Sin hallazgos detectados.</p>'}
  </div>

  <!-- LÍNEA DE TIEMPO -->
  <div class="section">
    <div class="section-title">Línea de tiempo ({len(report.timeline)} eventos)</div>
    <div class="tl-controls">
      <input class="tl-search" type="text" placeholder="Filtrar por IP, usuario, acción..." oninput="filterTimeline(this.value)">
      <button class="tl-btn active" onclick="filterSev('ALL', this)">Todo</button>
      <button class="tl-btn" onclick="filterSev('CRITICAL', this)" style="color:#dc2626">Crítico</button>
      <button class="tl-btn" onclick="filterSev('HIGH', this)" style="color:#f97316">Alto</button>
      <button class="tl-btn" onclick="filterSev('MEDIUM', this)" style="color:#eab308">Medio</button>
      <button class="tl-btn" onclick="filterSev('LOW', this)" style="color:#3b82f6">Bajo</button>
    </div>
    <div class="tl-table-wrap">
      <table id="tl-table">
        <thead>
          <tr>
            <th>Timestamp (UTC)</th>
            <th>Severidad</th>
            <th>Fuente</th>
            <th>IP</th>
            <th>Usuario</th>
            <th>Acción</th>
            <th>Recurso</th>
            <th>Status</th>
            <th>Hallazgo</th>
          </tr>
        </thead>
        <tbody id="tl-body">
          {timeline_html}
        </tbody>
      </table>
    </div>
  </div>

  <!-- FUENTES -->
  <div class="section">
    <div class="section-title">Fuentes analizadas</div>
    <ul class="sources-list">{sources_list}</ul>
  </div>

  <div class="footer">
    © VampSecure Studios — VampSecure Labs Security Research Division<br>
    Uso exclusivo en sistemas con autorización explícita por escrito.
  </div>
</div>

<script>
function toggle(id) {{
  var el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}

var _sevFilter = 'ALL';
var _textFilter = '';

function filterTimeline(val) {{
  _textFilter = val.toLowerCase();
  _applyFilters();
}}

function filterSev(sev, btn) {{
  _sevFilter = sev;
  document.querySelectorAll('.tl-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  if (btn) btn.classList.add('active');
  _applyFilters();
}}

function _applyFilters() {{
  var rows = document.querySelectorAll('#tl-body .tl-row');
  rows.forEach(function(row) {{
    var sev = row.dataset.sev || '';
    var txt = row.textContent.toLowerCase();
    var sevOk = _sevFilter === 'ALL' || sev === _sevFilter;
    var txtOk = !_textFilter || txt.indexOf(_textFilter) !== -1;
    row.style.display = (sevOk && txtOk) ? '' : 'none';
  }});
}}

// Abrir primer hallazgo crítico/alto automáticamente
(function() {{
  var first = document.querySelector('.finding-header');
  if (first) first.click();
}})();
</script>
</body>
</html>"""


def _esc(s: str) -> str:
    """Escapa HTML básico para incluir texto en el informe."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
