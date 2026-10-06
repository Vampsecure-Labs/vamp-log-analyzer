# © VampSecure Studios — VampSecure Labs Security Research Division
from __future__ import annotations
import base64
import collections
import csv
import dataclasses
import datetime
import gzip
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import re
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, Generator, List, Optional, Tuple
try:
    import yaml as _yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False
from ._models import (
    VERSION, TOOL, TOOL_NAME, FINDING_PREFIX,
    RE_SQLI, RE_XSS, RE_TRAVERSAL, RE_WEBSHELL, RE_RFI,
    RE_SCANNER_UA, RE_SCANNER_PATH, RE_SENSITIVE_FILES,
    RE_SUDO_PRIVESC, RE_SU_ROOT, RE_SUID_WRITE, RE_CRON_SUSPICIOUS,
    RE_LATERAL_SSH, RE_ROOT_LOGIN, RE_WIN_SUSPICIOUS_CMD, RE_WIN_LSASS,
    RE_WIN_LATERAL, RE_WIN_PERSISTENCE, RE_WIN_EVASION,
    RE_APACHE, _APACHE_TS_FMT, RE_MYSQL_TS, RE_MYSQL_GEN, RE_MYSQL_SLOW,
    RE_MONGO_TS, RE_AUTH_TS, RE_AUTH_SSH_FAIL, RE_AUTH_SSH_OK,
    RE_AUTH_SUDO, RE_AUTH_SU, RE_AUTH_NEW_USER, RE_AUTH_CRON,
    RE_SYSLOG_TS, RE_GENERIC_TS, RE_GENERIC_IP,
    RE_OSSEC_ALERT_HDR, RE_OSSEC_HOST_LINE,
    MITRE_MAPPING, BEACON_EXCLUDE_PATHS, _SIGMA_FIELD_MAP,
    _severity_rank, _ip_is_private,
    _BSD_MONTHS, _CURRENT_YEAR,
    LogEvent, Finding, Report, SigmaRule, ScopeConfig,
)

def _open_file(path: str):
    """Abre un fichero normal o gzip transparentemente."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def _ts_to_utc(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    """Convierte a UTC (sin tz → asume local; ya en UTC → no toca)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt  # se trata como UTC si no hay info de zona
    return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def parse_apache(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            m = RE_APACHE.match(line)
            if not m:
                continue
            ts_raw = m.group("ts")
            try:
                ts = _ts_to_utc(datetime.datetime.strptime(ts_raw, _APACHE_TS_FMT))
            except ValueError:
                ts = None
            try:
                status = int(m.group("status"))
            except (ValueError, TypeError):
                status = None
            bytes_raw = m.group("bytes")
            bytes_out = int(bytes_raw) if bytes_raw and bytes_raw != "-" else None
            ip = m.group("ip")
            if ip == "-":
                ip = None
            user = m.group("user")
            if user == "-":
                user = None
            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="web", raw=line,
                ip=ip, user=user,
                action=m.group("method"), resource=m.group("resource"),
                status=status, bytes_out=bytes_out,
                user_agent=m.group("ua") or None,
            )


# --- IIS W3C Extended Log Format ---
def parse_iis(path: str) -> Generator[LogEvent, None, None]:
    headers: List[str] = []
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if line.startswith("#Fields:"):
                headers = line[9:].strip().split()
                continue
            if line.startswith("#"):
                continue
            if not headers:
                continue
            parts = line.split()
            if len(parts) < len(headers):
                continue
            rec = dict(zip(headers, parts))
            ts = None
            date_str = rec.get("date", "")
            time_str = rec.get("time", "")
            if date_str and time_str:
                try:
                    ts = datetime.datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass
            try:
                status = int(rec.get("sc-status", 0)) or None
            except ValueError:
                status = None
            try:
                bytes_out = int(rec.get("sc-bytes", 0)) or None
            except ValueError:
                bytes_out = None
            resource = rec.get("cs-uri-stem", "")
            qs = rec.get("cs-uri-query", "")
            if qs and qs != "-":
                resource = f"{resource}?{qs}"
            ip = rec.get("c-ip") or rec.get("c-ip", None)
            if ip == "-":
                ip = None
            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="web", raw=line,
                ip=ip, user=rec.get("cs-username") if rec.get("cs-username") != "-" else None,
                action=rec.get("cs-method"), resource=resource,
                status=status, bytes_out=bytes_out,
                user_agent=rec.get("cs(User-Agent)") if rec.get("cs(User-Agent)", "-") != "-" else None,
            )


def parse_mysql(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        block_lines: List[str] = []
        block_start = 0
        current_ts = None
        current_ip = None
        current_user = None

        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")

            # slow query: encabezado de bloque
            m_slow = RE_MYSQL_SLOW.match(raw)
            if m_slow:
                if block_lines:
                    yield LogEvent(
                        timestamp=current_ts, source_file=path, source_line=block_start,
                        log_type="db_mysql", raw="\n".join(block_lines),
                        ip=current_ip, user=current_user, action="SLOW_QUERY",
                        resource="\n".join(block_lines),
                    )
                block_lines = [raw]
                block_start = lineno
                current_ip = m_slow.group("ip") or None
                current_user = m_slow.group("user") or None
                current_ts = None
                continue

            m_ts = RE_MYSQL_TS.match(raw)
            if m_ts:
                ts_str = m_ts.group(1).replace("T", " ")
                try:
                    current_ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            # general query log
            m_gen = RE_MYSQL_GEN.match(raw)
            if m_gen:
                yield LogEvent(
                    timestamp=current_ts, source_file=path, source_line=lineno,
                    log_type="db_mysql", raw=raw,
                    ip=None, user=None,
                    action=m_gen.group("cmd"),
                    resource=m_gen.group("detail"),
                )
                continue

            if block_lines:
                block_lines.append(raw)
            else:
                # línea de error o info genérica
                yield LogEvent(
                    timestamp=current_ts, source_file=path, source_line=lineno,
                    log_type="db_mysql", raw=raw,
                    action="ERROR" if "error" in raw.lower() else "INFO",
                )

        if block_lines:
            yield LogEvent(
                timestamp=current_ts, source_file=path, source_line=block_start,
                log_type="db_mysql", raw="\n".join(block_lines),
                ip=current_ip, user=current_user, action="SLOW_QUERY",
            )


# --- PostgreSQL CSV log ---
def parse_postgres_csv(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        reader = csv.reader(fh)
        for lineno, row in enumerate(reader, 1):
            if len(row) < 13:
                continue
            ts = None
            try:
                ts_str = row[0].split(".")[0]  # quita microsegundos
                ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except (ValueError, IndexError):
                pass
            user = row[1] if len(row) > 1 else None
            client = row[4] if len(row) > 4 else ""
            ip = client.split(":")[0] if client else None
            if ip in ("", "[local]", "localhost"):
                ip = None
            level = row[11] if len(row) > 11 else "LOG"
            message = row[13] if len(row) > 13 else (row[12] if len(row) > 12 else "")
            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="db_postgres", raw=",".join(row),
                ip=ip, user=user or None,
                action=level,
                resource=message,
            )


def parse_mongodb(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            ts = None
            ip = None
            user = None
            action = None
            resource = None

            # Intento JSON (4.4+)
            if raw.startswith("{"):
                try:
                    rec = json.loads(raw)
                    ts_str = rec.get("t", {}).get("$date", "") or rec.get("t", "")
                    if ts_str:
                        ts_str = ts_str[:19].replace("T", " ")
                        try:
                            ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            pass
                    action = rec.get("c") or rec.get("s")
                    attr = rec.get("attr") or {}
                    ip = attr.get("remote", "").split(":")[0] or None
                    resource = rec.get("msg", "")
                    user = attr.get("principalName") or None
                except json.JSONDecodeError:
                    pass
            else:
                m = RE_MONGO_TS.match(raw)
                if m:
                    try:
                        ts = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        pass
                parts = raw.split()
                action = parts[3] if len(parts) > 3 else None

            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="db_mongo", raw=raw,
                ip=ip, user=user, action=action, resource=resource,
            )

def _parse_auth_ts(raw: str) -> Optional[datetime.datetime]:
    m = RE_AUTH_TS.match(raw)
    if not m:
        return None
    if m.group("iso"):
        try:
            return datetime.datetime.strptime(m.group("iso"), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if m.group("bsd"):
        parts = m.group("bsd").split()
        if len(parts) == 3:
            month = _BSD_MONTHS.get(parts[0], 1)
            day = int(parts[1])
            h, mi, s = [int(x) for x in parts[2].split(":")]
            return datetime.datetime(_CURRENT_YEAR, month, day, h, mi, s)
    return None


def parse_auth(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            ts = _parse_auth_ts(raw)
            ip = None
            user = None
            action = "INFO"
            resource = None

            if m := RE_AUTH_SSH_FAIL.search(raw):
                user, ip = m.group(1), m.group(2)
                action = "SSH_FAIL"
            elif m := RE_AUTH_SSH_OK.search(raw):
                user, ip = m.group(1), m.group(2)
                action = "SSH_OK"
            elif m := RE_AUTH_SUDO.search(raw):
                user = m.group(1)
                resource = m.group(2).strip()
                action = "SUDO"
            elif m := RE_AUTH_SU.search(raw):
                user = m.group(1)
                action = "SU"
            elif m := RE_AUTH_NEW_USER.search(raw):
                user = m.group(1)
                action = "NEW_USER"
            elif m := RE_AUTH_CRON.search(raw):
                user = m.group(1)
                resource = m.group(2)
                action = "CRON_CMD"
            elif RE_ROOT_LOGIN.search(raw):
                action = "ROOT_LOGIN"

            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="linux_auth", raw=raw,
                ip=ip, user=user, action=action, resource=resource,
            )

def parse_syslog(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            # journald JSON
            if raw.startswith("{"):
                try:
                    rec = json.loads(raw)
                    ts_us = rec.get("__REALTIME_TIMESTAMP")
                    ts = None
                    if ts_us:
                        try:
                            ts = datetime.datetime.fromtimestamp(int(ts_us) / 1e6, tz=datetime.timezone.utc).replace(tzinfo=None)
                        except (ValueError, OverflowError):
                            pass
                    yield LogEvent(
                        timestamp=ts, source_file=path, source_line=lineno,
                        log_type="linux_sys", raw=raw,
                        user=rec.get("_UID") or rec.get("SYSLOG_IDENTIFIER"),
                        action=rec.get("PRIORITY", "INFO"),
                        resource=rec.get("MESSAGE", ""),
                    )
                    continue
                except json.JSONDecodeError:
                    pass
            ts = _parse_auth_ts(raw)
            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="linux_sys", raw=raw,
                action="LOG",
            )


def parse_windows_xml(path: str) -> Generator[LogEvent, None, None]:
    NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError:
        # Intentar parsear como stream de eventos sin raíz
        try:
            content = pathlib.Path(path).read_text(errors="replace")
            content = f"<Events>{content}</Events>"
            root = ET.fromstring(content)
        except ET.ParseError:
            return

    for lineno, event in enumerate(root.findall(".//e:Event", NS), 1):
        ts = None
        event_id = None
        ip = None
        user = None
        resource = None

        system = event.find("e:System", NS)
        if system is not None:
            ts_elem = system.find("e:TimeCreated", NS)
            if ts_elem is not None:
                ts_str = ts_elem.get("SystemTime", "")[:19]
                try:
                    ts = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    pass
            eid_elem = system.find("e:EventID", NS)
            if eid_elem is not None:
                try:
                    event_id = int(eid_elem.text or 0)
                except (ValueError, TypeError):
                    pass

        ev_data = event.find("e:EventData", NS)
        data: Dict[str, str] = {}
        if ev_data is not None:
            for d in ev_data.findall("e:Data", NS):
                name = d.get("Name", "")
                data[name] = (d.text or "").strip()

        ip = (data.get("IpAddress") or data.get("WorkstationName") or "").strip("-") or None
        user = (data.get("TargetUserName") or data.get("SubjectUserName") or "").strip("-") or None
        resource = data.get("ProcessName") or data.get("NewProcessName") or data.get("ScriptBlockText", "")[:200]

        sev, desc = ("INFO", "Evento")
        if event_id:
            sev, desc = {
                4624: ("INFO",    "Inicio de sesión correcto"),
                4625: ("MEDIUM",  "Inicio de sesión fallido"),
                4648: ("MEDIUM",  "Inicio de sesión con credenciales explícitas"),
                4672: ("MEDIUM",  "Privilegios especiales asignados"),
                4688: ("LOW",     "Proceso creado"),
                4698: ("HIGH",    "Tarea programada creada"),
                4702: ("HIGH",    "Tarea programada modificada"),
                4720: ("HIGH",    "Cuenta de usuario creada"),
                4724: ("HIGH",    "Contraseña cambiada"),
                4728: ("HIGH",    "Usuario añadido a grupo privilegiado"),
                4732: ("HIGH",    "Usuario añadido a grupo local privilegiado"),
                4740: ("MEDIUM",  "Cuenta bloqueada"),
                4771: ("MEDIUM",  "Pre-auth Kerberos fallida"),
                4776: ("MEDIUM",  "Validación NTLM fallida"),
                5140: ("LOW",     "Recurso de red accedido"),
                7045: ("HIGH",    "Nuevo servicio instalado"),
                4104: ("HIGH",    "Bloque de script PowerShell"),
                4103: ("MEDIUM",  "Invocación de módulo PowerShell"),
            }.get(event_id, ("INFO", f"Evento {event_id}"))

        yield LogEvent(
            timestamp=ts, source_file=path, source_line=lineno,
            log_type="windows", raw=ET.tostring(event, encoding="unicode"),
            ip=ip or None, user=user or None,
            action=str(event_id) if event_id else "EVT",
            resource=resource or None,
            extra={"event_id": event_id, "severity_hint": sev, "description": desc, "data": data},
        )


# --- macOS Unified Log JSON ---
# Exportar con: log show --style json --last 24h > unified.json
def parse_macos_unified(path: str) -> Generator[LogEvent, None, None]:
    try:
        with _open_file(path) as fh:
            data = json.load(fh)
        entries = data if isinstance(data, list) else []
    except (json.JSONDecodeError, UnicodeDecodeError):
        # fallback: JSON Objects separados por línea
        entries = []
        with _open_file(path) as fh:
            for lineno, line in enumerate(fh, 1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    entries.append((lineno, json.loads(raw)))
                except json.JSONDecodeError:
                    continue

    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        entries = list(enumerate(entries, 1))

    for lineno, rec in entries:
        ts = None
        ts_str = rec.get("timestamp", "")
        if ts_str:
            ts_str = ts_str[:19].replace("T", " ")
            try:
                ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        yield LogEvent(
            timestamp=ts, source_file=path, source_line=lineno,
            log_type="macos", raw=json.dumps(rec),
            user=rec.get("processID") or None,
            action=rec.get("messageType", "Default"),
            resource=rec.get("eventMessage", ""),
        )


# --- Parser genérico (JSON estructurado / texto libre) ---
RE_GENERIC_TS = re.compile(
    r'(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
    r'|(?P<bsd>\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)
RE_GENERIC_IP = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)


def parse_generic(path: str) -> Generator[LogEvent, None, None]:
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            ts = None
            m_ts = RE_GENERIC_TS.search(raw)
            if m_ts:
                ts_str = (m_ts.group("iso") or m_ts.group("bsd") or "").replace("T", " ")
                for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
                    try:
                        ts = datetime.datetime.strptime(ts_str, fmt)
                        if "%Y" not in fmt:
                            ts = ts.replace(year=_CURRENT_YEAR)
                        break
                    except ValueError:
                        pass

            ip = None
            m_ip = RE_GENERIC_IP.search(raw)
            if m_ip:
                try:
                    addr = ipaddress.ip_address(m_ip.group(1))
                    if not addr.is_loopback and not addr.is_link_local:
                        ip = m_ip.group(1)
                except ValueError:
                    pass

            # Intentar JSON
            if raw.startswith("{"):
                try:
                    rec = json.loads(raw)
                    if not ts:
                        for key in ("timestamp", "time", "datetime", "@timestamp", "ts"):
                            if key in rec:
                                ts_val = str(rec[key])[:19].replace("T", " ")
                                try:
                                    ts = datetime.datetime.strptime(ts_val, "%Y-%m-%d %H:%M:%S")
                                except ValueError:
                                    pass
                                break
                    if not ip:
                        for key in ("ip", "client_ip", "remote_addr", "src_ip", "source_ip"):
                            if key in rec:
                                ip = str(rec[key])
                                break
                    yield LogEvent(
                        timestamp=ts, source_file=path, source_line=lineno,
                        log_type="generic", raw=raw, ip=ip,
                        user=str(rec.get("user") or rec.get("username") or "") or None,
                        action=str(rec.get("action") or rec.get("level") or rec.get("severity") or "LOG"),
                        resource=str(rec.get("message") or rec.get("msg") or rec.get("path") or ""),
                    )
                    continue
                except json.JSONDecodeError:
                    pass

            yield LogEvent(
                timestamp=ts, source_file=path, source_line=lineno,
                log_type="generic", raw=raw, ip=ip,
            )


# ============================================================
# PARSERS WAZUH / OSSEC
# ============================================================

def _wazuh_level_to_severity(level: int) -> str:
    """Mapea nivel de regla Wazuh (1-15) a severidad VSL."""
    if level <= 5:
        return "INFO"
    if level <= 8:
        return "LOW"
    if level <= 11:
        return "MEDIUM"
    if level <= 14:
        return "HIGH"
    return "CRITICAL"


def _is_wazuh_json(rec: dict) -> bool:
    """
    Determina si un dict JSON corresponde a formato Wazuh/OSSEC.
    Heurística: presencia de campos característicos de Wazuh.
    """
    wazuh_keys = {"agent", "rule", "data", "full_log"}
    if wazuh_keys & rec.keys():
        return True
    # Variante: program_name + rule.id coexisten
    if "program_name" in rec and isinstance(rec.get("rule"), dict):
        return True
    return False


def parse_wazuh_json(path: str) -> Generator[LogEvent, None, None]:
    """
    Parser para logs Wazuh en formato JSON (un objeto JSON por línea).

    Campos parseados:
      rule.id, rule.description, rule.level → severidad VSL
      agent.name, agent.ip
      data.srcip, data.dstip
      timestamp
    """
    with _open_file(path) as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            # Intentar parseo JSON
            if not raw.strip().startswith("{"):
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # Aceptar objetos Wazuh o arrays de objetos Wazuh
            if isinstance(rec, list):
                items = rec
            else:
                items = [rec]

            for obj in items:
                if not isinstance(obj, dict):
                    continue
                # Detectar formato Wazuh
                if not _is_wazuh_json(obj):
                    yield LogEvent(
                        timestamp=None, source_file=path, source_line=lineno,
                        log_type="generic", raw=json.dumps(obj),
                    )
                    continue

                # Parsear timestamp
                ts = None
                ts_raw = obj.get("timestamp", "")
                if ts_raw:
                    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                                "%Y-%m-%d %H:%M:%S"):
                        try:
                            ts = datetime.datetime.strptime(ts_raw[:26], fmt)
                            break
                        except ValueError:
                            pass
                    if ts is None:
                        # Intentar parseo genérico con ISO fromisoformat
                        try:
                            ts = datetime.datetime.fromisoformat(ts_raw[:19])
                        except ValueError:
                            pass

                # Campos de regla
                rule = obj.get("rule", {}) if isinstance(obj.get("rule"), dict) else {}
                rule_id = str(rule.get("id", "")) or None
                rule_desc = rule.get("description", "")
                rule_level = int(rule.get("level", 0)) if rule.get("level") is not None else 0

                # Campos de agente
                agent = obj.get("agent", {}) if isinstance(obj.get("agent"), dict) else {}
                agent_name = agent.get("name", "") or None
                agent_ip = agent.get("ip", "") or None

                # Campos de datos: IP de origen
                data = obj.get("data", {}) if isinstance(obj.get("data"), dict) else {}
                src_ip = (data.get("srcip") or data.get("src_ip") or
                          agent_ip or obj.get("srcip")) or None
                dst_ip = (data.get("dstip") or data.get("dst_ip")) or None

                # Mensaje completo
                full_log = obj.get("full_log", "") or obj.get("message", "") or rule_desc

                yield LogEvent(
                    timestamp=ts,
                    source_file=path,
                    source_line=lineno,
                    log_type="wazuh",
                    raw=raw[:500],
                    ip=src_ip,
                    user=agent_name,
                    action=_wazuh_level_to_severity(rule_level),
                    resource=full_log[:300],
                    extra={
                        "rule_id": rule_id,
                        "rule_description": rule_desc,
                        "rule_level": rule_level,
                        "agent_name": agent_name,
                        "agent_ip": agent_ip,
                        "dst_ip": dst_ip,
                        "wazuh_severity": _wazuh_level_to_severity(rule_level),
                    },
                )


# Patrón cabecera OSSEC: ** Alert <epoch>.<seq>: - <groups>
RE_OSSEC_ALERT_HDR = re.compile(
    r'^\*\* Alert (\d+(?:\.\d+)?): - (.+)$'
)
# Patrón línea de fecha/host OSSEC: <fecha> <host>->/<componente>
RE_OSSEC_HOST_LINE = re.compile(
    r'^(\d{4} \w+ \d{2} \d{2}:\d{2}:\d{2})\s+(\S+)->(\S+)$'
)


def parse_ossec_text(path: str) -> Generator[LogEvent, None, None]:
    """
    Parser para logs OSSEC legacy en formato texto.

    Patrón de bloque OSSEC:
      ** Alert <timestamp>: - <groups>
      <date> <host>->/<component>: <message>
      <lines de mensaje>

    Se parsean: timestamp, host, componente y mensaje.
    """
    _OSSEC_TS_FMT = "%Y %b %d %H:%M:%S"

    with _open_file(path) as fh:
        lines = fh.readlines()

    i = 0
    while i < len(lines):
        raw_line = lines[i].rstrip("\n")
        m_hdr = RE_OSSEC_ALERT_HDR.match(raw_line)
        if not m_hdr:
            i += 1
            continue

        # Línea de cabecera
        epoch_str = m_hdr.group(1)
        groups = m_hdr.group(2)
        block_start = i + 1
        ts = None
        try:
            ts = datetime.datetime.fromtimestamp(float(epoch_str))
        except (ValueError, OSError):
            pass

        host = None
        component = None
        msg_lines = []

        # Siguiente línea: fecha + host->componente
        i += 1
        if i < len(lines):
            raw_host = lines[i].rstrip("\n")
            m_host = RE_OSSEC_HOST_LINE.match(raw_host)
            if m_host:
                ts_str = m_host.group(1)
                host = m_host.group(2)
                component = m_host.group(3)
                if ts is None:
                    try:
                        ts = datetime.datetime.strptime(ts_str, _OSSEC_TS_FMT)
                    except ValueError:
                        pass
                i += 1

        # Líneas de mensaje hasta el siguiente bloque o línea vacía
        while i < len(lines):
            raw_msg = lines[i].rstrip("\n")
            if RE_OSSEC_ALERT_HDR.match(raw_msg) or raw_msg == "":
                break
            msg_lines.append(raw_msg)
            i += 1

        message = " ".join(msg_lines[:5])

        # Extraer IP del mensaje si está disponible
        ip = None
        m_ip = RE_GENERIC_IP.search(message)
        if m_ip:
            try:
                addr = ipaddress.ip_address(m_ip.group(1))
                if not addr.is_loopback and not addr.is_link_local:
                    ip = m_ip.group(1)
            except ValueError:
                pass

        yield LogEvent(
            timestamp=ts,
            source_file=path,
            source_line=block_start,
            log_type="ossec",
            raw=raw_line[:400],
            ip=ip,
            user=host,
            action="OSSEC_ALERT",
            resource=message[:300],
            extra={
                "groups": groups,
                "host": host,
                "component": component,
            },
        )


# --- Detección automática del tipo de log ---
def detect_log_type(path: str) -> str:
    """Inspecciona las primeras líneas para determinar el tipo de log."""
    sample = []
    try:
        with _open_file(path) as fh:
            for i, line in enumerate(fh):
                sample.append(line)
                if i >= 20:
                    break
    except (OSError, IOError):
        return "generic"

    content = "".join(sample)

    # Wazuh JSON: campos característicos en objetos JSON
    if re.search(r'"rule"\s*:\s*\{', content) and (
        '"agent"' in content or '"full_log"' in content or '"program_name"' in content
    ):
        return "wazuh"

    # OSSEC legacy (texto plano)
    if "** Alert " in content and "->" in content:
        return "ossec"

    # Windows XML
    if "<Events" in content or "<Event xmlns" in content:
        return "windows"

    # IIS W3C
    if "#Software: Microsoft Internet Information" in content or "#Fields: date time" in content:
        return "iis"

    # PostgreSQL CSV (muchas comas, campos específicos)
    if re.search(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+.*,\w+,\w+,\d+,', content, re.M):
        return "db_postgres"

    # MongoDB JSON
    if re.search(r'^\{"t":\{"\$date":', content, re.M):
        return "db_mongo"

    # MySQL slow query
    if "# User@Host:" in content or "# Query_time:" in content:
        return "db_mysql"

    # MySQL general/error
    if re.search(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+\d+\s+(?:Query|Error|Warning)', content, re.M):
        return "db_mysql"

    # macOS Unified Log JSON
    if '"messageType"' in content and '"eventMessage"' in content:
        return "macos"

    # journald JSON
    if '"__REALTIME_TIMESTAMP"' in content:
        return "linux_sys"

    # Apache/Nginx Combined
    if RE_APACHE.search(content):
        return "web"

    # Linux auth.log
    if re.search(r'(?:sshd|sudo|su|PAM)\[', content):
        return "linux_auth"

    # Linux syslog
    if re.search(r'(?:kernel:|systemd\[|NetworkManager\[)', content):
        return "linux_sys"

    return "generic"


def get_parser(log_type: str):
    return {
        "web": parse_apache,
        "iis": parse_iis,
        "db_mysql": parse_mysql,
        "db_postgres": parse_postgres_csv,
        "db_mongo": parse_mongodb,
        "linux_auth": parse_auth,
        "linux_sys": parse_syslog,
        "windows": parse_windows_xml,
        "macos": parse_macos_unified,
        "wazuh": parse_wazuh_json,
        "ossec": parse_ossec_text,
        "generic": parse_generic,
    }.get(log_type, parse_generic)


# ============================================================
# MOTOR DE DETECCIÓN
class Detector:
    """Recorre eventos y emite hallazgos."""

    def __init__(self, config: dict):
        self.c = config
        # Estado interno para detecciones por ventana
        self._ssh_fails: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        self._web_fails: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        self._not_found: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        self._all_fail_users: Dict[str, List[str]] = collections.defaultdict(list)
        self._findings_raw: List[Finding] = []
        self._finding_counter = collections.Counter()
        # FORA-022: credential stuffing — {usuario: [(ip, exito, evento), ...]}
        self._login_attempts: Dict[str, List[tuple]] = collections.defaultdict(list)
        # FORA-023: beacon C2 — {(ip, ruta): [timestamps]}
        self._beacon_track: Dict[tuple, List[datetime.datetime]] = collections.defaultdict(list)
        # FORA-024: slow drip — {ip: [eventos de fallo SSH en ventana 6h]}
        self._slow_drip: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        # FORA-015: actividad nocturna — {ip_o_anon: [eventos nocturnos]}
        self._night_events: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        # Correlación total por IP — todos los eventos, para contexto forense
        self._ip_all_events: Dict[str, List[LogEvent]] = collections.defaultdict(list)
        # FORA-019: detección de cáscara de SPA (index.html servido como fallback a sondeos de
        # ficheros). Si el 200 a un fichero sensible mide lo mismo que la raíz "/" de esa IP, o que
        # otros ficheros sondeados por ella, no es una fuga: es el index.html de una SPA.
        self._root200_sizes: Dict[str, set] = collections.defaultdict(set)                       # ip -> tamaños de 200 a "/"
        self._sens200_sizes: Dict[str, "collections.Counter"] = collections.defaultdict(collections.Counter)  # ip -> Counter(tamaño)

    def _fid(self, n: int) -> str:
        self._finding_counter[n] += 1
        return f"{FINDING_PREFIX}-{n:03d}"

    def _trim_window(self, events: List[LogEvent], window_sec: int) -> List[LogEvent]:
        if not events:
            return events
        latest = max((e.timestamp for e in events if e.timestamp), default=None)
        if not latest:
            return events
        cutoff = latest - datetime.timedelta(seconds=window_sec)
        return [e for e in events if e.timestamp and e.timestamp >= cutoff]

    def _make_finding(self, n: int, severity: str, title: str, description: str,
                      phase: str, events: List[LogEvent], remediation: str) -> Finding:
        first = min((e.timestamp for e in events if e.timestamp), default=None)
        last  = max((e.timestamp for e in events if e.timestamp), default=None)
        ips   = sorted({e.ip for e in events if e.ip})
        users = sorted({e.user for e in events if e.user})
        evidence = []
        for e in events[:20]:  # máximo 20 líneas de evidencia por hallazgo
            evidence.append(f"[{e.source_file}:{e.source_line}] {e.raw[:300]}")
        return Finding(
            fid=self._fid(n), severity=severity, title=title,
            description=description, attack_phase=phase,
            evidence=evidence, events=events,
            first_seen=first, last_seen=last,
            ips=ips, users=users, remediation=remediation,
        )

    # -------- Procesamiento por evento --------

    def process(self, event: LogEvent) -> None:
        """Procesa un evento e actualiza el estado interno."""

        # --- Fuerza bruta SSH ---
        if event.action == "SSH_FAIL" and event.ip:
            self._ssh_fails[event.ip].append(event)
            self._ssh_fails[event.ip] = self._trim_window(
                self._ssh_fails[event.ip], self.c["brute_window_sec"]
            )
            if event.user:
                self._all_fail_users[event.ip].append(event.user)
            threshold = self.c["brute_threshold_ssh"]
            bucket = self._ssh_fails[event.ip]
            if len(bucket) == threshold:  # emitir solo cuando cruza el umbral
                self._findings_raw.append(self._make_finding(
                    1, "HIGH",
                    f"Fuerza bruta SSH desde {event.ip}",
                    f"Se detectaron {len(bucket)} intentos de autenticación SSH fallidos desde {event.ip} "
                    f"en una ventana de {self.c['brute_window_sec']}s.",
                    "Acceso inicial — Fuerza bruta",
                    list(bucket),
                    "Bloquear IP en firewall. Configurar fail2ban o similar. "
                    "Revisar si algún intento tuvo éxito (buscar SSH_OK del mismo IP). "
                    "Considerar autenticación solo por clave SSH.",
                ))

        # --- Fuerza bruta web (401/403 masivos) ---
        if event.log_type == "web" and event.status in (401, 403) and event.ip:
            self._web_fails[event.ip].append(event)
            self._web_fails[event.ip] = self._trim_window(
                self._web_fails[event.ip], self.c["brute_window_sec"]
            )
            threshold = self.c["brute_threshold_web"]
            bucket = self._web_fails[event.ip]
            if len(bucket) == threshold:
                self._findings_raw.append(self._make_finding(
                    2, "HIGH",
                    f"Fuerza bruta HTTP desde {event.ip}",
                    f"Se detectaron {len(bucket)} respuestas {event.status} (acceso denegado) "
                    f"desde {event.ip} en {self.c['brute_window_sec']}s.",
                    "Acceso inicial — Fuerza bruta",
                    list(bucket),
                    "Implementar rate limiting y bloqueo temporal por IP en el servidor web. "
                    "Revisar si el recurso objetivo tiene autenticación débil.",
                ))

        # --- Correlación global por IP (para contexto forense de FORA-015 y otros) ---
        if event.ip:
            self._ip_all_events[event.ip].append(event)

        # --- FORA-015: acumulación actividad nocturna por IP ---
        if event.timestamp:
            h = event.timestamp.hour
            if self.c["unusual_hours"][0] <= h < self.c["unusual_hours"][1]:
                clave = event.ip if event.ip else "__sin_ip__"
                self._night_events[clave].append(event)

        # --- FORA-022: tracking credential stuffing ---
        if event.action in ("SSH_OK", "SSH_FAIL") and event.user and event.ip:
            exito = event.action == "SSH_OK"
            self._login_attempts[event.user].append((event.ip, exito, event))

        # --- FORA-023: tracking beacon C2 ---
        # Solo clientes EXTERNOS y rutas no-feed: un contenedor interno sondeando
        # nuestros propios endpoints (sync de calendario, health, poll de agentes)
        # es tráfico legítimo periódico, no una baliza C2 -> evita falsos positivos.
        if (event.log_type in ("web", "iis") and event.ip
                and event.resource and event.timestamp and event.status == 200):
            ruta = (event.resource or "").split("?")[0][:80]
            if (len(ruta) > 3 and not _ip_is_private(event.ip)
                    and not ruta.startswith(BEACON_EXCLUDE_PATHS)):
                key = (event.ip, ruta)
                self._beacon_track[key].append(event.timestamp)

        # --- FORA-024: tracking slow drip brute force ---
        if event.action == "SSH_FAIL" and event.ip and event.timestamp:
            self._slow_drip[event.ip].append(event)
            cutoff = event.timestamp - datetime.timedelta(hours=6)
            self._slow_drip[event.ip] = [
                e for e in self._slow_drip[event.ip]
                if e.timestamp and e.timestamp >= cutoff
            ]

        # --- Enumeración de directorios (404 storm) ---
        if event.log_type in ("web", "iis") and event.status == 404 and event.ip:
            self._not_found[event.ip].append(event)
            self._not_found[event.ip] = self._trim_window(
                self._not_found[event.ip], self.c["brute_window_sec"]
            )
            bucket = self._not_found[event.ip]
            threshold = self.c["dir_enum_threshold"]
            if len(bucket) == threshold:
                self._findings_raw.append(self._make_finding(
                    10, "MEDIUM",
                    f"Enumeración de directorios desde {event.ip}",
                    f"{len(bucket)} peticiones a recursos inexistentes (404) desde {event.ip} "
                    f"en {self.c['brute_window_sec']}s. Posible escaneo de directorios.",
                    "Reconocimiento — Enumeración",
                    list(bucket),
                    "Bloquear IP. Revisar si el patrón de URLs coincide con herramientas conocidas (dirb, gobuster, ffuf). "
                    "Considerar honeypots en rutas comunes.",
                ))

    def analyze_event(self, event: LogEvent) -> List[Finding]:
        """Análisis estático del evento — no acumula estado."""
        findings = []

        # --- Inyección SQL web ---
        target = (event.resource or "") + (event.user_agent or "")
        if event.log_type in ("web", "iis") and RE_SQLI.search(target):
            findings.append(self._make_finding(
                4, "CRITICAL",
                f"Inyección SQL desde {event.ip or 'IP desconocida'}",
                f"Patrón de SQL injection detectado en la petición. "
                f"Recurso: {event.resource or '—'}",
                "Explotación de aplicación web",
                [event],
                "Revisar la petición completa. Verificar si la inyección fue exitosa "
                "(status 200 + respuesta con datos de DB). Aplicar consultas preparadas "
                "y validación de entrada en la aplicación.",
            ))

        # --- Inyección SQL en base de datos ---
        if event.log_type in ("db_mysql", "db_postgres", "db_mongo"):
            resource = (event.resource or event.raw or "")
            if RE_SQLI.search(resource):
                findings.append(self._make_finding(
                    5, "CRITICAL",
                    "Consulta SQL sospechosa en base de datos",
                    f"Patrón de SQL injection o consulta de explotación en log de base de datos. "
                    f"Usuario: {event.user or '—'}  IP: {event.ip or '—'}",
                    "Explotación — Base de datos",
                    [event],
                    "Revisar la consulta completa en el log. Verificar qué datos fueron accedidos. "
                    "Auditar permisos del usuario de base de datos.",
                ))

        # --- XSS ---
        if event.log_type in ("web", "iis") and RE_XSS.search(event.resource or ""):
            findings.append(self._make_finding(
                6, "HIGH",
                f"Intento XSS desde {event.ip or 'IP desconocida'}",
                f"Patrón de Cross-Site Scripting en URI: {(event.resource or '')[:200]}",
                "Explotación de aplicación web",
                [event],
                "Verificar si el payload fue almacenado (stored XSS) o reflejado. "
                "Implementar CSP, encoding de salida y sanitización de entrada.",
            ))

        # --- Path traversal / LFI / RFI ---
        if RE_TRAVERSAL.search((event.resource or "") + (event.user_agent or "")):
            findings.append(self._make_finding(
                7, "HIGH",
                f"Path traversal / LFI desde {event.ip or 'IP desconocida'}",
                f"Intento de lectura de fichero fuera de la raíz web o acceso a fichero del sistema: "
                f"{(event.resource or '')[:200]}",
                "Descubrimiento / Acceso a archivos",
                [event],
                "Verificar si el acceso fue exitoso (status 200). Revisar permisos del proceso web. "
                "Sanitizar rutas de fichero en la aplicación. Usar chroot/jail si procede.",
            ))

        # --- RFI (Remote File Inclusion) ---
        if event.log_type in ("web", "iis") and RE_RFI.search(event.resource or ""):
            findings.append(self._make_finding(
                7, "CRITICAL",
                f"Remote File Inclusion (RFI) desde {event.ip or 'IP desconocida'}",
                f"Intento de incluir fichero remoto: {(event.resource or '')[:200]}",
                "Ejecución remota",
                [event],
                "Deshabilitar allow_url_include en PHP. Validar y lista-blanca de paths permitidos.",
            ))

        # --- Webshell ---
        if RE_WEBSHELL.search((event.resource or "") + (event.raw or "")):
            findings.append(self._make_finding(
                8, "CRITICAL",
                f"Posible webshell desde {event.ip or 'IP desconocida'}",
                f"Acceso o uso de webshell detectado: {(event.resource or event.raw or '')[:200]}",
                "Ejecución — Webshell",
                [event],
                "Aislar el servidor inmediatamente. Buscar ficheros PHP/ASP subidos recientemente. "
                "Revisar procesos hijos del servidor web. Realizar análisis forense completo.",
            ))

        # --- Herramienta de escaneo por User-Agent ---
        if event.user_agent and RE_SCANNER_UA.search(event.user_agent):
            findings.append(self._make_finding(
                9, "MEDIUM",
                f"Herramienta de escaneo detectada desde {event.ip or 'IP desconocida'}",
                f"User-Agent identificado como herramienta de ataque/escaneo: {event.user_agent[:150]}",
                "Reconocimiento",
                [event],
                "Bloquear la IP. Revisar qué endpoints fueron accedidos durante el escaneo. "
                "Verificar si hubo hallazgos en los logs de aplicación posterior al escaneo.",
            ))

        # --- Rutas de escaneo conocidas ---
        if event.log_type in ("web", "iis") and RE_SCANNER_PATH.search(event.resource or ""):
            findings.append(self._make_finding(
                9, "MEDIUM",
                f"Reconocimiento de ruta sensible desde {event.ip or 'IP desconocida'}",
                f"Petición a ruta de administración o fichero sensible: {event.resource or ''}",
                "Reconocimiento",
                [event],
                "Bloquear acceso a rutas de administración por IP o VPN. "
                "Eliminar instalaciones de administración innecesarias.",
            ))

        # Registrar el tamaño de las respuestas 200 a la raíz "/" por IP (para detectar la cáscara
        # de una SPA: si un fichero sensible se sirve con 200 del mismo tamaño que "/", es el index.html).
        _rq = (event.resource or "").split()
        _path = (_rq[1] if len(_rq) >= 2 else (event.resource or "")).split("?")[0]
        if event.status in (200, 206) and _path in ("/", "/index.html") and event.bytes_out:
            self._root200_sizes[event.ip or "?"].add(event.bytes_out)

        # --- Acceso a ficheros sensibles ---
        # La severidad depende del RESULTADO: un 200 = el fichero se sirvió (exposición real);
        # un 403/404/301… = un escáner probó suerte y el servidor lo rechazó (ruido de fondo,
        # constante en cualquier web pública). Sin esta distinción la regla llena de falsos
        # positivos porque los bots sondean /.env en todo internet a todas horas.
        if RE_SENSITIVE_FILES.search(event.resource or ""):
            st = event.status
            if st in (200, 206):
                ip = event.ip or "IP desconocida"
                sz = event.bytes_out
                # ¿Cáscara de SPA? El fallback catch-all sirve el MISMO index.html (mismo tamaño) para
                # cualquier ruta: si coincide con el tamaño de "/" de esa IP, o si esa IP ya recibió otro
                # fichero sensible del mismo tamaño, NO es una fuga (es HTML, no el fichero real).
                self._sens200_sizes[ip][sz] += 1
                es_cascara_spa = sz is not None and (
                    sz in self._root200_sizes.get(ip, set()) or self._sens200_sizes[ip][sz] >= 2)
                if es_cascara_spa:
                    findings.append(self._make_finding(
                        19, "INFO",
                        f"SPA sirve su index.html a sondeos de ficheros (HTTP 200, {sz} B) — sin exposición · {ip}",
                        f"El servidor devolvió 200 a {event.resource or ''} pero con el MISMO tamaño ({sz} B) "
                        f"que su página raíz u otros ficheros sondeados por la misma IP: es el index.html de una "
                        f"SPA (fallback catch-all), no un fichero de configuración real. No hay fuga de secretos.",
                        "Descubrimiento / Acceso a archivos",
                        [event],
                        "Falso positivo típico de SPA. Opcional: que la app/nginx devuelva 404 en rutas de "
                        "configuración en vez del index.html. NO requiere rotar secretos.",
                    ))
                else:
                    findings.append(self._make_finding(
                        19, "CRITICAL",
                        f"FICHERO SENSIBLE SERVIDO (HTTP {st}) a {ip}",
                        f"El servidor DEVOLVIÓ (status {st}) un fichero de configuración/credenciales: "
                        f"{event.resource or ''} ({sz} B). Posible fuga real de secretos.",
                        "Descubrimiento / Acceso a archivos",
                        [event],
                        "URGENTE: confirmar qué se sirvió realmente; si contiene secretos, ROTARLOS ya y "
                        "bloquear el acceso web al fichero (deny en nginx). NOTA: si el tamaño coincide con "
                        "el del index.html podría ser una SPA — verificar el cuerpo antes de dar por cierta la fuga.",
                    ))
            elif st in (301, 302, 400, 401, 403, 404, 405, 410, 444):
                findings.append(self._make_finding(
                    19, "INFO",
                    f"Sondeo de fichero sensible (bloqueado, HTTP {st}) desde {event.ip or 'IP desconocida'}",
                    f"Un escáner pidió {event.resource or ''} y el servidor lo rechazó (status {st}). "
                    "Ruido de fondo habitual de internet; no hubo exposición.",
                    "Descubrimiento / Acceso a archivos",
                    [event],
                    "No requiere acción inmediata. Mantener el bloqueo de dotfiles en nginx. Si el "
                    "volumen desde una misma IP es alto, valorar fail2ban/CrowdSec para banearla.",
                ))
            else:
                findings.append(self._make_finding(
                    19, "MEDIUM",
                    f"Acceso a fichero sensible desde {event.ip or 'IP desconocida'} (status {st if st is not None else '?'})",
                    f"Petición a fichero de configuración o credenciales: {event.resource or ''}",
                    "Descubrimiento / Acceso a archivos",
                    [event],
                    "Verificar si el acceso fue exitoso. Rotar credenciales si el fichero contiene secretos. "
                    "Bloquear acceso web a ficheros de configuración con reglas nginx.",
                ))

        # --- Transferencia de datos anormalmente grande ---
        if event.bytes_out and event.bytes_out > self.c["large_response"]:
            mb = event.bytes_out / (1024 * 1024)
            findings.append(self._make_finding(
                11, "HIGH",
                f"Transferencia masiva de datos ({mb:.1f} MB) hacia {event.ip or '?'}",
                f"Respuesta de {mb:.1f} MB a {event.ip or 'IP desconocida'}. "
                f"Recurso: {event.resource or '—'}  Status: {event.status}",
                "Exfiltración potencial",
                [event],
                "Verificar el contenido de la respuesta si hay logs de aplicación. "
                "Revisar si el recurso debería ser accesible públicamente. "
                "Implementar DLP (Data Loss Prevention) en el servidor.",
            ))

        # --- FORA-025: Respuesta POST anormalmente grande ---
        if event.log_type in ("web", "iis") and event.bytes_out:
            resource_str = event.resource or ""
            if resource_str.upper().startswith("POST ") and event.bytes_out > 1_048_576:
                mb = event.bytes_out / 1_048_576
                findings.append(self._make_finding(
                    25, "HIGH",
                    f"Respuesta POST grande ({mb:.1f} MB) → {event.ip or '?'}",
                    f"Petición POST que genera respuesta de {mb:.1f} MB desde {event.ip or '?'}. "
                    f"Posible exfiltración de datos vía formulario o API. "
                    f"Recurso: {resource_str[:150]}",
                    "Exfiltración — API web",
                    [event],
                    "Revisar el endpoint POST y qué datos devuelve. "
                    "Verificar si la magnitud de la respuesta es esperable. "
                    "Implementar límites de respuesta en el proxy o API gateway.",
                ))

        # --- Consulta DB masiva ---
        if event.log_type in ("db_mysql", "db_postgres", "db_mongo"):
            resource_lower = (event.resource or event.raw or "").lower()
            if re.search(r'\blimit\s+\d{4,}\b|\bselect\s+\*\s+from\b', resource_lower):
                findings.append(self._make_finding(
                    12, "HIGH",
                    "Consulta de base de datos masiva (posible exfiltración)",
                    f"Consulta que retorna un volumen de datos inusualmente alto. "
                    f"Usuario: {event.user or '—'}",
                    "Exfiltración — Base de datos",
                    [event],
                    "Revisar qué datos devolvió la consulta. Auditar permisos del usuario. "
                    "Implementar query throttling y alertas sobre SELECT * en producción.",
                ))

        # --- Escalada de privilegios ---
        if event.action == "SUDO" and event.resource and RE_SUDO_PRIVESC.search(event.resource):
            findings.append(self._make_finding(
                13, "CRITICAL",
                f"Posible escalada de privilegios por {event.user or '?'} vía sudo",
                f"Sudo ejecutado con comando que permite escapar a shell root: {event.resource[:200]}",
                "Escalada de privilegios",
                [event],
                "Auditar el fichero sudoers. Eliminar permisos NOPASSWD para comandos peligrosos. "
                "Revisar el historial de comandos del usuario implicado.",
            ))

        if event.action == "SU":
            findings.append(self._make_finding(
                13, "MEDIUM",
                f"Cambio de usuario (su) a cuenta privilegiada por {event.user or '?'}",
                f"Se realizó un cambio de usuario. Destino: {event.resource or event.raw[:100]}",
                "Escalada de privilegios",
                [event],
                "Verificar si el cambio fue autorizado. Revisar quién tiene la contraseña de root. "
                "Preferir sudo sobre su para mejor auditabilidad.",
            ))

        # --- Cuenta privilegiada creada ---
        if event.action == "NEW_USER":
            findings.append(self._make_finding(
                14, "HIGH",
                f"Nueva cuenta de usuario creada: {event.user or '?'}",
                "Se creó una cuenta de usuario en el sistema. Verificar si es legítima.",
                "Persistencia — Cuenta nueva",
                [event],
                "Verificar si la creación fue autorizada. Comprobar grupos del usuario. "
                "Si no es reconocida, eliminar la cuenta y cambiar contraseñas de cuentas admin.",
            ))

        # --- Cron sospechoso ---
        if event.action == "CRON_CMD" and event.resource and RE_CRON_SUSPICIOUS.search(event.resource):
            findings.append(self._make_finding(
                16, "HIGH",
                f"Tarea cron sospechosa ejecutada por {event.user or '?'}",
                f"Cron job con comandos de red o shell inversa: {event.resource[:200]}",
                "Persistencia — Tarea programada",
                [event],
                "Revisar todos los crontabs del sistema (crontab -l -u usuario, /etc/cron.*). "
                "Verificar si el comando es legítimo. Buscar origen de la tarea.",
            ))

        # --- Login como root ---
        if event.action == "ROOT_LOGIN" or (event.action == "SSH_OK" and event.user == "root"):
            findings.append(self._make_finding(
                20, "HIGH",
                f"Login directo como root desde {event.ip or 'local'}",
                f"Se autenticó directamente como usuario root. Origen: {event.ip or 'consola local'}",
                "Acceso inicial / Escalada",
                [event],
                "Deshabilitar login directo como root en SSH (PermitRootLogin no). "
                "Usar cuentas con sudo para administración.",
            ))

        # --- Windows: comandos sospechosos ---
        if event.log_type == "windows":
            raw_combined = (event.resource or "") + (event.raw or "")
            if RE_WIN_SUSPICIOUS_CMD.search(raw_combined):
                findings.append(self._make_finding(
                    17, "CRITICAL",
                    "Comando PowerShell/CMD sospechoso detectado en Windows",
                    f"Patrón de comando ofuscado o evasivo: {raw_combined[:200]}",
                    "Ejecución — Windows",
                    [event],
                    "Habilitar PowerShell Script Block Logging. Revisar los artefactos de "
                    "ejecución (Prefetch, ShimCache, Amcache). Aislar el equipo si procede.",
                ))
            if RE_WIN_LSASS.search(raw_combined):
                findings.append(self._make_finding(
                    17, "CRITICAL",
                    "Posible volcado de credenciales (LSASS) en Windows",
                    f"Herramienta de volcado de credenciales detectada: {raw_combined[:150]}",
                    "Robo de credenciales",
                    [event],
                    "Aislar el equipo inmediatamente. Cambiar todas las contraseñas del dominio. "
                    "Habilitar Windows Defender Credential Guard. Revisar qué cuentas estaban activas.",
                ))
            if RE_WIN_LATERAL.search(raw_combined):
                findings.append(self._make_finding(
                    18, "HIGH",
                    "Movimiento lateral detectado en Windows",
                    f"Herramienta de movimiento lateral o conexión remota: {raw_combined[:200]}",
                    "Movimiento lateral",
                    [event],
                    "Revisar las conexiones de red del equipo afectado. "
                    "Verificar qué equipos se accedieron desde este host. "
                    "Aplicar segmentación de red para limitar el movimiento lateral.",
                ))
            if RE_WIN_PERSISTENCE.search(raw_combined):
                findings.append(self._make_finding(
                    16, "HIGH",
                    "Mecanismo de persistencia en Windows",
                    f"Creación de servicio, tarea programada o clave de registro de autoarranque: {raw_combined[:200]}",
                    "Persistencia — Windows",
                    [event],
                    "Revisar el elemento de persistencia creado. "
                    "Usar Autoruns (Sysinternals) para enumerar todos los puntos de persistencia. "
                    "Eliminar el mecanismo y verificar el origen del malware.",
                ))
            if RE_WIN_EVASION.search(raw_combined):
                findings.append(self._make_finding(
                    21, "HIGH",
                    "Técnica de evasión de defensa detectada en Windows",
                    f"Uso de herramienta nativa de Windows para evasión (LOLBAS): {raw_combined[:200]}",
                    "Evasión de defensa",
                    [event],
                    "Bloquear las herramientas LOLBAS identificadas mediante AppLocker o WDAC. "
                    "Habilitar logging de línea de comandos completo.",
                ))

        # --- Movimiento lateral Linux ---
        if event.log_type == "linux_sys" and RE_LATERAL_SSH.search(event.raw or ""):
            if not _ip_is_private(event.ip):
                findings.append(self._make_finding(
                    18, "HIGH",
                    "Posible movimiento lateral vía SSH interno",
                    f"Conexión SSH a dirección IP privada desde este host: {event.raw[:150]}",
                    "Movimiento lateral",
                    [event],
                    "Verificar si el SSH interno es esperado. Implementar registros de sesión "
                    "SSH (PAM + rsyslog). Considerar bastion host para acceso interno.",
                ))

        return findings

    def finalize(self) -> List[Finding]:
        """Devuelve todos los hallazgos acumulados (estadísticos + por evento)."""

        # --- Password spray: pocos intentos por usuario, muchos usuarios distintos ---
        for ip, users in self._all_fail_users.items():
            unique = set(users)
            if len(unique) >= self.c["spray_users_min"] and len(users) < len(unique) * 3:
                events = self._ssh_fails.get(ip, [])
                if events:
                    self._findings_raw.append(self._make_finding(
                        3, "HIGH",
                        f"Password spray detectado desde {ip}",
                        f"Intentos de autenticación contra {len(unique)} usuarios distintos "
                        f"desde {ip}. Patrón típico de password spray.",
                        "Acceso inicial — Password spray",
                        events,
                        "Bloquear la IP. Auditar las cuentas objetivo. "
                        "Revisar si alguna cuenta fue comprometida. "
                        "Implementar MFA para todos los usuarios.",
                    ))

        # --- FORA-015: Actividad nocturna consolidada por IP ---
        h0, h1 = self.c["unusual_hours"]
        for ip_clave, eventos_noche in self._night_events.items():
            if not eventos_noche:
                continue
            ip_real = ip_clave if ip_clave != "__sin_ip__" else None

            # Estadísticas de los eventos nocturnos de este IP
            total_noche = len(eventos_noche)
            primer_ev = min((e.timestamp for e in eventos_noche if e.timestamp), default=None)
            ultimo_ev = max((e.timestamp for e in eventos_noche if e.timestamp), default=None)

            # Acciones distintas (excluyendo None)
            acciones = collections.Counter(
                e.action for e in eventos_noche if e.action and e.action not in ("INFO", "LOG")
            )
            # Recursos más accedidos
            recursos = collections.Counter(
                (e.resource or "")[:80] for e in eventos_noche if e.resource
            )
            # Códigos de estado / éxitos-fallos
            status_counts = collections.Counter(e.status for e in eventos_noche if e.status)
            exitos = sum(c for s, c in status_counts.items() if isinstance(s, int) and 200 <= s < 300)
            fallos = sum(c for s, c in status_counts.items() if isinstance(s, int) and s >= 400)

            # Correlación global del IP en todo el log (no solo nocturnos)
            todos_ip = self._ip_all_events.get(ip_real or "", [])
            total_ip_global = len(todos_ip)
            horas_ip = sorted({e.timestamp.hour for e in todos_ip if e.timestamp})
            acc_global = collections.Counter(
                e.action for e in todos_ip if e.action and e.action not in ("INFO", "LOG")
            )

            # Construir descripción detallada
            acciones_str = ", ".join(f"{a}×{c}" for a, c in acciones.most_common(6)) or "genérica"
            recursos_top = "; ".join(r for r, _ in recursos.most_common(5)) if recursos else "—"
            horas_str = ", ".join(f"{h}h" for h in horas_ip) if horas_ip else "solo horario nocturno"
            acc_global_str = ", ".join(f"{a}×{c}" for a, c in acc_global.most_common(5)) or "—"

            descripcion = (
                f"IP {ip_real or '(sin IP)'} generó {total_noche} eventos entre las {h0}h y {h1}h UTC.\n"
                f"Período nocturno: {primer_ev.strftime('%Y-%m-%d %H:%M') if primer_ev else '?'} → "
                f"{ultimo_ev.strftime('%H:%M') if ultimo_ev else '?'} UTC.\n"
                f"Tipos de acción nocturnos: {acciones_str}.\n"
            )
            if exitos or fallos:
                descripcion += f"Éxitos HTTP: {exitos} | Fallos HTTP: {fallos}.\n"
            if recursos:
                descripcion += f"Recursos más accedidos: {recursos_top}.\n"
            descripcion += (
                f"\nCORRELACIÓN GLOBAL: {total_ip_global} eventos totales de este IP en todo el log. "
                f"Horas activas: {horas_str}. "
                f"Acciones totales: {acc_global_str}."
            )

            sorted({e.user for e in eventos_noche if e.user})

            self._findings_raw.append(self._make_finding(
                15, "LOW",
                f"Actividad nocturna ({total_noche} eventos, {h0}h-{h1}h UTC) desde {ip_real or 'IP desconocida'}",
                descripcion,
                "Comportamiento anómalo — Horario inusual",
                eventos_noche[:50],
                "Verificar si la actividad nocturna era esperada (mantenimiento, batch jobs, backup). "
                "Revisar si el acceso fue autorizado. "
                "Si es tráfico de aplicación legítimo fuera de horario, ajustar el umbral con --night-from/--night-to. "
                "Si el IP no es reconocido, investigar su origen y bloquear si procede.",
            ))

        # --- FORA-022: Credential stuffing ---
        # Patrón: múltiples IPs distintas fallan con el mismo usuario → luego una IP tiene éxito
        for user, intentos in self._login_attempts.items():
            ips_fallo = [ip for ip, ok, _ in intentos if not ok]
            ips_exito = [ip for ip, ok, _ in intentos if ok]
            ips_fallo_uniq = set(ips_fallo)
            # Al menos 3 IPs distintas fallaron Y hubo al menos un éxito desde una IP diferente
            if len(ips_fallo_uniq) >= 3 and ips_exito:
                ip_exito = ips_exito[-1]
                if ip_exito not in ips_fallo_uniq:
                    ev_todos = [ev for _, _, ev in intentos]
                    self._findings_raw.append(self._make_finding(
                        22, "HIGH",
                        f"Credential stuffing sobre la cuenta '{user}'",
                        f"La cuenta '{user}' recibió intentos fallidos desde {len(ips_fallo_uniq)} IPs distintas "
                        f"y posteriormente un acceso exitoso desde {ip_exito}. "
                        f"Patrón compatible con relleno de credenciales.",
                        "Acceso inicial — Credential stuffing",
                        ev_todos,
                        "Cambiar la contraseña de la cuenta afectada inmediatamente. "
                        "Habilitar MFA. Revisar actividad posterior al login exitoso. "
                        "Comprobar si las credenciales aparecen en filtraciones conocidas (HaveIBeenPwned).",
                    ))

        # --- FORA-023: Baliza C2 (beacon) ---
        # Patrón: misma IP → misma ruta → >= 5 peticiones → intervalo muy regular (CoV < 0.15)
        for (ip, ruta), timestamps in self._beacon_track.items():
            if len(timestamps) < 5:
                continue
            timestamps_sorted = sorted(timestamps)
            intervalos = [
                (timestamps_sorted[i + 1] - timestamps_sorted[i]).total_seconds()
                for i in range(len(timestamps_sorted) - 1)
            ]
            if not intervalos:
                continue
            media = sum(intervalos) / len(intervalos)
            if media < 5:
                continue  # demasiado rápido, no es un beacon
            try:
                desv = statistics.stdev(intervalos)
                cov = desv / media if media > 0 else 1.0
            except statistics.StatisticsError:
                continue
            if cov < 0.20 and media >= 10:
                ev_dummy: List[LogEvent] = []
                self._findings_raw.append(Finding(
                    fid=self._fid(23),
                    severity="HIGH",
                    title=f"Posible baliza C2 desde {ip} → '{ruta}'",
                    description=(
                        f"IP {ip} realiza peticiones a '{ruta}' con un intervalo medio de "
                        f"{media:.0f}s (CoV={cov:.2f}). Patrón altamente regular compatible "
                        f"con un agente de comando y control."
                    ),
                    attack_phase="Mando y Control — C2 beacon",
                    evidence=[f"Intervalo medio: {media:.0f}s | Desviación: {desv:.1f}s | CoV: {cov:.2f} | Peticiones: {len(timestamps)}"],
                    events=ev_dummy,
                    first_seen=timestamps_sorted[0],
                    last_seen=timestamps_sorted[-1],
                    ips=[ip],
                    users=[],
                    remediation=(
                        "Bloquear la IP e investigar el host de origen. "
                        "Revisar las peticiones completas en el log para identificar el payload. "
                        "Comprobar si hay procesos en el servidor que escuchan en puertos inusuales."
                    ),
                ))

        # --- FORA-024: Fuerza bruta lenta (slow drip) ---
        # Patrón: >= 10 fallos SSH en 6h, pero < umbral para FORA-001 en cualquier ventana corta
        brute_thresh = self.c["brute_threshold_ssh"]
        for ip, eventos in self._slow_drip.items():
            if len(eventos) < max(10, brute_thresh + 1):
                continue
            # Verificar que en ninguna ventana de 5 min superó el umbral normal (ya fue emitido por FORA-001)
            ya_emitido_brute = any(
                f.fid.startswith(f"{FINDING_PREFIX}-001") and ip in f.ips
                for f in self._findings_raw
            )
            if ya_emitido_brute:
                continue
            if eventos[0].timestamp and eventos[-1].timestamp:
                duracion = (eventos[-1].timestamp - eventos[0].timestamp).total_seconds()
                if duracion >= 3600:  # distribuido en al menos 1 hora
                    self._findings_raw.append(self._make_finding(
                        24, "MEDIUM",
                        f"Fuerza bruta lenta (slow drip) desde {ip}",
                        f"{len(eventos)} intentos SSH fallidos desde {ip} distribuidos en "
                        f"{duracion / 3600:.1f} horas. La baja cadencia evita el rate limiting, "
                        f"pero el patrón acumulado es inequívocamente de fuerza bruta.",
                        "Acceso inicial — Fuerza bruta lenta",
                        eventos,
                        "Implementar bloqueo por intentos acumulados en ventana larga (fail2ban recidive jail). "
                        "Revisar si algún intento tuvo éxito. "
                        "Considerar cambio de puerto SSH y lista blanca de IPs.",
                    ))

        return self._findings_raw

    def get_ip_events(self) -> Dict[str, List[LogEvent]]:
        """Devuelve todos los eventos acumulados por IP (para IPActivityProfiler)."""
        return dict(self._ip_all_events)

def _sigma_level_to_severity(level: str) -> str:
    """Convierte nivel Sigma a severidad VSL."""
    return {
        "informational": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }.get(level.lower(), "MEDIUM")


def _logsource_matches(rule_ls: Dict[str, str], log_type: str) -> bool:
    """
    Comprueba si la logsource de la regla es compatible con el tipo de log.
    Se usa matching flexible: una regla web se aplica a logs web, una regla
    windows a logs windows, etc. Si la logsource está vacía, se aplica a todo.
    """
    if not rule_ls:
        return True

    product = rule_ls.get("product", "").lower()
    category = rule_ls.get("category", "").lower()
    service = rule_ls.get("service", "").lower()

    web_types = {"web", "apache", "nginx", "iis", "generic"}
    linux_types = {"linux_auth", "linux_sys", "syslog", "generic"}
    win_types = {"windows", "generic"}
    mac_types = {"macos", "generic"}

    if product in ("windows", "microsoft"):
        return log_type in win_types
    if product == "linux":
        return log_type in linux_types
    if product == "macos":
        return log_type in mac_types
    if product in ("apache", "nginx", "iis", "webserver"):
        return log_type in web_types
    if category in ("webserver", "web"):
        return log_type in web_types
    if category in ("process_creation", "file_access", "authentication"):
        return log_type in (linux_types | win_types)
    if service in ("auth", "sshd", "sudo"):
        return log_type in linux_types
    # Sin restricción clara → aplicar a todos
    return True


def _get_event_field(field_name: str, event: LogEvent) -> Optional[str]:
    """
    Extrae el valor de un campo de LogEvent dado el nombre abstracto Sigma.
    Devuelve siempre str para comparaciones, None si no está disponible.
    """
    mapped = _SIGMA_FIELD_MAP.get(field_name.lower(), field_name.lower())

    if mapped == "ip":
        val = event.ip
    elif mapped == "user":
        val = event.user
    elif mapped == "action":
        val = event.action
    elif mapped == "resource":
        val = event.resource
    elif mapped == "status":
        val = str(event.status) if event.status is not None else None
    elif mapped == "user_agent":
        val = event.user_agent
    elif mapped == "raw":
        val = event.raw
    elif mapped.startswith("extra."):
        key = mapped[6:]
        val = (event.extra or {}).get(key)
    else:
        # Búsqueda en extra con el nombre original
        val = (event.extra or {}).get(field_name)
        if val is None:
            # Último recurso: buscar en raw
            val = event.raw

    return str(val) if val is not None else None


def _match_value(modifier: str, field_val: str, pattern) -> bool:
    """Aplica un modificador Sigma a un valor de campo."""
    if isinstance(pattern, list):
        return any(_match_value(modifier, field_val, p) for p in pattern)
    pattern_str = str(pattern)
    mod_lower = modifier.lower() if modifier else "exact"

    if mod_lower in ("exact", "equals", ""):
        return field_val.lower() == pattern_str.lower()
    if mod_lower == "contains":
        return pattern_str.lower() in field_val.lower()
    if mod_lower == "startswith":
        return field_val.lower().startswith(pattern_str.lower())
    if mod_lower == "endswith":
        return field_val.lower().endswith(pattern_str.lower())
    if mod_lower == "re":
        try:
            return bool(re.search(pattern_str, field_val, re.IGNORECASE))
        except re.error:
            return False
    if mod_lower == "cidr":
        try:
            ip_obj = ipaddress.ip_address(field_val)
            net_obj = ipaddress.ip_network(pattern_str, strict=False)
            return ip_obj in net_obj
        except ValueError:
            return False
    if mod_lower == "base64":
        try:
            decoded = base64.b64decode(pattern_str).decode("utf-8", errors="ignore")
            return decoded.lower() in field_val.lower()
        except Exception:
            return False
    # Modificador desconocido → búsqueda por contiene
    return pattern_str.lower() in field_val.lower()


def _parse_field_expr(key: str) -> Tuple[str, str]:
    """
    Descompone 'CommandLine|contains' en ('CommandLine', 'contains').
    Si no hay modificador devuelve ('CommandLine', 'exact').
    """
    if "|" in key:
        parts = key.split("|", 1)
        return parts[0], parts[1]
    return key, "exact"


def _eval_sigma_selection(selection_def, event: LogEvent) -> bool:
    """
    Evalúa una selección Sigma (dict de campo → valor / lista de valores).
    Todas las claves del dict deben coincidir (AND implícito entre campos).
    """
    if not isinstance(selection_def, dict):
        return False

    for key, val in selection_def.items():
        # El modificador "all" obliga a que todos los valores de la lista coincidan
        all_modifier = False
        if "|" in key and key.split("|", 1)[1].lower() == "all":
            field_name = key.split("|", 1)[0]
            modifier = "contains"  # all suele combinarse con contains
            all_modifier = True
        else:
            field_name, modifier = _parse_field_expr(key)

        field_val = _get_event_field(field_name, event)
        if field_val is None:
            return False

        if all_modifier:
            # Todos los valores de la lista deben estar presentes
            items = val if isinstance(val, list) else [val]
            if not all(_match_value(modifier, field_val, p) for p in items):
                return False
        else:
            if not _match_value(modifier, field_val, val):
                return False

    return True


def _eval_sigma_condition(condition_str: str, named_results: Dict[str, bool]) -> bool:
    """
    Evalúa la condición Sigma usando los resultados pre-calculados de cada selección.
    Soporta: and, or, not, 1 of X*, all of them, X of Y*
    """
    cond = condition_str.strip()

    # '1 of X*' — al menos 1 selección que case con el patrón wildcard
    m = re.match(r"(\d+)\s+of\s+(\S+)", cond, re.IGNORECASE)
    if m:
        n = int(m.group(1))
        pattern = re.compile(m.group(2).replace("*", ".*"), re.IGNORECASE)
        matches = [v for k, v in named_results.items() if pattern.match(k)]
        return sum(1 for v in matches if v) >= n

    # 'all of them' — todas las selecciones nominadas deben ser True
    if re.match(r"all\s+of\s+them", cond, re.IGNORECASE):
        return all(named_results.values())

    # 'all of X*' — todas las selecciones que casen con el patrón
    m2 = re.match(r"all\s+of\s+(\S+)", cond, re.IGNORECASE)
    if m2:
        pattern = re.compile(m2.group(1).replace("*", ".*"), re.IGNORECASE)
        matches = [v for k, v in named_results.items() if pattern.match(k)]
        return all(matches) if matches else False

    # Tokenizar para manejar and/or/not con paréntesis simples
    def _resolve_token(token: str) -> bool:
        token = token.strip().strip("()")
        return named_results.get(token, False)

    # Eliminar paréntesis externos y evaluar izquierda a derecha
    # Simplificación: soporte básico de una capa de and/or/not
    cond_clean = re.sub(r"[()]", "", cond).strip()

    # NOT simple
    if cond_clean.lower().startswith("not "):
        inner = cond_clean[4:].strip()
        return not _resolve_token(inner)

    # OR (evaluar antes de AND para respetar precedencia estándar Sigma)
    if " or " in cond_clean.lower():
        parts = re.split(r"\bor\b", cond_clean, flags=re.IGNORECASE)
        return any(_eval_sigma_condition(p.strip(), named_results) for p in parts)

    # AND
    if " and " in cond_clean.lower():
        parts = re.split(r"\band\b", cond_clean, flags=re.IGNORECASE)
        return all(_eval_sigma_condition(p.strip(), named_results) for p in parts)

    # Token simple
    return _resolve_token(cond_clean)


def _rule_matches_event(rule: SigmaRule, event: LogEvent) -> bool:
    """Devuelve True si la regla Sigma coincide con el evento."""
    if not _logsource_matches(rule.logsource, event.log_type):
        return False

    detection = rule.detection
    if not detection:
        return False

    # Construir resultados de cada selección nominada
    named_results: Dict[str, bool] = {}
    condition_str = detection.get("condition", "")

    for key, val in detection.items():
        if key == "condition" or not isinstance(val, dict):
            continue
        named_results[key] = _eval_sigma_selection(val, event)

    # Si no hay selecciones nominadas pero hay un dict anónimo
    if not named_results and isinstance(condition_str, str):
        # Intentar evaluar como selección única
        for key, val in detection.items():
            if key != "condition" and isinstance(val, dict):
                named_results[key] = _eval_sigma_selection(val, event)

    if not condition_str:
        # Sin condition → AND de todas las selecciones
        return all(named_results.values()) if named_results else False

    return _eval_sigma_condition(str(condition_str), named_results)


class SigmaLoader:
    """Carga y valida reglas Sigma desde ficheros YAML o directorios."""

    @staticmethod
    def from_file(path: str) -> Optional[SigmaRule]:
        """Carga una regla Sigma desde un fichero .yml/.yaml."""
        if not _YAML_OK:
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                data = _yaml.safe_load(fh)
            if not isinstance(data, dict) or "detection" not in data:
                return None
            return SigmaRule(
                title=data.get("title", pathlib.Path(path).stem),
                rule_id=data.get("id", str(uuid.uuid4())),
                status=data.get("status", "unknown"),
                description=data.get("description", ""),
                level=data.get("level", "medium"),
                tags=data.get("tags", []) or [],
                logsource=data.get("logsource", {}) or {},
                detection=data.get("detection", {}),
                falsepositives=data.get("falsepositives", []) or [],
                path=path,
            )
        except Exception:
            return None

    @staticmethod
    def from_dir(dir_path: str) -> List[SigmaRule]:
        """Carga todas las reglas Sigma de un directorio (recursivo)."""
        rules: List[SigmaRule] = []
        for root, _, files in os.walk(dir_path):
            for fname in files:
                if fname.endswith((".yml", ".yaml")):
                    rule = SigmaLoader.from_file(os.path.join(root, fname))
                    if rule:
                        rules.append(rule)
        return rules

    @staticmethod
    def load(path: str) -> List[SigmaRule]:
        """Acepta tanto un fichero como un directorio."""
        if not _YAML_OK:
            print("[!] PyYAML no instalado — soporte Sigma desactivado. "
                  "Instala con: pip install pyyaml", file=sys.stderr)
            return []
        p = pathlib.Path(path)
        if p.is_dir():
            return SigmaLoader.from_dir(path)
        rule = SigmaLoader.from_file(path)
        return [rule] if rule else []


def apply_sigma_rules(
    rules: List[SigmaRule],
    event: LogEvent,
) -> List[Finding]:
    """
    Aplica las reglas Sigma a un evento y devuelve los Finding generados.
    Cada regla que coincide produce un Finding con prefijo SIGMA-.
    """
    findings: List[Finding] = []
    for rule in rules:
        if _rule_matches_event(rule, event):
            # Extraer tácticas/técnicas ATT&CK de las tags
            attack_tags = [t for t in rule.tags if t.lower().startswith("attack.t")]
            attack_phase = attack_tags[0] if attack_tags else "Sigma Rule"

            findings.append(Finding(
                fid=f"SIGMA-{rule.rule_id[:8].upper()}",
                severity=_sigma_level_to_severity(rule.level),
                title=f"[Sigma] {rule.title}",
                description=rule.description or rule.title,
                attack_phase=attack_phase,
                evidence=[event.raw],
                events=[event],
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                ips=[event.ip] if event.ip else [],
                users=[event.user] if event.user else [],
                remediation=(
                    f"Revisar falsos positivos: {'; '.join(rule.falsepositives)}"
                    if rule.falsepositives else
                    f"Ver regla Sigma: {rule.path}"
                ),
            ))
    return findings


# ============================================================
# MOTOR DE ANÁLISIS PRINCIPAL
def analyze_files(
    paths: List[str],
    log_type: str,
    time_from: Optional[datetime.datetime],
    time_to: Optional[datetime.datetime],
    config: dict,
    verbose: bool = False,
    *,
    chain_of_custody: bool = False,
    analyst: str = "",
    case: str = "",
    enable_geoip: bool = False,
    scope: Optional[ScopeConfig] = None,
    session_gap_min: int = 30,
    sigma_rules: Optional[List[SigmaRule]] = None,
) -> Report:
    detector = Detector(config)
    all_findings: List[Finding] = []
    timeline_events: List[dict] = []
    total_events = 0
    ts_min: Optional[datetime.datetime] = None
    ts_max: Optional[datetime.datetime] = None
    # Contador de reglas Wazuh: {rule_id: count}
    wazuh_rule_counts: collections.Counter = collections.Counter()

    for path in paths:
        ltype = log_type if log_type != "auto" else detect_log_type(path)
        parser = get_parser(ltype)

        if verbose:
            print(f"  [+] {path} → tipo: {ltype}", file=sys.stderr)

        try:
            for event in parser(path):
                # Filtro de rango temporal
                if event.timestamp:
                    if time_from and event.timestamp < time_from:
                        continue
                    if time_to and event.timestamp > time_to:
                        continue
                    if ts_min is None or event.timestamp < ts_min:
                        ts_min = event.timestamp
                    if ts_max is None or event.timestamp > ts_max:
                        ts_max = event.timestamp

                total_events += 1

                # Acumular conteo de reglas Wazuh si aplica
                if event.log_type == "wazuh":
                    rule_id = event.extra.get("rule_id") if event.extra else None
                    if rule_id:
                        wazuh_rule_counts[rule_id] += 1

                # Análisis estático (detectores FORA)
                per_event = detector.analyze_event(event)
                all_findings.extend(per_event)

                # Reglas Sigma comunitarias
                if sigma_rules:
                    all_findings.extend(apply_sigma_rules(sigma_rules, event))

                # Estado acumulativo (brute force, spray, etc.)
                detector.process(event)

                # Línea de tiempo: solo eventos relevantes
                if event.action not in ("INFO", "LOG") or per_event:
                    timeline_events.append({
                        "ts": event.timestamp.isoformat() if event.timestamp else None,
                        "source": os.path.basename(event.source_file),
                        "type": event.log_type,
                        "ip": event.ip,
                        "user": event.user,
                        "action": event.action,
                        "resource": (event.resource or "")[:120],
                        "status": event.status,
                        "severity": per_event[0].severity if per_event else "INFO",
                        "finding": per_event[0].fid if per_event else None,
                    })
        except (OSError, IOError) as exc:
            print(f"  [!] No se pudo leer {path}: {exc}", file=sys.stderr)

    all_findings.extend(detector.finalize())

    # Deduplicar: consolidar hallazgos del mismo tipo+IP en uno solo
    all_findings = _deduplicate(all_findings)

    # Ordenar por severidad descendente, luego por timestamp
    all_findings.sort(key=lambda f: (
        -_severity_rank(f.severity),
        f.first_seen or datetime.datetime.min,
    ))

    # Línea de tiempo ordenada
    timeline_events.sort(key=lambda e: e.get("ts") or "")

    # --- Análisis forense extendido (v2.0) ---

    # Perfiles de actividad por IP (siempre activo)
    ip_profiles = IPActivityProfiler.perfilar(detector.get_ip_events())

    # Análisis de línea de tiempo
    ta = TimelineAnalyzer.analyze(timeline_events)

    # Reconstrucción de sesiones por IP
    sr = SessionReconstructor(gap_minutos=session_gap_min)
    sesiones = sr.reconstruir(timeline_events)

    # Extracción de IOCs
    iocs = IOCExtractor.extraer(all_findings, timeline_events)

    # Mapeo MITRE ATT&CK
    attack_chain = AttackChainMapper.mapear(all_findings)

    # Cadena de custodia (SHA-256)
    coc: dict = {}
    if chain_of_custody:
        coc = ChainOfCustody.generar(paths, analyst=analyst, case=case)

    # GeoIP (opcional, requiere red)
    geoip: dict = {}
    if enable_geoip:
        todas_ips = list({ip for f in all_findings for ip in f.ips})
        if todas_ips:
            print(f"  [*] Resolviendo {len(todas_ips)} IPs vía GeoIP...", file=sys.stderr)
            geoip = GeoIPResolver.resolver(todas_ips)
            resueltas = len(geoip)
            print(f"  [✓] {resueltas} IPs geolocalizadas.", file=sys.stderr)

    # Filtrado por scope: marcar hallazgos de IPs de confianza
    if scope:
        filtered = []
        for f in all_findings:
            if f.fid in scope.exclude_detectors:
                continue
            # Si TODAS las IPs del hallazgo son de confianza → descartar
            if f.ips and all(scope.is_trusted(ip) for ip in f.ips):
                continue
            filtered.append(f)
        all_findings = filtered

    return Report(
        tool=TOOL, version=VERSION,
        generated=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        sources=paths,
        time_range_start=ts_min.isoformat() if ts_min else None,
        time_range_end=ts_max.isoformat() if ts_max else None,
        total_events_parsed=total_events,
        findings=all_findings,
        timeline=timeline_events,
        sessions=sesiones,
        iocs=iocs,
        chain_of_custody=coc,
        attack_chain=attack_chain,
        timeline_analysis=ta,
        geoip_data=geoip,
        ip_profiles=ip_profiles,
        wazuh_rule_counts=dict(wazuh_rule_counts),
    )


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Consolida hallazgos del mismo tipo/IP para evitar ruido."""
    seen: Dict[str, Finding] = {}
    out: List[Finding] = []
    for f in findings:
        key = f"{f.fid[:8]}{(f.ips[0] if f.ips else '')}"
        if key in seen:
            existing = seen[key]
            existing.events.extend(f.events)
            existing.evidence.extend(f.evidence)
            existing.evidence = existing.evidence[:30]
            if f.first_seen and (existing.first_seen is None or f.first_seen < existing.first_seen):
                existing.first_seen = f.first_seen
            if f.last_seen and (existing.last_seen is None or f.last_seen > existing.last_seen):
                existing.last_seen = f.last_seen
            for ip in f.ips:
                if ip not in existing.ips:
                    existing.ips.append(ip)
        else:
            seen[key] = f
            out.append(f)
    return out


# ============================================================
# ANÁLISIS FORENSE — CLASES AUXILIARES
class TimelineAnalyzer:
    """Analiza la línea de tiempo unificada: detecta gaps, ráfagas y horas activas."""

    # Umbral: gap > 1 hora se considera silencio significativo
    GAP_THRESHOLD_SEC = 3600

    @staticmethod
    def analyze(timeline_events: List[dict]) -> dict:
        """Recibe la lista de eventos de timeline y devuelve métricas forenses."""
        timestamps = [
            datetime.datetime.fromisoformat(e["ts"])
            for e in timeline_events
            if e.get("ts")
        ]
        if len(timestamps) < 2:
            return {}

        timestamps.sort()

        # --- Intervalos entre eventos ---
        intervalos = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        # --- Gaps (silencios > 1h) ---
        gaps = []
        for i, intervalo in enumerate(intervalos):
            if intervalo >= TimelineAnalyzer.GAP_THRESHOLD_SEC:
                gaps.append({
                    "inicio": timestamps[i].isoformat(),
                    "fin": timestamps[i + 1].isoformat(),
                    "duracion_h": round(intervalo / 3600, 2),
                })

        # --- Ráfagas (>= 10 eventos en 60s) ---
        bursts = []
        i = 0
        while i < len(timestamps):
            ventana = [timestamps[i]]
            j = i + 1
            while j < len(timestamps) and (timestamps[j] - timestamps[i]).total_seconds() <= 60:
                ventana.append(timestamps[j])
                j += 1
            if len(ventana) >= 10:
                bursts.append({
                    "inicio": ventana[0].isoformat(),
                    "fin": ventana[-1].isoformat(),
                    "eventos": len(ventana),
                })
                i = j
            else:
                i += 1

        # --- Distribución por hora UTC ---
        hora_counter: Dict[int, int] = collections.Counter(ts.hour for ts in timestamps)
        horas_activas = sorted(hora_counter.items())

        # --- Primer y último evento ---
        return {
            "primer_evento": timestamps[0].isoformat(),
            "ultimo_evento": timestamps[-1].isoformat(),
            "duracion_total_h": round((timestamps[-1] - timestamps[0]).total_seconds() / 3600, 2),
            "total_eventos_timeline": len(timestamps),
            "gaps_silencio": gaps,
            "rafagas": bursts,
            "distribucion_por_hora_utc": {str(h): c for h, c in horas_activas},
        }


class SessionReconstructor:
    """Agrupa eventos por IP y ventana temporal para reconstruir sesiones de atacante."""

    def __init__(self, gap_minutos: int = 30):
        self.gap_sec = gap_minutos * 60

    def reconstruir(self, timeline_events: List[dict]) -> List[dict]:
        """Devuelve lista de sesiones {ip, inicio, fin, eventos, hallazgos}."""
        # Agrupar por IP
        por_ip: Dict[str, List[dict]] = collections.defaultdict(list)
        for ev in timeline_events:
            if ev.get("ip") and ev.get("ts"):
                por_ip[ev["ip"]].append(ev)

        sesiones = []
        for ip, eventos in por_ip.items():
            eventos_sorted = sorted(eventos, key=lambda e: e["ts"])
            # Dividir en sesiones según el gap
            sesion_actual: List[dict] = [eventos_sorted[0]]
            for ev in eventos_sorted[1:]:
                try:
                    t_prev = datetime.datetime.fromisoformat(sesion_actual[-1]["ts"])
                    t_curr = datetime.datetime.fromisoformat(ev["ts"])
                    if (t_curr - t_prev).total_seconds() > self.gap_sec:
                        sesiones.append(self._construir_sesion(ip, sesion_actual))
                        sesion_actual = [ev]
                    else:
                        sesion_actual.append(ev)
                except (ValueError, KeyError):
                    sesion_actual.append(ev)
            sesiones.append(self._construir_sesion(ip, sesion_actual))

        # Ordenar por peligrosidad (hallazgos CRITICAL/HIGH primero)
        def sev_score(s):
            return sum(1 for f in s["hallazgos_severidad"] if f in ("CRITICAL", "HIGH"))
        sesiones.sort(key=sev_score, reverse=True)
        return sesiones

    @staticmethod
    def _construir_sesion(ip: str, eventos: List[dict]) -> dict:
        hallazgos = [ev["finding"] for ev in eventos if ev.get("finding")]
        severidades = [ev["severity"] for ev in eventos if ev.get("severity") != "INFO"]
        acciones = list(dict.fromkeys(ev.get("action", "") for ev in eventos if ev.get("action")))
        rutas = list(dict.fromkeys(
            ev.get("resource", "")[:80] for ev in eventos if ev.get("resource")
        ))[:15]
        return {
            "ip": ip,
            "inicio": eventos[0]["ts"],
            "fin": eventos[-1]["ts"],
            "num_eventos": len(eventos),
            "hallazgos_fid": list(dict.fromkeys(hallazgos)),
            "hallazgos_severidad": severidades,
            "acciones": acciones[:10],
            "rutas_accedidas": rutas,
        }


class IOCExtractor:
    """Extrae indicadores de compromiso de hallazgos y eventos."""

    @staticmethod
    def extraer(findings: List[Finding], timeline_events: List[dict]) -> dict:
        """Devuelve dict con listas de IPs, rutas, user-agents y usuarios sospechosos."""
        ips: Dict[str, dict] = {}
        rutas: Dict[str, int] = collections.Counter()
        user_agents: Dict[str, int] = collections.Counter()
        usuarios: Dict[str, int] = collections.Counter()

        for f in findings:
            for ip in f.ips:
                if ip not in ips:
                    ips[ip] = {"ip": ip, "severidad_max": f.severity, "hallazgos": []}
                # Actualizar severidad máxima
                if _severity_rank(f.severity) > _severity_rank(ips[ip]["severidad_max"]):
                    ips[ip]["severidad_max"] = f.severity
                ips[ip]["hallazgos"].append(f.fid)
            for u in f.users:
                usuarios[u] += 1

        for ev in timeline_events:
            if ev.get("resource"):
                ruta = ev["resource"][:120]
                if ev.get("severity") in ("CRITICAL", "HIGH"):
                    rutas[ruta] += 1
            if ev.get("ip"):
                user_agents  # accedido desde IP, no UA directamente en timeline

        # User-agents de los eventos del detector
        # Los UAs no están en timeline; los obtenemos de los findings de FORA-009
        for f in findings:
            if "FORA-009" in f.fid:
                for ev_raw in f.evidence:
                    ua_match = re.search(r'"([^"]{10,200})"$', ev_raw)
                    if ua_match:
                        user_agents[ua_match.group(1)[:200]] += 1

        return {
            "ips_atacantes": sorted(ips.values(), key=lambda x: _severity_rank(x["severidad_max"]), reverse=True),
            "rutas_objetivo": [{"ruta": r, "ocurrencias": c} for r, c in rutas.most_common(30)],
            "user_agents_sospechosos": [{"ua": ua, "ocurrencias": c} for ua, c in user_agents.most_common(20)],
            "usuarios_objetivo": [{"usuario": u, "ocurrencias": c} for u, c in usuarios.most_common(20)],
        }


class ChainOfCustody:
    """Genera metadatos forenses: hashes SHA-256 de los ficheros analizados."""

    @staticmethod
    def generar(paths: List[str], analyst: str = "", case: str = "") -> dict:
        ficheros = []
        for p in paths:
            try:
                h = hashlib.sha256()
                size = 0
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                        size += len(chunk)
                ficheros.append({
                    "ruta": p,
                    "nombre": os.path.basename(p),
                    "sha256": h.hexdigest(),
                    "tamaño_bytes": size,
                })
            except OSError:
                ficheros.append({"ruta": p, "nombre": os.path.basename(p), "sha256": "ERROR", "tamaño_bytes": 0})

        return {
            "perito_analizador": analyst or "No especificado",
            "referencia_caso": case or "No especificado",
            "fecha_analisis_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "herramienta": f"{TOOL} v{VERSION}",
            "ficheros_evidencia": ficheros,
        }


class AttackChainMapper:
    """Mapea los hallazgos a tácticas MITRE ATT&CK y construye la cadena de ataque."""

    @staticmethod
    def mapear(findings: List[Finding]) -> dict:
        """Devuelve {táctica: [hallazgos]} ordenado por la kill chain típica."""
        orden_tacticas = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]

        por_tactica: Dict[str, List[dict]] = collections.defaultdict(list)
        for f in findings:
            fid_base = f.fid[:8]  # e.g. "FORA-001"
            info = MITRE_MAPPING.get(fid_base, {
                "tactic": "Other",
                "technique": "N/A",
            })
            por_tactica[info["tactic"]].append({
                "fid": f.fid,
                "severidad": f.severity,
                "titulo": f.title,
                "tecnica_mitre": info["technique"],
                "ips": f.ips[:5],
            })

        # Ordenar según kill chain
        resultado = {}
        for tactica in orden_tacticas:
            if tactica in por_tactica:
                resultado[tactica] = por_tactica[tactica]
        # Añadir tácticas no contempladas al final
        for tactica, hallazgos in por_tactica.items():
            if tactica not in resultado:
                resultado[tactica] = hallazgos

        return resultado


class IPActivityProfiler:
    """Construye perfiles de actividad completa por IP: días, horas, acciones, rutas, cuentas."""

    @staticmethod
    def perfilar(ip_events: Dict[str, List[LogEvent]]) -> Dict[str, dict]:
        """
        Recibe el dict {ip: [eventos]} del Detector y devuelve {ip: perfil_dict}.
        Los perfiles se ordenan por número total de eventos (descendente).
        """
        perfiles: Dict[str, dict] = {}

        for ip, eventos in sorted(ip_events.items(), key=lambda x: len(x[1]), reverse=True):
            eventos_ts = sorted(
                [e for e in eventos if e.timestamp],
                key=lambda e: e.timestamp,
            )

            # --- Fechas y períodos ---
            dias_set = sorted({e.timestamp.date().isoformat() for e in eventos_ts})
            primer_ev = eventos_ts[0].timestamp.isoformat() if eventos_ts else None
            ultimo_ev = eventos_ts[-1].timestamp.isoformat() if eventos_ts else None

            # --- Distribución por hora UTC ---
            dist_hora: Dict[int, int] = collections.Counter(e.timestamp.hour for e in eventos_ts)

            # --- Distribución por día de semana (0=Lun … 6=Dom) ---
            dias_semana_names = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]
            dist_diasem: Dict[str, int] = collections.Counter()
            for e in eventos_ts:
                dist_diasem[dias_semana_names[e.timestamp.weekday()]] += 1

            # --- Acciones ---
            acciones = collections.Counter(
                e.action for e in eventos if e.action and e.action not in ("INFO", "LOG")
            )

            # --- Recursos / rutas más accedidas ---
            recursos = collections.Counter(
                (e.resource or "")[:120] for e in eventos if e.resource
            )

            # --- Usuarios / cuentas ---
            usuarios = sorted({e.user for e in eventos if e.user})

            # --- Códigos HTTP ---
            status_c = collections.Counter(e.status for e in eventos if e.status is not None)
            exitos_http = sum(c for s, c in status_c.items() if isinstance(s, int) and 200 <= s < 300)
            fallos_http = sum(c for s, c in status_c.items() if isinstance(s, int) and s >= 400)

            # --- Éxitos/fallos de autenticación ---
            exitos_auth = acciones.get("SSH_OK", 0) + acciones.get("LOGIN_OK", 0)
            fallos_auth = (acciones.get("SSH_FAIL", 0) + acciones.get("LOGIN_FAIL", 0)
                           + acciones.get("AUTH_FAIL", 0))

            # --- Bytes transferidos ---
            bytes_total = sum(e.bytes_out or 0 for e in eventos)

            # --- Ficheros de log origen ---
            fuentes = sorted({os.path.basename(e.source_file) for e in eventos})

            # --- Actividad por franja horaria (para el informe) ---
            franja_noche  = sum(dist_hora.get(h, 0) for h in range(0, 6))
            franja_manana = sum(dist_hora.get(h, 0) for h in range(6, 12))
            franja_tarde  = sum(dist_hora.get(h, 0) for h in range(12, 18))
            franja_noche2 = sum(dist_hora.get(h, 0) for h in range(18, 24))

            perfiles[ip] = {
                "ip": ip,
                "total_eventos": len(eventos),
                "primer_evento": primer_ev,
                "ultimo_evento": ultimo_ev,
                "dias_activo": dias_set,
                "num_dias": len(dias_set),
                "distribucion_hora_utc": {str(h): dist_hora.get(h, 0) for h in range(24)},
                "distribucion_diasemana": dict(dist_diasem),
                "franja_madrugada_0_6h": franja_noche,
                "franja_manana_6_12h": franja_manana,
                "franja_tarde_12_18h": franja_tarde,
                "franja_noche_18_24h": franja_noche2,
                "acciones": dict(acciones.most_common(15)),
                "recursos_top": [{"ruta": r, "accesos": c} for r, c in recursos.most_common(30)],
                "usuarios_cuentas": usuarios,
                "status_http_dist": {str(s): c for s, c in status_c.most_common()},
                "exitos_http": exitos_http,
                "fallos_http": fallos_http,
                "exitos_auth": exitos_auth,
                "fallos_auth": fallos_auth,
                "bytes_total": bytes_total,
                "fuentes_log": fuentes,
            }

        return perfiles


class GeoIPResolver:
    """Resuelve IPs a país y ASN usando ip-api.com (batch, sin dependencias externas)."""

    BATCH_URL = "http://ip-api.com/batch"
    BATCH_SIZE = 100

    @staticmethod
    def resolver(ips: List[str]) -> Dict[str, dict]:
        """Devuelve {ip: {country, countryCode, org, as_, city}} para IPs públicas."""
        ips_publicas = [ip for ip in ips if not _ip_is_private(ip) and ip != "?"]
        ips_unicas = list(dict.fromkeys(ips_publicas))[:200]

        resultado: Dict[str, dict] = {}
        for i in range(0, len(ips_unicas), GeoIPResolver.BATCH_SIZE):
            lote = ips_unicas[i:i + GeoIPResolver.BATCH_SIZE]
            payload = json.dumps([
                {"query": ip, "fields": "query,country,countryCode,regionName,city,isp,org,as,status"}
                for ip in lote
            ]).encode()
            try:
                req = urllib.request.Request(
                    GeoIPResolver.BATCH_URL,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                for entry in data:
                    if entry.get("status") == "success":
                        resultado[entry["query"]] = {
                            "pais": entry.get("country", ""),
                            "codigo_pais": entry.get("countryCode", ""),
                            "region": entry.get("regionName", ""),
                            "ciudad": entry.get("city", ""),
                            "isp": entry.get("isp", ""),
                            "org": entry.get("org", ""),
                            "asn": entry.get("as", ""),
                        }
            except (urllib.error.URLError, OSError, json.JSONDecodeError):
                pass  # GeoIP es opcional; no interrumpir si falla la red

        return resultado


# ============================================================
# NUEVAS CAPACIDADES v2.1
# ============================================================

class BaselineProfiler:
    """Genera y compara perfiles estadísticos de comportamiento normal."""

    @staticmethod
    def generar(report: "Report") -> dict:
        baseline: dict = {
            "version": "1.0",
            "tool_version": VERSION,
            "created": datetime.datetime.utcnow().isoformat() + "Z",
            "sources": report.sources,
            "total_events": report.total_events_parsed,
            "known_ips": list(report.ip_profiles.keys()),
            "hourly_mean": {},
            "hourly_stdev": {},
            "bytes_mean": 0.0,
            "bytes_stdev": 0.0,
            "typical_detectors": {},
            "summary": dict(report.summary),
        }
        all_hourly: Dict[int, List[int]] = collections.defaultdict(list)
        all_bytes: List[float] = []
        for p in report.ip_profiles.values():
            for h_str, count in p["distribucion_hora_utc"].items():
                all_hourly[int(h_str)].append(count)
            if p.get("bytes_total"):
                all_bytes.append(float(p["bytes_total"]))
        for h in range(24):
            vals = all_hourly[h] or [0]
            baseline["hourly_mean"][str(h)] = round(statistics.mean(vals), 2)
            baseline["hourly_stdev"][str(h)] = round(
                statistics.stdev(vals) if len(vals) > 1 else 0.0, 2)
        if all_bytes:
            baseline["bytes_mean"] = round(statistics.mean(all_bytes), 0)
            baseline["bytes_stdev"] = round(
                statistics.stdev(all_bytes) if len(all_bytes) > 1 else 0.0, 0)
        for f in report.findings:
            baseline["typical_detectors"][f.fid] = (
                baseline["typical_detectors"].get(f.fid, 0) + 1)
        return baseline

    @staticmethod
    def comparar(baseline: dict, report: "Report") -> dict:
        baseline_ips = set(baseline.get("known_ips", []))
        current_ips = set(report.ip_profiles.keys())
        baseline_detectors = set(baseline.get("typical_detectors", {}).keys())
        current_detectors = set(f.fid for f in report.findings)

        anomalias_horarias: List[dict] = []
        for ip, p in report.ip_profiles.items():
            for h_str, count in p["distribucion_hora_utc"].items():
                h = int(h_str)
                mean = baseline["hourly_mean"].get(str(h), 0.0)
                stdev = baseline["hourly_stdev"].get(str(h), 0.0)
                if stdev > 0 and count > mean + 3 * stdev:
                    anomalias_horarias.append({
                        "ip": ip, "hora_utc": h, "eventos": count,
                        "media_baseline": mean,
                        "desviaciones_std": round((count - mean) / stdev, 1),
                    })
        anomalias_horarias.sort(key=lambda x: x["desviaciones_std"], reverse=True)

        # IPs nuevas con alta actividad
        threshold = 10
        if report.ip_profiles:
            max_ev = max(p["total_eventos"] for p in report.ip_profiles.values())
            threshold = max(10, max_ev // 20)
        ips_aumento = [
            {"ip": ip, "eventos": p["total_eventos"],
             "dias": p["num_dias"], "pico_hora": max(
                 p["distribucion_hora_utc"].items(), key=lambda x: x[1])[0]}
            for ip, p in sorted(report.ip_profiles.items(),
                                 key=lambda x: x[1]["total_eventos"], reverse=True)
            if ip not in baseline_ips and p["total_eventos"] >= threshold
        ][:20]

        return {
            "baseline_created": baseline.get("created", "?"),
            "baseline_sources": baseline.get("sources", []),
            "nuevas_ips": sorted(current_ips - baseline_ips),
            "ips_desaparecidas": sorted(baseline_ips - current_ips),
            "ips_nuevas_alta_actividad": ips_aumento,
            "nuevos_detectores": sorted(current_detectors - baseline_detectors),
            "detectores_desaparecidos": sorted(baseline_detectors - current_detectors),
            "anomalias_horarias": anomalias_horarias[:30],
            "resumen_baseline": baseline.get("summary", {}),
            "resumen_actual": dict(report.summary),
        }

class NarrativeGenerator:
    """Genera narrativa forense en español usando LLM (Ollama o Claude API)."""

    @staticmethod
    def _prompt(report: "Report") -> str:
        s = report.summary
        top_ips = list(report.ip_profiles.items())[:5]
        ip_lines = []
        for ip, p in top_ips:
            pico = max(p["distribucion_hora_utc"].items(), key=lambda x: x[1])
            ip_lines.append(
                f"  - {ip}: {p['total_eventos']} eventos, "
                f"{p['num_dias']} día(s), pico {pico[0]}h UTC, "
                f"franjas: madrugada {p['franja_madrugada_0_6h']} / "
                f"mañana {p['franja_manana_6_12h']} / "
                f"tarde {p['franja_tarde_12_18h']} / noche {p['franja_noche_18_24h']}"
            )
        top_f = sorted(report.findings,
                       key=lambda f: _severity_rank(f.severity), reverse=True)[:6]
        f_lines = [f"  - {f.fid} [{f.severity}]: {f.title}" for f in top_f]
        return (
            "Eres un perito informático forense experto en España. Redacta en español "
            "un párrafo narrativo técnico-jurídico de 180-280 palabras que describa el "
            "incidente de seguridad detectado. Usa lenguaje formal y preciso, apto para "
            "un informe pericial judicial. Sin listas ni viñetas. Incluye: período del "
            "incidente, patrones de actividad de las IPs más relevantes (franjas horarias, "
            "días activos), tipos de ataques o anomalías detectados y valoración de gravedad.\n\n"
            f"Período analizado : {report.time_range_start} → {report.time_range_end}\n"
            f"Eventos totales   : {report.total_events_parsed:,}\n"
            f"Hallazgos         : {s['total']} "
            f"({s['critical']} CRITICAL / {s['high']} HIGH / "
            f"{s['medium']} MEDIUM / {s['low']} LOW)\n"
            f"Fuentes de log    : {', '.join(report.sources)}\n\n"
            f"IPs más activas:\n{chr(10).join(ip_lines) or '  (sin datos de IP)'}\n\n"
            f"Hallazgos más graves:\n{chr(10).join(f_lines) or '  (sin hallazgos)'}\n\n"
            "Escribe SOLO el párrafo narrativo, sin títulos ni encabezados."
        )

    @staticmethod
    def ollama(report: "Report", model: str = "llama3.2:3b",
               host: str = "http://127.0.0.1:11434") -> str:
        payload = json.dumps({
            "model": model,
            "prompt": NarrativeGenerator._prompt(report),
            "stream": False,
            "options": {"temperature": 0.25, "num_predict": 500},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{host}/api/generate", data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read()).get("response", "").strip()
        except Exception as exc:
            return f"[Narrativa Ollama — error: {exc}]"

    @staticmethod
    def claude(report: "Report", api_key: str,
               model: str = "claude-haiku-4-5-20251001") -> str:
        payload = json.dumps({
            "model": model,
            "max_tokens": 600,
            "messages": [{"role": "user",
                           "content": NarrativeGenerator._prompt(report)}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                return data["content"][0]["text"].strip()
        except Exception as exc:
            return f"[Narrativa Claude — error: {exc}]"


class StreamingAnalyzer:
    """Monitorización en tiempo real de un log que crece (modo tail -f)."""

    COLORS = {
        "CRITICAL": "\033[1;37;41m", "HIGH": "\033[1;31m",
        "MEDIUM": "\033[1;33m", "LOW": "\033[1;36m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, path: str, log_type: str, config: dict,
                 min_severity: str = "MEDIUM", interval: float = 1.0):
        self.path = path
        self.log_type = log_type
        self.config = config
        self.min_severity = min_severity
        self.interval = interval
        self._seen: set = set()

    def seguir(self) -> None:
        ltype = (self.log_type if self.log_type != "auto"
                 else detect_log_type(self.path))
        parser = get_parser(ltype)
        detector = Detector(self.config)
        total_ev = 0

        print(f"\n{self.BOLD}[STREAM]{self.RESET} "
              f"Monitorizando: {self.path}  (tipo: {ltype})")
        print(f"         Umbral: {self.min_severity} | "
              f"Intervalo: {self.interval}s | Ctrl+C para detener\n")

        try:
            last_pos = pathlib.Path(self.path).stat().st_size
        except FileNotFoundError:
            print(f"[!] Fichero no encontrado: {self.path}", file=sys.stderr)
            return

        try:
            while True:
                time.sleep(self.interval)
                try:
                    cur_size = pathlib.Path(self.path).stat().st_size
                except OSError:
                    continue
                if cur_size <= last_pos:
                    continue

                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(last_pos)
                    new_content = fh.read()
                last_pos = cur_size

                if not new_content.strip():
                    continue

                # Parsear nuevas líneas vía fichero temporal
                tmp_fd, tmp_path = tempfile.mkstemp(suffix=f".{ltype}.log")
                try:
                    os.write(tmp_fd, new_content.encode("utf-8", errors="replace"))
                    os.close(tmp_fd)
                    for event in parser(tmp_path):
                        total_ev += 1
                        self._emit(detector.process(event))
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        except KeyboardInterrupt:
            print(f"\n{self.BOLD}[STREAM]{self.RESET} "
                  f"Detenido. {total_ev} eventos procesados.")
            final = detector.finalize()
            if final:
                print("\n[*] Hallazgos consolidados al cierre:")
                self._emit(final, force=True)

    def _emit(self, findings: List["Finding"], force: bool = False) -> None:
        min_rank = _severity_rank(self.min_severity)
        for f in findings:
            if _severity_rank(f.severity) < min_rank and not force:
                continue
            key = (f.fid, f.title, tuple(sorted(f.ips or [])))
            if key in self._seen:
                continue
            self._seen.add(key)
            ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
            color = self.COLORS.get(f.severity, "")
            ips_str = f"  ↳ IPs: {', '.join(f.ips[:5])}" if f.ips else ""
            print(f"[{ts}] {color}{f.severity:<8}{self.RESET} "
                  f"{f.fid}  {f.title}")
            if ips_str:
                print(ips_str)


# ============================================================
# GENERACIÓN DE INFORMES
# ============================================================

