#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vamp-log-analyzer — Analizador Forense de Logs Multiplataforma
==============================================================
VampSecure Labs · VampSecure Studios Security Research Division

DESCRIPCIÓN
-----------
Analiza logs de servidores web, bases de datos, sistemas operativos (Linux,
Windows, macOS) y aplicaciones en busca de patrones de ataque, accesos
indebidos y señales de fuga de datos. Reconstruye la línea de tiempo completa
del incidente y genera informes con evidencias aptas para uso forense.

Fuentes de logs soportadas:
  WEB:    Apache, Nginx (Combined Log Format)
          IIS (W3C Extended Log Format)
  DB:     MySQL (error log, slow query log, general query log)
          PostgreSQL (CSV log)
          MongoDB (JSON log 4.4+, texto 3.x)
  LINUX:  auth.log, syslog, kern.log, /var/log/secure (RHEL/CentOS)
          journald (exportación JSON via journalctl -o json)
  WIN:    Windows Event Log exportado como XML (wevtutil qe Security /f:XML)
  MACOS:  macOS Unified Log JSON (log show --style json --last Xh)
  GENÉR.: JSON estructurado (cualquier esquema con campo "timestamp")
          Texto libre (heurísticas de timestamp + patron)

Detecciones:
  FORA-001  Fuerza bruta SSH / FTP / Telnet
  FORA-002  Fuerza bruta HTTP (401/403 masivos)
  FORA-003  Password spray (pocos intentos, muchos usuarios)
  FORA-004  Inyección SQL en petición web
  FORA-005  Inyección SQL en log de base de datos
  FORA-006  Cross-Site Scripting (XSS)
  FORA-007  Path traversal / LFI / RFI
  FORA-008  Acceso o carga de webshell
  FORA-009  Herramienta de escaneo / reconocimiento detectada
  FORA-010  Enumeración masiva de directorios (404 storm)
  FORA-011  Transferencia de datos anormalmente grande (exfiltración)
  FORA-012  Consulta de base de datos masiva (exfiltración DB)
  FORA-013  Escalada de privilegios (sudo/su/SUID)
  FORA-014  Cuenta privilegiada creada o modificada
  FORA-015  Actividad en horario nocturno anómalo
  FORA-016  Tarea programada sospechosa (cron / Windows Task)
  FORA-017  Proceso o comando sospechoso (Windows)
  FORA-018  Movimiento lateral detectado
  FORA-019  Acceso a archivos sensibles del sistema
  FORA-020  Login directo como root / SYSTEM
  FORA-021  Técnica de evasión de defensa (ofuscación, encoding)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.

USO
---
  python3 vamp_log_analyzer.py /var/log/nginx/access.log
  python3 vamp_log_analyzer.py /logs/ --type auto --report-html forense.html
  python3 vamp_log_analyzer.py /logs/ --from 2026-01-01 --to 2026-01-31
  python3 vamp_log_analyzer.py auth.log nginx.log mysql.log --report-json ev.json

CÓDIGOS DE SALIDA
-----------------
  0 — Sin hallazgos sobre el umbral mínimo
  1 — Hallazgos HIGH detectados
  2 — Hallazgos CRITICAL detectados
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime
import gzip
import ipaddress
import json
import os
import pathlib
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from typing import Dict, Generator, Iterable, List, Optional, Tuple

# ============================================================
# VERSIÓN Y METADATOS
# ============================================================

VERSION = "1.0"
TOOL = "vamp-log-analyzer"
FINDING_PREFIX = "FORA"

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-log-analyzer v1.0 · Forensic Log Analysis Platform
     ─────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ANSI: negrita magenta (coincide con el estilo del resto del toolkit)
_ANSI_BOLD_MAGENTA = "\033[1;35m"
_ANSI_RESET        = "\033[0m"


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
RE_SQLI = re.compile(
    r"(?i)(\bunion\b.{1,60}?\bselect\b"
    r"|\bselect\b.{1,60}?\bfrom\b.{1,60}?\bwhere\b"
    r"|'\s*(or|and)\s+['\"\d]"
    r"|\bexec\s*\(|\bexecute\s*\("
    r"|\bsp_executesql\b|\bxp_cmdshell\b"
    r"|information_schema|sys\.tables|sys\.columns"
    r"|SLEEP\s*\(\s*\d+|BENCHMARK\s*\(|WAITFOR\s+DELAY"
    r"|\bload_file\s*\(|into\s+outfile\s*['\"]"
    r"|extractvalue\s*\(|updatexml\s*\("
    r"|sqlmap|havij|sqlninja|pangolin)"
)

RE_XSS = re.compile(
    r"(?i)(<\s*script[^>]*>"
    r"|javascript\s*:"
    r"|on(?:load|error|click|mouseover|focus|blur|change|submit|keydown|keyup)\s*="
    r"|<\s*(?:iframe|frame|object|embed|applet|base)\b"
    r"|document\.(?:cookie|write|location)"
    r"|eval\s*\("
    r"|%3Cscript|&lt;script)"
)

RE_TRAVERSAL = re.compile(
    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c"
    r"|\/etc\/(?:passwd|shadow|group|hosts|sudoers|ssh\/)"
    r"|\\windows\\(?:system32|sam|win\.ini)"
    r"|\/proc\/(?:self|version|net\/)"
    r"|php:\/\/|file:\/\/|data:\/\/|zip:\/\/|phar:\/\/|glob:\/\/|expect:\/\/)"
)

RE_WEBSHELL = re.compile(
    r"(?i)(cmd=|exec=|command=|shell=|passthru=|system=|popen=|proc_open="
    r"|eval%28|base64_decode%28|str_rot13"
    r"|c99|r57|b374k|weevely|laudanum|phpspy|p0wnyshell"
    r"|net\+user|net%20user|whoami|id;|uname\+-a"
    r"|\.php\d?\?.{0,30}(?:=|\%3D)(?:\.\.\/|\/etc\/|\/proc\/))"
)

RE_RFI = re.compile(
    r"(?i)=(?:https?|ftp):\/\/(?!(?:www\.)?(?:google|youtube|facebook|twitter))[^\s&]{4,}"
)

RE_SCANNER_UA = re.compile(
    r"(?i)(sqlmap|nikto|nessus|openvas|nmap|masscan"
    r"|owasp.*zap|burpsuite|acunetix|dirbuster|dirb\b"
    r"|wfuzz|gobuster|ffuf|nuclei|feroxbuster"
    r"|hydra|medusa|metasploit|msfconsole"
    r"|havij|pangolin|zgrab|shodan|censys|binaryedge"
    r"|python-requests\/[0-9]|go-http-client\/[0-9]"
    r"|curl\/[0-9]|wget\/[0-9]"
    r"|masscan|netsparker|appscan|webscarab)"
)

RE_SCANNER_PATH = re.compile(
    r"(?i)\/(?:phpinfo|phpmyadmin|adminer|wp-login|wp-admin|xmlrpc)\.php"
    r"|\/\.(?:git|svn|env|htaccess|htpasswd|DS_Store)\b"
    r"|\/(?:web|app)?\.config\b"
    r"|\/(?:admin|administrator|manager|panel|cpanel|webadmin)\b"
    r"|\/(?:actuator|metrics|health|env|mappings)(?:\/|\?|$)"
    r"|\/(?:swagger|api-docs|graphql|graphiql)(?:\/|\?|$)"
    r"|\/(?:install|setup|update|upgrade)\.php"
    r"|\/(?:backup|dump|db)\.(sql|zip|tar|gz|bak)"
)

RE_SENSITIVE_FILES = re.compile(
    r"(?i)\/(?:\.env|\.env\.\w+|config\.php|wp-config\.php|settings\.py"
    r"|database\.yml|secrets\.yml|credentials\.json"
    r"|id_rsa|id_dsa|\.pem|\.key|\.p12|\.pfx"
    r"|passwd|shadow|sudoers|\.bash_history|\.ssh\/authorized_keys)"
)

# --- Linux / Unix ---
RE_SUDO_PRIVESC = re.compile(
    r"(?i)sudo\s+(?:-[a-z]+\s+)*(?:bash|sh|zsh|python\d?|perl|ruby|php"
    r"|nc\b|ncat\b|socat\b|find\s|vim|vi\b|nano|less|more|awk|sed"
    r"|cp\s|mv\s|cat\s|tee\s|dd\s|chmod|chown|install)"
)

RE_SU_ROOT = re.compile(r"\bsu\s+(?:-\s+)?(?:root|-\b|$)")

RE_SUID_WRITE = re.compile(r"chmod\s+(?:u\+s|[2-7][0-9]{3})\s+|chown\s+root")

RE_CRON_SUSPICIOUS = re.compile(
    r"(?i)(?:crontab|cron\.d|cron\.daily|cron\.hourly).*"
    r"(?:curl\s|wget\s|bash\s+-[ci]|nc\b|ncat\b|python\s+-c|perl\s+-e|php\s+-r"
    r"|base64\s+-d|eval\s*\(|exec\s*\(|\/tmp\/|\/dev\/shm\/|rm\s+-rf)"
)

RE_LATERAL_SSH = re.compile(
    r"ssh\s+(?:-[a-zA-Z]\s+\S+\s+)*"
    r"(?:(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d+\.\d+|localhost)"
)

RE_ROOT_LOGIN = re.compile(r"(?i)(?:Accepted|session opened for user|login)\s+(?:password|publickey)?\s+(?:for\s+)?root\b")

# --- Windows ---
RE_WIN_SUSPICIOUS_CMD = re.compile(
    r"(?i)(?:powershell|cmd\.exe).*"
    r"(?:-(?:enc|encoded|nop|noprofile|exec(?:ution)?(?:policy)?)\b"
    r"|(?:bypass|hidden|noninteractive)"
    r"|IEX\s*\(|Invoke-Expression\s*\("
    r"|-(?:W(?:indow)?S(?:tyle)?)\s+[Hh]idden)"
)

RE_WIN_LSASS = re.compile(r"(?i)(lsass|mimikatz|procdump.*lsass|sekurlsa|wce\.exe|fgdump)")

RE_WIN_LATERAL = re.compile(
    r"(?i)(psexec|wmic.*\/node:|winrm|sc\s+\\\\|net\s+use\s+\\\\|"
    r"copy\s+\S+\s+\\\\\S+|xcopy.*\\\\|robocopy.*\\\\)"
)

RE_WIN_PERSISTENCE = re.compile(
    r"(?i)(reg\s+add.*\\(?:Run|RunOnce|Services)\\"
    r"|schtasks.*/create"
    r"|sc\s+(?:create|config)\s+\S+\s+binpath"
    r"|New-Service\s|Install-Service\s"
    r"|Set-ItemProperty.*run\b)"
)

RE_WIN_EVASION = re.compile(
    r"(?i)(certutil.*-decode\b|certutil.*-urlcache\b"
    r"|bitsadmin.*/transfer\b"
    r"|mshta\s+(?:vbscript:|javascript:|https?:)"
    r"|regsvr32.*/[su]\s+/n\s+/i:"
    r"|rundll32.*,?\s*(?:DllRegisterServer|Control_RunDLL)"
    r"|wscript.*\.(?:vbs|js|hta)"
    r"|cscript.*\.(?:vbs|js)"
    r"|odbcconf.*\.rsp)"
)

# ============================================================
# MODELOS DE DATOS
# ============================================================

@dataclasses.dataclass
class LogEvent:
    """Evento normalizado extraído de cualquier fuente de log."""
    timestamp: Optional[datetime.datetime]
    source_file: str
    source_line: int
    log_type: str            # web, db_mysql, db_postgres, db_mongo, linux_auth,
                             # linux_sys, windows, macos, generic
    raw: str                 # línea original íntegra — evidencia
    ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    status: Optional[int] = None
    bytes_out: Optional[int] = None
    user_agent: Optional[str] = None
    extra: dataclasses.field(default_factory=dict) = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Finding:
    """Hallazgo de seguridad con evidencias."""
    fid: str                 # FORA-001, FORA-002, ...
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    attack_phase: str        # fase MITRE ATT&CK aproximada
    evidence: List[str]      # líneas raw del log
    events: List[LogEvent]
    first_seen: Optional[datetime.datetime]
    last_seen: Optional[datetime.datetime]
    ips: List[str]
    users: List[str]
    remediation: str

    @property
    def duration_str(self) -> str:
        if self.first_seen and self.last_seen and self.first_seen != self.last_seen:
            delta = self.last_seen - self.first_seen
            secs = int(delta.total_seconds())
            if secs < 60:
                return f"{secs}s"
            if secs < 3600:
                return f"{secs // 60}m {secs % 60}s"
            return f"{secs // 3600}h {(secs % 3600) // 60}m"
        return "—"


@dataclasses.dataclass
class Report:
    """Informe consolidado de análisis."""
    tool: str
    version: str
    generated: str
    sources: List[str]
    time_range_start: Optional[str]
    time_range_end: Optional[str]
    total_events_parsed: int
    findings: List[Finding]
    timeline: List[dict]

    @property
    def summary(self) -> dict:
        counts = collections.Counter(f.severity for f in self.findings)
        return {
            "total": len(self.findings),
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "info": counts.get("INFO", 0),
        }


# ============================================================
# PARSERS DE LOGS
# ============================================================

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


# --- Apache / Nginx (Combined Log Format) ---
RE_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]{1,10})\s+(?P<resource>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


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


# --- MySQL error / general / slow query log ---
RE_MYSQL_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
RE_MYSQL_GEN = re.compile(
    r'^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\s+)?'
    r'(?P<thread>\d+)\s+(?P<cmd>Query|Connect|Quit|Init DB|Field List)\s+(?P<detail>.*)'
)
RE_MYSQL_SLOW = re.compile(r'^# User@Host:\s+(?P<user>\S+)\[.*?\]\s+@\s+(?P<host>\S+)\s+\[(?P<ip>[^\]]+)\]')


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
# Formato: timestamp_with_ms, user, database, pid, client_host:port, session_id,
#          line_num, command_tag, session_start, vxid, txid, level, message, ...
def parse_postgres_csv(path: str) -> Generator[LogEvent, None, None]:
    import csv
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


# --- MongoDB log (JSON 4.4+ y texto 3.x) ---
RE_MONGO_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+')


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


# --- Linux auth.log / /var/log/secure ---
RE_AUTH_TS = re.compile(
    r'^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})|'
    r'(?P<bsd>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))'
)
RE_AUTH_SSH_FAIL = re.compile(
    r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.a-f:]+)'
)
RE_AUTH_SSH_OK = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from ([\d.a-f:]+)'
)
RE_AUTH_SUDO = re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.*)')
RE_AUTH_SU = re.compile(r'su(?:\[.+\])?:\s+(?:pam_)?(?:unix)?.*?:\s*(?:session opened for user|Successful su) (\S+)')
RE_AUTH_NEW_USER = re.compile(r'(?:useradd|adduser)\[.*\]:\s+new user.*name=(\S+)')
RE_AUTH_CRON = re.compile(r'(?:CRON|cron)\[.*\]:\s+\((\S+)\)\s+CMD\s+\((.+)\)')

_BSD_MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1
)}
_CURRENT_YEAR = datetime.datetime.now(datetime.timezone.utc).year


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


# --- Linux syslog / journald JSON ---
RE_SYSLOG_TS = RE_AUTH_TS  # mismo formato


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


# --- Windows Event Log XML ---
# Exportar con: wevtutil qe Security /f:XML /c:10000 > security.xml
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
        "generic": parse_generic,
    }.get(log_type, parse_generic)


# ============================================================
# MOTOR DE DETECCIÓN
# ============================================================

def _ip_is_private(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


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

        # --- Acceso a ficheros sensibles ---
        if RE_SENSITIVE_FILES.search(event.resource or ""):
            findings.append(self._make_finding(
                19, "HIGH",
                f"Acceso a fichero sensible desde {event.ip or 'IP desconocida'}",
                f"Petición a fichero de configuración o credenciales: {event.resource or ''}",
                "Descubrimiento / Acceso a archivos",
                [event],
                "Verificar si el acceso fue exitoso. Rotar credenciales si el fichero contiene secretos. "
                "Bloquear acceso web a ficheros de configuración con .htaccess o reglas nginx.",
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
                f"Se creó una cuenta de usuario en el sistema. Verificar si es legítima.",
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

        # --- Actividad nocturna anómala ---
        if event.timestamp:
            h = event.timestamp.hour
            if (self.c["unusual_hours"][0] <= h < self.c["unusual_hours"][1]
                    and event.action not in ("INFO", "LOG", "404")):
                findings.append(self._make_finding(
                    15, "LOW",
                    f"Actividad en horario nocturno ({event.timestamp.strftime('%H:%M')} UTC)",
                    f"Evento de tipo {event.action} registrado entre las "
                    f"{self.c['unusual_hours'][0]}h y {self.c['unusual_hours'][1]}h UTC. "
                    f"IP: {event.ip or '—'}  Usuario: {event.user or '—'}",
                    "Comportamiento anómalo",
                    [event],
                    "Verificar si la actividad era esperada (mantenimiento, backup, etc.). "
                    "Correlacionar con otros eventos del mismo IP/usuario.",
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
        # Password spray: pocos intentos por usuario, muchos usuarios distintos
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
        return self._findings_raw


# ============================================================
# MOTOR DE ANÁLISIS PRINCIPAL
# ============================================================

def analyze_files(
    paths: List[str],
    log_type: str,
    time_from: Optional[datetime.datetime],
    time_to: Optional[datetime.datetime],
    config: dict,
    verbose: bool = False,
) -> Report:
    detector = Detector(config)
    all_findings: List[Finding] = []
    timeline_events: List[dict] = []
    total_events = 0
    ts_min: Optional[datetime.datetime] = None
    ts_max: Optional[datetime.datetime] = None

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

                # Análisis estático
                per_event = detector.analyze_event(event)
                all_findings.extend(per_event)

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

    return Report(
        tool=TOOL, version=VERSION,
        generated=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        sources=paths,
        time_range_start=ts_min.isoformat() if ts_min else None,
        time_range_end=ts_max.isoformat() if ts_max else None,
        total_events_parsed=total_events,
        findings=all_findings,
        timeline=timeline_events,
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
# GENERACIÓN DE INFORMES
# ============================================================

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
        "timeline": report.timeline[:500],  # limitar a 500 entradas en JSON
    }
    return json.dumps(obj, ensure_ascii=False, indent=2)


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


# ============================================================
# CLI
# ============================================================

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


def build_config(args) -> dict:
    return {
        "large_response":       args.large_response_mb * 1024 * 1024,
        "brute_window_sec":     args.brute_window,
        "brute_threshold_ssh":  args.brute_ssh,
        "brute_threshold_web":  args.brute_web,
        "spray_users_min":      args.spray_min_users,
        "dir_enum_threshold":   args.dir_enum,
        "unusual_hours":        (args.night_from, args.night_to),
    }


def print_summary(report: Report) -> None:
    s = report.summary
    print(f"\n{'═' * 60}")
    print(f"  {TOOL} v{VERSION}")
    print(f"  © VampSecure Studios — VampSecure Labs")
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
    print(f"{'═' * 60}\n")


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
    parser.add_argument("paths", nargs="+", help="Ficheros o directorios de log a analizar")
    parser.add_argument("--type", default="auto",
                        choices=["auto","web","iis","db_mysql","db_postgres","db_mongo",
                                 "linux_auth","linux_sys","windows","macos","generic"],
                        help="Tipo de log (default: auto-detectar)")
    parser.add_argument("--from", dest="time_from", metavar="YYYY-MM-DD",
                        help="Analizar solo eventos desde esta fecha UTC")
    parser.add_argument("--to", dest="time_to", metavar="YYYY-MM-DD",
                        help="Analizar solo eventos hasta esta fecha UTC")
    parser.add_argument("--report-html", metavar="FICHERO", help="Guardar informe HTML")
    parser.add_argument("--report-json", metavar="FICHERO", help="Guardar informe JSON")
    parser.add_argument("--min-severity", default="LOW",
                        choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
                        help="Severidad mínima a reportar (default: LOW)")
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

    args = parser.parse_args()

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

    # Análisis
    config = build_config(args)
    report = analyze_files(paths, args.type, time_from, time_to, config, args.verbose)

    # Filtrar por severidad mínima
    min_rank = _severity_rank(args.min_severity)
    report.findings = [f for f in report.findings if _severity_rank(f.severity) >= min_rank]

    # Mostrar resumen en consola
    print_summary(report)

    # Guardar informes
    if args.report_json:
        out = pathlib.Path(args.report_json)
        out.write_text(to_json(report), encoding="utf-8")
        print(f"[✓] JSON guardado en: {out}", file=sys.stderr)

    if args.report_html:
        out = pathlib.Path(args.report_html)
        out.write_text(to_html(report), encoding="utf-8")
        print(f"[✓] HTML guardado en: {out}", file=sys.stderr)

    if not args.report_json and not args.report_html:
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
