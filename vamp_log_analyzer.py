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
  FORA-022  Credential stuffing (mismas credenciales, múltiples IPs)
  FORA-023  Baliza C2 — peticiones HTTP periódicas a intervalos regulares
  FORA-024  Fuerza bruta lenta (slow drip) distribuida en el tiempo
  FORA-025  Respuesta POST anormalmente grande (exfiltración vía API)

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
import textwrap
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, Generator, Iterable, List, Optional, Tuple

# ============================================================
# VERSIÓN Y METADATOS
# ============================================================

VERSION = "2.1"
TOOL = "vamp-log-analyzer"
FINDING_PREFIX = "FORA"

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-log-analyzer v2.0 · Forensic Log Analysis Platform
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
# MAPEO MITRE ATT&CK
# ============================================================

MITRE_MAPPING: Dict[str, dict] = {
    "FORA-001": {"tactic": "Credential Access",    "technique": "T1110.001 — Brute Force: Password Guessing (SSH)"},
    "FORA-002": {"tactic": "Credential Access",    "technique": "T1110.001 — Brute Force: Password Guessing (HTTP)"},
    "FORA-003": {"tactic": "Credential Access",    "technique": "T1110.003 — Brute Force: Password Spraying"},
    "FORA-004": {"tactic": "Initial Access",       "technique": "T1190 — Exploit Public-Facing Application (SQLi web)"},
    "FORA-005": {"tactic": "Initial Access",       "technique": "T1190 — Exploit Public-Facing Application (SQLi DB)"},
    "FORA-006": {"tactic": "Initial Access",       "technique": "T1190 — Exploit Public-Facing Application (XSS)"},
    "FORA-007": {"tactic": "Initial Access",       "technique": "T1190 — Exploit Public-Facing Application (LFI/RFI)"},
    "FORA-008": {"tactic": "Execution",            "technique": "T1505.003 — Server Software Component: Web Shell"},
    "FORA-009": {"tactic": "Reconnaissance",       "technique": "T1595 — Active Scanning"},
    "FORA-010": {"tactic": "Reconnaissance",       "technique": "T1595.001 — Active Scanning: Directory Fuzzing"},
    "FORA-011": {"tactic": "Exfiltration",         "technique": "T1048 — Exfiltration Over Alternative Protocol"},
    "FORA-012": {"tactic": "Collection",           "technique": "T1213 — Data from Information Repositories"},
    "FORA-013": {"tactic": "Privilege Escalation", "technique": "T1548 — Abuse Elevation Control Mechanism"},
    "FORA-014": {"tactic": "Persistence",          "technique": "T1136 — Create Account"},
    "FORA-015": {"tactic": "Defense Evasion",      "technique": "T1036 — Masquerading (horario inusual)"},
    "FORA-016": {"tactic": "Persistence",          "technique": "T1053 — Scheduled Task/Job"},
    "FORA-017": {"tactic": "Execution",            "technique": "T1059 — Command and Scripting Interpreter"},
    "FORA-018": {"tactic": "Lateral Movement",     "technique": "T1021 — Remote Services"},
    "FORA-019": {"tactic": "Discovery",            "technique": "T1083 — File and Directory Discovery"},
    "FORA-020": {"tactic": "Initial Access",       "technique": "T1078.003 — Valid Accounts: Local Accounts (root)"},
    "FORA-021": {"tactic": "Defense Evasion",      "technique": "T1027 — Obfuscated Files or Information"},
    "FORA-022": {"tactic": "Credential Access",    "technique": "T1110.004 — Brute Force: Credential Stuffing"},
    "FORA-023": {"tactic": "Command and Control",  "technique": "T1071.001 — Application Layer Protocol: Web Protocols (C2 beacon)"},
    "FORA-024": {"tactic": "Credential Access",    "technique": "T1110.001 — Brute Force: Slow Drip"},
    "FORA-025": {"tactic": "Exfiltration",         "technique": "T1041 — Exfiltration Over C2 Channel (POST response)"},
}

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
    # Campos extendidos (v2.0)
    sessions: List[dict] = dataclasses.field(default_factory=list)
    iocs: dict = dataclasses.field(default_factory=dict)
    chain_of_custody: dict = dataclasses.field(default_factory=dict)
    attack_chain: dict = dataclasses.field(default_factory=dict)
    timeline_analysis: dict = dataclasses.field(default_factory=dict)
    geoip_data: dict = dataclasses.field(default_factory=dict)
    ip_profiles: dict = dataclasses.field(default_factory=dict)  # {ip: perfil de actividad completa}
    baseline_delta: dict = dataclasses.field(default_factory=dict)  # comparativa vs baseline (v2.1)
    narrative: str = ""  # narrativa LLM del incidente (v2.1)

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
        if (event.log_type in ("web", "iis") and event.ip
                and event.resource and event.timestamp and event.status == 200):
            ruta = (event.resource or "").split("?")[0][:80]
            if len(ruta) > 3:
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

            usuarios_noche = sorted({e.user for e in eventos_noche if e.user})

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
    *,
    chain_of_custody: bool = False,
    analyst: str = "",
    case: str = "",
    enable_geoip: bool = False,
    scope: Optional[ScopeConfig] = None,
    session_gap_min: int = 30,
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
# ============================================================

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

class ScopeConfig:
    """Configuración del entorno del cliente para calibrar detectores."""

    def __init__(self, path: str):
        raw = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        self.business_start: int = raw.get("business_hours_start", 8)
        self.business_end: int = raw.get("business_hours_end", 20)
        self.tz_offset: int = raw.get("timezone_offset_hours", 0)
        self.trusted_nets: List[ipaddress.IPv4Network] = []
        for n in raw.get("trusted_ips", []):
            try:
                self.trusted_nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
        self.admin_ips: set = set(raw.get("admin_ips", []))
        self.exclude_detectors: set = set(raw.get("exclude_detectors", []))
        self.organization: str = raw.get("organization", "")
        self.case_name: str = raw.get("case_name", "")
        self.analyst_name: str = raw.get("analyst_name", "")
        self.normal_peak_hour: Optional[int] = raw.get("normal_peak_hour")

    def is_trusted(self, ip_str: Optional[str]) -> bool:
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.trusted_nets)
        except ValueError:
            return False

    def is_business_hour(self, hour_utc: int) -> bool:
        h = (hour_utc + self.tz_offset) % 24
        if self.business_start <= self.business_end:
            return self.business_start <= h < self.business_end
        return h >= self.business_start or h < self.business_end

    @staticmethod
    def ejemplo() -> str:
        return json.dumps({
            "organization": "Mi Empresa S.L.",
            "case_name": "CASO-2026-001",
            "analyst_name": "Nombre Apellido, Perito Informático Col. 00000",
            "business_hours_start": 8,
            "business_hours_end": 20,
            "timezone_offset_hours": 1,
            "trusted_ips": ["10.0.0.0/8", "192.168.0.0/16"],
            "admin_ips": ["192.168.1.10", "192.168.1.11"],
            "exclude_detectors": [],
            "normal_peak_hour": 11,
        }, ensure_ascii=False, indent=2)


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
    lineas.append(f"  INFORME FORENSE DE ANÁLISIS DE LOGS")
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
            lineas.append(f"\n  Rutas objetivo más atacadas:")
            for entry in rutas_ioc[:20]:
                lineas.append(f"    · ({entry['ocurrencias']:>4}x)  {entry['ruta']}")
        ua_ioc = iocs.get("user_agents_sospechosos", [])
        if ua_ioc:
            lineas.append(f"\n  User-Agents de herramientas de ataque:")
            for entry in ua_ioc[:10]:
                lineas.append(f"    · ({entry['ocurrencias']:>3}x)  {entry['ua'][:100]}")
        usr_ioc = iocs.get("usuarios_objetivo", [])
        if usr_ioc:
            lineas.append(f"\n  Usuarios objetivo (cuentas atacadas):")
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
            lineas.append(f"  Franjas horarias (UTC):")
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
    lineas.append(f"  © VampSecure Studios — VampSecure Labs Security Research Division")
    lineas.append(f"  Uso exclusivo en entornos autorizados.")
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
    parser.add_argument("paths", nargs="*", help="Ficheros o directorios de log a analizar")
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
    parser.add_argument("--follow", metavar="FICHERO",
                        help="Modo streaming: monitorizar fichero en tiempo real (tail -f)")

    args = parser.parse_args()

    # --- Modo --scope-example ---
    if getattr(args, "scope_example", False):
        print(ScopeConfig.ejemplo())
        return 0

    # --- Sin argumentos ---
    if not args.paths and not getattr(args, "follow", None):
        parser.print_help()
        return 0

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
