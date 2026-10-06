# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, patrones de detección y modelos de datos.

Sin I/O. Contiene toda la nomenclatura estática, expresiones regulares,
mapeos MITRE ATT&CK y clases de datos (dataclasses) del analizador.
"""
from __future__ import annotations

import collections
import dataclasses
import datetime
import ipaddress
import json
import pathlib
import re
from typing import Dict, List, Optional

# ============================================================
# VERSIÓN Y METADATOS
# ============================================================

VERSION = "2.4.0"
TOOL_NAME = "vamp-log-analyzer"
TOOL = TOOL_NAME          # alias de compatibilidad
FINDING_PREFIX = "FORA"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-log-analyzer v2.4.0 · Forensic Log Analysis Platform
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ANSI: negrita magenta (coincide con el estilo del resto del toolkit)
_ANSI_BOLD_MAGENTA = "\033[1;35m"
_ANSI_RESET        = "\033[0m"

# ============================================================
# PATRONES DE DETECCIÓN — ATAQUES WEB
# ============================================================

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

# --- Parsers de logs: expresiones regulares y constantes ---
RE_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]{1,10})\s+(?P<resource>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

RE_MYSQL_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
RE_MYSQL_GEN = re.compile(
    r'^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\s+)?'
    r'(?P<thread>\d+)\s+(?P<cmd>Query|Connect|Quit|Init DB|Field List)\s+(?P<detail>.*)'
)
RE_MYSQL_SLOW = re.compile(r'^# User@Host:\s+(?P<user>\S+)\[.*?\]\s+@\s+(?P<host>\S+)\s+\[(?P<ip>[^\]]+)\]')

RE_MONGO_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+')

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

RE_SYSLOG_TS = RE_AUTH_TS  # mismo formato

RE_GENERIC_TS = re.compile(
    r'(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
    r'|(?P<bsd>\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)
RE_GENERIC_IP = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)

RE_OSSEC_ALERT_HDR = re.compile(r'^\*\* Alert (\d+(?:\.\d+)?): - (.+)$')
RE_OSSEC_HOST_LINE = re.compile(
    r'^(\d{4} \w+ \d{2} \d{2}:\d{2}:\d{2})\s+(\S+)->(\S+)$'
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
# CONSTANTES AUXILIARES
# ============================================================

# Rutas cuyo acceso periódico es legítimo por diseño (no marcar como C2 beacon)
BEACON_EXCLUDE_PATHS = (
    "/api/ical", "/ical", "/health", "/api/health", "/healthz", "/metrics",
    "/api/agent/poll", "/ws", "/api/notifications/poll", "/api/updates",
)

# Meses en formato BSD para parseo de timestamps auth.log
_BSD_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
)}
_CURRENT_YEAR = datetime.datetime.now(datetime.timezone.utc).year

# Mapeo de campos Sigma abstractos → atributos de LogEvent / extra
_SIGMA_FIELD_MAP: Dict[str, str] = {
    # red / web
    "src_ip": "ip", "c-ip": "ip", "src-ip": "ip",
    "destinationip": "ip", "dst_ip": "ip",
    "cs-uri-stem": "resource", "cs-uri-query": "resource",
    "requesturi": "resource", "uri": "resource", "path": "resource",
    "method": "action", "http_method": "action", "cs-method": "action",
    "useragent": "user_agent", "user_agent": "user_agent",
    "cs(user-agent)": "user_agent", "http_user_agent": "user_agent",
    "sc-status": "status", "status": "status",
    # autenticación
    "user": "user", "username": "user", "targetusername": "user",
    "subjectusername": "user", "accountname": "user",
    # proceso (Windows)
    "commandline": "action", "parentcommandline": "action",
    "image": "resource", "parentimage": "resource",
    "processname": "resource", "originalfilename": "resource",
    # syslog / genérico
    "message": "raw", "msg": "raw", "log.message": "raw",
    "eventid": "extra.event_id", "event_id": "extra.event_id",
    "servicename": "extra.service", "service": "extra.service",
    # Wazuh
    "rule.description": "raw", "full_log": "raw",
}

# ============================================================
# FUNCIONES AUXILIARES PURAS
# ============================================================


def _severity_rank(s: str) -> int:
    """Convierte severidad a rango numérico para comparación."""
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


def _ip_is_private(ip_str: Optional[str]) -> bool:
    """Devuelve True si la IP pertenece a un rango privado RFC-1918."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


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
    ip_profiles: dict = dataclasses.field(default_factory=dict)
    baseline_delta: dict = dataclasses.field(default_factory=dict)
    narrative: str = ""
    wazuh_rule_counts: dict = dataclasses.field(default_factory=dict)

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


@dataclasses.dataclass
class SigmaRule:
    """Regla Sigma parseada."""
    title: str
    rule_id: str
    status: str
    description: str
    level: str          # informational, low, medium, high, critical
    tags: List[str]
    logsource: Dict[str, str]
    detection: Dict
    falsepositives: List[str]
    path: str


# ============================================================
# CONFIGURACIÓN DE SCOPE
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
