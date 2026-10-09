<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-log-analyzer</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/stdlib%20only-no%20deps-brightgreen" alt="stdlib only"/>
  <img src="https://img.shields.io/badge/version-2.4-orange" alt="v2.4"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-AGPL--3.0-green" alt="License AGPL-3.0"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-log-analyzer/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

**VampSecure Labs · Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-log-analyzer` is a forensic log analysis platform for security incidents. It ingests logs from multiple sources — web servers, databases, operating systems, and applications — normalizes them into a unified timeline, and applies 25+ detectors to identify attacks, unauthorized access, privilege escalation, and exfiltration signals.

Designed for use in authorized audits, digital forensic expert witness work, and incident response. No external dependencies required: Python 3.9+ standard library only.

### Supported log sources

| Category | Sources |
|----------|---------|
| **Web** | Apache/Nginx (Combined Log Format), IIS (W3C Extended) |
| **Database** | MySQL (error/slow query/general log), PostgreSQL (CSV log), MongoDB (JSON 4.4+ / text 3.x) |
| **Linux/Unix** | `auth.log`, `syslog`, `kern.log`, `/var/log/secure` (RHEL/CentOS), journald (JSON export) |
| **Windows** | Windows Event Log exported as XML (`wevtutil qe Security /f:XML`) |
| **macOS** | macOS Unified Log JSON (`log show --style json`) |
| **Generic** | Structured JSON with timestamp field, free text with timestamp heuristics |

Log type detection is automatic (`--type auto`, default).

### Features — v2.1

- **No external dependencies** — stdlib Python 3.9+ only; works in any environment without additional installation
- **Multi-file and directories** — accepts individual paths, multiple files, or an entire directory (optional recursive with `--recursive`)
- **25 forensic detectors** (prefix `FORA-001` to `FORA-025`) with CRITICAL / HIGH / MEDIUM / LOW severity
- **Unified timeline** — all events from all files in chronological order with gap and burst detection
- **Session reconstruction** — groups events by IP and time window to reconstruct an attacker's sequence
- **IOC extractor** — exports indicators of compromise (IPs, paths, user-agents, users) to CSV for SIEM import
- **Forensic chain of custody** — SHA-256 hashes of analyzed files, analysis timestamp, and analyst data
- **GeoIP enrichment** — IP resolution to country/ASN via public API (no dependencies, `--geoip`)
- **MITRE ATT&CK mapping** — classifies findings by tactic: Reconnaissance, Initial Access, Credential Access, Lateral Movement, Exfiltration, etc.
- **Risk scoring** — compound formula: severity × frequency × IP context
- **Time filter** — `--from` / `--to` to restrict analysis to a date range
- **Multiple output formats** — console, JSON, HTML (dark theme), full forensic TXT report
- **[v2.1] ScopeConfig** — calibration JSON: business hours, trusted IPs, detectors excluded per environment
- **[v2.1] BaselineProfiler** — learns normal environment behavior and compares future analyses against it (delta)
- **[v2.1] STIX 2.1** — exports indicators of compromise in STIX 2.1 bundle format for MISP / OpenCTI / TheHive
- **[v2.1] EvidencePackager** — packages into a sealed ZIP with SHA-256 MANIFEST for judicial expert witness work with chain of custody
- **[v2.1] NarrativeGenerator** — generates forensic narrative in Spanish via Ollama (local) or Claude API (cloud)
- **[v2.1] StreamingAnalyzer** — real-time monitoring of growing logs (`tail -f` mode with live detection)
- **[v2.2] Sigma rules engine** — loads and evaluates Sigma rules (YAML) on the event stream; `--sigma-rules FILE_OR_DIR` accepts a `.yml` file or rules directory; generates `SIGMA-*` findings with the original rule's id/title/level; configurable field map to adapt non-standard logs
- **[v2.3] Real-time Wazuh API monitoring** — `--watch-wazuh-api HOST[:PORT]` connects to the Wazuh REST API (JWT), polls `/alerts` periodically and writes alerts to NDJSON (`--wazuh-output`); closes the VampPurple purple loop (P7) without manual ingestion

### Requirements

- Python 3.9 or higher
- No external dependencies (stdlib only)

### Installation

```bash
pip install vamp-log-analyzer
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-log-analyzer
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-log-analyzer.git
cd vamp-log-analyzer
# No pip install or virtualenv needed
python3 vamp_log_analyzer.py --help
```

### Usage

```bash
python3 vamp_log_analyzer.py FILE_OR_DIRECTORY [options]
```

#### Basic examples

```bash
# Quick analysis of an Nginx access log
python3 vamp_log_analyzer.py /var/log/nginx/access.log

# Complete log directory with auto-detected type
python3 vamp_log_analyzer.py /var/log/ --recursive

# Date range + HTML report
python3 vamp_log_analyzer.py /logs/nginx/ --from 2026-01-01 --to 2026-01-31 \
    --report-html incident_january.html

# Multiple simultaneous sources (cross-correlation)
python3 vamp_log_analyzer.py auth.log nginx/access.log mysql/error.log \
    --report-json report.json

# Full forensic mode: chain of custody + GeoIP + timeline + forensic report
python3 vamp_log_analyzer.py /logs/ \
    --chain-of-custody --analyst "John Smith" --case "CASE-2026-001" \
    --geoip --timeline \
    --report-forensic forensic_report.txt \
    --ioc-csv iocs_export.csv \
    --report-html visual_report.html

# Only CRITICAL or HIGH findings (useful in CI/CD pipelines)
python3 vamp_log_analyzer.py /var/log/ --min-severity HIGH -o findings.json
```

#### v2.1 examples — New capabilities

```bash
# Generate a scope file example
python3 vamp_log_analyzer.py --scope-example > environment.json

# Environment-calibrated analysis: suppress false positives from trusted IPs and business hours
python3 vamp_log_analyzer.py /logs/ --scope environment.json

# Learn normal environment behavior (first time)
python3 vamp_log_analyzer.py /logs/normal_week/ --learn baseline.json

# Compare an incident against the baseline: shows new IPs, anomalous detectors, time deviations
python3 vamp_log_analyzer.py /logs/incident/ --baseline baseline.json

# Export indicators in STIX 2.1 format (for MISP, OpenCTI, TheHive)
python3 vamp_log_analyzer.py /logs/ --stix findings.stix.json

# Package all evidence in a sealed ZIP with SHA-256 MANIFEST
python3 vamp_log_analyzer.py /logs/ \
    --chain-of-custody --analyst "Forensic Expert" --case "CASE-2026-001" \
    --stix findings.stix.json \
    --package evidence_case.zip

# Generate incident narrative with local AI (Ollama, default model llama3.2:3b)
python3 vamp_log_analyzer.py /logs/ --narrative ollama

# Narrative with remote Ollama or different model
python3 vamp_log_analyzer.py /logs/ \
    --narrative ollama \
    --narrative-model llama3.1:8b \
    --narrative-host http://my-server:11434

# Narrative with Claude API
python3 vamp_log_analyzer.py /logs/ \
    --narrative claude \
    --claude-api-key sk-ant-...

# Real-time monitoring of a growing log (Ctrl+C to stop)
python3 vamp_log_analyzer.py --follow /var/log/nginx/access.log
```

### Full CLI Reference

#### Input

| Flag | Default | Description |
|------|---------|-------------|
| `FILE [FILE ...]` | — | One or more log files, or a directory |
| `--type TYPE` | `auto` | Log type: `apache`, `nginx`, `iis`, `mysql`, `postgres`, `mongodb`, `auth`, `syslog`, `windows`, `macos`, `json`, `text`, `auto` |
| `--recursive / -R` | off | Scan directories recursively |
| `--follow FILE` | — | Real-time monitoring (streaming mode, Ctrl+C to stop) |

#### Filters

| Flag | Default | Description |
|------|---------|-------------|
| `--from DATE` | — | Filter events from this date (ISO 8601) |
| `--to DATE` | — | Filter events until this date |
| `--min-severity SEV` | `LOW` | Minimum severity threshold: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--top-n N` | `10` | Number of elements in rankings (IPs, paths, UAs) |
| `--min-session-gap N` | `30` | Minutes of silence to separate attacker sessions |

#### Enrichment

| Flag | Default | Description |
|------|---------|-------------|
| `--geoip` | off | Enrich IPs with country/ASN via public API |
| `--timeline` | off | Generate timeline analysis with gaps and bursts |

#### Forensic chain of custody

| Flag | Default | Description |
|------|---------|-------------|
| `--chain-of-custody` | off | Include SHA-256 hashes of files + analysis metadata |
| `--analyst "Name"` | — | Analyst name for forensic report |
| `--case "REF"` | — | Case reference for forensic report |

#### Environment calibration (v2.1)

| Flag | Default | Description |
|------|---------|-------------|
| `--scope FILE.json` | — | Environment configuration JSON file (business hours, trusted IPs, excluded detectors) |
| `--scope-example` | — | Print an environment file example and exit |

#### Statistical baseline (v2.1)

| Flag | Default | Description |
|------|---------|-------------|
| `--learn BASELINE.json` | — | Analyze log and save normal behavior profile to the indicated file |
| `--baseline BASELINE.json` | — | Compare current analysis against a previously saved baseline |

#### AI narrative (v2.1)

| Flag | Default | Description |
|------|---------|-------------|
| `--narrative [ollama\|claude]` | — | Generate forensic narrative with local AI (Ollama) or Claude API |
| `--narrative-model MODEL` | `llama3.2:3b` / `claude-haiku-4-5-20251001` | Model to use for narrative |
| `--narrative-host URL` | `http://127.0.0.1:11434` | Ollama host (only if `--narrative ollama`) |
| `--claude-api-key KEY` | — | Claude API key (only if `--narrative claude`) |

#### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o / --output FILE` | — | Save results to JSON |
| `--report-html FILE` | — | Generate HTML report with dark theme |
| `--report-forensic FILE` | — | Full forensic TXT report |
| `--ioc-csv FILE` | — | Export IOCs to CSV for SIEM |
| `--stix FILE.json` | — | Export STIX 2.1 bundle for MISP / OpenCTI / TheHive |
| `--package FILE.zip` | — | Package evidence in sealed ZIP with SHA-256 MANIFEST |
| `--sigma-rules PATH` | — | Sigma rules file or directory (YAML) to evaluate on the event stream |
| `-v / --verbose` | off | Detailed per-event output |

### Forensic detectors (FORA-001 to FORA-025)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| FORA-001 | SSH/FTP/Telnet brute force | HIGH | Multiple authentication failures on remote access services |
| FORA-002 | HTTP brute force | HIGH | Massive 401/403 responses from same IP in short period |
| FORA-003 | Password spray | HIGH | Few attempts per user but across many distinct users |
| FORA-004 | SQL injection (web) | CRITICAL | SQLi patterns in HTTP requests (Union, Blind, Time-based, OOB) |
| FORA-005 | SQL injection (database) | HIGH | Suspicious queries detected in database log |
| FORA-006 | Cross-Site Scripting (XSS) | HIGH | XSS patterns in web requests |
| FORA-007 | Path traversal / LFI / RFI | CRITICAL | Attempts to read files outside docroot or remote inclusion |
| FORA-008 | Webshell access/upload | CRITICAL | Calls to known webshells or backdoor patterns |
| FORA-009 | Scanning tool | HIGH | User-agent or traffic patterns from known scanners (sqlmap, nikto, nmap…) |
| FORA-010 | Directory enumeration (404 storm) | MEDIUM | Burst of 404s from same IP (path fuzzing) |
| FORA-011 | Abnormally large transfer | HIGH | Exceptionally large HTTP responses (possible exfiltration) |
| FORA-012 | Massive DB query | HIGH | Database query returning an anomalous volume of data |
| FORA-013 | Privilege escalation | HIGH | Use of sudo/su with shells or dangerous tools, SUID bits |
| FORA-014 | Privileged account created/modified | CRITICAL | Creation or modification of accounts with elevated privileges |
| FORA-015 | Nocturnal activity | MEDIUM | Authentication or admin events outside business hours |
| FORA-016 | Suspicious scheduled task | HIGH | Creation of cron jobs or Windows Tasks with anomalous commands |
| FORA-017 | Suspicious Windows process/command | HIGH | cmd.exe, PowerShell with encoding, wscript, certutil or other LOLBins |
| FORA-018 | Lateral movement | HIGH | Connections between internal hosts using credentials or admin protocols |
| FORA-019 | Sensitive file access | HIGH | Access to /etc/passwd, /etc/shadow, SSH keys, configuration files |
| FORA-020 | Direct root/SYSTEM login | CRITICAL | Direct authentication with system administrator account |
| FORA-021 | Evasion technique | HIGH | Encoding, obfuscation, double-encoding, SQL comments, string concatenation |
| FORA-022 | Credential stuffing | HIGH | Distinct IPs trying same credentials followed by success |
| FORA-023 | C2 beacon | HIGH | HTTP requests at regular intervals from a single agent (possible command and control) |
| FORA-024 | Slow brute force (slow drip) | MEDIUM | Password attempts distributed over hours to evade rate limiting |
| FORA-025 | Anomalous POST response size | HIGH | Large responses to POST requests (possible exfiltration via form or API) |

### Sample Output

```
  vamp-log-analyzer v2.4 · analyzing /var/log/nginx/access.log (1.2 GB)
  ──────────────────────────────────────────────────────────────────────
  [+] 847,231 events parsed · 25 detectors active · baseline: loaded

  ┌─ CRITICAL ──────────────────────────────────────────────────────────┐
  │  FORA-024  Distributed brute-force (slow drip over 4h 23min)        │
  │  Source: 34 IPs · 1,247 failed logins · Admin accounts: root, admin │
  │  First seen: 2026-10-03T02:14:17Z                                   │
  │  ATT&CK: T1110.001 (Password Guessing)                              │
  └─────────────────────────────────────────────────────────────────────┘

  [HIGH]   FORA-003  SQL injection attempts detected (47 requests from 18.197.x.x)
  [HIGH]   FORA-007  Path traversal: ../../../../etc/passwd (6 sources)
  [MEDIUM] FORA-015  Directory enumeration: 2,341 404s in 8min (gobuster pattern)
  [MEDIUM] FORA-019  Suspicious large response: 18.4 MB at /api/export
  [INFO]   FORA-025  New IP geolocation: RU (first appearance in 90d baseline)

  ──────────────────────────────────────────────────
  Δ vs baseline: +3 new anomaly types · -1 known pattern
  Total: 6 findings · STIX bundle: 23 objects
```

### Output formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Color-coded table + findings panel grouped by severity |
| JSON | `-o / --output FILE` | Complete structured output for integration with other tools |
| HTML | `--report-html FILE` | Standalone dark-theme report with finding cards, timeline, and rankings |
| Forensic TXT | `--report-forensic FILE` | Full expert witness report: chain of custody, chronology, IOCs, ATT&CK, baseline delta, AI narrative |
| IOC CSV | `--ioc-csv FILE` | Indicators of compromise in CSV for SIEM or TI platforms |
| STIX 2.1 | `--stix FILE` | STIX 2.1 bundle with identity, attack-pattern, indicator, observed-data and relationships |
| Evidence ZIP | `--package FILE` | Sealed ZIP: original logs + reports + chain_of_custody.json + MANIFEST.sha256 |

### Exit codes

| Code | Meaning | CI/CD behavior |
|------|---------|----------------|
| `0` | No findings above minimum threshold | Pipeline passes |
| `1` | HIGH findings detected | Pipeline fails — review required |
| `2` | CRITICAL findings detected | Pipeline fails — immediate action required |

### MITRE ATT&CK mapping

Findings are automatically classified by ATT&CK tactic:

| Tactic | Detectors |
|--------|----------|
| Reconnaissance | FORA-009, FORA-010 |
| Initial Access | FORA-004, FORA-006, FORA-007, FORA-008 |
| Credential Access | FORA-001, FORA-002, FORA-003, FORA-022, FORA-024 |
| Privilege Escalation | FORA-013, FORA-014, FORA-020 |
| Defense Evasion | FORA-021 |
| Persistence | FORA-016 |
| Lateral Movement | FORA-018 |
| Command & Control | FORA-023 |
| Collection / Exfiltration | FORA-011, FORA-012, FORA-025 |
| Discovery | FORA-019 |

### ScopeConfig — Environment calibration

The environment file allows the analyzer to distinguish normal from suspicious activity in context:

```bash
python3 vamp_log_analyzer.py --scope-example > environment.json
```

```json
{
  "organization": "My Company Ltd.",
  "case_name": "CASE-2026-001",
  "analyst_name": "First Last, Forensic Expert",
  "business_hours_start": 8,
  "business_hours_end": 20,
  "timezone_offset_hours": 1,
  "trusted_ips": ["10.0.0.0/8", "192.168.0.0/16"],
  "admin_ips": ["192.168.1.10", "192.168.1.11"],
  "exclude_detectors": [],
  "normal_peak_hour": 11
}
```

With `--scope environment.json`:
- Findings from IPs in `trusted_ips` are suppressed if **all** involved IPs are trusted
- Detector FORA-015 (nocturnal activity) uses the environment's business hours instead of the default value
- Detectors in `exclude_detectors` are skipped entirely

### BaselineProfiler — Differential analysis

```bash
# Step 1: learn normal behavior (incident-free week)
python3 vamp_log_analyzer.py /logs/normal_week/ --learn baseline.json

# Step 2: analyze and compare incident against baseline
python3 vamp_log_analyzer.py /logs/incident/ --baseline baseline.json
```

The differential report shows:
- New IPs not present in the baseline
- Disappeared IPs (possible attacker infrastructure change)
- New IPs with abnormally high activity
- New detectors not seen in the baseline
- Time anomalies with statistical deviation (mean ± 3σ)
- Comparative finding count table by severity (▲ up / ▼ down / ═ stable)

### STIX 2.1 — Integration with TI platforms

```bash
python3 vamp_log_analyzer.py /logs/ --stix findings.stix.json
```

The generated STIX 2.1 bundle contains:
- `identity` — VampSecure Labs identity as source
- `attack-pattern` — one per each ATT&CK technique detected
- `indicator` — one per IP with findings (internal IPs marked as such)
- `observed-data` — global observed event of the analysis
- `relationship` — deduplicated indicator→attack-pattern links

The file is compatible with MISP, OpenCTI, TheHive, and any platform that supports STIX 2.1.

### EvidencePackager — Judicial evidence package

```bash
python3 vamp_log_analyzer.py /logs/ \
    --chain-of-custody --analyst "John Smith, Expert Witness" --case "CASE-2026-001" \
    --stix findings.stix.json \
    --package evidence_package.zip
```

The ZIP contains:
```
evidence/
    <original_log_name>       # literal copy of the analyzed log
reports/
    forensic_report.txt       # full expert witness report
    iocs.csv                  # indicators of compromise
    findings.stix.json        # STIX 2.1 bundle
    analysis.json             # full JSON dump
chain_of_custody.json         # analyst, case, UTC date, SHA-256 of each file
MANIFEST.sha256               # SHA-256 hash of all files in the package
```

The MANIFEST allows verifying the package integrity at any later time.

### NarrativeGenerator — AI forensic narrative

```bash
# With local Ollama (default llama3.2:3b, no cost)
python3 vamp_log_analyzer.py /logs/ --narrative ollama

# With Claude API
python3 vamp_log_analyzer.py /logs/ --narrative claude --claude-api-key sk-ant-...
```

The narrative is generated in forensic Spanish, describing the incident from the expert witness perspective: most active IPs, time ranges, detected techniques, and probable attack sequence. Automatically included in section 9 of the forensic TXT report.

### StreamingAnalyzer — Real-time monitoring

```bash
python3 vamp_log_analyzer.py --follow /var/log/nginx/access.log
python3 vamp_log_analyzer.py --follow /var/log/auth.log --min-severity HIGH
```

Monitors the indicated file from its current end, processing new lines every second. Press Ctrl+C to consolidate and display final findings for the monitored period. Useful for real-time incident response without additional infrastructure.

### Why vamp-log-analyzer vs. Splunk · Elastic SIEM · Graylog

| Feature | vamp-log-analyzer | Splunk | Elastic SIEM | Graylog |
|---------|:-----------------:|:------:|:------------:|:-------:|
| Zero external dependencies (stdlib only) | ✅ | ❌ | ❌ | ❌ |
| Offline / air-gapped forensics | ✅ | ❌ | ❌ | ❌ |
| STIX 2.1 bundle export | ✅ | ❌ | ✅ | ❌ |
| Evidence package with SHA-256 chain of custody | ✅ | ❌ | ❌ | ❌ |
| Sigma rules evaluation | ✅ | ✅ | ✅ | ✅ |
| AI narrative generation (Ollama / Claude) | ✅ | ❌ | ❌ | ❌ |
| Baseline differential analysis (delta) | ✅ | ✅ | ✅ | ❌ |
| Single-file deployment, no agent or index required | ✅ | ❌ | ❌ | ❌ |

- **Forensically sound out of the box.** SHA-256 chain of custody, analyst/case metadata, and ZIP evidence packaging are first-class features — not add-ons. Splunk and Elastic require custom workflows to achieve the same result.
- **No infrastructure required.** Run it on a laptop in an air-gapped investigation room. Splunk/Elastic/Graylog require deployed stacks, indexes, and agents before any analysis can begin.
- **Purpose-built for incident response and legal proceedings.** The `--report-forensic` output follows expert witness format with numbered sections, analyst identification, and hash verification — not a generic dashboard.
- **STIX 2.1 + MITRE ATT&CK natively.** Findings map to ATT&CK techniques and export as importable STIX 2.1 bundles for MISP, OpenCTI, or TheHive — without a paid connector or plugin.

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| FORA-001 | Brute-force on SSH / FTP / Telnet (repeated authentication failures) | MITRE T1110.001 | HIGH |
| FORA-004 | SQL injection patterns in HTTP requests (Union, Blind, Time-based) | OWASP A03:2021 · MITRE T1190 | CRITICAL |
| FORA-007 | Path traversal / LFI / RFI in URI parameters | OWASP A01:2021 · MITRE T1083 | CRITICAL |
| FORA-008 | Webshell access or RCE parameter detected in web logs | MITRE T1505.003 | CRITICAL |
| FORA-013 | Privilege escalation via sudo/su with dangerous commands | MITRE T1548.003 | HIGH |
| FORA-014 | Privileged account creation or modification detected | MITRE T1136 | CRITICAL |
| FORA-018 | Lateral movement: admin-protocol connections between internal hosts | MITRE T1021 | HIGH |
| FORA-020 | Direct root/SYSTEM login via SSH or console | MITRE T1078.003 | CRITICAL |
| FORA-022 | Credential stuffing: distinct IPs using same credentials with success | MITRE T1110.004 | HIGH |
| FORA-023 | C2 beacon: periodic HTTP calls at fixed intervals from single agent | MITRE T1071.001 | HIGH |
| FORA-024 | Slow-drip brute force distributed over hours to evade rate limiting | MITRE T1110 | MEDIUM |
| SIGMA-* | Custom Sigma rule match (YAML-defined, user-supplied ruleset) | Sigma Specification | Variable |

### Legal Notice

For exclusive use on your own systems or with written authorization from the owner.
VampSecure Studios assumes no liability for unauthorized use of this tool.

### Part of VampSecure Labs Toolkit

`vamp-log-analyzer` is a tool in the VampSecure Labs security research toolkit.

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)

### Version History

| Version | Main changes |
|---------|-------------|
| v2.4 | Bilingual README (EN/ES) |
| v2.3 | Real-time Wazuh API monitoring — `--watch-wazuh-api`, JWT, NDJSON, VampPurple P7 |
| v2.2 | Sigma rules engine — `--sigma-rules`, SigmaLoader + SigmaEngine, `SIGMA-*` findings |
| v2.1 | ScopeConfig, BaselineProfiler, STIX 2.1, EvidencePackager, NarrativeGenerator, StreamingAnalyzer |
| v2.0 | 25 FORA detectors, multi-source, GeoIP enrichment, MITRE ATT&CK |

---

© VampSecure Studios — VampSecure Labs Security Research Division

---
---

<a name="español"></a>
## 🇪🇸 Español

`vamp-log-analyzer` es una plataforma forense de análisis de logs para incidentes de seguridad.
Ingesta logs de múltiples fuentes —servidores web, bases de datos, sistemas operativos y
aplicaciones— los normaliza en una línea de tiempo unificada y aplica 25+ detectores para
identificar ataques, accesos indebidos, escaladas de privilegios y señales de exfiltración.

Diseñado para uso en auditorías autorizadas, peritajes informáticos y respuesta a incidentes.
No requiere dependencias externas: únicamente librería estándar de Python 3.9+.

### Fuentes de logs soportadas

| Categoría | Fuentes |
|-----------|---------|
| **Web** | Apache/Nginx (Combined Log Format), IIS (W3C Extended) |
| **Base de datos** | MySQL (error/slow query/general log), PostgreSQL (CSV log), MongoDB (JSON 4.4+ / texto 3.x) |
| **Linux/Unix** | `auth.log`, `syslog`, `kern.log`, `/var/log/secure` (RHEL/CentOS), journald (exportación JSON) |
| **Windows** | Windows Event Log exportado como XML (`wevtutil qe Security /f:XML`) |
| **macOS** | macOS Unified Log JSON (`log show --style json`) |
| **Genérico** | JSON estructurado con campo timestamp, texto libre con heurísticas de timestamp |

La detección del tipo de log es automática (`--type auto`, predeterminada).

### Características — v2.1

- **Sin dependencias externas** — únicamente stdlib Python 3.9+; funciona en cualquier entorno sin instalación adicional
- **Multi-fichero y directorios** — acepta rutas individuales, múltiples ficheros o un directorio completo (recursivo opcional con `--recursive`)
- **25 detectores forenses** (prefijo `FORA-001` a `FORA-025`) con severidad CRITICAL / HIGH / MEDIUM / LOW
- **Timeline unificada** — todos los eventos de todos los ficheros en orden cronológico con detección de saltos y ráfagas
- **Reconstrucción de sesiones** — agrupa eventos por IP y ventana temporal para reconstruir la secuencia de un atacante
- **Extractor de IOCs** — exporta indicadores de compromiso (IPs, rutas, user-agents, usuarios) a CSV para importar en SIEM
- **Cadena de custodia forense** — hashes SHA-256 de los ficheros analizados, timestamp de análisis y datos del perito
- **Enriquecimiento GeoIP** — resolución de IPs a país/ASN vía API pública (sin dependencias, `--geoip`)
- **Mapeo MITRE ATT&CK** — clasifica los hallazgos por táctica: Reconnaissance, Initial Access, Credential Access, Lateral Movement, Exfiltration, etc.
- **Puntuación de riesgo** — fórmula compuesta por severidad × frecuencia × contexto de IP
- **Filtro temporal** — `--from` / `--to` para acotar el análisis a un rango de fechas
- **Formato de salida múltiple** — consola, JSON, HTML (tema oscuro), informe forense TXT completo
- **[v2.1] ScopeConfig** — JSON de calibración: horas laborales, IPs de confianza, detectores excluidos por entorno
- **[v2.1] BaselineProfiler** — aprende el comportamiento normal de un entorno y compara análisis futuros contra él (delta)
- **[v2.1] STIX 2.1** — exporta indicadores de compromiso en formato STIX 2.1 bundle para MISP / OpenCTI / TheHive
- **[v2.1] EvidencePackager** — empaqueta en ZIP sellado con MANIFEST SHA-256 para peritaje judicial con cadena de custodia
- **[v2.1] NarrativeGenerator** — genera narrativa forense en español vía Ollama (local) o Claude API (cloud)
- **[v2.1] StreamingAnalyzer** — monitorización en tiempo real de logs en crecimiento (modo `tail -f` con detección live)
- **[v2.2] Motor de reglas Sigma** — carga y evalúa reglas Sigma (YAML) sobre el stream de eventos; `--sigma-rules FICHERO_O_DIR` acepta un fichero `.yml` o un directorio de reglas; genera hallazgos `SIGMA-*` con el id/título/nivel de la regla original; campo-map configurable para adaptar logs no estándar
- **[v2.3] Vigilancia Wazuh API en tiempo real** — `--watch-wazuh-api HOST[:PUERTO]` conecta a la API REST Wazuh (JWT), sondea `/alerts` periódicamente y escribe alertas en NDJSON (`--wazuh-output`); cierra el loop purple de VampPurple (P7) sin ingesta manual

### Requisitos

- Python 3.9 o superior
- Sin dependencias externas (stdlib only)

### Instalación

```bash
pip install vamp-log-analyzer
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-log-analyzer
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-log-analyzer.git
cd vamp-log-analyzer
# No se necesita pip install ni virtualenv
python3 vamp_log_analyzer.py --help
```

### Uso

```bash
python3 vamp_log_analyzer.py FICHERO_O_DIRECTORIO [opciones]
```

#### Ejemplos básicos

```bash
# Análisis rápido de un log de acceso de Nginx
python3 vamp_log_analyzer.py /var/log/nginx/access.log

# Directorio completo de logs con tipo auto-detectado
python3 vamp_log_analyzer.py /var/log/ --recursive

# Rango de fechas + informe HTML
python3 vamp_log_analyzer.py /logs/nginx/ --from 2026-01-01 --to 2026-01-31 \
    --report-html incidente_enero.html

# Múltiples fuentes simultáneas (correlación cruzada)
python3 vamp_log_analyzer.py auth.log nginx/access.log mysql/error.log \
    --report-json informe.json

# Modo forense completo: cadena de custodia + GeoIP + timeline + informe forense
python3 vamp_log_analyzer.py /logs/ \
    --chain-of-custody --analyst "Juan Pérez" --case "CASE-2026-001" \
    --geoip --timeline \
    --report-forensic informe_pericial.txt \
    --ioc-csv iocs_exportar.csv \
    --report-html informe_visual.html

# Solo hallazgos CRITICAL o HIGH (útil en pipelines CI/CD)
python3 vamp_log_analyzer.py /var/log/ --min-severity HIGH -o findings.json
```

#### Ejemplos v2.1 — Nuevas capacidades

```bash
# Generar un ejemplo de fichero de entorno (scope)
python3 vamp_log_analyzer.py --scope-example > entorno.json

# Análisis calibrado al entorno: suprime falsos positivos de IPs de confianza y horario laboral
python3 vamp_log_analyzer.py /logs/ --scope entorno.json

# Aprender el comportamiento normal de un entorno (primera vez)
python3 vamp_log_analyzer.py /logs/semana_normal/ --learn baseline.json

# Comparar un incidente contra el baseline: muestra IPs nuevas, detectores anómalos y desviaciones horarias
python3 vamp_log_analyzer.py /logs/incidente/ --baseline baseline.json

# Exportar indicadores en formato STIX 2.1 (para MISP, OpenCTI, TheHive)
python3 vamp_log_analyzer.py /logs/ --stix hallazgos.stix.json

# Empaquetar todas las evidencias en un ZIP sellado con MANIFEST SHA-256
python3 vamp_log_analyzer.py /logs/ \
    --chain-of-custody --analyst "Perito Forense" --case "CASO-2026-001" \
    --stix hallazgos.stix.json \
    --package evidencias_caso.zip

# Generar narrativa del incidente con IA local (Ollama, modelo por defecto llama3.2:3b)
python3 vamp_log_analyzer.py /logs/ --narrative ollama

# Narrativa con Ollama remoto o modelo diferente
python3 vamp_log_analyzer.py /logs/ \
    --narrative ollama \
    --narrative-model llama3.1:8b \
    --narrative-host http://mi-servidor:11434

# Narrativa con Claude API
python3 vamp_log_analyzer.py /logs/ \
    --narrative claude \
    --claude-api-key sk-ant-...

# Monitorización en tiempo real de un log en crecimiento (Ctrl+C para finalizar)
python3 vamp_log_analyzer.py --follow /var/log/nginx/access.log

# Flujo peritaje completo con todas las capacidades
python3 vamp_log_analyzer.py /evidencias/ \
    --chain-of-custody --analyst "Juan Pérez, Perito Col. 00000" --case "Diligencias XX/2026" \
    --scope entorno_cliente.json \
    --baseline baseline_cliente.json \
    --geoip --timeline \
    --report-forensic informe_pericial.txt \
    --ioc-csv iocs.csv \
    --stix hallazgos.stix.json \
    --narrative ollama \
    --package paquete_evidencias.zip
```

### Referencia CLI completa

#### Entrada

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `FICHERO [FICHERO ...]` | — | Uno o más ficheros de log, o un directorio |
| `--type TYPE` | `auto` | Tipo de log: `apache`, `nginx`, `iis`, `mysql`, `postgres`, `mongodb`, `auth`, `syslog`, `windows`, `macos`, `json`, `text`, `auto` |
| `--recursive / -R` | off | Escanear directorios recursivamente |
| `--follow FICHERO` | — | Monitorización en tiempo real (modo streaming, Ctrl+C para finalizar) |

#### Filtros

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--from FECHA` | — | Filtrar eventos a partir de esta fecha (ISO 8601) |
| `--to FECHA` | — | Filtrar eventos hasta esta fecha |
| `--min-severity SEV` | `LOW` | Umbral mínimo de severidad: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--top-n N` | `10` | Número de elementos en rankings (IPs, rutas, UAs) |
| `--min-session-gap N` | `30` | Minutos de silencio para separar sesiones de atacante |

#### Enriquecimiento

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--geoip` | off | Enriquecer IPs con país/ASN vía API pública |
| `--timeline` | off | Generar análisis de línea de tiempo con gaps y ráfagas |

#### Cadena de custodia forense

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--chain-of-custody` | off | Incluir hashes SHA-256 de ficheros + metadatos de análisis |
| `--analyst "Nombre"` | — | Nombre del perito para informe forense |
| `--case "REF"` | — | Referencia del caso para informe forense |

#### Calibración de entorno (v2.1)

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--scope FICHERO.json` | — | Fichero JSON de configuración de entorno (horas laborales, IPs de confianza, detectores excluidos) |
| `--scope-example` | — | Imprimir un ejemplo de fichero de entorno y salir |

#### Baseline estadístico (v2.1)

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--learn BASELINE.json` | — | Analizar el log y guardar el perfil de comportamiento normal en el fichero indicado |
| `--baseline BASELINE.json` | — | Comparar el análisis actual contra un baseline guardado previamente |

#### Narrativa IA (v2.1)

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--narrative [ollama\|claude]` | — | Generar narrativa forense en español con IA local (Ollama) o Claude API |
| `--narrative-model MODELO` | `llama3.2:3b` / `claude-haiku-4-5-20251001` | Modelo a usar para la narrativa |
| `--narrative-host URL` | `http://127.0.0.1:11434` | Host de Ollama (solo si `--narrative ollama`) |
| `--claude-api-key KEY` | — | API key de Claude (solo si `--narrative claude`) |

#### Salida

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `-o / --output FILE` | — | Guardar resultados en JSON |
| `--report-html FILE` | — | Generar informe HTML con tema oscuro |
| `--report-forensic FILE` | — | Informe forense TXT completo |
| `--ioc-csv FILE` | — | Exportar IOCs en CSV para SIEM |
| `--stix FICHERO.json` | — | Exportar bundle STIX 2.1 para MISP / OpenCTI / TheHive |
| `--package FICHERO.zip` | — | Empaquetar evidencias en ZIP sellado con MANIFEST SHA-256 |
| `--sigma-rules RUTA` | — | Fichero o directorio de reglas Sigma (YAML) a evaluar sobre el stream de eventos |
| `-v / --verbose` | off | Salida detallada por evento |

### Detectores forenses (FORA-001 a FORA-025)

| ID | Nombre | Severidad | Descripción |
|----|--------|-----------|-------------|
| FORA-001 | Fuerza bruta SSH/FTP/Telnet | HIGH | Múltiples autenticaciones fallidas en servicios de acceso remoto |
| FORA-002 | Fuerza bruta HTTP | HIGH | Código 401/403 masivo desde misma IP en corto periodo |
| FORA-003 | Password spray | HIGH | Pocos intentos por usuario pero sobre muchos usuarios distintos |
| FORA-004 | Inyección SQL (web) | CRITICAL | Patrones SQLi en peticiones HTTP (Union, Blind, Time-based, OOB) |
| FORA-005 | Inyección SQL (base de datos) | HIGH | Consultas sospechosas detectadas en log de base de datos |
| FORA-006 | Cross-Site Scripting (XSS) | HIGH | Patrones XSS en peticiones web |
| FORA-007 | Path traversal / LFI / RFI | CRITICAL | Intentos de lectura de ficheros fuera del docroot o inclusión remota |
| FORA-008 | Acceso/carga de webshell | CRITICAL | Llamadas a webshells conocidas o patrones de backdoor |
| FORA-009 | Herramienta de escaneo | HIGH | User-agent o patrones de tráfico de escáneres conocidos (sqlmap, nikto, nmap…) |
| FORA-010 | Enumeración de directorios (404 storm) | MEDIUM | Ráfaga de 404 desde misma IP (fuzzing de rutas) |
| FORA-011 | Transferencia anormalmente grande | HIGH | Respuestas HTTP de tamaño excepcional (posible exfiltración) |
| FORA-012 | Consulta DB masiva | HIGH | Consulta de base de datos que devuelve un volumen anómalo de datos |
| FORA-013 | Escalada de privilegios | HIGH | Uso de sudo/su con shells o herramientas peligrosas, SUID bits |
| FORA-014 | Cuenta privilegiada creada/modificada | CRITICAL | Creación o modificación de cuentas con privilegios elevados |
| FORA-015 | Actividad en horario nocturno | MEDIUM | Eventos de autenticación o administración fuera del horario laboral |
| FORA-016 | Tarea programada sospechosa | HIGH | Creación de cron jobs o Windows Tasks con comandos anómalos |
| FORA-017 | Proceso/comando Windows sospechoso | HIGH | cmd.exe, PowerShell con codificación, wscript, certutil u otros LOLBins |
| FORA-018 | Movimiento lateral | HIGH | Conexiones entre hosts internos usando credenciales o protocolos de administración |
| FORA-019 | Acceso a ficheros sensibles | HIGH | Acceso a /etc/passwd, /etc/shadow, claves SSH, ficheros de configuración |
| FORA-020 | Login directo como root/SYSTEM | CRITICAL | Autenticación directa con cuenta de administrador del sistema |
| FORA-021 | Técnica de evasión | HIGH | Encoding, ofuscación, double-encoding, comentarios SQL, concatenación de strings |
| FORA-022 | Credential stuffing | HIGH | IPs distintas prueban mismas credenciales seguidas de éxito (relleno de credenciales) |
| FORA-023 | Baliza C2 (beacon) | HIGH | Peticiones HTTP a intervalos regulares desde un único agente (posible mando y control) |
| FORA-024 | Fuerza bruta lenta (slow drip) | MEDIUM | Intentos de contraseña distribuidos en horas para evadir rate limiting |
| FORA-025 | Anomalía en tamaño de respuesta POST | HIGH | Respuestas grandes a peticiones POST (posible exfiltración vía formulario o API) |

### Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola | (predeterminado) | Tabla coloreada + panel de hallazgos agrupados por severidad |
| JSON | `-o / --output FILE` | Salida estructurada completa para integración con otras herramientas |
| HTML | `--report-html FILE` | Informe standalone tema oscuro con cards de hallazgos, timeline y rankings |
| Forense TXT | `--report-forensic FILE` | Informe pericial completo: cadena de custodia, cronología, IOCs, ATT&CK, delta baseline, narrativa IA |
| IOC CSV | `--ioc-csv FILE` | Indicadores de compromiso en CSV para importar en SIEM o plataformas de TI |
| STIX 2.1 | `--stix FILE` | Bundle STIX 2.1 con identity, attack-pattern, indicator, observed-data y relationships |
| ZIP evidencias | `--package FILE` | ZIP sellado: logs originales + informes + cadena_de_custodia.json + MANIFEST.sha256 |

### Códigos de salida

| Código | Significado | Comportamiento CI/CD |
|--------|-------------|----------------------|
| `0` | Sin hallazgos sobre el umbral mínimo | Pipeline pasa |
| `1` | Hallazgos HIGH detectados | Pipeline falla — revisión requerida |
| `2` | Hallazgos CRITICAL detectados | Pipeline falla — acción inmediata requerida |

### Mapeo MITRE ATT&CK

Los hallazgos se clasifican automáticamente por táctica ATT&CK:

| Táctica | Detectores |
|---------|-----------|
| Reconnaissance | FORA-009, FORA-010 |
| Initial Access | FORA-004, FORA-006, FORA-007, FORA-008 |
| Credential Access | FORA-001, FORA-002, FORA-003, FORA-022, FORA-024 |
| Privilege Escalation | FORA-013, FORA-014, FORA-020 |
| Defense Evasion | FORA-021 |
| Persistence | FORA-016 |
| Lateral Movement | FORA-018 |
| Command & Control | FORA-023 |
| Collection / Exfiltration | FORA-011, FORA-012, FORA-025 |
| Discovery | FORA-019 |

### ScopeConfig — Calibración de entorno

El fichero de entorno permite al analizador distinguir actividad normal de actividad sospechosa en contexto:

```json
{
  "organization": "Mi Empresa S.L.",
  "case_name": "CASO-2026-001",
  "analyst_name": "Nombre Apellido, Perito Informático Col. 00000",
  "business_hours_start": 8,
  "business_hours_end": 20,
  "timezone_offset_hours": 1,
  "trusted_ips": ["10.0.0.0/8", "192.168.0.0/16"],
  "admin_ips": ["192.168.1.10", "192.168.1.11"],
  "exclude_detectors": [],
  "normal_peak_hour": 11
}
```

### BaselineProfiler — Análisis diferencial

```bash
# Paso 1: aprender el comportamiento normal (semana sin incidentes)
python3 vamp_log_analyzer.py /logs/semana_normal/ --learn baseline.json

# Paso 2: analizar y comparar incidente contra baseline
python3 vamp_log_analyzer.py /logs/incidente/ --baseline baseline.json
```

### Aviso legal

Uso exclusivo en sistemas propios o con autorización escrita del titular.
VampSecure Studios no asume responsabilidad por el uso no autorizado de esta herramienta.

### Parte del toolkit VampSecure Labs

`vamp-log-analyzer` es una herramienta del toolkit de investigación en seguridad de VampSecure Labs.

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v2.4 | README bilingüe (EN/ES) |
| v2.3 | Vigilancia Wazuh API en tiempo real — `--watch-wazuh-api`, JWT, NDJSON, VampPurple P7 |
| v2.2 | Motor de reglas Sigma — `--sigma-rules`, SigmaLoader + SigmaEngine, hallazgos `SIGMA-*` |
| v2.1 | ScopeConfig, BaselineProfiler, STIX 2.1, EvidencePackager, NarrativeGenerator, StreamingAnalyzer |
| v2.0 | 25 detectores FORA, multi-fuente, enriquecimiento GeoIP, MITRE ATT&CK |

---

© VampSecure Studios — VampSecure Labs Security Research Division
