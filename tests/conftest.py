# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-log-analyzer.

Proporciona configuraciones por defecto del Detector, fixtures de ficheros
de log y eventos de prueba para test_unit.py y test_integration.py.
"""

import sys
import datetime
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_log_analyzer import (
    Detector,
    LogEvent,
)

# ── Configuración por defecto del Detector ────────────────────────────────────

DETECTOR_CONFIG = {
    "brute_threshold_ssh": 10,
    "brute_threshold_web": 10,
    "dir_enum_threshold": 20,
    "brute_window_sec": 60,
    "unusual_hours": (2, 6),
    "exfil_bytes_threshold": 50_000_000,
    "slow_query_ms": 5000,
    "max_events_per_finding": 50,
    "spray_users_min": 5,
    "large_response": 10 * 1024 * 1024,
}


@pytest.fixture
def config_detector():
    """Devuelve la configuración estándar del Detector."""
    return dict(DETECTOR_CONFIG)


@pytest.fixture
def detector_defecto(config_detector):
    """Instancia de Detector con configuración por defecto."""
    return Detector(config_detector)


@pytest.fixture
def detector_umbral_bajo():
    """Detector con umbrales bajos para provocar hallazgos fácilmente."""
    config = dict(DETECTOR_CONFIG)
    config["brute_threshold_ssh"] = 3
    config["brute_threshold_web"] = 3
    config["dir_enum_threshold"] = 5
    return Detector(config)


def _crear_evento_ssh_fail(ip: str, ts_offset_sec: int = 0) -> LogEvent:
    """Crea un evento de fallo SSH para tests."""
    base = datetime.datetime(2026, 10, 1, 10, 0, 0)
    return LogEvent(
        timestamp=base + datetime.timedelta(seconds=ts_offset_sec),
        source_file="auth.log",
        source_line=1,
        log_type="linux_auth",
        raw=f"Failed password for root from {ip} port 22 ssh2",
        ip=ip,
        user="root",
        action="SSH_FAIL",
    )


def _crear_evento_web(ip: str, path: str, status: int,
                      ua: str = "Mozilla/5.0",
                      ts_offset_sec: int = 0) -> LogEvent:
    """Crea un evento web para tests."""
    base = datetime.datetime(2026, 10, 1, 10, 0, 0)
    return LogEvent(
        timestamp=base + datetime.timedelta(seconds=ts_offset_sec),
        source_file="access.log",
        source_line=1,
        log_type="web",
        raw=f'10.0.0.1 - - "GET {path} HTTP/1.1" {status} 512',
        ip=ip,
        user=None,
        action="GET",
        resource=path,
        status=status,
        bytes_out=512,
        user_agent=ua,
    )


@pytest.fixture
def log_brute_force(tmp_path):
    """
    Access log con 100 intentos fallidos consecutivos de la misma IP.
    Sirve como fuente de datos de integración para FORA-001.
    """
    lineas = []
    for i in range(100):
        ts = f"01/Oct/2026:10:00:{i:02d} +0000"
        lineas.append(
            f'10.0.0.99 - admin [{ts}] "POST /wp-login.php HTTP/1.1" 401 0\n'
        )
    # 5 peticiones legítimas para no confundir
    lineas.append(
        '192.168.1.1 - - [01/Oct/2026:10:01:00 +0000] "GET / HTTP/1.1" 200 5000\n'
    )
    ruta = tmp_path / "access.log"
    ruta.write_text("".join(lineas))
    return ruta


@pytest.fixture
def log_brute_ssh(tmp_path):
    """auth.log con 20 fallos SSH de la misma IP en ventana de 60s."""
    lineas = []
    for i in range(20):
        lineas.append(
            f"Oct  1 10:00:{i:02d} srv sshd[100{i}]: "
            f"Failed password for root from 172.16.0.55 port 22 ssh2\n"
        )
    ruta = tmp_path / "auth.log"
    ruta.write_text("".join(lineas))
    return ruta
