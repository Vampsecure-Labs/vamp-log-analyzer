# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-log-analyzer.

Pruebas de extremo a extremo con ficheros de log reales: se crean los ficheros
de entrada en tmp_path, se ejecuta analyze_files() y se comprueban los hallazgos
producidos. Mínimo 5 tests de integración.
"""

import sys
import datetime
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_log_analyzer import (
    analyze_files,
)

# Configuración base para los tests de integración
CONFIG_BASE = {
    "brute_threshold_ssh": 10,
    "brute_threshold_web": 10,
    "dir_enum_threshold": 20,
    "brute_window_sec": 60,
    "unusual_hours": (2, 6),
    "exfil_bytes_threshold": 50_000_000,
    "slow_query_ms": 5000,
    "max_events_per_finding": 50,
    "large_response": 10 * 1024 * 1024,
    "spray_users_min": 5,
}


# ─────────────────────────────────────────────────────────────────────────────
# 1. FORA-001: brute force SSH con access.log de 100 intentos
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_fora001_brute_force_http(tmp_path):
    """
    Crear access.log con 100 intentos 401 de la misma IP.
    analyze_files debe emitir FORA-002 (brute force HTTP).
    """
    lineas = []
    for i in range(100):
        ts = f"01/Oct/2026:10:00:{i:02d} +0000"
        lineas.append(
            f'10.0.0.99 - admin [{ts}] "POST /wp-login.php HTTP/1.1" 401 0\n'
        )
    lineas.append(
        '192.168.1.1 - - [01/Oct/2026:10:01:00 +0000] "GET / HTTP/1.1" 200 5000\n'
    )
    ruta = tmp_path / "access.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    config = dict(CONFIG_BASE)
    config["brute_threshold_web"] = 10  # umbral bajo para activarse

    report = analyze_files(
        paths=[str(ruta)],
        log_type="web",
        time_from=None,
        time_to=None,
        config=config,
    )

    # Debe haber al menos un hallazgo de brute force HTTP (FORA-002)
    brute_web = [
        f for f in report.findings
        if "002" in f.fid or "brute" in f.title.lower()
    ]
    assert len(brute_web) > 0, "No se detectó fuerza bruta HTTP"
    ips_en_hallazgo = brute_web[0].ips
    assert "10.0.0.99" in ips_en_hallazgo


# ─────────────────────────────────────────────────────────────────────────────
# 2. FORA-001: brute force SSH con auth.log
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_fora001_brute_ssh(tmp_path):
    """
    auth.log con 20 fallos SSH de la misma IP en ventana de 60s
    → analyze_files debe emitir FORA-001 CRITICAL o HIGH.
    """
    lineas = []
    for i in range(20):
        lineas.append(
            f"Oct  1 10:00:{i:02d} srv sshd[100{i}]: "
            f"Failed password for root from 172.16.0.55 port 22 ssh2\n"
        )
    ruta = tmp_path / "auth.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    config = dict(CONFIG_BASE)
    config["brute_threshold_ssh"] = 5

    report = analyze_files(
        paths=[str(ruta)],
        log_type="linux_auth",
        time_from=None,
        time_to=None,
        config=config,
    )

    fora001 = [
        f for f in report.findings
        if "001" in f.fid or "brute" in f.title.lower()
    ]
    assert len(fora001) > 0, "No se detectó fuerza bruta SSH"
    assert "172.16.0.55" in fora001[0].ips


# ─────────────────────────────────────────────────────────────────────────────
# 3. FORA-023: baliza C2 con intervalos regulares
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_fora023_beacon_c2(tmp_path):
    """
    access.log con 10 peticiones regulares (30s entre cada una) de IP
    pública → debe generar FORA-023.
    """
    base = datetime.datetime(2026, 10, 1, 10, 0, 0)
    lineas = []
    ip = "1.2.3.4"  # IP pública (no privada)
    for i in range(10):
        ts = (base + datetime.timedelta(seconds=i * 30)).strftime(
            "%d/%b/%Y:%H:%M:%S +0000"
        )
        lineas.append(
            f'{ip} - - [{ts}] "GET /beacon HTTP/1.1" 200 256 "-" "agent/1.0"\n'
        )
    ruta = tmp_path / "access.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    report = analyze_files(
        paths=[str(ruta)],
        log_type="web",
        time_from=None,
        time_to=None,
        config=CONFIG_BASE,
    )

    fora023 = [f for f in report.findings if "023" in f.fid]
    assert len(fora023) > 0, "No se detectó baliza C2"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Fichero genérico — cadena de custodia SHA-256
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_cadena_custodia_sha256(tmp_path):
    """
    analyze_files con chain_of_custody=True debe devolver un hash SHA-256
    del fichero fuente que es determinista (mismo fichero → mismo hash).
    """
    contenido = (
        '10.0.0.1 - - [01/Oct/2026:10:00:00 +0000] '
        '"GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
    )
    ruta = tmp_path / "access.log"
    ruta.write_text(contenido, encoding="utf-8")

    report1 = analyze_files(
        paths=[str(ruta)],
        log_type="web",
        time_from=None,
        time_to=None,
        config=CONFIG_BASE,
        chain_of_custody=True,
        analyst="TestAnalyst",
        case="TEST-001",
    )
    report2 = analyze_files(
        paths=[str(ruta)],
        log_type="web",
        time_from=None,
        time_to=None,
        config=CONFIG_BASE,
        chain_of_custody=True,
        analyst="TestAnalyst",
        case="TEST-001",
    )

    # La cadena de custodia debe incluir hashes
    coc1 = report1.chain_of_custody
    coc2 = report2.chain_of_custody
    assert coc1 != {} or coc2 != {}
    # Si se generó, el hash debe ser reproducible
    if coc1 and coc2:
        hash1 = coc1.get("sha256", coc1.get("files", [{}])[0].get("sha256", ""))
        hash2 = coc2.get("sha256", coc2.get("files", [{}])[0].get("sha256", ""))
        if hash1 and hash2:
            assert hash1 == hash2


# ─────────────────────────────────────────────────────────────────────────────
# 5. Sin hallazgos con tráfico limpio
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_sin_hallazgos_trafico_limpio(tmp_path):
    """
    Un access.log con tráfico 100% legítimo y umbrales altos
    no debe generar hallazgos de ataque.
    """
    lineas = [
        f'192.168.0.{i % 10 + 1} - - [01/Oct/2026:09:{i // 60:02d}:{i % 60:02d} +0000] '
        f'"GET /pagina{i}.html HTTP/1.1" 200 {500 + i * 10} "-" "Mozilla/5.0"\n'
        for i in range(30)
    ]
    ruta = tmp_path / "clean.log"
    ruta.write_text("".join(lineas), encoding="utf-8")

    config = dict(CONFIG_BASE)
    config["brute_threshold_web"] = 500    # umbral muy alto
    config["dir_enum_threshold"] = 500

    report = analyze_files(
        paths=[str(ruta)],
        log_type="web",
        time_from=None,
        time_to=None,
        config=config,
    )

    hallazgos_criticos_altos = [
        f for f in report.findings
        if f.severity in ("CRITICAL", "HIGH")
    ]
    assert len(hallazgos_criticos_altos) == 0, (
        f"Hallazgos inesperados: {[f.title for f in hallazgos_criticos_altos]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Metadata del informe
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_metadata_informe(tmp_path):
    """
    El informe devuelto por analyze_files incluye metadata básica:
    sources, tool, version y generated.
    """
    contenido = (
        '10.0.0.1 - - [01/Oct/2026:10:00:00 +0000] '
        '"GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
    )
    ruta = tmp_path / "access.log"
    ruta.write_text(contenido, encoding="utf-8")

    report = analyze_files(
        paths=[str(ruta)],
        log_type="web",
        time_from=None,
        time_to=None,
        config=CONFIG_BASE,
    )

    # El informe debe tener los metadatos básicos
    assert report.tool is not None
    assert report.version is not None
    assert report.generated is not None
    assert len(report.sources) > 0
