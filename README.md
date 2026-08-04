<h1 align="center">vamp-log-analyzer</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/stdlib%20only-no%20deps-brightgreen" alt="stdlib only"/>
  <img src="https://img.shields.io/badge/version-2.1-orange" alt="v2.1"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
</p>

## Overview

`vamp-log-analyzer` es una plataforma forense de análisis de logs para incidentes de seguridad.
Ingesta logs de múltiples fuentes —servidores web, bases de datos, sistemas operativos y
aplicaciones— los normaliza en una línea de tiempo unificada y aplica 25+ detectores para
identificar ataques, accesos indebidos, escaladas de privilegios y señales de exfiltración.

Diseñado para uso en auditorías autorizadas, peritajes informáticos y respuesta a incidentes.
No requiere dependencias externas: únicamente librería estándar de Python 3.9+.

## Fuentes de logs soportadas

| Categoría | Fuentes |
|-----------|---------|
| **Web** | Apache/Nginx (Combined Log Format), IIS (W3C Extended) |
| **Base de datos** | MySQL (error/slow query/general log), PostgreSQL (CSV log), MongoDB (JSON 4.4+ / texto 3.x) |
| **Linux/Unix** | `auth.log`, `syslog`, `kern.log`, `/var/log/secure` (RHEL/CentOS), journald (exportación JSON) |
| **Windows** | Windows Event Log exportado como XML (`wevtutil qe Security /f:XML`) |
| **macOS** | macOS Unified Log JSON (`log show --style json`) |
| **Genérico** | JSON estructurado con campo timestamp, texto libre con heurísticas de timestamp |

La detección del tipo de log es automática (`--type auto`, predeterminada).

## Características — v2.1

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

## Requisitos

- Python 3.9 o superior
- Sin dependencias externas (stdlib only)

## Instalación

```bash
git clone https://github.com/Vampsecure-Labs/vamp-log-analyzer.git
cd vamp-log-analyzer
# No se necesita pip install ni virtualenv
python3 vamp_log_analyzer.py --help
```

## Uso

```bash
python3 vamp_log_analyzer.py FICHERO_O_DIRECTORIO [opciones]
```

### Ejemplos básicos

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

### Ejemplos v2.1 — Nuevas capacidades

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

## Referencia CLI completa

### Entrada

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `FICHERO [FICHERO ...]` | — | Uno o más ficheros de log, o un directorio |
| `--type TYPE` | `auto` | Tipo de log: `apache`, `nginx`, `iis`, `mysql`, `postgres`, `mongodb`, `auth`, `syslog`, `windows`, `macos`, `json`, `text`, `auto` |
| `--recursive / -R` | off | Escanear directorios recursivamente |
| `--follow FICHERO` | — | Monitorización en tiempo real (modo streaming, Ctrl+C para finalizar) |

### Filtros

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--from FECHA` | — | Filtrar eventos a partir de esta fecha (ISO 8601) |
| `--to FECHA` | — | Filtrar eventos hasta esta fecha |
| `--min-severity SEV` | `LOW` | Umbral mínimo de severidad: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--top-n N` | `10` | Número de elementos en rankings (IPs, rutas, UAs) |
| `--min-session-gap N` | `30` | Minutos de silencio para separar sesiones de atacante |

### Enriquecimiento

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--geoip` | off | Enriquecer IPs con país/ASN vía API pública |
| `--timeline` | off | Generar análisis de línea de tiempo con gaps y ráfagas |

### Cadena de custodia forense

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--chain-of-custody` | off | Incluir hashes SHA-256 de ficheros + metadatos de análisis |
| `--analyst "Nombre"` | — | Nombre del perito para informe forense |
| `--case "REF"` | — | Referencia del caso para informe forense |

### Calibración de entorno (v2.1)

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--scope FICHERO.json` | — | Fichero JSON de configuración de entorno (horas laborales, IPs de confianza, detectores excluidos) |
| `--scope-example` | — | Imprimir un ejemplo de fichero de entorno y salir |

### Baseline estadístico (v2.1)

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--learn BASELINE.json` | — | Analizar el log y guardar el perfil de comportamiento normal en el fichero indicado |
| `--baseline BASELINE.json` | — | Comparar el análisis actual contra un baseline guardado previamente |

### Narrativa IA (v2.1)

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `--narrative [ollama\|claude]` | — | Generar narrativa forense en español con IA local (Ollama) o Claude API |
| `--narrative-model MODELO` | `llama3.2:3b` / `claude-haiku-4-5-20251001` | Modelo a usar para la narrativa |
| `--narrative-host URL` | `http://127.0.0.1:11434` | Host de Ollama (solo si `--narrative ollama`) |
| `--claude-api-key KEY` | — | API key de Claude (solo si `--narrative claude`) |

### Salida

| Flag | Valor pred. | Descripción |
|------|-------------|-------------|
| `-o / --output FILE` | — | Guardar resultados en JSON |
| `--report-html FILE` | — | Generar informe HTML con tema oscuro |
| `--report-forensic FILE` | — | Informe forense TXT completo |
| `--ioc-csv FILE` | — | Exportar IOCs en CSV para SIEM |
| `--stix FICHERO.json` | — | Exportar bundle STIX 2.1 para MISP / OpenCTI / TheHive |
| `--package FICHERO.zip` | — | Empaquetar evidencias en ZIP sellado con MANIFEST SHA-256 |
| `-v / --verbose` | off | Salida detallada por evento |

## Detectores forenses (FORA-001 a FORA-025)

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

## Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola | (predeterminado) | Tabla coloreada + panel de hallazgos agrupados por severidad |
| JSON | `-o / --output FILE` | Salida estructurada completa para integración con otras herramientas |
| HTML | `--report-html FILE` | Informe standalone tema oscuro con cards de hallazgos, timeline y rankings |
| Forense TXT | `--report-forensic FILE` | Informe pericial completo: cadena de custodia, cronología, IOCs, ATT&CK, delta baseline, narrativa IA |
| IOC CSV | `--ioc-csv FILE` | Indicadores de compromiso en CSV para importar en SIEM o plataformas de TI |
| STIX 2.1 | `--stix FILE` | Bundle STIX 2.1 con identity, attack-pattern, indicator, observed-data y relationships |
| ZIP evidencias | `--package FILE` | ZIP sellado: logs originales + informes + cadena_de_custodia.json + MANIFEST.sha256 |

## Códigos de salida

| Código | Significado | Comportamiento CI/CD |
|--------|-------------|----------------------|
| `0` | Sin hallazgos sobre el umbral mínimo | Pipeline pasa |
| `1` | Hallazgos HIGH detectados | Pipeline falla — revisión requerida |
| `2` | Hallazgos CRITICAL detectados | Pipeline falla — acción inmediata requerida |

## Mapeo MITRE ATT&CK

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

## ScopeConfig — Calibración de entorno

El fichero de entorno permite al analizador distinguir actividad normal de actividad sospechosa en contexto:

```bash
python3 vamp_log_analyzer.py --scope-example > entorno.json
```

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

Con `--scope entorno.json`:
- Los hallazgos de IPs en `trusted_ips` se suprimen si **todas** las IPs implicadas son de confianza
- El detector FORA-015 (horario nocturno) usa las horas laborales del entorno en lugar del valor por defecto
- Los detectores en `exclude_detectors` se omiten completamente

## BaselineProfiler — Análisis diferencial

```bash
# Paso 1: aprender el comportamiento normal (semana sin incidentes)
python3 vamp_log_analyzer.py /logs/semana_normal/ --learn baseline.json

# Paso 2: analizar y comparar incidente contra baseline
python3 vamp_log_analyzer.py /logs/incidente/ --baseline baseline.json
```

El informe diferencial muestra:
- IPs nuevas no presentes en el baseline
- IPs desaparecidas (posible cambio de infraestructura del atacante)
- IPs nuevas con actividad anormalmente alta
- Detectores nuevos no vistos en el baseline
- Anomalías horarias con desviación estadística (media ± 3σ)
- Tabla comparativa de conteo de hallazgos por severidad (▲ sube / ▼ baja / ═ estable)

## STIX 2.1 — Integración con plataformas de TI

```bash
python3 vamp_log_analyzer.py /logs/ --stix hallazgos.stix.json
```

El bundle STIX 2.1 generado contiene:
- `identity` — identidad de VampSecure Labs como fuente
- `attack-pattern` — uno por cada técnica ATT&CK detectada
- `indicator` — uno por cada IP con hallazgos (incluye IPs internas marcadas como tal)
- `observed-data` — evento observado global del análisis
- `relationship` — vínculos indicator→attack-pattern deduplicados

El fichero es compatible con MISP, OpenCTI, TheHive y cualquier plataforma que soporte STIX 2.1.

## EvidencePackager — Paquete de evidencias judicial

```bash
python3 vamp_log_analyzer.py /logs/ \
    --chain-of-custody --analyst "Juan Pérez, Perito Col. 00000" --case "CASO-2026-001" \
    --stix hallazgos.stix.json \
    --package paquete_evidencias.zip
```

El ZIP contiene:
```
evidencias/
    <nombre_log_original>        # copia literal del log analizado
informes/
    informe_forense.txt          # informe pericial completo
    iocs.csv                     # indicadores de compromiso
    hallazgos.stix.json          # bundle STIX 2.1
    analisis.json                # volcado JSON completo
cadena_de_custodia.json          # perito, caso, fecha UTC, SHA-256 de cada fichero
MANIFEST.sha256                  # hash SHA-256 de todos los ficheros del paquete
```

El MANIFEST permite verificar la integridad del paquete en cualquier momento posterior.

## NarrativeGenerator — Narrativa forense con IA

```bash
# Con Ollama local (por defecto llama3.2:3b, sin coste)
python3 vamp_log_analyzer.py /logs/ --narrative ollama

# Con Claude API
python3 vamp_log_analyzer.py /logs/ --narrative claude --claude-api-key sk-ant-...
```

La narrativa se genera en español forense, describiendo el incidente desde la perspectiva del
perito: IPs más activas, franjas horarias, técnicas detectadas y secuencia probable del ataque.
Se incluye automáticamente en la sección 9 del informe forense TXT.

## StreamingAnalyzer — Monitorización en tiempo real

```bash
python3 vamp_log_analyzer.py --follow /var/log/nginx/access.log
python3 vamp_log_analyzer.py --follow /var/log/auth.log --min-severity HIGH
```

Monitoriza el fichero indicado desde el final actual, procesando nuevas líneas cada segundo.
Al pulsar Ctrl+C se consolidan y muestran los hallazgos finales del periodo monitorizado.
Útil para respuesta a incidentes en tiempo real sin necesidad de infraestructura adicional.

## Uso forense / peritaje completo

```bash
python3 vamp_log_analyzer.py /evidencias/ \
    --chain-of-custody \
    --analyst "Perito Informático Forense — Nombre Apellidos, Col. 00000" \
    --case "Diligencias Previas XX/2026" \
    --scope entorno_cliente.json \
    --baseline baseline_previo.json \
    --geoip \
    --timeline \
    --narrative ollama \
    --report-forensic informe_pericial.txt \
    --ioc-csv iocs.csv \
    --stix hallazgos.stix.json \
    --report-html informe_visual.html \
    --package paquete_judicial.zip
```

El informe forense TXT incluye:
- Identificación del caso y del perito
- Hashes SHA-256 de cada fichero analizado (integridad de evidencias)
- Fecha y hora de análisis (UTC)
- Resumen ejecutivo de hallazgos
- Línea de tiempo completa del incidente
- Sesiones reconstruidas por IP (secuencia de acciones del atacante)
- Indicadores de compromiso exportables
- Clasificación por táctica MITRE ATT&CK
- **[v2.1]** Análisis diferencial contra baseline (si se proporciona)
- **[v2.1]** Narrativa del incidente generada por IA (si se activa)

## Aviso legal

Uso exclusivo en sistemas propios o con autorización escrita del titular.
VampSecure Studios no asume responsabilidad por el uso no autorizado de esta herramienta.

## Parte del toolkit VampSecure Labs

`vamp-log-analyzer` es una herramienta del toolkit de investigación en seguridad de VampSecure Labs.

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)

---

© VampSecure Studios — VampSecure Labs Security Research Division
