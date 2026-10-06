# © VampSecure Studios — VampSecure Labs Security Research Division
"""vamp_log_analyzer — paquete de análisis forense de logs."""
from __future__ import annotations
from ._models import (
    VERSION, TOOL_NAME, FINDING_PREFIX,
    LogEvent, Finding, Report, SigmaRule, ScopeConfig,
    MITRE_MAPPING,
    RE_SQLI, RE_XSS, RE_TRAVERSAL, RE_WEBSHELL, RE_RFI,
)
from ._core import (
    Detector,
    detect_log_type, get_parser,
    parse_apache, parse_auth,
    _parse_auth_ts,
    analyze_files,
    TimelineAnalyzer, SessionReconstructor, IOCExtractor,
    ChainOfCustody, AttackChainMapper, IPActivityProfiler,
    GeoIPResolver, BaselineProfiler, NarrativeGenerator, StreamingAnalyzer,
    SigmaLoader, apply_sigma_rules,
    _rule_matches_event, _eval_sigma_condition, _sigma_level_to_severity,
)
from ._report import (
    to_json, to_forensic_txt, to_ioc_csv, to_stix, to_baseline_delta_txt, to_html,
    STIXExporter, EvidencePackager,
)
from .cli import main
__all__ = [
    "VERSION", "TOOL_NAME", "FINDING_PREFIX",
    "LogEvent", "Finding", "Report", "SigmaRule", "ScopeConfig",
    "MITRE_MAPPING", "RE_SQLI", "RE_XSS", "RE_TRAVERSAL", "RE_WEBSHELL", "RE_RFI",
    "Detector", "detect_log_type", "get_parser",
    "parse_apache", "parse_auth", "_parse_auth_ts", "analyze_files",
    "TimelineAnalyzer", "SessionReconstructor", "IOCExtractor",
    "ChainOfCustody", "AttackChainMapper", "IPActivityProfiler",
    "GeoIPResolver", "BaselineProfiler", "NarrativeGenerator", "StreamingAnalyzer",
    "SigmaLoader", "apply_sigma_rules",
    "_rule_matches_event", "_eval_sigma_condition", "_sigma_level_to_severity",
    "to_json", "to_forensic_txt", "to_ioc_csv", "to_stix", "to_baseline_delta_txt", "to_html",
    "STIXExporter", "EvidencePackager",
    "main",
]
