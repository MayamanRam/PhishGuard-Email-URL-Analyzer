"""Pure-Python Defensive YARA-Compatible File Signature Engine.

Provides offline, in-memory attachment signature inspection without executing binaries,
spawning sub-processes, or requiring external C compiler toolchains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Callable, Pattern


@dataclass
class YaraMatch:
    """Represents a triggered YARA / signature match."""

    rule_name: str
    category: str
    severity: str
    description: str
    tags: list[str] = field(default_factory=list)
    matched_strings: list[str] = field(default_factory=list)
    mitre_attack_id: str | None = None


@dataclass
class YaraRule:
    """Deterministic defensive signature rule."""

    name: str
    category: str
    severity: str
    description: str
    tags: list[str]
    mitre_attack_id: str | None
    condition: Callable[[bytes, str], tuple[bool, list[str]]]


class LocalYaraScanner:
    """In-memory defensive pattern scanner evaluating attachment payloads."""

    def __init__(self) -> None:
        self.rules: list[YaraRule] = self._load_default_rules()

    def scan_bytes(self, payload: bytes, filename: str = "") -> list[YaraMatch]:
        """Scan raw attachment bytes and filename against signature rules."""
        if not payload:
            return []

        matches: list[YaraMatch] = []
        for rule in self.rules:
            matched, matched_strings = rule.condition(payload, filename)
            if matched:
                matches.append(
                    YaraMatch(
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        tags=rule.tags,
                        matched_strings=matched_strings[:5],  # Cap strings for telemetry
                        mitre_attack_id=rule.mitre_attack_id,
                    )
                )
        return matches

    def _load_default_rules(self) -> list[YaraRule]:
        """Initialize curated defensive attachment signature rules."""
        rules: list[YaraRule] = []

        # -------------------------------------------------------------
        # 1. Embedded Portable Executable (PE / MZ) in Non-Executable
        # -------------------------------------------------------------
        def match_embedded_pe(data: bytes, filename: str) -> tuple[bool, list[str]]:
            lower_name = filename.lower()
            # If declared extension is supposedly document/image but contains MZ + PE
            is_doc = any(lower_name.endswith(ext) for ext in [".pdf", ".docx", ".xlsx", ".png", ".jpg", ".txt"])
            if data.startswith(b"MZ"):
                pe_offset = data.find(b"PE\x00\x00")
                if 0 < pe_offset < 4096:
                    reason = f"MZ header with PE signature at offset {pe_offset}"
                    if is_doc:
                        reason += f" masked as {lower_name.split('.')[-1].upper()} document"
                    return True, [reason]
            return False, []

        rules.append(
            YaraRule(
                name="SUSPICIOUS_EMBEDDED_PE",
                category="attachment_risk",
                severity="CRITICAL",
                description="Executable PE header (MZ/PE) detected in attachment payload.",
                tags=["malware", "executable", "pe", "masquerade"],
                mitre_attack_id="T1036.008",
                condition=match_embedded_pe,
            )
        )

        # -------------------------------------------------------------
        # 2. Obfuscated PowerShell Execution Cradle
        # -------------------------------------------------------------
        ps_patterns: list[tuple[Pattern[bytes], str]] = [
            (re.compile(rb"powershell(?:\.exe)?\s+-[eE][a-zA-Z]*\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE), "Base64 PowerShell command"),
            (re.compile(rb"\[System\.Convert\]::FromBase64String", re.IGNORECASE), "Base64 decode invocation"),
            (re.compile(rb"-[wW][a-zA-Z]*\s+hidden\s+-[nN][a-zA-Z]*\s+-[eE][a-zA-Z]*", re.IGNORECASE), "Hidden encoded PowerShell cradle"),
            (re.compile(rb"IEX\s*\(\s*New-Object\s+Net\.WebClient", re.IGNORECASE), "WebClient IEX download cradle"),
        ]

        def match_powershell(data: bytes, _fn: str) -> tuple[bool, list[str]]:
            hits = []
            for pat, label in ps_patterns:
                if pat.search(data):
                    hits.append(label)
            return len(hits) > 0, hits

        rules.append(
            YaraRule(
                name="OBFUSCATED_POWERSHELL_CRADLE",
                category="attachment_risk",
                severity="HIGH",
                description="Obfuscated PowerShell download cradle or base64 execution string.",
                tags=["powershell", "obfuscation", "downloader"],
                mitre_attack_id="T1059.001",
                condition=match_powershell,
            )
        )

        # -------------------------------------------------------------
        # 3. Malicious VBA Macro Auto-Execution
        # -------------------------------------------------------------
        vba_triggers: list[tuple[Pattern[bytes], str]] = [
            (re.compile(rb"\b(AutoOpen|Document_Open|Workbook_Open|Auto_Open)\b", re.IGNORECASE), "Auto-execution entrypoint"),
            (re.compile(rb"\b(WScript\.Shell|ShellExecute|CreateObject\s*\(\s*[\"']WScript)", re.IGNORECASE), "Shell execution object"),
            (re.compile(rb"\b(URLDownloadToFile|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest)\b", re.IGNORECASE), "Macro HTTP download API"),
        ]

        def match_vba_macro(data: bytes, filename: str) -> tuple[bool, list[str]]:
            hits = []
            for pat, label in vba_triggers:
                if pat.search(data):
                    hits.append(label)
            # Require at least two triggers or auto-entry + shell
            return len(hits) >= 2, hits

        rules.append(
            YaraRule(
                name="VBA_MACRO_EXECUTION_CHAIN",
                category="attachment_risk",
                severity="CRITICAL",
                description="VBA macro containing auto-execution hooks combined with shell or network invocation.",
                tags=["macro", "vba", "office"],
                mitre_attack_id="T1204.002",
                condition=match_vba_macro,
            )
        )

        # -------------------------------------------------------------
        # 4. HTML Smuggling & Data Blob Assembly
        # -------------------------------------------------------------
        html_smuggle_pats: list[tuple[Pattern[bytes], str]] = [
            (re.compile(rb"URL\.createObjectURL\s*\(", re.IGNORECASE), "createObjectURL payload generator"),
            (re.compile(rb"window\.navigator\.msSaveOrOpenBlob", re.IGNORECASE), "msSaveOrOpenBlob auto-download"),
            (re.compile(rb"data:application/octet-stream;base64,", re.IGNORECASE), "Octet-stream data URI"),
            (re.compile(rb"Uint8Array\s*\(\s*atob\s*\(", re.IGNORECASE), "Base64 to binary buffer assembly"),
        ]

        def match_html_smuggling(data: bytes, filename: str) -> tuple[bool, list[str]]:
            lower_name = filename.lower()
            if lower_name.endswith((".html", ".htm", ".xhtml", ".svg")):
                hits = []
                for pat, label in html_smuggle_pats:
                    if pat.search(data):
                        hits.append(label)
                if len(hits) >= 2:
                    return True, hits
            return False, []

        rules.append(
            YaraRule(
                name="HTML_SMUGGLING_PAYLOAD",
                category="attachment_risk",
                severity="HIGH",
                description="HTML file assembling an executable binary blob dynamically in-browser.",
                tags=["html_smuggling", "evasion", "blob"],
                mitre_attack_id="T1027.006",
                condition=match_html_smuggling,
            )
        )

        # -------------------------------------------------------------
        # 5. Script Downloader Objects (VBScript / JScript)
        # -------------------------------------------------------------
        downloader_pats: list[tuple[Pattern[bytes], str]] = [
            (re.compile(rb"ADODB\.Stream", re.IGNORECASE), "ADODB.Stream binary writer"),
            (re.compile(rb"MSXML2\.XMLHTTP|Microsoft\.XMLHTTP", re.IGNORECASE), "XMLHTTP request component"),
            (re.compile(rb"CertUtil(?:\.exe)?\s+-[uU][rR][lL][cC][aA][cC][hH][eE]", re.IGNORECASE), "CertUtil download command"),
            (re.compile(rb"Bitsadmin(?:\.exe)?\s+/transfer", re.IGNORECASE), "Bitsadmin transfer command"),
        ]

        def match_downloader(data: bytes, _fn: str) -> tuple[bool, list[str]]:
            hits = []
            for pat, label in downloader_pats:
                if pat.search(data):
                    hits.append(label)
            return len(hits) >= 2, hits

        rules.append(
            YaraRule(
                name="SCRIPT_DOWNLOADER_OBJECTS",
                category="attachment_risk",
                severity="HIGH",
                description="Active Script or batch instructions creating downloader stream objects.",
                tags=["downloader", "vbs", "jscript"],
                mitre_attack_id="T1105",
                condition=match_downloader,
            )
        )

        return rules

