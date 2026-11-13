"""Static URL Threat and Normalization Engine.

Analyzes submitted URLs completely offline without sending any network probes,
resolving DNS records, or retrieving remote payloads.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse, urlunparse

import tldextract


@dataclass
class StaticUrlAnalysisResult:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    subdomain: str
    registrable_domain: str  # eTLD+1
    public_suffix: str  # eTLD
    has_ip_hostname: bool
    ip_type: str | None  # ipv4, ipv6, dword, octal, hex
    has_userinfo_spoof: bool
    userinfo: str | None
    is_punycode: bool
    decoded_punycode_host: str | None
    has_mixed_script_homoglyphs: bool
    homoglyph_details: list[str]
    has_suspicious_tld: bool
    suspicious_tld_name: str | None
    has_open_redirect_param: bool
    open_redirect_target: str | None
    has_brand_impersonation: bool
    impersonated_brand_name: str | None
    entropy: float
    total_length: int
    anomalies: list[str]


class StaticUrlAnalyzer:
    """Offline static URL analyzer with RFC 3986 compliance and heuristic detection."""

    IPV4_DOTTED = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    IPV6_BRACKETED = re.compile(r"^\[[0-9a-fA-F:]+\]$")
    DWORD_IP = re.compile(r"^\d{7,12}$")

    # High abuse or dangerous file-extension TLDs
    SUSPICIOUS_TLDS = {
        "zip", "mov", "top", "xyz", "buzz", "work", "click", "gq",
        "cf", "tk", "ml", "fit", "surf", "rest", "cam", "kim",
    }

    # Open redirect parameter names
    OPEN_REDIRECT_PARAMS = {
        "url", "redirect", "redirect_to", "redirect_url", "redirect_uri", "dest", "destination",
        "next", "target", "goto", "out", "link", "r", "continue", "return", "return_url", "return_to",
        "callback", "forward", "forward_url",
    }

    # High-profile brands frequently targeted by phishing
    AUTHENTIC_BRAND_DOMAINS: dict[str, set[str]] = {
        "paypal": {"paypal.com", "paypal.me"},
        "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "sharepoint.com", "outlook.com"},
        "google": {"google.com", "gmail.com", "googlemail.com", "accounts.google.com"},
        "apple": {"apple.com", "icloud.com"},
        "netflix": {"netflix.com"},
        "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp"},
        "chase": {"chase.com"},
        "wellsfargo": {"wellsfargo.com"},
        "bankofamerica": {"bankofamerica.com"},
        "docusign": {"docusign.com", "docusign.net"},
        "dhl": {"dhl.com"},
        "fedex": {"fedex.com"},
        "usps": {"usps.com"},
        "dropbox": {"dropbox.com"},
        "meta": {"facebook.com", "meta.com", "instagram.com", "whatsapp.com"},
        "linkedin": {"linkedin.com"},
    }

    # Lookalike characters (Cyrillic/Greek to Latin lookalikes)
    CONFUSABLE_MAP: dict[str, str] = {
        "\u0430": "a",  # Cyrillic small a
        "\u0441": "c",  # Cyrillic small es
        "\u0435": "e",  # Cyrillic small ie
        "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
        "\u0458": "j",  # Cyrillic small je
        "\u043e": "o",  # Cyrillic small o
        "\u0440": "p",  # Cyrillic small er
        "\u0455": "s",  # Cyrillic small dze
        "\u0443": "y",  # Cyrillic small u
        "\u0445": "x",  # Cyrillic small ha
        "\u03bf": "o",  # Greek small omicron
        "\u03c1": "p",  # Greek small rho
    }

    def __init__(self) -> None:
        # Enforce offline mode by disabling Public Suffix List remote updates
        self._tld_extractor = tldextract.TLDExtract(
            cache_dir=None,
            suffix_list_urls=(),
        )

    def analyze(self, raw_url: str) -> StaticUrlAnalysisResult:
        """Perform comprehensive offline static analysis of a single URL."""
        stripped = raw_url.strip()
        if not stripped.startswith(("http://", "https://", "ftp://")):
            # If no scheme, default to http:// for normalization
            stripped = "http://" + stripped

        parsed = urlparse(stripped)

        # Normalize scheme & port
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

        userinfo: str | None = None
        has_userinfo = False
        if parsed.username or parsed.password:
            has_userinfo = True
            if parsed.password:
                userinfo = f"{parsed.username}:{parsed.password}"
            else:
                userinfo = parsed.username

        # Construct normalized URL
        netloc = hostname
        if userinfo:
            netloc = f"{userinfo}@{netloc}"
        if port:
            netloc = f"{netloc}:{port}"

        normalized_url = urlunparse(
            (scheme, netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment)
        )

        # eTLD+1 extraction via offline tldextract
        ext = self._tld_extractor(hostname)
        subdomain = ext.subdomain
        registrable_domain = ext.registered_domain or hostname
        public_suffix = ext.suffix

        anomalies: list[str] = []

        # 1. IP Hostname Check
        has_ip, ip_type = self._check_ip_hostname(hostname)
        if has_ip:
            anomalies.append(f"Host uses literal IP address ({ip_type}) instead of domain name")

        # 2. Userinfo Spoofing Check (e.g. https://paypal.com@evil.com)
        if has_userinfo:
            anomalies.append(f"URL contains embedded credentials/userinfo: '{userinfo}'")

        # 3. IDN / Punycode & Homoglyph Check
        is_punycode, decoded_puny, has_homoglyphs, homoglyph_details = self._check_homoglyphs(hostname)
        if is_punycode:
            anomalies.append(f"Domain is Punycode encoded: '{hostname}' decodes to '{decoded_puny}'")
        if has_homoglyphs:
            anomalies.append(f"Mixed-script homoglyphs detected in hostname: {', '.join(homoglyph_details)}")

        # 4. Suspicious TLD Check
        has_suspicious_tld = False
        suspicious_tld_name: str | None = None
        tld_check = public_suffix.lower()
        if tld_check in self.SUSPICIOUS_TLDS:
            has_suspicious_tld = True
            suspicious_tld_name = tld_check
            anomalies.append(f"High-abuse top-level domain: '.{suspicious_tld_name}'")

        # 5. Open Redirect Check
        has_open_redirect, redirect_target = self._check_open_redirect(parsed.query)
        if has_open_redirect:
            anomalies.append(f"Potential open redirect parameter pointing to external target: '{redirect_target}'")

        # 6. Brand Impersonation Check
        has_brand, brand_name = self._check_brand_impersonation(hostname, registrable_domain)
        if has_brand:
            anomalies.append(
                f"Domain references brand '{brand_name.capitalize()}' but registrable domain '{registrable_domain}' is not authorized"
            )

        # 7. Entropy Calculation
        entropy = self._shannon_entropy(hostname + parsed.path)
        if entropy > 4.2 and len(hostname) > 15:
            anomalies.append(f"High character entropy ({entropy:.2f}) indicates potential DGA or obfuscated path")

        # 8. Excessive URL Length
        if len(normalized_url) > 200:
            anomalies.append(f"Excessive URL length ({len(normalized_url)} characters)")

        return StaticUrlAnalysisResult(
            original_url=raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=parsed.path or "/",
            query=parsed.query,
            fragment=parsed.fragment,
            subdomain=subdomain,
            registrable_domain=registrable_domain,
            public_suffix=public_suffix,
            has_ip_hostname=has_ip,
            ip_type=ip_type,
            has_userinfo_spoof=has_userinfo,
            userinfo=userinfo,
            is_punycode=is_punycode,
            decoded_punycode_host=decoded_puny,
            has_mixed_script_homoglyphs=has_homoglyphs,
            homoglyph_details=homoglyph_details,
            has_suspicious_tld=has_suspicious_tld,
            suspicious_tld_name=suspicious_tld_name,
            has_open_redirect_param=has_open_redirect,
            open_redirect_target=redirect_target,
            has_brand_impersonation=has_brand,
            impersonated_brand_name=brand_name,
            entropy=round(entropy, 2),
            total_length=len(normalized_url),
            anomalies=anomalies,
        )

    def _check_ip_hostname(self, hostname: str) -> tuple[bool, str | None]:
        clean_host = hostname.strip("[]")
        if self.IPV4_DOTTED.match(clean_host):
            return True, "ipv4"
        if ":" in clean_host:
            return True, "ipv6"
        if self.DWORD_IP.match(clean_host):
            return True, "dword"
        return False, None

    def _check_homoglyphs(self, hostname: str) -> tuple[bool, str | None, bool, list[str]]:
        is_punycode = False
        decoded_puny: str | None = None
        has_homoglyphs = False
        homoglyph_details: list[str] = []

        if "xn--" in hostname.lower():
            is_punycode = True
            try:
                decoded_puny = hostname.encode("ascii").decode("idna")
            except Exception:
                decoded_puny = hostname

        target_host = decoded_puny or hostname
        scripts: set[str] = set()

        for char in target_host:
            if char in (".", "-", "_"):
                continue
            script = unicodedata.name(char, "").split()[0]
            scripts.add(script)

            if char in self.CONFUSABLE_MAP:
                has_homoglyphs = True
                homoglyph_details.append(
                    f"'{char}' ({unicodedata.name(char, 'unknown')}) lookalike for '{self.CONFUSABLE_MAP[char]}'"
                )

        if len(scripts) > 1 and "LATIN" in scripts:
            has_homoglyphs = True
            other_scripts = scripts - {"LATIN"}
            homoglyph_details.append(f"Mixed scripts: LATIN + {', '.join(other_scripts)}")

        return is_punycode, decoded_puny, has_homoglyphs, homoglyph_details

    def _check_open_redirect(self, query: str) -> tuple[bool, str | None]:
        if not query:
            return False, None

        params = parse_qs(query, keep_blank_values=False)
        for param_name, values in params.items():
            param_lower = param_name.lower()
            if param_lower in self.OPEN_REDIRECT_PARAMS:
                for val in values:
                    decoded = unquote(val).strip().lower()
                    if decoded.startswith(("http://", "https://", "//")):
                        return True, val
        return False, None

    def _check_brand_impersonation(self, hostname: str, registrable_domain: str) -> tuple[bool, str | None]:
        host_lower = hostname.lower()
        reg_lower = registrable_domain.lower()

        for brand, legitimate_domains in self.AUTHENTIC_BRAND_DOMAINS.items():
            if brand in host_lower:
                # If the domain is actually one of the legitimate brand domains, it is genuine
                if any(reg_lower == leg or reg_lower.endswith("." + leg) for leg in legitimate_domains):
                    continue
                # Brand appears in hostname, but domain is NOT legitimate!
                return True, brand

        return False, None

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies: dict[str, int] = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy
