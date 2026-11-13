"""Detection Rule Definition Catalog.

Defines deterministic rule metadata, weights, confidence values,
remediation guidelines, and MITRE ATT&CK mappings.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    rule_name: str
    category: str  # AUTH, HEADER, SENDER, URL, ATTACH, CONTENT
    severity: str  # low, medium, high, critical
    base_weight: float
    confidence_multiplier: float
    description: str
    remediation_advice: str
    mitre_attack_id: str | None


RULE_CATALOG: dict[str, RuleDefinition] = {
    # -------------------------------------------------------------
    # AUTHENTICATION CLAIMS (AUTH)
    # -------------------------------------------------------------
    "AUTH-01": RuleDefinition(
        rule_id="AUTH-01",
        rule_name="SPF Hard Fail Claimed in Headers",
        category="AUTH",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.85,
        description="The incoming message headers record an SPF 'fail' verdict, indicating the sending IP is not authorized by the declared domain's SPF record.",
        remediation_advice="Treat sender identity with high suspicion. Cross-reference with DKIM and DMARC alignment before trusting any requests in the message.",
        mitre_attack_id="T1566.002",
    ),
    "AUTH-02": RuleDefinition(
        rule_id="AUTH-02",
        rule_name="SPF SoftFail Claimed in Headers",
        category="AUTH",
        severity="medium",
        base_weight=10.0,
        confidence_multiplier=0.70,
        description="The incoming message headers record an SPF 'softfail' verdict (~all), indicating the sender IP is likely not authorized but the domain does not strictly mandate rejection.",
        remediation_advice="Verify through secondary out-of-band communication if this is an expected sender or a third-party relay service.",
        mitre_attack_id="T1566.002",
    ),
    "AUTH-03": RuleDefinition(
        rule_id="AUTH-03",
        rule_name="DKIM Verification Failure Claimed",
        category="AUTH",
        severity="high",
        base_weight=20.0,
        confidence_multiplier=0.85,
        description="The cryptographic signature verification (DKIM) failed or was marked invalid, suggesting potential transit tampering or unauthorized sending.",
        remediation_advice="Do not trust message authenticity. Treat attachments and links as untrusted.",
        mitre_attack_id="T1566.002",
    ),
    "AUTH-04": RuleDefinition(
        rule_id="AUTH-04",
        rule_name="DMARC Policy Failure Claimed",
        category="AUTH",
        severity="critical",
        base_weight=30.0,
        confidence_multiplier=0.90,
        description="The domain owner's DMARC policy evaluation resulted in a failure, indicating neither SPF nor DKIM aligned with the visible From address.",
        remediation_advice="Quarantine or reject message. The sender domain actively enforces DMARC protection against domain spoofing.",
        mitre_attack_id="T1566.002",
    ),
    "AUTH-05": RuleDefinition(
        rule_id="AUTH-05",
        rule_name="Complete Absence of Authentication Claims",
        category="AUTH",
        severity="low",
        base_weight=10.0,
        confidence_multiplier=0.60,
        description="No Authentication-Results, SPF, or DKIM evaluation claims were present in the message headers.",
        remediation_advice="Review whether the sending domain publishes SPF/DKIM records. Missing claims alone are not proof of malice but require vigilance.",
        mitre_attack_id="T1566",
    ),

    # -------------------------------------------------------------
    # HEADER ANOMALIES (HEADER)
    # -------------------------------------------------------------
    "HDR-01": RuleDefinition(
        rule_id="HDR-01",
        rule_name="From vs Reply-To Domain Mismatch",
        category="HEADER",
        severity="medium",
        base_weight=15.0,
        confidence_multiplier=0.75,
        description="The Reply-To address domain differs from the From address domain. While used in legitimate newsletters, it is a primary technique in business email compromise (BEC).",
        remediation_advice="Ensure replies are not directed to an external mailbox. Confirm the recipient address before responding.",
        mitre_attack_id="T1566.001",
    ),
    "HDR-02": RuleDefinition(
        rule_id="HDR-02",
        rule_name="From vs Return-Path Domain Mismatch",
        category="HEADER",
        severity="medium",
        base_weight=12.0,
        confidence_multiplier=0.70,
        description="The envelope Return-Path (bounce address) domain does not align with the visible From header domain.",
        remediation_advice="Inspect relay headers to determine if an authorized third-party delivery provider (e.g., SendGrid, Mailchimp) was utilized.",
        mitre_attack_id="T1566.001",
    ),
    "HDR-03": RuleDefinition(
        rule_id="HDR-03",
        rule_name="Hop Delay Skew / Timestamp Inversion",
        category="HEADER",
        severity="medium",
        base_weight=15.0,
        confidence_multiplier=0.75,
        description="A chronologically later Received hop has a timestamp earlier than an earlier relay hop, indicating clock skew or synthetic header fabrication.",
        remediation_advice="Examine raw Received lines to identify if upstream relays were forged.",
        mitre_attack_id="T1070.006",
    ),
    "HDR-04": RuleDefinition(
        rule_id="HDR-04",
        rule_name="Missing Relay Origin / Suspect Delivery",
        category="HEADER",
        severity="low",
        base_weight=8.0,
        confidence_multiplier=0.60,
        description="The message contains minimal or ambiguous Received hops without clear originating client host or IP information.",
        remediation_advice="Check incoming perimeter MTA logs for original connection metadata.",
        mitre_attack_id="T1566",
    ),

    # -------------------------------------------------------------
    # SENDER IMPERSONATION (SENDER)
    # -------------------------------------------------------------
    "SND-01": RuleDefinition(
        rule_id="SND-01",
        rule_name="Display Name Embedded Address Spoofing",
        category="SENDER",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The sender display name embeds an email address (e.g., 'security@paypal.com') that is completely different from the actual mailbox sending the message.",
        remediation_advice="Block sender. This is a deliberate deception technique designed to trick mobile email clients.",
        mitre_attack_id="T1566.001",
    ),
    "SND-02": RuleDefinition(
        rule_id="SND-02",
        rule_name="Brand Name Impersonation in Sender Name",
        category="SENDER",
        severity="high",
        base_weight=20.0,
        confidence_multiplier=0.85,
        description="The display name references a major recognized brand or service, but the actual sending domain is not affiliated with the brand.",
        remediation_advice="Verify authenticity through the brand's official verified portal. Do not click links or call numbers provided in the message.",
        mitre_attack_id="T1566.001",
    ),
    "SND-03": RuleDefinition(
        rule_id="SND-03",
        rule_name="Executive / Authority Pretext in Sender Name",
        category="SENDER",
        severity="medium",
        base_weight=15.0,
        confidence_multiplier=0.75,
        description="The sender name employs high-authority keywords (CEO, CFO, HR, Payroll, IT Admin) alongside an external or freemail domain.",
        remediation_advice="Confirm identity directly via corporate instant messaging or official internal phone directory.",
        mitre_attack_id="T1566.001",
    ),

    # -------------------------------------------------------------
    # URL & DOMAIN RISK (URL)
    # -------------------------------------------------------------
    "URL-01": RuleDefinition(
        rule_id="URL-01",
        rule_name="Literal IP Address Host in Hyperlink",
        category="URL",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="A hyperlink target uses a raw IP address (IPv4, IPv6, or DWORD) instead of a registered domain name, bypassing domain reputation mechanisms.",
        remediation_advice="Never visit raw IP links. Legitimate services virtually always utilize registered domain names.",
        mitre_attack_id="T1566.002",
    ),
    "URL-02": RuleDefinition(
        rule_id="URL-02",
        rule_name="Punycode / IDN Homoglyph Domain in Link",
        category="URL",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The link hostname uses Punycode (xn--) or mixed Unicode scripts with lookalike Cyrillic/Greek characters to visually deceive the user.",
        remediation_advice="Do not follow the link. Inspect the decoded Unicode name to observe the exact visual deception.",
        mitre_attack_id="T1566.002",
    ),
    "URL-03": RuleDefinition(
        rule_id="URL-03",
        rule_name="Brand Impersonation in Domain / Subdomain",
        category="URL",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The destination domain or subdomain embeds a well-known brand name, but the registrable domain (eTLD+1) is not owned by the authentic organization.",
        remediation_advice="Report domain for takedown to brand abuse contacts and hosting registrar.",
        mitre_attack_id="T1566.002",
    ),
    "URL-04": RuleDefinition(
        rule_id="URL-04",
        rule_name="Open Redirect Parameter in URL",
        category="URL",
        severity="high",
        base_weight=20.0,
        confidence_multiplier=0.85,
        description="The URL queries include parameters (e.g. ?url=, ?redirect=) pointing to an external destination, frequently abused to bounce victims to malicious landing pages.",
        remediation_advice="Evaluate the nested destination parameter directly to determine the actual final landing target.",
        mitre_attack_id="T1566.002",
    ),
    "URL-05": RuleDefinition(
        rule_id="URL-05",
        rule_name="High-Abuse Top-Level Domain",
        category="URL",
        severity="medium",
        base_weight=15.0,
        confidence_multiplier=0.80,
        description="The link uses a top-level domain with statistically high abuse rates or dangerous file extension confusion (e.g. .zip, .mov, .xyz, .top).",
        remediation_advice="Scrutinize the organization behind the domain. Restrict web gateway access if no business justification exists.",
        mitre_attack_id="T1566.002",
    ),
    "URL-06": RuleDefinition(
        rule_id="URL-06",
        rule_name="Embedded Userinfo / Credentials in URL",
        category="URL",
        severity="high",
        base_weight=20.0,
        confidence_multiplier=0.85,
        description="The URL contains embedded userinfo (e.g. 'https://trusted.com@evil.com'), a classic technique to mislead users into believing they are visiting a trusted site.",
        remediation_advice="Recognize that everything preceding the '@' symbol in the authority component is ignored by HTTP parsers, directing to the host following it.",
        mitre_attack_id="T1566.002",
    ),
    "URL-07": RuleDefinition(
        rule_id="URL-07",
        rule_name="Anchor Text vs Destination Link Mismatch",
        category="URL",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The visible text shown to the user displays one URL (e.g., 'https://paypal.com'), while the underlying HTML href attribute routes to an entirely different host.",
        remediation_advice="Do not click. This is intentional visual deception.",
        mitre_attack_id="T1566.002",
    ),
    "URL-08": RuleDefinition(
        rule_id="URL-08",
        rule_name="Excessive URL Length / High Entropy",
        category="URL",
        severity="low",
        base_weight=8.0,
        confidence_multiplier=0.60,
        description="The URL is excessively long (>200 characters) or displays high Shannon entropy, suggesting tracking identifiers or base64 payload transport.",
        remediation_advice="Review URL path tokens for embedded base64 or obfuscated target parameters.",
        mitre_attack_id="T1027",
    ),

    # -------------------------------------------------------------
    # ATTACHMENT RISK (ATTACH)
    # -------------------------------------------------------------
    "ATT-01": RuleDefinition(
        rule_id="ATT-01",
        rule_name="Executable or Script Attachment Extension",
        category="ATTACH",
        severity="critical",
        base_weight=30.0,
        confidence_multiplier=0.95,
        description="The attachment carries an executable or script file extension (.exe, .scr, .vbs, .bat, .cmd, .js, .hta) that can run arbitrary code upon execution.",
        remediation_advice="Never open or run executable attachments received via email. Submit to an isolated sandbox for forensic detonation if authorized.",
        mitre_attack_id="T1204.002",
    ),
    "ATT-02": RuleDefinition(
        rule_id="ATT-02",
        rule_name="Double File Extension Evasion",
        category="ATTACH",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The attachment utilizes a double extension (e.g., 'invoice.pdf.exe') to exploit default Windows settings that hide known extensions.",
        remediation_advice="Block file. Enable 'Show file extensions' in Windows Explorer to reveal hidden dangerous extensions.",
        mitre_attack_id="T1036.007",
    ),
    "ATT-03": RuleDefinition(
        rule_id="ATT-03",
        rule_name="Disk Image Container Attachment",
        category="ATTACH",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The attachment is a disk image container (.iso, .img, .vhd), commonly used by threat actors to evade Mark-of-the-Web (MOTW) security flags.",
        remediation_advice="Inspect disk image contents in an offline forensic environment without mounting automatically.",
        mitre_attack_id="T1553.005",
    ),
    "ATT-04": RuleDefinition(
        rule_id="ATT-04",
        rule_name="Macro-Enabled Document Attachment",
        category="ATTACH",
        severity="high",
        base_weight=20.0,
        confidence_multiplier=0.85,
        description="The document is macro-enabled (.docm, .xlsm, .pptm). Malicious VBA macros remain a pervasive delivery vector for initial access malware.",
        remediation_advice="Do not enable macros or bypass protected view. Request plain XLSX/DOCX versions from the sender.",
        mitre_attack_id="T1566.001",
    ),
    "ATT-05": RuleDefinition(
        rule_id="ATT-05",
        rule_name="MIME Type Declaration Mismatch with Extension",
        category="ATTACH",
        severity="medium",
        base_weight=18.0,
        confidence_multiplier=0.80,
        description="The MIME content-type declared in headers (e.g. image/jpeg) contradicts the file extension (.exe, .vbs), indicating an evasion attempt against gateway filters.",
        remediation_advice="Hold file in gateway quarantine and perform binary inspection.",
        mitre_attack_id="T1036",
    ),
    "ATT-06": RuleDefinition(
        rule_id="ATT-06",
        rule_name="YARA Signature Match in Attachment Payload",
        category="ATTACH",
        severity="critical",
        base_weight=30.0,
        confidence_multiplier=0.95,
        description="The attachment payload matched a known defensive YARA signature (e.g. embedded PE executable, VBA execution chain, obfuscated PowerShell cradle, HTML smuggling).",
        remediation_advice="Isolate attachment. The file contains confirmed malicious signatures or exploitation patterns.",
        mitre_attack_id="T1027",
    ),

    # -------------------------------------------------------------
    # CONTENT HEURISTICS (CONTENT)
    # -------------------------------------------------------------
    "CNT-01": RuleDefinition(
        rule_id="CNT-01",
        rule_name="Urgent / Coercive Financial Pretext in Body",
        category="CONTENT",
        severity="medium",
        base_weight=12.0,
        confidence_multiplier=0.70,
        description="The email content uses intense urgency, account suspension threats, or immediate wire transfer language to induce hasty action.",
        remediation_advice="Pause and verify through standard operating procedures. Genuine financial institutions do not demand urgent wire transfers via email.",
        mitre_attack_id="T1566.001",
    ),
    "CNT-02": RuleDefinition(
        rule_id="CNT-02",
        rule_name="HTML Credential Harvesting Form Action",
        category="CONTENT",
        severity="high",
        base_weight=25.0,
        confidence_multiplier=0.90,
        description="The email body includes an interactive HTML <form> element designed to submit credentials or data directly to an external endpoint.",
        remediation_advice="Never enter credentials into forms embedded directly inside an email. Legitimate services authenticate exclusively on official HTTPS portals.",
        mitre_attack_id="T1056.003",
    ),
}

