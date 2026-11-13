"""Defensive RFC 5322 and MIME Email Parser.

Parses email content safely in-memory without rendering HTML scripts,
executing attachments, or initiating any external network requests.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup


@dataclass
class ExtractedLink:
    href: str
    anchor_text: str
    is_mismatch: bool = False
    source: str = "body"


@dataclass
class ExtractedAttachment:
    filename: str
    content_type: str
    content_disposition: str
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    raw_payload: bytes = field(repr=False)


@dataclass
class ParsedEmail:
    sha256_fingerprint: str
    md5_fingerprint: str
    raw_size_bytes: int
    subject: str
    from_header: str
    to_header: str
    cc_header: str
    reply_to_header: str
    return_path_header: str
    date_header: str
    message_id_header: str
    all_headers: dict[str, list[str]]
    received_headers: list[str]
    auth_results_headers: list[str]
    plain_text_body: str
    html_body_raw: str
    html_text_extracted: str
    links: list[ExtractedLink]
    form_actions: list[str]
    image_sources: list[str]
    attachments: list[ExtractedAttachment]


def _extract_payload_bytes(msg_part: email.message.Message) -> bytes:
    """Safely extract bytes from a Message payload under decode=True."""
    raw = msg_part.get_payload(decode=True)
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


class DefensiveEmailParser:
    """Robust, memory-safe email parser with strict defensive sanitization."""

    URL_REGEX = re.compile(
        r"(https?://[^\s<>\"'()]+|ftp://[^\s<>\"'()]+)",
        re.IGNORECASE,
    )

    def parse(self, raw_input: bytes | str) -> ParsedEmail:
        """Parse raw RFC 5322 / MIME bytes or string into a structured ParsedEmail object."""
        if isinstance(raw_input, str):
            raw_bytes = raw_input.encode("utf-8", errors="replace")
        else:
            raw_bytes = raw_input

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        md5_hash = hashlib.md5(raw_bytes, usedforsecurity=False).hexdigest()
        raw_size = len(raw_bytes)

        # Parse message using Python's modern email policy
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

        # Extract all headers
        all_headers: dict[str, list[str]] = {}
        for key, val in msg.items():
            key_lower = key.lower()
            all_headers.setdefault(key_lower, []).append(str(val))

        subject = str(msg.get("Subject", "") or "").strip()
        from_header = str(msg.get("From", "") or "").strip()
        to_header = str(msg.get("To", "") or "").strip()
        cc_header = str(msg.get("Cc", "") or "").strip()
        reply_to = str(msg.get("Reply-To", "") or "").strip()
        return_path = str(msg.get("Return-Path", "") or "").strip()
        date_header = str(msg.get("Date", "") or "").strip()
        message_id = str(msg.get("Message-ID", "") or "").strip()

        received_headers = all_headers.get("received", [])
        auth_results_headers = (
            all_headers.get("authentication-results", [])
            + all_headers.get("arc-authentication-results", [])
        )

        plain_text_parts: list[str] = []
        html_parts: list[str] = []
        attachments: list[ExtractedAttachment] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = (part.get_content_disposition() or "").lower()
                content_type = part.get_content_type().lower()
                filename = part.get_filename() or ""

                # Treat as attachment if explicitly marked or has a filename
                if content_disposition == "attachment" or (filename and content_disposition != "inline"):
                    payload: bytes = _extract_payload_bytes(part)
                    att_sha256 = hashlib.sha256(payload).hexdigest()
                    att_md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest()
                    attachments.append(
                        ExtractedAttachment(
                            filename=filename or "unnamed_attachment",
                            content_type=content_type,
                            content_disposition=content_disposition or "attachment",
                            size_bytes=len(payload),
                            sha256_hash=att_sha256,
                            md5_hash=att_md5,
                            raw_payload=payload,
                        )
                    )
                elif content_type == "text/plain":
                    try:
                        text_content = part.get_content()
                        if isinstance(text_content, str):
                            plain_text_parts.append(text_content)
                    except Exception:
                        payload_bytes: bytes = _extract_payload_bytes(part)
                        plain_text_parts.append(payload_bytes.decode("utf-8", errors="replace"))
                elif content_type == "text/html":
                    try:
                        html_content = part.get_content()
                        if isinstance(html_content, str):
                            html_parts.append(html_content)
                    except Exception:
                        payload_bytes: bytes = _extract_payload_bytes(part)
                        html_parts.append(payload_bytes.decode("utf-8", errors="replace"))
                elif filename:  # Inline attachment with filename
                    payload: bytes = _extract_payload_bytes(part)
                    att_sha256 = hashlib.sha256(payload).hexdigest()
                    att_md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest()
                    attachments.append(
                        ExtractedAttachment(
                            filename=filename,
                            content_type=content_type,
                            content_disposition=content_disposition or "inline",
                            size_bytes=len(payload),
                            sha256_hash=att_sha256,
                            md5_hash=att_md5,
                            raw_payload=payload,
                        )
                    )
        else:
            content_type = msg.get_content_type().lower()
            try:
                content = msg.get_content()
                if isinstance(content, str):
                    if content_type == "text/html":
                        html_parts.append(content)
                    else:
                        plain_text_parts.append(content)
            except Exception:
                payload_bytes: bytes = _extract_payload_bytes(msg)
                decoded = payload_bytes.decode("utf-8", errors="replace")
                if content_type == "text/html":
                    html_parts.append(decoded)
                else:
                    plain_text_parts.append(decoded)

        plain_text_body = "\n\n".join(plain_text_parts)
        html_body_raw = "\n\n".join(html_parts)

        # Parse HTML safely
        html_text_extracted = ""
        links: list[ExtractedLink] = []
        form_actions: list[str] = []
        image_sources: list[str] = []

        if html_body_raw.strip():
            soup = BeautifulSoup(html_body_raw, "lxml")

            # Strip active or unsafe elements
            for tag in soup.find_all(["script", "style", "iframe", "object", "embed", "applet"]):
                tag.decompose()

            html_text_extracted = soup.get_text(separator=" ", strip=True)

            # Extract <a> links
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag["href"]).strip()
                anchor_text = a_tag.get_text(strip=True)
                if href and not href.startswith(("mailto:", "tel:", "javascript:")):
                    is_mismatch = self._check_anchor_mismatch(anchor_text, href)
                    links.append(
                        ExtractedLink(
                            href=href,
                            anchor_text=anchor_text,
                            is_mismatch=is_mismatch,
                            source="html_link",
                        )
                    )

            # Extract <form> action targets
            for form in soup.find_all("form", action=True):
                action = str(form["action"]).strip()
                if action:
                    form_actions.append(action)

            # Extract <img src>
            for img in soup.find_all("img", src=True):
                src = str(img["src"]).strip()
                if src:
                    image_sources.append(src)

        # Also extract plain text URLs from the plain text body
        seen_urls = {link.href for link in links}
        for match in self.URL_REGEX.finditer(plain_text_body):
            found_url = match.group(0).rstrip(".,;!?'\")>]}")
            if found_url and found_url not in seen_urls:
                seen_urls.add(found_url)
                links.append(
                    ExtractedLink(
                        href=found_url,
                        anchor_text=found_url,
                        is_mismatch=False,
                        source="plain_text",
                    )
                )

        return ParsedEmail(
            sha256_fingerprint=sha256_hash,
            md5_fingerprint=md5_hash,
            raw_size_bytes=raw_size,
            subject=subject,
            from_header=from_header,
            to_header=to_header,
            cc_header=cc_header,
            reply_to_header=reply_to,
            return_path_header=return_path,
            date_header=date_header,
            message_id_header=message_id,
            all_headers=all_headers,
            received_headers=received_headers,
            auth_results_headers=auth_results_headers,
            plain_text_body=plain_text_body,
            html_body_raw=html_body_raw,
            html_text_extracted=html_text_extracted,
            links=links,
            form_actions=form_actions,
            image_sources=image_sources,
            attachments=attachments,
        )

    @staticmethod
    def _check_anchor_mismatch(anchor_text: str, href: str) -> bool:
        """Check if anchor text resembles a URL pointing to a different host than href."""
        clean_anchor = anchor_text.strip().lower()
        if not clean_anchor.startswith(("http://", "https://", "www.")):
            return False

        if clean_anchor.startswith("www."):
            clean_anchor = "http://" + clean_anchor

        try:
            anchor_parsed = urlparse(clean_anchor)
            href_parsed = urlparse(href.strip().lower())

            anchor_host = (anchor_parsed.hostname or "").lower()
            href_host = (href_parsed.hostname or "").lower()

            if anchor_host and href_host:
                return anchor_host != href_host
        except Exception:
            return False

        return False
