"""Test Suite verifying Offline Network Isolation Enforcement and PSL Safety."""

import http.client
import urllib.request
import pytest
import tldextract


def test_offline_isolation_blocks_external_http_connect():
    """Asserts that attempted external HTTP connections trigger an immediate AssertionError."""
    conn = http.client.HTTPConnection("8.8.8.8", 80)
    with pytest.raises(AssertionError) as exc_info:
        conn.connect()

    assert "Unauthorized outbound HTTP/HTTPS network connection attempt" in str(exc_info.value)
    conn.close()


def test_offline_isolation_blocks_external_urllib_request():
    """Asserts that attempted urllib requests trigger an immediate AssertionError."""
    with pytest.raises(AssertionError) as exc_info:
        urllib.request.urlopen("https://example.com")

    assert "Unauthorized urllib.request.urlopen call detected" in str(exc_info.value)


def test_tldextract_offline_mode_zero_network():
    """Asserts that tldextract with suffix_list_urls=None parses domains with zero network requests."""
    # When suffix_list_urls is None or empty, tldextract never fetches from the internet
    extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    extracted = extractor("https://admin.portal.service.gov.uk/login")

    assert extracted.subdomain == "admin.portal"
    assert extracted.domain == "service"
    assert extracted.suffix == "gov.uk"
    assert extracted.registered_domain == "service.gov.uk"
