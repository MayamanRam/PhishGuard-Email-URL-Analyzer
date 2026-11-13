"""Tests for Static URL Threat and Normalization Engine."""

from app.url_analysis.engine import StaticUrlAnalyzer


def test_url_normalization_and_clean_domain():
    analyzer = StaticUrlAnalyzer()
    res = analyzer.analyze("https://WWW.Example.COM:443/path/to/page?b=2&a=1#section")

    assert res.scheme == "https"
    assert res.hostname == "www.example.com"
    assert res.port is None  # Standard port 443 normalized out
    assert res.registrable_domain == "example.com"
    assert res.has_ip_hostname is False
    assert res.has_brand_impersonation is False


def test_url_literal_ip_and_userinfo_spoof():
    analyzer = StaticUrlAnalyzer()
    res = analyzer.analyze("http://www.paypal.com:password@192.168.1.100/login.php")

    assert res.has_ip_hostname is True
    assert res.ip_type == "ipv4"
    assert res.has_userinfo_spoof is True
    assert "paypal.com" in (res.userinfo or "")
    assert len(res.anomalies) >= 2


def test_url_punycode_and_cyrillic_homoglyphs():
    analyzer = StaticUrlAnalyzer()
    # Cyrillic 'а' replacing Latin 'a' in paypal: p\u0430ypal.com
    cyrillic_url = "https://p\u0430ypal.com/signin"
    res = analyzer.analyze(cyrillic_url)

    assert res.has_mixed_script_homoglyphs is True
    assert any("lookalike" in d for d in res.homoglyph_details)


def test_url_brand_impersonation_detection():
    analyzer = StaticUrlAnalyzer()

    # Brand in subdomain/domain on untrusted eTLD+1
    fake_res = analyzer.analyze("https://security-verify.paypal.com.phish-site.net/account")
    assert fake_res.has_brand_impersonation is True
    assert fake_res.impersonated_brand_name == "paypal"
    assert fake_res.registrable_domain == "phish-site.net"

    # Authentic brand domain should NOT be flagged as impersonation
    real_res = analyzer.analyze("https://www.paypal.com/myaccount/summary")
    assert real_res.has_brand_impersonation is False
    assert real_res.registrable_domain == "paypal.com"


def test_url_open_redirect_detection():
    analyzer = StaticUrlAnalyzer()
    res = analyzer.analyze("https://login.example.com/oauth?redirect_uri=https://malicious-target.com/harvest")

    assert res.has_open_redirect_param is True
    assert res.open_redirect_target == "https://malicious-target.com/harvest"

