"""Tests for Email Header & In-Transit Hop Routing Engine."""

from app.email_analysis.headers import EmailHeaderAnalyzer


def test_routing_hop_chronological_order_and_delays():
    received_headers = [
        # Final receiver (latest hop - index 0 in raw headers)
        "from mail-relay.target.com (mail-relay.target.com [198.51.100.20]) by mx.target.com with ESMTPS; Thu, 12 Nov 2026 12:00:10 +0000",
        # Intermediate relay
        "from mail.origin.com (mail.origin.com [203.0.113.15]) by mail-relay.target.com with ESMTPS; Thu, 12 Nov 2026 12:00:02 +0000",
        # Originating MTA (earliest hop - bottom of email)
        "from client.local (client.local [192.168.1.50]) by mail.origin.com with ESMTP; Thu, 12 Nov 2026 12:00:00 +0000",
    ]

    analyzer = EmailHeaderAnalyzer()
    hops = analyzer.analyze_routing_hops(received_headers)

    assert len(hops) == 3
    # Hop 1 must be earliest (originating)
    assert hops[0].hop_number == 1
    assert hops[0].ip_address == "192.168.1.50"
    assert hops[0].is_private_ip is True

    # Hop 2
    assert hops[1].hop_number == 2
    assert hops[1].ip_address == "203.0.113.15"
    assert hops[1].delay_seconds == 2.0

    # Hop 3 (final)
    assert hops[2].hop_number == 3
    assert hops[2].delay_seconds == 8.0


def test_sender_identity_anomalies_and_brand_impersonation():
    analyzer = EmailHeaderAnalyzer()

    # Test display name email spoofing
    analysis = analyzer.analyze_sender_identities(
        from_header='"security@paypal.com" <phisher@malicious-domain.ru>',
        reply_to_header='support@another-external.com',
        return_path_header='bounce@malicious-domain.ru',
    )

    assert analysis.has_display_name_email_spoofing is True
    assert analysis.has_from_reply_to_mismatch is True
    assert analysis.has_brand_impersonation_in_name is True
    assert analysis.detected_impersonated_brand == "paypal"
    assert len(analysis.anomalies) >= 3


def test_sender_identity_legitimate_newsletter_alignment():
    analyzer = EmailHeaderAnalyzer()

    analysis = analyzer.analyze_sender_identities(
        from_header='"Acme Security Updates" <updates@acme.com>',
        reply_to_header='support@acme.com',
        return_path_header='bounces@mail.acme.com',
    )

    assert analysis.has_display_name_email_spoofing is False
    assert analysis.has_brand_impersonation_in_name is False
    assert analysis.has_from_reply_to_mismatch is False

