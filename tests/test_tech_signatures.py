from __future__ import annotations

from lodan.enrich.tech_signatures import match


def test_nginx_server_header() -> None:
    assert match({"Server": "nginx/1.25.3"}, b"") == ["nginx"]


def test_apache_server_header() -> None:
    assert "apache" in match({"Server": "Apache/2.4.54 (Ubuntu)"}, b"")


def test_iis_server_header() -> None:
    assert "IIS" in match({"Server": "Microsoft-IIS/10.0"}, b"")


def test_cloudflare_via_cf_ray() -> None:
    assert "cloudflare" in match({"CF-Ray": "abcdef1234567890-IAD"}, b"")


def test_gitlab_body_marker() -> None:
    body = b"<html>... GitLab.com hosted runner ..."
    assert "GitLab" in match({}, body)


def test_jenkins_via_header() -> None:
    assert "Jenkins" in match({"X-Jenkins": "2.401.3"}, b"")


def test_jenkins_via_title() -> None:
    body = b"<title>Dashboard [Jenkins]</title>"
    assert "Jenkins" in match({}, body)


def test_grafana_via_cookie() -> None:
    hits = match({}, b"<html></html>", {"grafana_session"})
    assert "Grafana" in hits


def test_grafana_via_body() -> None:
    assert "Grafana" in match({}, b"<title>Grafana</title>")


def test_wordpress_via_content_path() -> None:
    assert "WordPress" in match({}, b'<link href="/wp-content/themes/x/style.css">')


def test_drupal_via_generator() -> None:
    assert "Drupal" in match({"X-Generator": "Drupal 10"}, b"")


def test_phpmyadmin_body() -> None:
    assert "phpMyAdmin" in match({}, b"Welcome to phpMyAdmin")


def test_keycloak_cookie() -> None:
    hits = match({}, b"", {"KEYCLOAK_IDENTITY"})
    assert "Keycloak" in hits


def test_no_false_positive_on_blank() -> None:
    assert match({}, b"") == []


def test_multiple_signatures_can_match() -> None:
    hits = match(
        {"Server": "nginx/1.25", "CF-Ray": "abc123"},
        b"",
    )
    assert "nginx" in hits
    assert "cloudflare" in hits


def test_body_window_is_bounded() -> None:
    # Marker placed past 128KB must not match.
    body = b"A" * 200000 + b"<title>[Jenkins]"
    assert "Jenkins" not in match({}, body)
