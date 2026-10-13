"""Тесты этапа 2. Браузер и сеть не нужны: тестируется чистая логика."""

from __future__ import annotations

import ssl
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from phishguard.models import CertInfo, FormInfo, IframeInfo, PageFeatures  # noqa: E402
from phishguard.page_analyzer import (  # noqa: E402
    RULES,
    _cert_from_error,
    _hostname_in_cert,
    _days_left,
    _score,
)


def _features(final_url="https://www.shop.example/", **overrides) -> PageFeatures:
    base = PageFeatures(
        title="Вход в аккаунт",
        final_url=final_url,
        page_text="введите логин и пароль",
        login_keywords=["пароль", "вход"],
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _form(host, password=False, action="/submit", method="post") -> FormInfo:
    return FormInfo(
        action=action,
        method=method,
        host_of_action=host,
        has_password_field=password,
        visible_fields=["login", "password"] if password else ["q"],
        hidden_fields=[],
    )


def test_clean_page_scores_zero():
    report = _score(
        "https://www.shop.example/",
        _features(forms=[_form("www.shop.example", password=True)]),
    )
    assert report.score == 0.0, report.reasons
    assert report.implemented is True


def test_password_form_on_external_host_is_strongest_signal():
    report = _score(
        "https://www.bank.example/",
        _features(forms=[_form("collector.evil.example", password=True)]),
    )
    assert report.score >= RULES["password_form_external"]
    assert any("сторонний хост" in r for r in report.reasons)


def test_form_without_password_scores_less_than_with():
    with_pwd = _score(
        "https://www.shop.example/",
        _features(forms=[_form("x.evil.example", password=True)]),
    ).score
    without = _score(
        "https://www.shop.example/",
        _features(forms=[_form("x.evil.example", password=False)]),
    ).score
    assert with_pwd > without


def test_hidden_external_iframe_scored():
    report = _score(
        "https://www.shop.example/",
        _features(
            iframes=[
                IframeInfo(src="/inline", host_of_src="www.shop.example", hidden=False),
                IframeInfo(src="//evil.example/f", host_of_src="evil.example", hidden=True),
            ]
        ),
    )
    assert report.score >= RULES["hidden_external_iframe"]
    assert any("iframe" in r for r in report.reasons)


def test_visible_external_iframe_is_not_scored():
    report = _score(
        "https://www.shop.example/",
        _features(
            iframes=[
                IframeInfo(
                    src="//cdn.example/player",
                    host_of_src="cdn.example",
                    hidden=False,
                )
            ]
        ),
    )
    assert report.score == 0.0


def test_redirect_to_other_host_scored():
    report = _score(
        "https://www.pay.example/",
        _features(final_url="https://collector.other.example/pay"),
    )
    assert report.score >= RULES["redirect_host_changed"]
    assert any("переадресация" in r for r in report.reasons)


def test_expired_cert_scored():
    report = _score(
        "https://www.shop.example/",
        _features(cert=CertInfo(expired=True)),
    )
    assert report.score >= RULES["cert_expired"]
    assert any("истёк" in r for r in report.reasons)


def test_cert_expiring_soon_scores():
    report = _score(
        "https://www.shop.example/",
        _features(cert=CertInfo(days_left=5)),
    )
    assert report.score >= RULES["cert_expires_soon"]


def test_brand_not_owner_of_domain_scored():
    report = _score(
        "https://sberbank.secure-login.ru/",
        _features(
            final_url="https://www.sberbank.secure-login.ru/",
            brand_names=["сбербанк", "sberbank"],
        ),
    )
    assert report.score >= RULES["brand_not_owner_of_domain"]
    assert any("бренду не принадлежит" in r for r in report.reasons)


def test_brand_that_owns_domain_is_not_scored():
    report = _score(
        "https://www.sberbank.ru/",
        _features(final_url="https://www.sberbank.ru/", brand_names=["sberbank"]),
    )
    assert report.score == 0.0, report.reasons


def test_score_is_capped_at_100():
    report = _score(
        "https://www.pay.example/",
        _features(
            final_url="https://evil.example/",
            forms=[
                _form("evil1.example", password=True),
                _form("evil2.example", password=True),
                _form("evil3.example", password=True),
            ],
            iframes=[
                IframeInfo(src="a", host_of_src="x.example", hidden=True),
                IframeInfo(src="b", host_of_src="y.example", hidden=True),
            ],
            cert=CertInfo(expired=True, self_signed=True, hostname_mismatch=True),
            brand_names=["сбербанк"],
            external_hosts=[f"h{i}.example" for i in range(12)],
        ),
    )
    assert 0.0 <= report.score <= 100.0


def test_reasons_never_empty():
    report = _score("https://www.shop.example/", _features())
    assert report.reasons


@pytest.mark.parametrize(
    ("reason", "expected_field"),
    [
        ("self signed certificate", "self_signed"),
        ("certificate has expired", "expired"),
        ("Hostname mismatch", "hostname_mismatch"),
        ("unable to get local issuer certificate", "untrusted"),
    ],
)
def test_cert_error_classification(reason, expected_field):
    exc = ssl.SSLCertVerificationError(1, reason)
    info = _cert_from_error(exc)
    assert getattr(info, expected_field) is True
    assert info.error


def test_days_left_positive_for_future():
    # База считается чуть раньше, чем момент вычисления внутри функции,
    # поэтому граница суток может уехать на 1 день.
    future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )
    assert abs(_days_left(future) - 10) <= 1


def test_days_left_negative_for_past():
    past = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )
    assert abs(_days_left(past) - (-3)) <= 1


def test_days_left_none_when_unparsable():
    assert _days_left(None) is None
    assert _days_left("не дата") is None


def test_hostname_matching():
    cert = {"subjectAltName": (("DNS", "*.example.com"),)}
    assert _hostname_in_cert(cert, "login.example.com") is True
    assert _hostname_in_cert(cert, "example.com") is False
    assert _hostname_in_cert(cert, "evil.net") is False


def test_hostname_falls_back_to_common_name():
    cert = {"subject": ((("commonName", "www.a.example"),),)}
    assert _hostname_in_cert(cert, "www.a.example") is True


def test_seven_reasons_can_coexist():
    report = _score(
        "https://www.bank.example/",
        _features(
            final_url="https://collector.other.example/",
            forms=[_form("other.example", password=True)],
            iframes=[IframeInfo(src="/x", host_of_src="z.example", hidden=True)],
            cert=CertInfo(expired=True, self_signed=True, hostname_mismatch=True),
            brand_names=["сбербанк"],
            external_hosts=[f"h{i}.example" for i in range(10)],
        ),
    )
    assert len(report.reasons) >= 6
