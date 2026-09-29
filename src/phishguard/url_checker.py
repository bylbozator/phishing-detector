"""Этап 1. Проверка URL — быстрый рубеж.

Исполнитель: модуль №1.

Это эталонная реализация одного из четырёх этапов: показывает, как устроен
модуль, который возвращает типизированный отчёт и не падает на плохих входных
данных. Остальные три этапа пишутся по этому же образцу.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

from .models import STAGE_URL, StageResult, UrlReport, risk_level

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "vk.cc", "clck.ru",
    "u.to", "rb.gy", "shorte.st", "tiny.cc",
}

SUSPICIOUS_CHARS = re.compile(r"@|\\|\.\.|&#|%2[0-9a-fA-F]%")
BRANDS = [
    "sberbank", "сбербанк", "tinkoff", "тинкофф", "alfabank", "альфа",
    "vtb", "втб", "mail.ru", "mail", "yandex", "яндекс", "gosuslugi",
    "госуслуги", "wildberries", "ozon", "яндекс.маркет", "wb", "cdek",
    "вконтакте", "vk", "ok.ru", "telegram", "телеграм",
]

WEIGHTS = {
    "has_ip_host": 40.0,
    "is_shortener": 30.0,
    "has_punycode": 35.0,
    "has_suspicious_chars": 20.0,
    "deep_subdomain": 15.0,
    "brand_in_subdomain": 30.0,
    "brand_in_host_but_not_in_domain": 25.0,
    "insecure_scheme": 15.0,
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parts = urlparse(url)
    netloc = parts.netloc.lower()
    hostname = parts.hostname or ""
    is_domain = "." in hostname and not _is_ip(hostname) and hostname != "localhost"
    if is_domain and not netloc.startswith("www."):
        netloc = "www." + netloc
    return urlunparse(parts._replace(netloc=netloc))


def _host(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host[4:] if host.startswith("www.") else host


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def _registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if host.endswith(".co.uk") or host.endswith(".com.tr"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_shortener(host: str) -> bool:
    return _registrable_domain(host) in SHORTENERS or host in SHORTENERS


def check_url(url: str) -> UrlReport:
    normalized = normalize_url(url)
    parts = urlparse(normalized)
    host = _host(normalized)
    report = UrlReport(
        original_url=url,
        normalized_url=normalized,
        registrable_domain=_registrable_domain(host),
        has_ip_host=_is_ip(host),
        is_shortener=_is_shortener(host),
        has_punycode=host.startswith("xn--") or ".xn--" in host,
        has_suspicious_chars=bool(SUSPICIOUS_CHARS.search(parts.path + "?" + parts.query)),
        subdomain_depth=max(0, len(host.split(".")) - 2),
    )
    # «apple.com@evil.ru» — пользовательская часть в адресе, реальный
    # домен при этом evil.ru, поэтому проверяем весь netloc, а не только путь.
    has_userinfo = "@" in parts.netloc
    report.has_suspicious_chars = has_userinfo or bool(
        SUSPICIOUS_CHARS.search(parts.path + "?" + parts.query)
    )

    score = 0.0
    reasons: list[str] = []

    if report.has_ip_host:
        score += WEIGHTS["has_ip_host"]
        reasons.append(f"вместо домена указан IP-адрес ({host})")
    if report.is_shortener:
        score += WEIGHTS["is_shortener"]
        reasons.append(f"используется сокращатель ссылок ({report.registrable_domain})")
    if report.has_punycode:
        score += WEIGHTS["has_punycode"]
        reasons.append("домен записан в punycode, возможна имитация символов")
    if report.has_suspicious_chars:
        score += WEIGHTS["has_suspicious_chars"]
        if has_userinfo:
            reasons.append(
                f"в адресе есть «{parts.username}@», реальный домен — {host}"
            )
        else:
            reasons.append("в пути или параметрах есть нетипичные символы (@, кодировки, ..)")
    if report.subdomain_depth >= 3:
        score += WEIGHTS["deep_subdomain"]
        reasons.append(f"глубокая вложенность поддоменов ({report.subdomain_depth})")
    if parts.scheme == "http":
        score += WEIGHTS["insecure_scheme"]
        reasons.append("соединение без HTTPS")

    host_brand = next((b for b in BRANDS if b in host), None)
    if host_brand:
        in_registrable = host_brand in report.registrable_domain
        if report.subdomain_depth >= 2 and not in_registrable:
            score += WEIGHTS["brand_in_subdomain"]
            reasons.append(f"название бренда «{host_brand}» в поддомене, а не в основном домене")
        elif report.subdomain_depth == 1 and not in_registrable:
            score += WEIGHTS["brand_in_host_but_not_in_domain"]
            reasons.append(f"домен имитирует бренд «{host_brand}»: {host}")

    report.score = min(100.0, score)
    report.reasons = reasons
    return report


def stage_result(report: UrlReport) -> StageResult:
    return StageResult(
        stage=STAGE_URL,
        score=report.score,
        reasons=report.reasons,
        details={
            "normalized_url": report.normalized_url,
            "registrable_domain": report.registrable_domain,
            "risk_level": risk_level(report.score),
        },
    )
