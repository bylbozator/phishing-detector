"""Этап 2. Алгоритмический анализ структуры страницы.

Исполнитель: Михайлова А. + Кузнецов Н.

Модуль состоит из двух частей:
  1. _fetch_features  — управляет реальным браузером и собирает PageFeatures.
     Selenium запускает Chrome без окна, страница сама расшифровывает TLS,
     поэтому мы работаем уже с расшифрованным DOM.
  2. _score           — чистая функция: по собранным признакам считает балл
     и наполняет reasons. Из неё удобно писать тесты, браузер не нужен.

Сознательно не проверяется здесь то, что уже проверяет этап 1 (сам URL:
IP вместо домена, сокращатели, punycode). Этот этап отвечает только за
содержимое страницы: формы, фреймы, редиректы, сертификат, бренды.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from .models import (
    CertInfo,
    FormInfo,
    IframeInfo,
    PageFeatures,
    PageReport,
)
from .url_checker import BRANDS, registrable_domain

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    SELENIUM_AVAILABLE = True
except ImportError:  # pragma: no cover - падение импорта не должно ронять пайплайн
    SELENIUM_AVAILABLE = False

NOT_IMPLEMENTED = "Модуль №2 в разработке"
MAX_TEXT_CHARS = 4000
CERT_TIMEOUT = 6

LOGIN_KEYWORDS = [
    "пароль", "логин", "вход", "авторизация", "sign in", "log in",
    "password", "username", "forgot", "забыли",
    "оплатить", "карта", "cvv", "срок действия", "cvc",
    "код из смс", "подтвердите", "recaptcha", "не передавайте",
    "срочно", "срок истекает", "ограниченное время",
]

RULES = {
    "password_form_external": 45.0,
    "form_action_external": 30.0,
    "hidden_external_iframe": 35.0,
    "redirect_host_changed": 40.0,
    "cert_hostname_mismatch": 30.0,
    "cert_self_signed": 35.0,
    "cert_expired": 30.0,
    "cert_untrusted": 25.0,
    "cert_expires_soon": 15.0,
    "brand_not_owner_of_domain": 30.0,
}


def _find_brands(haystack: str, page_host: str) -> list[str]:
    """Ищет бренды по границам слов, а не подстрокой.

    Иначе «mail» совпадал бы с «email», а «втб» — с любой строкой,
    где встретилась эта последовательность. В домене бренд должен быть
    отдельной меткой, а не частью чужого слова.
    """
    found = set()
    labels = [l for l in (page_host or "").lower().split(".") if l]
    for brand in BRANDS:
        pattern = r"(?<![\w])" + re.escape(brand) + r"(?![\w])"
        if re.search(pattern, haystack, re.IGNORECASE):
            found.add(brand)
        if brand in labels:
            found.add(brand)
    return sorted(found)


def _host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def _visible_fields(inputs) -> tuple[list[str], list[str]]:
    visible, hidden = [], []
    for inp in inputs:
        name = (inp.get_attribute("name") or inp.get_attribute("id") or "").strip()
        placeholder = (inp.get_attribute("placeholder") or "").strip()
        label = name or placeholder
        if not label:
            continue
        kind = (inp.get_attribute("type") or "text").lower()
        if kind == "hidden":
            hidden.append(label)
        elif kind not in ("submit", "button", "image"):
            visible.append(label)
    return visible, hidden


def _check_cert(host: str, port: int = 443, timeout: float = CERT_TIMEOUT) -> CertInfo:
    """Проверяет TLS-сертификат хоста.

    Полный разбор цепочки доступен только когда проверка прошла. Если
    проверка отклонена, по тексту ошибки ставим флаг причины — для
    детектора сам факт отказа и есть главный сигнал.
    """
    if not host or _host_is_ip(host):
        return CertInfo(error="не проверяется: нужен домен, а не IP")

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return _cert_from_dict(ssock.getpeercert(), host)
    except ssl.SSLCertVerificationError as exc:
        info = _cert_from_error(exc)
        if info.hostname_mismatch:
            info = _cert_from_error_with_details(exc, host, port, timeout)
        return info
    except (socket.timeout, ConnectionError, OSError) as exc:
        return CertInfo(error=f"{type(exc).__name__}: {exc}")


def _cert_from_error(exc: ssl.SSLCertVerificationError) -> CertInfo:
    reason = (getattr(exc, "verify_message", "") or str(exc)).lower()
    info = CertInfo(error=reason or "сертификат не прошёл проверку")
    if "self signed" in reason:
        info.self_signed = True
    elif "expired" in reason or "has expired" in reason:
        info.expired = True
    elif "hostname" in reason:
        info.hostname_mismatch = True
    elif "issuer" in reason or "unable to get" in reason:
        info.untrusted = True
    return info


def _cert_from_error_with_details(
    exc: ssl.SSLCertVerificationError, host: str, port: int, timeout: float
) -> CertInfo:
    """При расхождении имён сервер всё равно присылает валидную цепочку,
    поэтому повторяем подключение без сверки имён, чтобы получить данные."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info = _cert_from_dict(ssock.getpeercert(), host)
    except ssl.SSLCertVerificationError as retry_exc:
        info = _cert_from_error(retry_exc)
    except (socket.timeout, ConnectionError, OSError) as retry_exc:
        info = CertInfo(error=f"{type(retry_exc).__name__}: {retry_exc}")
    info.hostname_mismatch = True
    return info


def _cert_from_dict(cert: dict, host: str) -> CertInfo:
    info = CertInfo(
        subject=_dn(cert.get("subject")),
        issuer=_dn(cert.get("issuer")),
        valid_from=_fmt_date(cert.get("notBefore")),
        valid_to=_fmt_date(cert.get("notAfter")),
    )
    days = _days_left(cert.get("notAfter"))
    info.days_left = days
    if days is not None:
        info.expired = days < 0
    info.untrusted = False
    if info.subject and info.issuer and info.subject == info.issuer:
        info.self_signed = True
    if not _hostname_in_cert(cert, host):
        info.hostname_mismatch = True
    return info


def _dn(rdn_pairs) -> str | None:
    if not rdn_pairs:
        return None
    parts = []
    for rdn in rdn_pairs:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _fmt_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").astimezone(
            timezone.utc
        ).isoformat()
    except ValueError:
        return value


def _days_left(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return (expires - datetime.now(timezone.utc)).days


def _hostname_in_cert(cert: dict, host: str) -> bool:
    names: list[str] = []
    for typ, value in cert.get("subjectAltName", ()):
        if typ == "DNS":
            names.append(value.lower())
    if not names:
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    names.append(value.lower())
    host = host.lower()
    for name in names:
        if name.startswith("*.") and host.endswith(name[1:]):
            return True
        if name == host:
            return True
    return False


def _host_is_ip(host: str) -> bool:
    return ":" in host or host.replace(".", "").isdigit()


def _build_driver(timeout: int, headless: bool):
    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--lang=ru-RU")
    options.add_argument("--hide-scrollbars")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    driver = webdriver.Chrome(options=options, service=Service())
    driver.set_page_load_timeout(timeout)
    return driver


def _collect_external_hosts(driver, page_host: str) -> list[str]:
    hosts = driver.execute_script(
        """
        const out = new Set();
        const origin = location.hostname;
        document.querySelectorAll('[src],[href],[action]').forEach(el => {
            const raw = el.src || el.href || el.action;
            if (!raw || typeof raw !== 'string') return;
            try {
                const u = new URL(raw, location.href);
                if (u.protocol === 'http:' || u.protocol === 'https:') out.add(u.hostname);
            } catch (e) {}
        });
        return Array.from(out);
        """
    ) or []
    return sorted({h.lstrip("www.") for h in hosts if h.lstrip("www.") != page_host})


def _fetch_features(url: str, timeout: int, headless: bool) -> PageFeatures:
    if not SELENIUM_AVAILABLE:
        raise NotImplementedError(NOT_IMPLEMENTED)

    driver = _build_driver(timeout, headless)
    try:
        driver.get(url)
        try:
            WebDriverWait(driver, min(timeout, 10)).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except Exception:
            pass

        features = PageFeatures(
            title=(driver.title or "").strip(),
            final_url=driver.current_url or url,
            html_size=len(driver.page_source or ""),
        )

        page_host = _host_of(features.final_url)
        features.page_text = _visible_text(driver)

        features.forms = _collect_forms(driver, features.final_url, page_host)
        features.iframes = _collect_iframes(driver, features.final_url, page_host)
        features.external_hosts = _collect_external_hosts(driver, page_host)
        features.has_login_form = any(f.has_password_field for f in features.forms)

        haystack = " ".join(
            [features.title, features.page_text]
            + [v for f in features.forms for v in f.visible_fields]
        ).lower()
        features.login_keywords = sorted(
            {k for k in LOGIN_KEYWORDS if k in haystack}
        )
        features.brand_names = _find_brands(haystack, page_host)

        features.cert = _check_cert(page_host)
        return features
    finally:
        driver.quit()


def _visible_text(driver) -> str:
    try:
        text = driver.find_element(By.TAG_NAME, "body").text or ""
    except Exception:
        text = ""
    text = " ".join(text.split())
    return text[:MAX_TEXT_CHARS]


def _collect_forms(driver, final_url: str, page_host: str) -> list[FormInfo]:
    forms: list[FormInfo] = []
    for form in driver.find_elements(By.TAG_NAME, "form"):
        action_raw = form.get_attribute("action") or ""
        action_url = urljoin(final_url, action_raw)
        action_host = urlparse(action_url).hostname or ""
        inputs = form.find_elements(By.CSS_SELECTOR, "input")
        visible, hidden = _visible_fields(inputs)
        forms.append(
            FormInfo(
                action=action_raw or "(нет action)",
                method=(form.get_attribute("method") or "get").lower(),
                host_of_action=action_host or page_host,
                has_password_field=any(
                    (i.get_attribute("type") or "").lower() == "password"
                    for i in inputs
                ),
                visible_fields=visible,
                hidden_fields=hidden,
            )
        )
    return forms


def _collect_iframes(
    driver, final_url: str, page_host: str
) -> list[IframeInfo]:
    frames: list[IframeInfo] = []
    for frame in driver.find_elements(By.TAG_NAME, "iframe"):
        src_raw = frame.get_attribute("src") or ""
        src_url = urljoin(final_url, src_raw)
        size = frame.size or {}
        frames.append(
            IframeInfo(
                src=src_raw,
                host_of_src=urlparse(src_url).hostname or "",
                hidden=(
                    size.get("width", 0) <= 1
                    or size.get("height", 0) <= 1
                    or (frame.get_attribute("style") or "").replace(" ", "")
                    .lower()
                    .find("display:none") >= 0
                ),
            )
        )
    return frames


def _score(url: str, features: PageFeatures) -> PageReport:
    score = 0.0
    reasons: list[str] = []

    page_host = _host_of(url)
    final_host = _host_of(features.final_url or url) or page_host

    if page_host and final_host and page_host.lstrip("www.") != final_host.lstrip("www."):
        score += RULES["redirect_host_changed"]
        reasons.append(
            f"переадресация на другой хост: {page_host} → {final_host}"
        )

    for form in features.forms:
        action_host = (form.host_of_action or "").lstrip("www.")
        if action_host and action_host != final_host.lstrip("www."):
            if form.has_password_field:
                score += RULES["password_form_external"]
                reasons.append(
                    f"форма с паролем отправляет данные на сторонний хост "
                    f"{form.host_of_action}"
                )
            else:
                score += RULES["form_action_external"]
                reasons.append(
                    f"форма отправляет данные на сторонний хост "
                    f"{form.host_of_action}"
                )

    for frame in features.iframes:
        frame_host = (frame.host_of_src or "").lstrip("www.")
        if frame.hidden and frame_host and frame_host != final_host.lstrip("www."):
            score += RULES["hidden_external_iframe"]
            reasons.append(f"скрытый iframe с внешним источником {frame.host_of_src}")

    cert = features.cert
    if cert.hostname_mismatch:
        score += RULES["cert_hostname_mismatch"]
        reasons.append("имя в сертификате не совпадает с доменом страницы")
    if cert.self_signed:
        score += RULES["cert_self_signed"]
        reasons.append("сертификат самоподписанный")
    if cert.expired:
        score += RULES["cert_expired"]
        reasons.append("срок действия сертификата истёк")
    if cert.untrusted:
        score += RULES["cert_untrusted"]
        reasons.append("сертификат выдан неизвестным центром сертификации")
    if cert.days_left is not None and 0 <= cert.days_left < 15:
        score += RULES["cert_expires_soon"]
        reasons.append(f"сертификат истекает через {cert.days_left} дн.")

    if features.brand_names:
        domain = registrable_domain(final_host) if final_host else ""
        if domain and not any(b in domain for b in features.brand_names):
            score += RULES["brand_not_owner_of_domain"]
            shown = ", ".join(features.brand_names)
            reasons.append(
                f"страница говорит о «{shown}», но домен {domain} "
                f"бренду не принадлежит"
            )

    if not reasons:
        reasons.append("существенных признаков в содержимом страницы не найдено")

    return PageReport(
        url=url,
        features=features,
        score=min(100.0, score),
        reasons=reasons,
        implemented=True,
    )


def analyze_page(
    url: str, timeout: int = 25, headless: bool = True
) -> PageReport:
    """Открывает страницу в headless-браузере и возвращает разбор."""
    features = _fetch_features(url, timeout, headless)
    return _score(url, features)


def stub_report(url: str) -> PageReport:
    return PageReport(
        url=url,
        features=PageFeatures(final_url=url),
        score=0.0,
        reasons=[],
        implemented=False,
        error=NOT_IMPLEMENTED,
    )
