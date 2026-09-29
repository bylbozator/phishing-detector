"""Контракт данных между этапами детектора.

Этот файл — единственная точка соглашения всей группы. Менять его можно
только согласованно со всеми четырьмя исполнителями: остальные модули
импортируют отсюда типы и рассчитывают на их поля.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

STAGE_URL = "url"
STAGE_PAGE = "page"
STAGE_LLM = "llm"
STAGE_SUMMARY = "summary"


@dataclass
class StageResult:
    """Результат одного этапа конвейера.

    score        вклад этапа в общий риск, 0..100
    reasons      человекочитаемые причины, попадут в финальный вердикт
    details      служебные поля для отладки и отчёта
    implemented  False, если этап ещё не написан (заглушка)
    """

    stage: str
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    implemented: bool = True
    error: str | None = None


@dataclass
class UrlReport:
    """Выход этапа 1. Вход для этапов 2 и 4."""

    original_url: str
    normalized_url: str
    registrable_domain: str
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    has_ip_host: bool = False
    is_shortener: bool = False
    has_punycode: bool = False
    has_suspicious_chars: bool = False
    subdomain_depth: int = 0


@dataclass
class FormInfo:
    action: str
    method: str
    host_of_action: str | None
    has_password_field: bool
    visible_fields: list[str] = field(default_factory=list)
    hidden_fields: list[str] = field(default_factory=list)


@dataclass
class IframeInfo:
    src: str
    host_of_src: str | None
    hidden: bool


@dataclass
class CertInfo:
    subject: str | None = None
    issuer: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    days_left: int | None = None
    hostname_mismatch: bool = False
    self_signed: bool = False


@dataclass
class PageFeatures:
    """Компактные признаки страницы.

    Именно этот объект уходит в LLM. Сырой HTML в модель не отправляем:
    страница бывает сотни килобайт и модель на ней деградирует.
    """

    title: str = ""
    final_url: str = ""
    page_text: str = ""
    forms: list[FormInfo] = field(default_factory=list)
    iframes: list[IframeInfo] = field(default_factory=list)
    external_hosts: list[str] = field(default_factory=list)
    login_keywords: list[str] = field(default_factory=list)
    brand_names: list[str] = field(default_factory=list)
    has_login_form: bool = False
    html_size: int = 0
    cert: CertInfo = field(default_factory=CertInfo)

    def to_prompt_dict(self) -> dict[str, Any]:
        """Урезанное представление для промпта."""
        return {
            "url": self.final_url,
            "title": self.title,
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "action_host": f.host_of_action,
                    "password_field": f.has_password_field,
                    "visible_fields": f.visible_fields,
                }
                for f in self.forms
            ],
            "iframes": [
                {"src": i.src, "host": i.host_of_src, "hidden": i.hidden}
                for i in self.iframes
            ],
            "external_hosts": self.external_hosts,
            "login_keywords": self.login_keywords,
            "brand_names": self.brand_names,
            "has_login_form": self.has_login_form,
            "certificate": asdict(self.cert),
        }


@dataclass
class PageReport:
    """Выход этапа 2. Вход для этапов 3 и 4."""

    url: str
    features: PageFeatures = field(default_factory=PageFeatures)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    implemented: bool = True
    error: str | None = None


@dataclass
class LlmReport:
    """Выход этапа 3. Вход для этапа 4."""

    url: str
    model: str = ""
    score: float = 0.0
    verdict: str = "unknown"
    reasons: list[str] = field(default_factory=list)
    raw_response: str = ""
    implemented: bool = True
    error: str | None = None


@dataclass
class Report:
    """Итоговый вердикт, то, что видит пользователь в терминале."""

    url: str
    final_score: float
    risk: str
    recommendation: str
    reasons: list[str] = field(default_factory=list)
    url_report: UrlReport | None = None
    page_report: PageReport | None = None
    llm_report: LlmReport | None = None
    stages: list[StageResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def risk_level(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


RECOMMENDATIONS = {
    "low": "Признаков фишинга не обнаружено. Можно работать с сайтом.",
    "medium": "Есть сомнительные признаки. Проверьте домен и не вводите данные.",
    "high": "Высокий риск. Не вводите логин и пароль, не проходите оплату.",
    "critical": "Похоже на фишинг. Не вводите учётные данные, закройте страницу.",
}
