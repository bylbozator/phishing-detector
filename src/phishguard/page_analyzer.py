"""Этап 2. Алгоритмический анализ структуры страницы.

Исполнитель: модуль №2.

Что нужно сделать:
  1. Поднять headless-браузер (Selenium или Playwright — на ваш выбор,
     но выбор зафиксируйте в README, чтобы остальные не разделились).
  2. Загрузить страницу, дождаться отрисовки, снять DOM.
  3. Заполнить PageFeatures из phishguard.models:
     - title, final_url (URL после редиректов), page_text (видимый текст,
       обрезанный примерно до 4000 символов),
     - формы: action, method, хост action, наличие input[type=password],
       имена видимых и скрытых полей,
     - iframe: src, хост, скрыт ли (ширина/высота <= 1 или style display:none),
     - external_hosts: все хосты, отличные от хоста страницы,
     - login_keywords: слова, найденные в тексте (login, вход, авторизация,
       sign in, password, пароль, оплата, подтвердите и т.п.),
     - brand_names: какие бренды из списка url_checker.BRANDS встретились,
     - cert: subject, issuer, срок действия, дни до истечения,
       расхождение имени в сертификате с доменом, self-signed.
  4. Посчитать балл риска по правилам и записать причины в reasons.
     За каждое сработавшее правило обязательно добавляй текст в reasons:
     пользователь в конце должен видеть, что именно смутило.

Примерка с URL-этапом: url — это то, что ввёл пользователь;
final_url — то, куда реально привели редиректы. Если домены разные,
это самостоятельный сильный признак фишинга.

Пока модуль не дописан, analyze_page возвращает заглушку с implemented=False,
и пайплайн продолжает работать.
"""

from __future__ import annotations

from .models import PageFeatures, PageReport

NOT_IMPLEMENTED = "Модуль №2 в разработке"


def analyze_page(url: str, features: PageFeatures | None = None) -> PageReport:
    """Открывает url в headless-браузере и возвращает разбор страницы."""
    raise NotImplementedError(NOT_IMPLEMENTED)


def stub_report(url: str) -> PageReport:
    return PageReport(
        url=url,
        features=PageFeatures(final_url=url),
        score=0.0,
        reasons=[],
        implemented=False,
        error=NOT_IMPLEMENTED,
    )
