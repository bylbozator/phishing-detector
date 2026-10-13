"""Этап 3. Оценка страницы локальной LLM.

Исполнитель: модуль №3.

Модуль отправляет в локальную модель (Ollama) не сырой HTML, а компактное
описание страницы из ``PageFeatures.to_prompt_dict()``: URL, заголовок,
формы, iframe, внешние хосты, слова входа/оплаты, бренды и сведения о
сертификате. Сырой HTML не отправляем: на реальных страницах он достигает
сотен килобайт, и модель на нём деградирует.

Модель держится в памяти между вызовами (``keep_alive``), отвечает строго
JSON (``format="json"``, ``temperature=0``). Любая ошибка — невалидный JSON,
недоступная Ollama, недопустимый verdict — не роняет пайплайн: метод
возвращает ``LlmReport`` с заполненным ``error`` и ``implemented=True``,
тогда этап просто не добавляет баллов (см. ``synthesizer.combine``).

Внешние API не используются: подозрительный HTML не покидает машину.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .models import LlmReport, PageFeatures, UrlReport

DEFAULT_MODEL = "qwen2.5:7b-instruct"

# Модель остаётся загруженной между запросами, а не читается с диска заново.
KEEP_ALIVE = "10m"
OLLAMA_HOST = "http://127.0.0.1:11434"
REQUEST_TIMEOUT = 120.0

VERDICTS = ("phishing", "suspicious", "benign", "insufficient_data")
MAX_REASONS = 8

# Заглушка нужна пайплайну на случай, если этап ещё не подключён.
NOT_IMPLEMENTED = "Модуль №3 в разработке"

SYSTEM_PROMPT = (
    "Ты — аналитик безопасности. По признакам веб-страницы, собранным при\n"
    "разборе DOM, определи, является ли страница фишинговой.\n"
    "\n"
    "Признаки сильного риска:\n"
    "- форма пароля отправляет данные на домен, отличный от домена страницы;\n"
    "- скрытый iframe с внешним источником;\n"
    "- домен имитирует известный бренд, но сам им не является;\n"
    "- страница просит пароль, данные карты или код из СМС, хотя выглядит\n"
    "  как обычный информационный сайт.\n"
    "\n"
    "Признак умеренного риска:\n"
    "- просроченный или самоподписанный сертификат, расхождение имени\n"
    "  сертификата с доменом.\n"
    "\n"
    "Слабый признак (сам по себе фишинг не доказывает):\n"
    "- ошибки, смешение языков, срочные требования ввести данные.\n"
    "\n"
    "Правила:\n"
    "1. Опирайся только на переданные признаки. Ничего не додумывай.\n"
    "2. Если данных мало (нет форм, нет признаков входа или оплаты), верни\n"
    '   verdict "insufficient_data" и score 0.\n'
    "3. score должен соответствовать verdict: benign 0-20, suspicious 21-60,\n"
    "   phishing 61-100.\n"
    "4. Ответ — строго один JSON-объект, без пояснений и без markdown.\n"
    "\n"
    "Схема ответа:\n"
    '{"verdict": "phishing | suspicious | benign | insufficient_data", '
    '"score": 0, "reasons": ["кратко, по-русски"]}'
)

# Few-shot примеры: (признаки страницы, ожидаемый ответ модели).
_EXAMPLES: list[tuple[dict[str, Any], dict[str, Any]]] = [
    (
        {
            "url": "https://www.sberbank.ru/login",
            "title": "СберБанк — вход",
            "forms": [
                {
                    "action": "https://www.sberbank.ru/auth",
                    "method": "POST",
                    "action_host": "www.sberbank.ru",
                    "password_field": True,
                    "visible_fields": ["login", "password"],
                }
            ],
            "iframes": [],
            "external_hosts": [],
            "login_keywords": ["вход"],
            "brand_names": ["sberbank"],
            "has_login_form": True,
            "certificate": {"hostname_mismatch": False, "days_left": 200},
        },
        {
            "verdict": "benign",
            "score": 5,
            "reasons": ["домен официальный, форма отправляет данные на тот же домен"],
        },
    ),
    (
        {
            "url": "https://sberbank.secure-login.ru/verify",
            "title": "Вход в СберБанк",
            "forms": [
                {
                    "action": "https://collector.example.net/post",
                    "method": "POST",
                    "action_host": "collector.example.net",
                    "password_field": True,
                    "visible_fields": ["phone", "password"],
                }
            ],
            "iframes": [
                {
                    "src": "https://collector.example.net/f",
                    "host": "collector.example.net",
                    "hidden": True,
                }
            ],
            "external_hosts": ["collector.example.net"],
            "login_keywords": ["вход", "пароль"],
            "brand_names": ["sberbank"],
            "has_login_form": True,
            "certificate": {"hostname_mismatch": True, "days_left": -3},
        },
        {
            "verdict": "phishing",
            "score": 95,
            "reasons": [
                "домен имитирует СберБанк, но не является им",
                "форма пароля отправляется на сторонний домен",
                "скрытый iframe на внешний домен",
                "сертификат просрочен",
            ],
        },
    ),
    (
        {
            "url": "https://example.com/blog/post",
            "title": "Новости",
            "forms": [],
            "iframes": [],
            "external_hosts": [],
            "login_keywords": [],
            "brand_names": [],
            "has_login_form": False,
            "certificate": {"hostname_mismatch": False, "days_left": 120},
        },
        {
            "verdict": "insufficient_data",
            "score": 0,
            "reasons": ["нет форм, признаков входа и оплаты — оценивать нечего"],
        },
    ),
]

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _build_payload(url_report: UrlReport, features: PageFeatures) -> dict[str, Any]:
    """Компактное описание страницы для модели."""
    payload = features.to_prompt_dict()
    if not payload.get("url"):
        payload["url"] = url_report.normalized_url or url_report.original_url
    return payload


def _build_messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Системная инструкция + few-shot примеры + признаки страницы."""
    blocks = []
    for index, (example_features, example_answer) in enumerate(_EXAMPLES, start=1):
        blocks.append(
            f"Пример {index}:\n"
            f"Признаки: {json.dumps(example_features, ensure_ascii=False)}\n"
            f"Ответ: {json.dumps(example_answer, ensure_ascii=False)}"
        )
    user = (
        "Примеры:\n\n"
        + "\n\n".join(blocks)
        + "\n\nТеперь оцени эту страницу.\n\n"
        + f"Признаки: {json.dumps(payload, ensure_ascii=False)}\n\n"
        + "Ответь только JSON."
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def _ask_ollama(payload: dict[str, Any], model: str) -> str:
    """Отправляет промпт в локальную Ollama и возвращает текст ответа."""
    try:
        import ollama
    except ImportError as exc:  # пакет есть в requirements.lock.txt
        raise RuntimeError(
            "пакет ollama не установлен: pip install -r requirements.lock.txt"
        ) from exc

    client = ollama.Client(host=OLLAMA_HOST, timeout=REQUEST_TIMEOUT)
    try:
        response = client.chat(
            model=model,
            messages=_build_messages(payload),
            format="json",
            options={"temperature": 0, "seed": 0},
            keep_alive=KEEP_ALIVE,
        )
    except Exception as exc:  # noqa: BLE001 - сообщаем понятную причину
        raise RuntimeError(
            f"Ollama недоступна или модель «{model}» не загружена "
            f"({type(exc).__name__}: {exc}). "
            f"Проверьте: ollama serve и ollama pull {model}"
        ) from exc

    message = response["message"]
    return message["content"] if isinstance(message, dict) else message.content


def _extract_json(text: str) -> Any:
    """Достаёт JSON из ответа, даже если модель обернула его в markdown."""
    text = (text or "").strip()
    match = _FENCE.search(text)
    if match:
        text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise ValueError("ответ модели не является JSON") from None


def _to_score(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("score должен быть числом")
    try:
        score = float(value)
    except (TypeError, ValueError):
        raise ValueError("score должен быть числом") from None
    return max(0.0, min(100.0, score))


def _to_reasons(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("reasons должен быть списком строк")
    reasons = [str(item).strip() for item in value if str(item).strip()]
    return reasons[:MAX_REASONS]


def _parse_response(content: str) -> tuple[str, float, list[str]]:
    data = _extract_json(content)
    if not isinstance(data, dict):
        raise ValueError("ответ модели не является JSON-объектом")

    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict not in VERDICTS:
        raise ValueError(f"недопустимый verdict: {verdict!r}")

    return verdict, _to_score(data.get("score")), _to_reasons(data.get("reasons"))


def _report(
    url_report: UrlReport,
    model: str,
    *,
    verdict: str = "unknown",
    score: float = 0.0,
    reasons: list[str] | None = None,
    raw_response: str = "",
    error: str | None = None,
) -> LlmReport:
    return LlmReport(
        url=url_report.normalized_url or url_report.original_url,
        model=model,
        score=score,
        verdict=verdict,
        reasons=reasons or [],
        raw_response=raw_response,
        implemented=True,
        error=error,
    )


def judge(
    url_report: UrlReport,
    features: PageFeatures,
    model: str = DEFAULT_MODEL,
) -> LlmReport:
    """Спрашивает у локальной LLM, является ли страница фишингом.

    Никогда не бросает исключение: при любой ошибке возвращает LlmReport
    с заполненным error, и этап не добавляет баллов к итоговому риску.
    """
    payload = _build_payload(url_report, features)

    try:
        content = _ask_ollama(payload, model)
    except Exception as exc:  # noqa: BLE001 - падение этапа не роняет пайплайн
        return _report(url_report, model, error=f"{type(exc).__name__}: {exc}")

    try:
        verdict, score, reasons = _parse_response(content)
    except ValueError as exc:
        return _report(url_report, model, raw_response=content, error=str(exc))

    if verdict == "insufficient_data":
        # Модель прямо сказала, что данных мало: это не сигнал риска,
        # поэтому этап исключается из итогового балла (synthesizer смотрит
        # на error), но вердикт сохраняем для отчёта.
        return _report(
            url_report,
            model,
            verdict=verdict,
            score=0.0,
            reasons=reasons,
            raw_response=content,
            error="недостаточно данных для оценки",
        )

    return _report(
        url_report,
        model,
        verdict=verdict,
        score=score,
        reasons=reasons,
        raw_response=content,
    )


def stub_report(url: str, model: str = DEFAULT_MODEL) -> LlmReport:
    """Заглушка на случай, если этап ещё не подключён в пайплайне."""
    return LlmReport(
        url=url,
        model=model,
        score=0.0,
        verdict="unknown",
        reasons=[],
        implemented=False,
        error=NOT_IMPLEMENTED,
    )
