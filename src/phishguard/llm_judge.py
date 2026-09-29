"""Этап 3. Оценка страницы локальной LLM.

Исполнитель: модуль №3.

Что нужно сделать:
  1. Поднять локальную модель через Ollama (например qwen2.5:7b-instruct)
     и держать её в памяти, а не перезапускать на каждый URL.
  2. Собрать компактное описание страницы:
     features.to_prompt_dict() из phishguard.models. Сырой HTML в модель
     не отправляем, на реальных страницах он достигает сотен килобайт
     и модель выдаёт бессвязный ответ.
  3. Отправить промпт и разобрать ответ в LlmReport: score (0..100),
     verdict (phishing / suspicious / benign), reasons.
  4. Ответ модели должен быть строго в JSON, чтобы разбор не ломался.
     На случай невалидного JSON предусмотри запасной вариант: если разбор
     не удался, не роняй пайплайн, а верни error и implemented=True,
     тогда этап просто не добавит баллов.

Промпт лежит в docs/prompt.md, его нужно доработать — это прямая просьба
преподавателя. Правила хорошего промпта:
  - роль и задача одной фразой,
  - чёткие критерии оценки, а не «насколько это похоже на фишинг»,
  - формат ответа: только JSON без пояснений,
  - 2-3 примера в сообщении пользователя (few-shot),
  - запрет на додумывание: если данных мало, проси ответить «мало данных»,
    а не выдумывать признаки.

Пока модуль не дописан, judge возвращает заглушку.
"""

from __future__ import annotations

from .models import LlmReport, PageFeatures, UrlReport

NOT_IMPLEMENTED = "Модуль №3 в разработке"
DEFAULT_MODEL = "qwen2.5:7b-instruct"


def judge(
    url_report: UrlReport,
    features: PageFeatures,
    model: str = DEFAULT_MODEL,
) -> LlmReport:
    """Спрашивает у локальной LLM, является ли страница фишингом."""
    raise NotImplementedError(NOT_IMPLEMENTED)


def stub_report(url: str, model: str = DEFAULT_MODEL) -> LlmReport:
    return LlmReport(
        url=url,
        model=model,
        score=0.0,
        verdict="unknown",
        reasons=[],
        implemented=False,
        error=NOT_IMPLEMENTED,
    )
