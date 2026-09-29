"""Этап 4. Суммаризация вывода.

Исполнитель: модуль №4.

Сейчас реализована шаблонная версия: баллы этапов взвешиваются и
превращаются в короткий вердикт. Открытый вопрос преподавателю —
делать ли суммаризацию шаблоном или генерировать через LLM, поэтому
вторая версия оставлена точкой расширения: см. render_with_llm.

Веса подобраны так, чтобы алгоритмические признаки (этап 2) и мнение
модели (этап 3) не могли друг друга перебить, а быстрый фильтр URL
поднимал итог, но не определял его.
"""

from __future__ import annotations

from .models import (
    RECOMMENDATIONS,
    LlmReport,
    PageReport,
    Report,
    STAGE_SUMMARY,
    StageResult,
    UrlReport,
    risk_level,
)

WEIGHTS = {"url": 0.25, "page": 0.40, "llm": 0.35}


def combine(
    url_report: UrlReport,
    page_report: PageReport | None,
    llm_report: LlmReport | None,
) -> float:
    """Итоговый балл 0..100. Незапущенные этапы в сумму не входят,
    их вес перераспределяется между работающими."""
    parts: list[tuple[float, float]] = []
    if url_report is not None:
        parts.append((url_report.score, WEIGHTS["url"]))
    if page_report is not None and page_report.implemented:
        parts.append((page_report.score, WEIGHTS["page"]))
    if llm_report is not None and llm_report.implemented and llm_report.error is None:
        parts.append((llm_report.score, WEIGHTS["llm"]))
    if not parts:
        return 0.0
    total_weight = sum(w for _, w in parts)
    return min(100.0, sum(score * w for score, w in parts) / total_weight)


def collect_reasons(
    url_report: UrlReport,
    page_report: PageReport | None,
    llm_report: LlmReport | None,
) -> list[str]:
    reasons: list[str] = []
    reasons += [f"[URL] {r}" for r in url_report.reasons]
    if page_report is not None and page_report.implemented:
        reasons += [f"[структура] {r}" for r in page_report.reasons]
    if llm_report is not None and llm_report.implemented and llm_report.error is None:
        reasons += [f"[LLM] {r}" for r in llm_report.reasons]
    if not reasons:
        reasons.append("существенных признаков фишинга не найдено")
    return reasons


def render(report: Report) -> str:
    """Человекочитаемый вердикт для терминала."""
    lines = [
        "",
        "=" * 68,
        f"  {report.url}",
        "=" * 68,
    ]
    for stage in report.stages:
        if stage.error:
            state = f"пропущен ({stage.error})"
        elif not stage.implemented:
            state = "пропущен (не реализован)"
        else:
            state = f"{stage.score:5.1f}"
        lines.append(f"  {stage.stage:<8} {state}")

    lines.append("-" * 68)
    lines.append(f"  Итоговый риск: {report.final_score:.0f}/100  [{report.risk}]")
    lines.append(f"  Рекомендация:   {report.recommendation}")
    lines.append("-" * 68)
    lines.append("  Почему:")
    for reason in report.reasons:
        lines.append(f"    - {reason}")
    lines.append("=" * 68)
    return "\n".join(lines)


def render_with_llm(report: Report, generate) -> str:
    """Заглушка под LLM-суммаризацию.

    Аргумент generate — вызов локальной модели: на вход Report,
    на выходе строка с предупреждением для пользователя.
    Пока используется шаблонный render, LLM-версию можно не трогать.
    """
    return generate(report)


def summarize(
    url_report: UrlReport,
    page_report: PageReport | None = None,
    llm_report: LlmReport | None = None,
    extra_stages: list[StageResult] | None = None,
) -> Report:
    score = combine(url_report, page_report, llm_report)
    level = risk_level(score)
    report = Report(
        url=url_report.normalized_url or url_report.original_url,
        final_score=score,
        risk=level,
        recommendation=RECOMMENDATIONS[level],
        reasons=collect_reasons(url_report, page_report, llm_report),
        url_report=url_report,
        page_report=page_report,
        llm_report=llm_report,
    )
    report.stages = list(extra_stages or [])
    report.stages.append(StageResult(stage=STAGE_SUMMARY, score=score, details={"risk": level}))
    return report
