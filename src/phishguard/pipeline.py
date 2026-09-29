"""Сборка четырёх этапов в единый конвейер.

Пайплайн специально сделан устойчивым к незавершённым модулям: если этап
не дописан или упал, он помечается в отчёте и не обрушает весь запуск.
Так сквозной прототип работает уже сейчас, а модули добавляются по одному.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from . import llm_judge, page_analyzer, synthesizer, url_checker
from .models import Report, StageResult


@dataclass
class PipelineConfig:
    use_page_analyzer: bool = True
    use_llm: bool = True
    llm_model: str = llm_judge.DEFAULT_MODEL
    timeout: int = 30


def _safe(stage: str, fn: Callable[[], StageResult], error: str) -> StageResult:
    try:
        return fn()
    except NotImplementedError:
        return StageResult(stage=stage, implemented=False, error=error)
    except Exception as exc:  # noqa: BLE001 - падение одного этапа не роняет всё
        return StageResult(
            stage=stage,
            implemented=True,
            error=f"{type(exc).__name__}: {exc}",
        )


def run(url: str, config: PipelineConfig | None = None) -> Report:
    config = config or PipelineConfig()
    started = time.perf_counter()
    stages: list[StageResult] = []

    url_report = url_checker.check_url(url)
    stages.append(url_checker.stage_result(url_report))

    page_report = None
    if config.use_page_analyzer:
        try:
            page_report = page_analyzer.analyze_page(url_report.normalized_url)
        except NotImplementedError:
            page_report = page_analyzer.stub_report(url_report.normalized_url)
            stages.append(StageResult(stage="page", implemented=False, error=page_report.error))
        except Exception as exc:  # noqa: BLE001
            page_report = page_analyzer.stub_report(url_report.normalized_url)
            page_report.error = f"{type(exc).__name__}: {exc}"
            stages.append(StageResult(stage="page", implemented=True, error=page_report.error))
        else:
            page_report.implemented = True
            stages.append(
                StageResult(
                    stage="page",
                    score=page_report.score,
                    reasons=page_report.reasons,
                )
            )

    llm_report = None
    if config.use_llm and page_report is not None:
        try:
            llm_report = llm_judge.judge(url_report, page_report.features, config.llm_model)
        except NotImplementedError:
            llm_report = llm_judge.stub_report(url_report.normalized_url, config.llm_model)
            stages.append(StageResult(stage="llm", implemented=False, error=llm_report.error))
        except Exception as exc:  # noqa: BLE001
            llm_report = llm_judge.stub_report(url_report.normalized_url, config.llm_model)
            llm_report.error = f"{type(exc).__name__}: {exc}"
            stages.append(StageResult(stage="llm", implemented=True, error=llm_report.error))
        else:
            stages.append(
                StageResult(
                    stage="llm",
                    score=llm_report.score,
                    reasons=llm_report.reasons,
                    details={"model": llm_report.model, "verdict": llm_report.verdict},
                )
            )
    elif config.use_llm:
        stages.append(StageResult(stage="llm", implemented=False, error="нет данных от этапа 2"))

    report = synthesizer.summarize(
        url_report,
        page_report=page_report,
        llm_report=llm_report,
        extra_stages=stages,
    )
    report.url_report = url_report
    report.stages[0].details["elapsed_sec"] = round(time.perf_counter() - started, 2)
    return report
