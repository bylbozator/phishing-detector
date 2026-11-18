"""Сравнение шаблонной и LLM-суммаризации отчёта (неделя 4).

Запуск: python scripts/compare_summary.py <url> [--model ...] [--repeats 3]

Две версии вердикта из одного и того же отчёта:
- шаблон: synthesizer.render(report) — детерминированный, мгновенный;
- LLM: synthesizer.render_with_llm(report, generate) — генерация через
  локальную Ollama, замеряем время и повторяемость при нескольких запусках.

Повторяемость меряем количеством совпадающих пар запусков (exact match):
шаблон должен совпадать всегда, LLM — показывает разброс.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from phishguard import llm_judge, pipeline, synthesizer  # noqa: E402
from phishguard.models import Report  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if _stream is not None and _stream.encoding and _stream.encoding.lower() != "utf-8":
        _stream.reconfigure(encoding="utf-8", errors="replace")

# Сжатое описание отчёта для модели: баллы этапов, вердикты и причины.
_REPORT_PROMPT = (
    "Ты — аналитик безопасности. Ниже отчёт детектора фишинга в JSON.\n"
    "Напиши короткое резюме для пользователя (3-5 предложений): итоговый риск,\n"
    "главные причины и что делать. Не выдумывай факты, которых нет в отчёте.\n"
    "Ответ — только текст резюме, без заголовков и списков.\n\n"
    "Отчёт: {payload}"
)


def _report_payload(report: Report) -> str:
    """Компактное представление отчёта для промпта."""
    return json.dumps(
        {
            "url": report.url,
            "final_score": round(report.final_score, 1),
            "risk": report.risk,
            "recommendation": report.recommendation,
            "reasons": report.reasons,
        },
        ensure_ascii=False,
    )


def make_llm_generate(model: str):
    """Генератор для render_with_llm: Report -> строка-резюме через Ollama."""
    import ollama

    client = ollama.Client(host=llm_judge.OLLAMA_HOST, timeout=llm_judge.REQUEST_TIMEOUT)

    def generate(report: Report) -> str:
        response = client.chat(
            model=model,
            messages=[{"role": "user", "content": _REPORT_PROMPT.format(payload=_report_payload(report))}],
            options={"temperature": 0, "seed": 0},
            keep_alive=llm_judge.KEEP_ALIVE,
        )
        message = response["message"]
        return message["content"] if isinstance(message, dict) else message.content

    return generate


def _timed(fn) -> tuple[str, float]:
    started = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - started


def _match_rate(outputs: list[str]) -> float:
    """Доля пар запусков с полностью одинаковым текстом."""
    pairs = 0
    matches = 0
    for i in range(len(outputs)):
        for j in range(i + 1, len(outputs)):
            pairs += 1
            if outputs[i] == outputs[j]:
                matches += 1
    return matches / pairs if pairs else 1.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Сравнение шаблонной и LLM-суммаризации.")
    parser.add_argument("url", help="проверяемый адрес")
    parser.add_argument("--model", default=llm_judge.DEFAULT_MODEL, help="локальная модель Ollama")
    parser.add_argument("--repeats", type=int, default=3, help="сколько раз генерировать LLM-версию")
    parser.add_argument("--no-llm", action="store_true", help="только шаблонная версия")
    args = parser.parse_args()

    # Один и тот же отчёт кормим обеим версиям: отличается только способ
    # превращения отчёта в текст для пользователя.
    report = pipeline.run(args.url, pipeline.PipelineConfig(use_llm=False))

    template_text, template_sec = _timed(lambda: synthesizer.render(report))
    print(f"шаблон:    {template_sec * 1000:8.1f} мс, {len(template_text)} симв.")

    if not args.no_llm:
        generate = make_llm_generate(args.model)
        outputs: list[str] = []
        times: list[float] = []
        for index in range(args.repeats):
            try:
                text, sec = _timed(lambda: synthesizer.render_with_llm(report, generate))
            except Exception as exc:  # noqa: BLE001 - сравнение не должно падать
                print(f"LLM #{index + 1}: ошибка {type(exc).__name__}: {exc}")
                return 1
            outputs.append(text)
            times.append(sec)
            print(f"LLM #{index + 1}:     {sec * 1000:8.1f} мс, {len(text)} симв.")

        avg = sum(times) / len(times)
        print(f"LLM в среднем: {avg * 1000:.1f} мс (в {avg / template_sec:.0f} раз медленнее шаблона)")
        print(f"повторяемость: шаблон 1.00, LLM {_match_rate(outputs):.2f}")
        print("\n--- шаблонный вердикт ---\n" + template_text)
        print("\n--- LLM-версия (последний запуск) ---\n" + outputs[-1])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
