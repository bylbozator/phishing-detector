"""Точка входа. Запуск: python main.py <url>"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from phishguard import llm_judge, pipeline, synthesizer  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Детектор фишинговых сайтов по URL и содержимому."
    )
    parser.add_argument("url", help="проверяемый адрес")
    parser.add_argument(
        "--no-page", action="store_true", help="пропустить анализ страницы"
    )
    parser.add_argument("--no-llm", action="store_true", help="пропустить оценку LLM")
    parser.add_argument(
        "--model", default=llm_judge.DEFAULT_MODEL, help="локальная модель Ollama"
    )
    parser.add_argument("--json", action="store_true", help="вывести отчёт в JSON")
    args = parser.parse_args()

    config = pipeline.PipelineConfig(
        use_page_analyzer=not args.no_page,
        use_llm=not args.no_llm,
        llm_model=args.model,
    )
    report = pipeline.run(args.url, config)

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(synthesizer.render(report))

    return 2 if report.risk in ("high", "critical") else 0


if __name__ == "__main__":
    raise SystemExit(main())
