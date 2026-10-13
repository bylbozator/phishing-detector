"""Тесты этапа 3: разбор ответа локальной LLM без запущенной Ollama.

Запуск: python -m pytest tests -q

Клиент Ollama подменяется, поэтому тесты не требуют ни сервера, ни модели
и проходят в CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from phishguard import llm_judge  # noqa: E402
from phishguard.models import PageFeatures, UrlReport  # noqa: E402


def make_url_report(url: str = "https://example.com") -> UrlReport:
    return UrlReport(
        original_url=url,
        normalized_url=url,
        registrable_domain="example.com",
    )


def make_features() -> PageFeatures:
    return PageFeatures(final_url="https://example.com/login", title="Вход")


def fake_answer(monkeypatch, content: str) -> None:
    monkeypatch.setattr(llm_judge, "_ask_ollama", lambda payload, model: content)


def test_valid_json_is_parsed(monkeypatch):
    fake_answer(
        monkeypatch,
        '{"verdict": "phishing", "score": 92, '
        '"reasons": ["форма уходит на чужой домен"]}',
    )
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.implemented is True
    assert report.error is None
    assert report.verdict == "phishing"
    assert report.score == 92.0
    assert report.reasons == ["форма уходит на чужой домен"]
    assert report.model == llm_judge.DEFAULT_MODEL
    assert report.raw_response


def test_json_inside_code_fence_is_parsed(monkeypatch):
    fake_answer(
        monkeypatch,
        "```json\n"
        '{"verdict": "benign", "score": 3, "reasons": ["всё чисто"]}\n'
        "```",
    )
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.error is None
    assert report.verdict == "benign"
    assert report.score == 3.0


def test_json_with_surrounding_text_is_parsed(monkeypatch):
    fake_answer(
        monkeypatch,
        'Вот ответ: {"verdict": "suspicious", "score": 40, '
        '"reasons": ["одно поле выглядит подозрительно"]} — готово.',
    )
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.error is None
    assert report.verdict == "suspicious"
    assert report.score == 40.0


def test_invalid_json_sets_error_and_does_not_raise(monkeypatch):
    fake_answer(monkeypatch, "извините, я не могу ответить")
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.implemented is True
    assert report.error is not None
    assert report.score == 0.0


def test_unknown_verdict_is_rejected(monkeypatch):
    fake_answer(
        monkeypatch,
        '{"verdict": "maybe", "score": 50, "reasons": []}',
    )
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.error is not None
    assert "verdict" in report.error


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("150", 100.0), ("-20", 0.0), ("77.5", 77.5)],
)
def test_score_is_clamped(monkeypatch, raw, expected):
    fake_answer(
        monkeypatch,
        f'{{"verdict": "phishing", "score": {raw}, "reasons": []}}',
    )
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.error is None
    assert report.score == expected


def test_insufficient_data_is_excluded_from_scoring(monkeypatch):
    fake_answer(
        monkeypatch,
        '{"verdict": "insufficient_data", "score": 0, '
        '"reasons": ["мало данных"]}',
    )
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.verdict == "insufficient_data"
    assert report.score == 0.0
    # error выставлен намеренно: этап не должен тянуть итог к нулю.
    assert report.error is not None


def test_ollama_failure_returns_error_instead_of_raising(monkeypatch):
    def boom(payload, model):
        raise RuntimeError("Ollama недоступна")

    monkeypatch.setattr(llm_judge, "_ask_ollama", boom)
    report = llm_judge.judge(make_url_report(), make_features())
    assert report.implemented is True
    assert report.error is not None
    assert report.score == 0.0


def test_judge_works_with_empty_features(monkeypatch):
    fake_answer(
        monkeypatch,
        '{"verdict": "insufficient_data", "score": 0, "reasons": []}',
    )
    url_report = make_url_report()
    report = llm_judge.judge(url_report, PageFeatures())
    assert report.url == url_report.normalized_url


def test_messages_contain_examples_and_page_features():
    messages = llm_judge._build_messages({"url": "https://target.test/x"})
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "https://target.test/x" in messages[1]["content"]
    assert messages[1]["content"].count("Ответ:") >= 2


def test_payload_url_falls_back_to_url_report():
    url_report = make_url_report("https://fallback.test/")
    payload = llm_judge._build_payload(url_report, PageFeatures())
    assert payload["url"] == "https://fallback.test/"


def test_report_is_json_serializable(monkeypatch):
    fake_answer(
        monkeypatch,
        '{"verdict": "benign", "score": 1, "reasons": ["ok"]}',
    )
    report = llm_judge.judge(make_url_report(), make_features())
    json.dumps(report.__dict__, ensure_ascii=False)
