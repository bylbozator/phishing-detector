"""Проверки контракта и сквозного прохода пайплайна.

Запуск: python -m pytest tests -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from phishguard import pipeline, synthesizer, url_checker  # noqa: E402
from phishguard.models import PageFeatures, risk_level  # noqa: E402


@pytest.mark.parametrize(
    ("url", "expected_flag"),
    [
        ("http://192.168.1.1/login", "has_ip_host"),
        ("http://bit.ly/abc123", "is_shortener"),
        ("http://xn--80ak6aa92e.com/", "has_punycode"),
    ],
)
def test_url_flags(url, expected_flag):
    report = url_checker.check_url(url)
    assert getattr(report, expected_flag) is True, f"{url}: не сработал {expected_flag}"
    assert report.score > 0


@pytest.mark.parametrize(
    "url",
    [
        "https://www.python.org/",
        "https://github.com/anthropics",
        "https://www.google.com/search?q=python",
    ],
)
def test_clean_urls_score_zero(url):
    report = url_checker.check_url(url)
    assert report.score == 0.0, f"{url} не должен набирать баллы: {report.reasons}"


def test_brand_in_subdomain_is_flagged():
    report = url_checker.check_url("https://sberbank.secure-login.ru/verify")
    assert report.score > 0
    assert any("sberbank" in r or "бренд" in r for r in report.reasons)


def test_clean_url_has_no_reasons():
    report = url_checker.check_url("https://www.python.org/")
    assert report.reasons == []
    assert report.normalized_url == "https://www.python.org/"


def test_ip_url_is_not_prefixed_with_www():
    report = url_checker.check_url("192.168.1.1/login")
    assert report.normalized_url.startswith("http://192.168.1.1")
    assert "www" not in report.normalized_url


def test_score_is_capped_at_100():
    report = url_checker.check_url("http://xn--sberbank-80ak6aa92e.a.bit.ly/login?a=1&b=2")
    assert 0.0 <= report.score <= 100.0


@pytest.mark.parametrize(
    ("score", "level"),
    [(0, "low"), (25, "medium"), (50, "high"), (90, "critical")],
)
def test_risk_levels(score, level):
    assert risk_level(score) == level


def test_page_features_prompt_dict_is_json_serializable():
    features = PageFeatures(final_url="https://example.com", title="Login")
    payload = features.to_prompt_dict()
    assert json.loads(json.dumps(payload, ensure_ascii=False))["title"] == "Login"


def offline_config() -> pipeline.PipelineConfig:
    """Этапы 2 и 3 не запускаются: тесты идут без браузера и без сети."""
    return pipeline.PipelineConfig(use_page_analyzer=False, use_llm=False)


def test_pipeline_runs_offline():
    report = pipeline.run("http://bit.ly/sberbank-login", offline_config())
    assert report.final_score > 0
    assert report.risk in ("medium", "high", "critical")
    stages = {s.stage: s for s in report.stages}
    assert stages["url"].implemented is True
    assert stages["summary"].implemented is True
    assert "page" not in stages


def test_pipeline_survives_unimplemented_module(monkeypatch):
    monkeypatch.setattr(
        pipeline.page_analyzer,
        "analyze_page",
        lambda url: (_ for _ in ()).throw(NotImplementedError("в разработке")),
    )
    report = pipeline.run(
        "https://www.python.org/", pipeline.PipelineConfig(use_llm=False)
    )
    stages = {s.stage: s for s in report.stages}
    assert stages["page"].implemented is False
    assert "в разработке" in stages["page"].error
    assert report.final_score >= 0.0


def test_pipeline_survives_broken_module(monkeypatch):
    def boom(url):
        raise RuntimeError("браузер не запустился")

    monkeypatch.setattr(pipeline.page_analyzer, "analyze_page", boom)
    report = pipeline.run(
        "https://www.python.org/", pipeline.PipelineConfig(use_llm=False)
    )
    stages = {s.stage: s for s in report.stages}
    assert stages["page"].error and "браузер не запустился" in stages["page"].error
    assert report.final_score >= 0.0


def test_pipeline_survives_bad_input():
    report = pipeline.run("", offline_config())
    assert report.final_score >= 0.0


def test_report_is_json_serializable():
    report = pipeline.run("https://www.python.org/", offline_config())
    json.dumps(report.to_dict(), ensure_ascii=False)


def test_render_outputs_verdict():
    report = pipeline.run("http://bit.ly/sberbank-login", offline_config())
    text = synthesizer.render(report)
    assert "Итоговый риск" in text
    assert "Рекомендация" in text
    assert "[URL]" in text
