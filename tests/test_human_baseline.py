"""Human-baseline recording — schema round-trip + CLI."""
import io
from pathlib import Path

import yaml  # type: ignore[import-not-found]
import pytest

from reasonchain.human_baseline import HumanBaseline, record_baseline


def test_yaml_round_trip(tmp_path):
    b = HumanBaseline(
        target="juiceshop", expert_id="E01",
        findings_count=15, high_count=2, medium_count=8,
        duration_minutes=120.0,
        tools_used=["burp", "sqlmap", "nmap"],
        notes="auth flow + checkout flow only",
    )
    out = tmp_path / "E01.yaml"
    b.to_yaml(out)
    loaded = HumanBaseline.from_yaml(out)
    assert loaded == b


def test_cli_writes_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "reasonchain.human_baseline.BASELINES_DIR", tmp_path,
    )
    rc = record_baseline([
        "--target", "juiceshop", "--expert-id", "E02",
        "--findings", "12", "--high", "3",
        "--duration-minutes", "90",
        "--tools", "burp,nmap",
        "--notes", "first pass",
    ])
    assert rc == 0
    written = tmp_path / "juiceshop" / "E02.yaml"
    assert written.exists()
    data = yaml.safe_load(written.read_text())
    assert data["findings_count"] == 12
    assert data["tools_used"] == ["burp", "nmap"]


def test_load_all_baselines(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "reasonchain.human_baseline.BASELINES_DIR", tmp_path,
    )
    HumanBaseline(
        target="dvwa", expert_id="E01", findings_count=5,
    ).to_yaml(tmp_path / "dvwa" / "E01.yaml")
    HumanBaseline(
        target="juiceshop", expert_id="E01", findings_count=15,
    ).to_yaml(tmp_path / "juiceshop" / "E01.yaml")
    from reasonchain.human_baseline import load_all_baselines
    bs = load_all_baselines()
    assert len(bs) == 2
    assert sorted(b.target for b in bs) == ["dvwa", "juiceshop"]
