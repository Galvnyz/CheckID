"""Tests for Generate-ImpactRationale.py"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "Generate-ImpactRationale.py"


def _load_module():
    """Import Generate-ImpactRationale as a module for unit testing."""
    spec = importlib.util.spec_from_file_location("gen_rationale", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_script_exists():
    assert SCRIPT.exists(), "Generate-ImpactRationale.py must exist"


def test_question_to_statement_standard_prefix():
    mod = _load_module()
    result = mod._question_to_statement("Does the organization restrict privileged accounts?")
    assert result == "restrict privileged accounts"
    assert not result.startswith("Does")


def test_question_to_statement_nonconforming_returns_empty():
    mod = _load_module()
    result = mod._question_to_statement("Are privileged accounts restricted?")
    assert result == "", "Non-matching prefix should return empty string"


def test_generate_rationale_with_risks():
    mod = _load_module()
    result = mod.generate_rationale(
        "Does the organization restrict privileged accounts?",
        ["Unauthorized access", "Privilege escalation", "Data loss / corruption"]
    )
    assert result.startswith("Failure to")
    assert "Unauthorized access" in result
    assert len(result) <= 300
    assert not result.startswith("Does")


def test_generate_rationale_filters_financial_risks():
    mod = _load_module()
    result = mod.generate_rationale(
        "Does the organization restrict privileged accounts?",
        ["Loss of revenue", "Diminished reputation", "Unauthorized access"]
    )
    assert "revenue" not in result.lower()
    assert "reputation" not in result.lower()
    assert "Unauthorized access" in result


def test_generate_rationale_empty_risks_uses_fallback():
    mod = _load_module()
    result = mod.generate_rationale(
        "Does the organization restrict privileged accounts?",
        []
    )
    assert "unauthorized access" in result.lower() or "compliance" in result.lower()


def test_all_checks_have_rationale_in_mapping():
    """Integration: mapping file has no empty rationale strings."""
    mapping = json.loads((REPO_ROOT / "data" / "scf-check-mapping.json").read_text(encoding="utf-8"))
    empty = [c["checkId"] for c in mapping["checks"] if not c.get("impactRationale")]
    assert len(empty) == 0, f"These checks have empty rationale: {empty[:5]}"


def test_rationale_length_in_mapping():
    mapping = json.loads((REPO_ROOT / "data" / "scf-check-mapping.json").read_text(encoding="utf-8"))
    too_long = [c["checkId"] for c in mapping["checks"]
                if len(c.get("impactRationale", "")) > 300]
    assert len(too_long) == 0, f"Rationale too long: {too_long[:3]}"
