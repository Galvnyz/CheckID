"""Tests for Generate-ImpactRationale.py"""
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "Generate-ImpactRationale.py"


def test_script_exists():
    assert SCRIPT.exists(), "Generate-ImpactRationale.py must exist"


def test_all_checks_have_rationale_after_run():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dry-run"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"Script failed: {result.stderr}"
    output = json.loads(result.stdout)
    empty = [c["checkId"] for c in output["checks"] if not c.get("impactRationale")]
    assert len(empty) == 0, f"These checks still have empty rationale: {empty[:5]}"


def test_rationale_is_reasonable_length():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dry-run"],
        capture_output=True, text=True
    )
    output = json.loads(result.stdout)
    too_long = [c["checkId"] for c in output["checks"]
                if len(c.get("impactRationale", "")) > 300]
    assert len(too_long) == 0, f"Rationale too long (>300 chars): {too_long[:3]}"


def test_rationale_is_not_a_question():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dry-run"],
        capture_output=True, text=True
    )
    output = json.loads(result.stdout)
    questions = [c["checkId"] for c in output["checks"]
                 if c.get("impactRationale", "").strip().startswith("Does")]
    assert len(questions) == 0, f"Rationale starts with 'Does' (unconverted question): {questions[:3]}"
