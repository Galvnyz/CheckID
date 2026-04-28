"""Tests for apply_fw_overrides in Build-Registry.py — covers all three override modes."""
import importlib.util
from collections import OrderedDict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "Build-Registry.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("build_registry", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def br():
    return _load_module()


@pytest.fixture
def titles():
    return {
        "soc2": {"CC5": "Control Activities", "CC2.2": "COSO Principle 14: Internal Communication"},
        "nist-csf": {"PR.AA-01": "Identities and credentials are managed"},
    }


def test_replace_default_fills_when_key_absent(br, titles):
    frameworks = OrderedDict()
    overrides = {"nist-csf": {"controlId": "PR.AA-01"}}
    br.apply_fw_overrides(frameworks, overrides, titles)
    assert frameworks["nist-csf"]["controlId"] == "PR.AA-01"
    assert frameworks["nist-csf"]["title"] == "Identities and credentials are managed"
    assert frameworks["nist-csf"]["source"] == "manual-override"


def test_replace_default_preserves_scf_controlid_when_present(br, titles):
    frameworks = OrderedDict({
        "soc2": OrderedDict([("controlId", "CC2.2"), ("title", "COSO Principle 14: Internal Communication")]),
    })
    overrides = {"soc2": {"controlId": "CC5"}}
    br.apply_fw_overrides(frameworks, overrides, titles)
    assert frameworks["soc2"]["controlId"] == "CC2.2", \
        "default 'replace' mode must NOT overwrite SCF-derived controlId"
    assert frameworks["soc2"]["source"] == "manual-override", \
        "the override should still tag provenance"


def test_append_merges_into_existing(br, titles):
    frameworks = OrderedDict({
        "soc2": OrderedDict([("controlId", "CC2.2")]),
    })
    overrides = {"soc2": {"controlId": "CC5", "mode": "append"}}
    br.apply_fw_overrides(frameworks, overrides, titles)
    assert "CC2.2" in frameworks["soc2"]["controlId"]
    assert "CC5" in frameworks["soc2"]["controlId"]
    assert frameworks["soc2"]["source"] == "manual-override"


def test_force_replace_discards_scf_entry(br, titles):
    """The motivating fix for #316: SCF maps SEA-18 to soc2 CC2.2, but
    CC2 is non-automatable per soc2-tsc.json. force-replace must let the
    curator land cleanly on CC5 instead."""
    frameworks = OrderedDict({
        "soc2": OrderedDict([
            ("controlId", "CC2.2"),
            ("title", "COSO Principle 14: Internal Communication"),
        ]),
    })
    overrides = {"soc2": {"controlId": "CC5", "mode": "force-replace", "reason": "CC2 is non-automatable"}}
    br.apply_fw_overrides(frameworks, overrides, titles)
    assert frameworks["soc2"]["controlId"] == "CC5"
    assert frameworks["soc2"]["title"] == "Control Activities", \
        "force-replace must look up the title for the new controlId, not preserve SCF's"
    assert frameworks["soc2"]["source"] == "manual-override"
    assert frameworks["soc2"]["reason"] == "CC2 is non-automatable"


def test_force_replace_works_when_key_absent(br, titles):
    """force-replace should still succeed if SCF didn't produce an entry —
    the 'discard SCF' part is just a no-op in that case."""
    frameworks = OrderedDict()
    overrides = {"soc2": {"controlId": "CC5", "mode": "force-replace"}}
    br.apply_fw_overrides(frameworks, overrides, titles)
    assert frameworks["soc2"]["controlId"] == "CC5"
    assert frameworks["soc2"]["source"] == "manual-override"


def test_override_without_controlid_is_skipped(br, titles):
    frameworks = OrderedDict({"soc2": OrderedDict([("controlId", "CC2.2")])})
    overrides = {"soc2": {"mode": "force-replace"}}  # no controlId
    br.apply_fw_overrides(frameworks, overrides, titles)
    assert frameworks["soc2"]["controlId"] == "CC2.2", \
        "overrides without a controlId must be skipped, not produce empty entries"
