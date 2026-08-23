"""Blast-radius probe for W1 — measures what landing policy_judge_v2 would break,
WITHOUT editing a single existing file.

Usage:
    python3 -m pytest tests/ sdlc/evals/ -q -p w1_tristate_impact_probe

It swaps judge_engine.v1.policy_judge.evaluate for the v2 implementation at
pytest_configure time, i.e. before collection, so every caller -- including
engine.evaluate() and the receipt path -- sees the replacement.

Delete nothing to undo it: just omit the -p flag.
"""
from judge_engine.v1 import policy_judge as _v1
from judge_engine.v1 import policy_judge_v2 as _v2

_ORIGINAL = _v1.evaluate


def pytest_configure(config):
    _v1.evaluate = _v2.evaluate
    config.addinivalue_line("markers", "w1probe: unused; keeps pytest quiet")


def pytest_unconfigure(config):
    _v1.evaluate = _ORIGINAL


def pytest_report_header(config):
    return "W1 PROBE ACTIVE: judge_engine.v1.policy_judge.evaluate -> policy_judge_v2.evaluate"
