"""Alert status advance on investigation launch (alert half of the ladder fix).

Launching an agent investigation from an alert must mark the alert itself
'investigating' - not only the case. The UPDATE's status guard is the
contract tested here: forward-only from the open states, never backwards.
Source-contract tests because the bump lives inline in investigate_case
(same-request, never-blocks-the-launch semantics).
"""

import re
from pathlib import Path

import pytest

CASES = Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints" / "cases.py"

SOURCE = CASES.read_text()


def _bump_sql() -> str:
    m = re.search(
        r"UPDATE alerts SET status = 'investigating'.*?AND status IN \(([^)]*)\)",
        SOURCE,
        re.DOTALL,
    )
    assert m, "alerts investigate bump missing from cases.py"
    return m.group(0)


def _open_statuses() -> set[str]:
    m = re.search(r"AND status IN \(([^)]*)\)", _bump_sql())
    assert m, "status IN clause missing from bump SQL"
    raw = m.group(1)
    if "{" in raw:
        # The guard expands from the pinned tuple via .format() — resolve it
        # from the source rather than parsing the placeholder text.
        t = re.search(r"_ALERT_OPEN_STATUSES[^=]*=\s*\(([^)]*)\)", SOURCE)
        assert t, "_ALERT_OPEN_STATUSES tuple missing from cases.py"
        raw = t.group(1)
    return {s.strip().strip("'\"") for s in raw.split(",") if s.strip()}


def test_alert_bump_is_tenant_scoped() -> None:
    assert "tenant_id = :tenant_id" in _bump_sql()


def test_alert_bump_never_blocks_launch() -> None:
    idx = SOURCE.index("UPDATE alerts SET status = 'investigating'")
    tail = SOURCE[idx : idx + 1200]
    assert "except Exception" in tail
    assert "investigate.launch.alerts_advance_failed" in tail


@pytest.mark.parametrize(
    ("current", "advances"),
    [
        ("new", True),
        ("triaged", True),
        ("triaging", True),
        ("investigating", False),
        ("in_progress", False),
        ("resolved", False),
        ("false_positive", False),
        ("closed", False),
    ],
)
def test_bump_predicate_matrix(current: str, advances: bool) -> None:
    """Mirror of the WHERE guard: membership in the open set decides."""
    assert (current in _open_statuses()) is advances
