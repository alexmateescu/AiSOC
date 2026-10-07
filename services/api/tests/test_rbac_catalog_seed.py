"""Pin the seeded RBAC catalog: migration 092 and rbac_catalog.py agree.

``app.core.rbac_catalog`` and ``migrations/092_rbac_catalog_seed.sql`` carry
the same role/permission vocabulary in two places by design (the migration
seeds the primary tenant at deploy time; the module seeds other tenants at
runtime). This test is the pin that stops them drifting: the permission
names, the system role names, and every role→grant set must match exactly.

Static-only test — no database, no FastAPI app. Runs under plain pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.rbac_catalog import (
    PERMISSIONS,
    ROLE_GRANTS,
    SYSTEM_ROLE_LABELS,
    SYSTEM_ROLES,
)

MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "092_rbac_catalog_seed.sql"


def _migration_sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_exists() -> None:
    assert MIGRATION.exists(), f"missing migration: {MIGRATION}"


def _migration_permission_rows(sql: str) -> set[str]:
    """Names from the `INSERT INTO permissions ... VALUES (...)` block —
    the first element of each ('name', 'description', 'category') tuple."""
    block = sql.split("INSERT INTO permissions", 1)[1].split(";", 1)[0]
    return set(re.findall(r"\(\s*'([^']+)'\s*,", block))


def test_permission_names_pinned() -> None:
    """The permission rows the migration inserts must exactly equal the
    module's PERMISSIONS vocabulary."""
    sql = _migration_sql()
    in_migration = _migration_permission_rows(sql)
    in_module = {name for name, _desc, _cat in PERMISSIONS}
    assert in_migration == in_module, (
        f"permission vocabulary drifted; only-in-migration={sorted(in_migration - in_module)}, "
        f"only-in-module={sorted(in_module - in_migration)}"
    )


def test_system_role_names_pinned() -> None:
    sql = _migration_sql()
    module_roles = {name for name, _desc in SYSTEM_ROLES}
    assert {"viewer", "infosec", "admin"} == module_roles
    for role in module_roles:
        assert re.search(rf"r\.name\s*=\s*'{role}'", sql) or f"'{role}'" in sql, f"role '{role}' not referenced in migration 092"


def test_role_grants_pinned() -> None:
    """The migration's inline viewer/infosec IN-lists must equal the
    module's ROLE_GRANTS sets; admin is the wildcard in both."""
    sql = _migration_sql()
    assert ROLE_GRANTS["admin"] == frozenset({"*"}), "admin wildcard grant drifted"
    assert "'admin' AND p.name = '*'" in sql, "migration no longer grants admin the wildcard"

    for role in ("viewer", "infosec"):
        block = re.search(
            rf"r\.name\s*=\s*'{role}'\s+AND\s+p\.name\s+IN\s*\((.*?)\)\s*\)",
            sql,
            re.DOTALL,
        )
        assert block, f"could not locate the grant IN-list for role '{role}' in 092"
        in_migration = set(re.findall(r"'([a-z_]+:[a-z_]+|\*)'", block.group(1)))
        in_module = set(ROLE_GRANTS[role])
        assert in_migration == in_module, (
            f"grants drifted for role '{role}': "
            f"only-in-migration={sorted(in_migration - in_module)}, "
            f"only-in-module={sorted(in_module - in_migration)}"
        )


def test_labels_pinned() -> None:
    assert set(SYSTEM_ROLE_LABELS) == {name for name, _desc in SYSTEM_ROLES}
