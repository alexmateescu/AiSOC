"""audit_log immutability: the FK SET NULL exemption stays pinned to actor_id.

Migration 101_audit_immutable_nullify.sql relaxed trg_audit_log_immutable
just enough for ON DELETE SET NULL to fire when an admin hard-deletes a
user. Review on #1231 showed a value->NULL exemption that does not name the
column lets one UPDATE strip every forensic column at once (actor_email,
actor_ip, resource, changes, metadata) while the trigger stays silent.

Every case runs inside a transaction that ROLLBACKs: no live audit row is
ever durably mutated, not even in the legal case.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_AUDIT_DSN", "").strip(),
        reason="ISOLATION_AUDIT_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_AUDIT_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_AUDIT_DSN is not set")
    return value.replace("postgresql://", "postgresql+asyncpg://", 1) if value.startswith(
        "postgresql://"
    ) else value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def row(engine):
    """A fresh audit row to attack, deleted on teardown. Its actor is then
    deleted too, so the FK SET NULL path is exercised for real."""
    import uuid

    from sqlalchemy import text

    aid = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
            {"id": tenant_id, "n": f"imm-{aid[:8]}", "s": f"imm-{aid[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password) "
                "VALUES (:id, :t, :e, :u, :h)"
            ),
            {
                "id": user_id,
                "t": tenant_id,
                "e": f"imm-{aid[:8]}@test.local",
                "u": f"imm-{aid[:8]}",
                "h": "!locked-by-test-no-login",
            },
        )
        await conn.execute(
            text(
                "INSERT INTO audit_log (id, tenant_id, actor_id, actor_email, "
                "actor_ip, action, resource, resource_id, changes, metadata) "
                "VALUES (:id, :t, :a, :e, :i, :ac, :r, :ri, :c, :m)"
            ),
            {
                "id": aid,
                "t": tenant_id,
                "a": user_id,
                "e": "operator@corp.example",
                "i": "203.0.113.7",
                "ac": "roles:grant",
                "r": "role/infosec",
                "ri": "00000000-0000-0000-0000-000000000009",
                "c": '{"role": "infosec"}',
                "m": '{"via": "console"}',
            },
        )
    yield {"id": aid, "user_id": user_id, "tenant_id": tenant_id}
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM audit_log WHERE id = :id"), {"id": aid})
        # delete the actor user: FK ON DELETE SET NULL must fire through the
        # trigger, exactly the path migration 101 exists for.
        await conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})


async def _attempt(engine, sql: str, params: dict) -> str:
    """Run a mutating UPDATE inside a rolled-back transaction.
    Returns 'ALLOWED' or 'REFUSED (<message>)'."""
    from sqlalchemy import text

    conn = await engine.connect()
    try:
        trans = await conn.begin()
        try:
            await conn.execute(text(sql), params)
            outcome = "ALLOWED"
        finally:
            await trans.rollback()
        return outcome
    except Exception as exc:  # trigger raise
        return f"REFUSED ({exc.orig})"
    finally:
        await conn.close()


class TestAuditImmutabilityExemption:
    async def test_actor_id_nullify_is_allowed(self, engine, row) -> None:
        """The FK case: ON DELETE SET NULL on actor_id must pass."""
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_id = NULL WHERE id = :id",
            {"id": row["id"]},
        )
        assert outcome == "ALLOWED", outcome

    async def test_single_other_column_nullify_is_refused(self, engine, row) -> None:
        """The review's hole: stripping actor_email (nullable, no SET NULL
        FK) must raise, not pass silently."""
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_email = NULL WHERE id = :id",
            {"id": row["id"]},
        )
        assert outcome.startswith("REFUSED"), outcome
        assert "actor_email" in outcome

    async def test_multi_column_strip_is_refused(self, engine, row) -> None:
        """The exact statement from the review evidence: every forensic
        column NULLed in one UPDATE. This is the case that was silent
        before the column-name guard."""
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_email = NULL, actor_ip = NULL, "
            "resource = NULL, resource_id = NULL, changes = NULL, "
            "metadata = NULL WHERE id = :id",
            {"id": row["id"]},
        )
        assert outcome.startswith("REFUSED"), outcome

    async def test_content_mutation_still_refused(self, engine, row) -> None:
        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET action = :a WHERE id = :id",
            {"id": row["id"], "a": "roles:revoke"},
        )
        assert outcome.startswith("REFUSED"), outcome

    async def test_actor_id_value_change_is_refused(self, engine, row) -> None:
        """Only value -> NULL is exempt on actor_id; swapping actors is
        still attribution forgery."""
        import uuid

        outcome = await _attempt(
            engine,
            "UPDATE audit_log SET actor_id = :other WHERE id = :id",
            {"id": row["id"], "other": str(uuid.uuid4())},
        )
        assert outcome.startswith("REFUSED"), outcome
