"""Kafka consumer — reads security events, scores them, emits anomalies.

The consumer reads ``aisoc.raw_events``: the ingest-normalized OCSF envelope
that every connector and webhook already produces. Entity and features are
recovered by :mod:`app.services.feature_extraction`, which also still accepts
the pre-extracted shape below for operators feeding UEBA from their own
pipeline:

  {
    "event_id":       "uuid-string",
    "tenant_id":      "uuid-string",
    "entity_type":    "user" | "device" | "ip",
    "entity_id":      "alice@example.com",
    "event_type":     "login" | "file_access" | "network" | ...,
    "peer_group_id":  "dept:engineering",   // optional
    "features": {
      "hour_of_day":   14,
      "login_count":   3,
      "bytes_sent":    1024000,
      ...
    },
    "ts": "2026-05-03T12:00:00Z"
  }

Anomalies are published to ``ueba.anomalies``:
  {
    "anomaly_id":     "uuid",
    "tenant_id":      "uuid",
    "entity_type":    "user",
    "entity_id":      "alice@example.com",
    "event_type":     "login",
    "anomaly_score":  4.7,
    "risk_level":     "high",
    "features":       {...},
    "detected_at":    "2026-05-03T12:00:01Z"
  }

What happens when the handler raises
------------------------------------

It logs at ``error``, dead-letters the event, and carries on. A single
unprocessable event must not stop the stream, which is already the policy in
``services/fusion`` and ``services/agents`` — one answer across the three
consumers is worth more than a cleverer answer here.

What must never happen again is the previous behaviour. There was no
``except`` at all: the first event that raised left the ``async for``, the
``finally`` stopped the consumer, and the exception went into the task
object. Because the task was held in a module global it was never
garbage-collected, so asyncio never emitted "Task exception was never
retrieved". The container stayed ``running`` with restarts 0, ``/health``
answered 200, and ``/readyz`` answered 200, for as long as anyone left it up.

Continuing is only safe if a subscription that *does* end says so, so this
class tracks whether it is attached and ``app/main.py`` registers that as a
readiness probe. Detaching is not treated as recoverable in place: there is
no reconnect loop here, because a loop would turn a permanent fault — a
missing column, a revoked grant — into an indefinite retry that reads as
ordinary churn. The honest report is a 503 on ``/readyz``, the exception in
the log, and the restart decision left to whatever is supervising the
container.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.kafka_security import kafka_client_kwargs
from app.services.dead_letters import DeadLetterSink
from app.services.feature_extraction import extract
from app.services.peer_group import PeerGroupService
from app.services.scoring import ScoringService

LOG = logging.getLogger(__name__)


#: Failures no retry can fix, mapped to the operator action that says so.
#: Everything absent from this table is transient and retried — a wrong
#: "permanent" verdict keeps a recoverable service down.
_PERMANENT_FAILURE_ACTIONS = {
    "TopicAuthorizationError": "grant the service principal access to aisoc.raw_events / ueba.anomalies",
    "GroupAuthorizationError": "grant the service principal Read on the UEBA consumer group",
    "SaslAuthenticationFailed": "fix the SASL credentials in .env and restart",
}


def _permanent_failure_action(exc: BaseException) -> str | None:
    return _PERMANENT_FAILURE_ACTIONS.get(type(exc).__name__)



class UEBAKafkaConsumer:
    def __init__(self) -> None:
        self._engine = create_async_engine(settings.database_url, pool_size=5)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._running = False
        # True only while the ``async for`` is iterating a started consumer.
        # Read through ``attached`` by the readiness probe; set False in the
        # loop's ``finally`` so every exit path — clean stop, broker loss,
        # unhandled error — is reported the same way.
        self._attached = False
        self._dlq = DeadLetterSink(self._session_factory)
        self._stats: dict[str, Any] = {
            "processed": 0,
            "handler_failures": 0,
            "dead_lettered": 0,
            "last_error": None,
        }

    @property
    def attached(self) -> bool:
        """Whether this consumer is currently subscribed and iterating."""
        return self._attached

    def stats(self) -> dict[str, Any]:
        """Counters for ``/health``. A copy, so a caller cannot edit them."""
        return dict(self._stats)

    async def _process_message(self, raw: bytes, producer: Any) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            LOG.warning("Invalid JSON message; skipping.")
            return

        # An event with no recoverable entity or no numeric feature is a
        # normal outcome, not an error — most telemetry names no identity, and
        # something with no baseline cannot deviate from one.
        event = extract(msg)
        if event is None:
            return

        entity_type = event.entity_type
        entity_id = event.entity_id
        event_type = event.event_type
        peer_group_id = event.peer_group_id
        features = event.features
        source_event_id = event.source_event_id

        try:
            tenant_id = uuid.UUID(event.tenant_id)
        except ValueError:
            LOG.warning("Invalid tenant_id: %s", event.tenant_id)
            return

        async with self._session_factory() as session:
            async with session.begin():
                # Update peer group if provided
                if peer_group_id:
                    peer_svc = PeerGroupService(session)
                    await peer_svc.update(tenant_id, peer_group_id, entity_type, features)

                scorer = ScoringService(session)
                anomaly = await scorer.score_event(
                    tenant_id=tenant_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    event_type=event_type,
                    features=features,
                    source_event_id=source_event_id,
                    peer_group_id=peer_group_id,
                )

        if anomaly and producer:
            payload = {
                "anomaly_id": str(anomaly.id),
                "tenant_id": str(anomaly.tenant_id),
                "entity_type": anomaly.entity_type,
                "entity_id": anomaly.entity_id,
                "event_type": anomaly.event_type,
                "anomaly_score": anomaly.anomaly_score,
                "risk_level": anomaly.risk_level,
                "features": anomaly.features,
                "peer_group_id": anomaly.peer_group_id,
                "peer_deviation_score": anomaly.peer_deviation_score,
                "detected_at": anomaly.detected_at.isoformat() if anomaly.detected_at else None,
            }
            await producer.send_and_wait(
                settings.kafka_output_topic,
                json.dumps(payload).encode(),
            )
            LOG.info(
                "Anomaly emitted: entity=%s/%s score=%.2f risk=%s",
                entity_type,
                entity_id,
                anomaly.anomaly_score,
                anomaly.risk_level,
            )

    async def run(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        except ImportError:
            LOG.error("aiokafka not installed; Kafka consumer disabled.")
            return

        consumer = AIOKafkaConsumer(
            settings.kafka_input_topic,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            **kafka_client_kwargs(),
        )
        producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            **kafka_client_kwargs(),
        )

        await consumer.start()
        await producer.start()
        self._running = True
        self._attached = True
        LOG.info("UEBA Kafka consumer started (topic=%s)", settings.kafka_input_topic)

        try:
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    await self._process_message(msg.value, producer)
                except Exception as exc:  # noqa: BLE001 — one event must not end the subscription
                    await self._handler_failed(msg, exc)
                else:
                    self._stats["processed"] += 1
        finally:
            # Before the awaits below, not after: ``consumer.stop()`` can
            # itself raise on a broker that has gone away, and readiness must
            # already be reporting detached by then rather than staying 200
            # through a failed teardown.
            self._attached = False
            await consumer.stop()
            await producer.stop()
            LOG.info("UEBA Kafka consumer stopped.")

    async def _handler_failed(self, msg: Any, exc: Exception) -> None:
        """Report one unprocessable event and keep the subscription.

        Loud on purpose. This is the exact point the old code exited from
        without writing anything anywhere, so the log line carries the
        partition and offset needed to find the event again, and
        ``exc_info`` carries the traceback that says which column or grant
        was missing.
        """
        self._stats["handler_failures"] += 1
        self._stats["last_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"

        topic = getattr(msg, "topic", settings.kafka_input_topic)
        partition = getattr(msg, "partition", None)
        offset = getattr(msg, "offset", None)
        raw = getattr(msg, "value", msg)

        LOG.error(
            "UEBA handler failed; event dead-lettered and the subscription kept. topic=%s partition=%s offset=%s error=%s: %s",
            topic,
            partition,
            offset,
            type(exc).__name__,
            exc,
            exc_info=True,
        )

        payload: Any
        try:
            payload = json.loads(raw) if isinstance(raw, bytes | bytearray) else raw
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"undecodable": str(raw)[:500]}

        tenant_id = payload.get("tenant_id") if isinstance(payload, dict) else None
        source_event_id = payload.get("event_id") if isinstance(payload, dict) else None

        recorded = await self._dlq.record(
            topic=str(topic),
            reason=f"{type(exc).__name__}: {str(exc)[:400]}",
            payload=payload,
            tenant_id=str(tenant_id) if tenant_id else None,
            source_event_id=str(source_event_id) if source_event_id else None,
        )
        if recorded:
            self._stats["dead_lettered"] += 1

    async def run_forever(
        self,
        initial_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 60.0,
        stuck_after_seconds: float | None = None,
    ) -> None:
        """Supervise :meth:`run`: retry transient Kafka failures, stop on permanent ones.

        Parity with the fusion worker (PR #1725). The Oct-31 outage was this
        exact gap: a broker blip raised out of the ``async for``, ``run``
        returned, and the service served /readyz 200 for days with nothing
        scored. Transient faults retry with capped backoff; an unrecoverable
        fault says so once with the operator action and lets readiness go 503;
        a failure that outlives any transient explanation escalates to error
        while still retrying.
        """
        stuck_after = stuck_after_seconds or float(os.getenv("AISOC_UEA_SUPERVISOR_STUCK_AFTER_SECONDS", "600"))
        backoff = max(0.1, initial_backoff_seconds)
        failing_since: float | None = None
        # Not `while self._running`: stop() clears _running and then run()
        # returns cleanly, so a running-guard here would exit before the first
        # attempt ever started. The loop exits on run()'s clean return, on
        # cancellation, and on a permanent classification.
        while True:
            attached_before = self._attached
            try:
                await self.run()
                return  # clean stop — stop() cleared _running
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — classified below, not swallowed
                if not self._running and not attached_before:
                    return
                action = _permanent_failure_action(exc)
                if action is not None:
                    LOG.error(
                        "UEBA consumer failed permanently; supervision stopped. error=%s: %s operator_action=%s",
                        type(exc).__name__, exc, action,
                        exc_info=True,
                    )
                    return

                now = time.monotonic()
                if self._attached or attached_before:
                    failing_since = None
                if failing_since is None:
                    failing_since = now
                failing_for = now - failing_since

                if failing_for >= stuck_after:
                    LOG.error(
                        "UEBA consumer not resolving; still retrying but this has outlived any transient "
                        "explanation. error=%s: %s failing_for_seconds=%.0f backoff_seconds=%.1f "
                        "operator_action=check AISOC_KAFKA_BOOTSTRAP_SERVERS names a reachable broker",
                        type(exc).__name__, exc, failing_for, backoff,
                        exc_info=True,
                    )
                else:
                    LOG.warning(
                        "UEBA consumer crashed; retrying in %.1fs. error=%s: %s",
                        backoff, type(exc).__name__, exc,
                        exc_info=True,
                    )

                self._attached = False
                await asyncio.sleep(backoff)
                backoff = min(max_backoff_seconds, backoff * 2)

    def stop(self) -> None:
        self._running = False
