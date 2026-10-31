# escalations — ack-clock escalation bridge

Teams escalations for cases nobody has acknowledged, until the native
outbound-webhook emitters are wired (`services/api/app/services/
outbound_webhooks.py::enqueue_event` currently has no production callers).

Watches the platform's own ack clock (`aisoc_cases.acknowledged_at`):

- **CRITICAL** unacknowledged >= 30 min -> immediate card, re-nag every 4 h,
  max 3 sends per case.
- **HIGH** unacknowledged -> one digest per day (08:00 UTC) plus a pipeline
  health line (failed investigations / dead-letters, last 24 h).

Dedup + nag state persists in the `escalation-state` volume; restarts never
double-send. All thresholds are env-tunable (`ESC_*`, see docker-compose.yml).

## Run

    docker compose --profile escalations up -d

The webhook target is any JSON POST endpoint that renders an Adaptive Card
(payload fields: `severity`, `title`, `summary`, `case_id`, `opened_at`,
`url`). The documented setup uses a Power Automate "Post card in a chat or
channel" flow; note that that action requires the bare Adaptive Card object,
not a `message`/`attachments` envelope.

## Tests

    python -m pytest tests/ -q
