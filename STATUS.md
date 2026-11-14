
## Operator-review mode (06-Nov ~10:45 UTC)
Root cause of "no needs review": alerts were being closed before an operator
could ever see them — (a) worker passed auto_closed=COMPLETED -> every
completed triage resolved itself; (b) Wave-1 outcome-memory suppression
auto-resolved repeats pre-triage. Fixes: auto_closed=False at contract+ledger
(32a9d3da8), AISOC_AGENT_MEMORY_SUPPRESSION=0 in compose (1779f06b2),
disposition query param on GET /alerts, Needs Review chip -> status=triaged
default (49 open rows live now). API + web rebuilt/redeployed, verified
/alerts 200. Traffic currently idle (last ingest ~19:00 local); queue will
fill as fresh alerts arrive. Buttons: no failing mutations in api logs;
if still broken, need exact button + browser-console error.

## Search fix (06-Nov ~11:00 UTC)
`search` param on GET /alerts was declared but never added to the WHERE
filters -> every search returned the full queue (looked broken). Now ILIKE
over title/description/rule_name/rule_id/category/id. Verified via SQL:
'Golden'=16 rows, 'zzzznotfound'=0. api rebuilt/redeployed, readyz ok.
Commit 8c5650001.

## Secret rotation (06-Nov ~14:15 UTC)
Leaked blob c26ffee (.env.bak on upstream/Prasanth595 fork, Oct-7) = same
live Auth0 client T8mXdDSX. New OIDC_CLIENT_SECRET deployed to .env +
aisoc-api recreated, readyz ok, container hash verified. All local .env.bak*
files deleted from fra-hq-soc-01 (were gitignored; .gitignore default-deny
already in place). Fork history confirmed clean of .env* (scan all refs).
Old secret dead once Auth0-side rotation completes on their dashboard.
TODO owner: rotate OPENAI_API_KEY + AISOC_AGENTS_API_KEY from same blob;
ask beenuar to filter-repo upstream + delete Prasanth595 fork.

## Post-rotation verification (06-Nov ~14:20 UTC)
SSO verified live end-to-end: OIDC token exchange succeeded with the rotated
secret in container (hash match), 0 oidc errors, readyz ok. Leaked Auth0
secret is dead. AISOC_AGENTS_API_KEY in the blob was a DEAD variable —
compose never passed it, agents/tools use per-user API keys since b8c903089;
nothing to rotate there. REMAINING: OPENAI_API_KEY in the leaked blob is
still live (placeholder 'wadsadasfd' causes embedding 401s anyway) — needs
new key from platform.openai.com -> .env -> recreate agents.

## Upstream sync plan (06-Nov, awaiting GO)
Upstream 68 commits ahead of our base (v23.0.0+v23.1.0). 7 overlap files,
dry-run merge: conflicts ONLY in AlertsView.tsx (i18n #1747 vs our operator
queue) + alerts.py (copilot scoping #1828 vs our search/disposition).
Workers untouched upstream. High-value pulls: connector cursor paging suite,
METRICS_TOKEN fix (#1823 = our /metrics 401 noise), session renewal (#1818).
Recipe ready: backup tag -> merge -> resolve 2 -> tests -> rebuild api/web/
connectors -> verify queue/search/SSO.

## Upstream sync complete (11-Nov ~18:50 UTC)
Merged origin/main through 1da3b2233 (v23.0.0+v23.1.0, ~70 commits).
Backup tag backup/pre-upstream-sync-20261111-1842. Conflicts resolved:
alerts.py (import union), AlertsView.tsx (kept operator queue default +
adopted useLocale). Applied migration 160_alert_reopen_on_recurrence.sql
(GHSA-qp9f-459j-w89c: closed alerts now reopen on recurrence — matters for
operator-review mode: closed FP that refires will reappear in queue).
readyz fully green incl. schema_migrations_current; web 200; queue:
37 triaged + 1 new. Pushed fork main f30311187. METRICS_TOKEN now in
agents env (upstream #1823) -> /metrics 401 noise should stop.

## Forensic truncation gate (12-Nov 09:30 UTC)
Live incident: truncated forensic reply (finish_reason=length at 8192 test)
fabricated a kernel-rootkit narrative about fra-hq-soc-01. Host verified
clean (kernel/modules/ld.so.preload/SSH/persistence all checked; zero rule-
521 hits in Wazuh index). Root cause: truncated JSON parsed verbatim into
report. Fix 31e37f28d: finish_reason=length -> suppress narrative, mark
INCONCLUSIVE conf 0.1; JSON extraction anchored to EOS + strict parse.
Unit-tested clean/truncated/ramble/chatty. Deployed, agents healthy.

## Upstream sync #2 (14-Nov 05:10 UTC)
Merged v23.2.0-v23.4.0 (35 commits, clean, zero conflicts). Tag
backup/pre-upstream-sync-20261114-0507. Security: GHSA-xh3r (passwords),
GHSA-qf6m (/enrich auth), GHSA-qfvv (fusion tenant scoping) + CVE relocks.
Ops: wazuh durable-cursor backfill, hunt-scheduler UUID fix, tracing self-
target fix, OTX/MISP poll bounding. 12 services rebuilt+recreated; readyz
green, web 200, truncation gate + token passthrough verified intact.
NOTE: Wazuh durable-cursor backfill dumped ~5.5k historical alerts into
'new' queue as expected — operator triage backlog now needs a bulk-triage
decision (awaiting Alexandru).

## Prometheus scrape reconciliation (14-Nov 05:40 UTC)
Upstream #1823 gave agents a METRICS_TOKEN but never the scraper -> every
agents/api scrape 401'd. Fixed 55f1c978f: bearer credentials_file (untracked
infra/docker/secrets/, mode 644) on api+agents+ingest jobs; ingest target
corrected 9090->8080 (no listener on 9090); dead fusion job removed (no
/metrics route). All scrape targets now up, zero /metrics 401s.
