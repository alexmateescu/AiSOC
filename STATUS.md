
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
