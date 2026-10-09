#!/bin/bash
set -u
cd ~/AiSOC
git checkout -q feat/cve-patch-windows-v3
git diff --stat docs/openapi.yaml | tail -1
# what paths does the diff add?
git diff docs/openapi.yaml | grep -E "^\s+/api/" | head -8
printf '%s\n' "fix(review): regenerate docs/openapi.yaml for this branch" "" "The rebase took upstream's spec verbatim as shared surface, which dropped" "this PR's own additions (bulk-close + vulnerability inventory routes, the" "+134 lines the export now re-adds). Regenerated with the repo exporter on" "this tree so the gate diff is empty." > /tmp/cm4.txt
git add docs/openapi.yaml
git commit -q -F /tmp/cm4.txt && git log --oneline -1
git push fork feat/cve-patch-windows-v3:feat/cve-patch-windows 2>&1 | tail -1
