#!/bin/sh
set -eu
# Only fixture-generated logs exist here; expose bounded diagnostics on failure.
trap 'status=$?; if [ "$status" -ne 0 ]; then for f in /tmp/import.log /tmp/export.log /tmp/execution.log; do [ ! -f "$f" ] || tail -n 80 "$f"; done; fi' EXIT
# No server runs in this container. Each CLI process exits before the next begins.
n8n --version > /tmp/version.txt
[ "$(cat /tmp/version.txt)" = '2.38.4' ]
n8n import:workflow --input=/fixture/workflow.json --activeState=false > /tmp/import.log 2>&1
n8n export:workflow --id=fixtureSmoke2384 --output=/tmp/export.json > /tmp/export.log 2>&1
n8n execute --id=fixtureSmoke2384 --rawOutput > /tmp/execution.log 2>&1
node /fixture/verify.cjs
