#!/usr/bin/env bash
set -euo pipefail
readonly image='n8nio/n8n@sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae'
[[ ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[0-9]+$ ]] || { echo "Numeric CI run ID and attempt required"; exit 1; }
readonly prefix="n8n-fixture-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
readonly fixture="$(cd "$(dirname "$0")" && pwd)"
cli_created=false
server_created=false
cli_id=
server_id=
cleanup() {
  if [ "$cli_created" = true ]; then docker rm -f "$cli_id" >/dev/null 2>&1 || true; fi
  if [ "$server_created" = true ]; then docker rm -f "$server_id" >/dev/null 2>&1 || true; fi
}
# Verify daemon availability, then fail before ownership or cleanup on name collisions.
docker info >/dev/null
for name in "$prefix-cli" "$prefix-server"; do
  if docker container inspect "$name" >/dev/null 2>&1; then echo "Container name already exists: $name"; exit 1; fi
done
trap cleanup EXIT
# Image download is the only network-using stage; application containers have none.
[ "$(df -Pk . | awk 'NR==2 {print $4}')" -ge 10485760 ] || { echo "Need at least 10 GiB free disk"; exit 1; }
timeout 300 docker pull --platform linux/amd64 "$image"
args=(--platform linux/amd64 --network none --user 1000:1000 --cap-drop ALL
  --security-opt no-new-privileges --read-only --pids-limit 256 --memory 3g --cpus 2
  --tmpfs /home/node/.n8n:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=512m
  --tmpfs /home/node/.cache:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=128m
  --tmpfs /tmp:rw,nosuid,nodev,uid=1000,gid=1000,mode=1777,size=512m
  -e DB_TYPE=sqlite -e EXECUTIONS_MODE=regular
  -e N8N_ENCRYPTION_KEY=synthetic-fixture-only-not-a-real-secret
  -e N8N_DIAGNOSTICS_ENABLED=false -e N8N_TEMPLATES_ENABLED=false
  -e N8N_VERSION_NOTIFICATIONS_ENABLED=false -e N8N_VERSION_NOTIFICATIONS_WHATS_NEW_ENABLED=false
  -e N8N_SENTRY_DSN= -e N8N_FRONTEND_SENTRY_DSN=)
# No -p, Docker socket, host credentials, environment pass-through or real volume.
cli_id=$(docker create --name "$prefix-cli" "${args[@]}" \
  --mount "type=bind,src=$fixture,dst=/fixture,readonly" \
  --entrypoint /bin/sh "$image" /fixture/inside.sh)
cli_created=true
timeout 240 docker start --attach "$cli_id"
[ "$(docker inspect -f '{{.State.ExitCode}}' "$cli_id")" -eq 0 ]
# Separate fresh SQLite. This exercises the vendor default entrypoint and startup.
server_id=$(docker create --name "$prefix-server" "${args[@]}" "$image")
server_created=true
docker start "$server_id" >/dev/null
ready=false
for _ in $(seq 1 60); do
  if timeout 5 docker exec "$prefix-server" node -e '
    Promise.all(["healthz", "healthz/readiness"].map(async path => {
      const r = await fetch(`http://127.0.0.1:5678/${path}`, {signal: AbortSignal.timeout(2000)});
      if (r.status !== 200 || (await r.json()).status !== "ok") throw Error("not ready");
    })).catch(() => process.exit(1));
  ' >/dev/null 2>&1; then ready=true; break; fi
  [ "$(docker inspect -f '{{.State.Running}}' "$prefix-server")" = true ] || break
  sleep 2
done
if [ "$ready" != true ]; then docker logs --tail 100 "$prefix-server"; exit 1; fi
[ "$(timeout 15 docker exec "$prefix-server" n8n --version)" = '2.46.6' ]
[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$prefix-server")" = none ]
[ "$(docker port "$prefix-server" | wc -l)" -eq 0 ]
timeout 30 docker stop --time 20 "$prefix-server" >/dev/null
printf '%s\n' 'PASS: official default entrypoint, HTTP health/readiness JSON, exact version, no network/ports'
