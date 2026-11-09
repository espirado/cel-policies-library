#!/usr/bin/env bash
# Throwaway Keycloak with the `cel` realm for tests/test_keycloak.py and scripts/live_rcintel_authz.py.
# Test-only credentials (realm users op/adm/view/norole, password pw-<user>); binds 127.0.0.1 only.
#   tests/keycloak/start.sh [port]     start (default 19180)
#   docker rm -f cel-keycloak          stop and remove
# The realm file is copied into the container (a bind mount from /tmp was empty on Docker Desktop).
set -euo pipefail
PORT="${1:-19180}"
HERE="$(cd "$(dirname "$0")" && pwd)"
docker rm -f cel-keycloak >/dev/null 2>&1 || true
docker create --name cel-keycloak -p "127.0.0.1:${PORT}:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-local-test \
  quay.io/keycloak/keycloak:26.0 start-dev --import-realm >/dev/null
TMP="$(mktemp -d)"; mkdir -p "$TMP/import" && cp "$HERE/cel-realm.json" "$TMP/import/"
docker cp "$TMP/import" cel-keycloak:/opt/keycloak/data/
rm -rf "$TMP"
docker start cel-keycloak >/dev/null
for _ in $(seq 1 60); do
  curl -sf -m 3 "http://127.0.0.1:${PORT}/realms/cel/.well-known/openid-configuration" >/dev/null && { echo "keycloak ready: http://127.0.0.1:${PORT}/realms/cel"; exit 0; }
  sleep 3
done
echo "keycloak did not become ready" >&2; docker logs cel-keycloak | tail -20 >&2; exit 1
