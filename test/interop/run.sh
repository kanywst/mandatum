#!/usr/bin/env bash
#
# Start the three interop PDPs on loopback, load the scenario's policy into
# each, and run the interop test against all of them. CI runs exactly this;
# so can anyone with the binaries.
#
#   CERBOS=/path/to/cerbos OPENFGA=/path/to/openfga OPA=/path/to/opa \
#   PROXY_DIR=/path/to/open-policy-agent/contrib/authzen/authzen-proxy \
#     test/interop/run.sh
#
# PROXY_DIR must already have had `npm ci` run in it.

set -euo pipefail

: "${CERBOS:?path to the cerbos binary}"
: "${OPENFGA:?path to the openfga binary}"
: "${OPA:?path to the opa binary}"
: "${PROXY_DIR:?path to open-policy-agent/contrib authzen/authzen-proxy}"

here="$(cd "$(dirname "$0")" && pwd)"
logs="$(mktemp -d)"
pids=()

cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# Logs are printed on failure, since a PDP that did not start looks to the
# test like a PDP that denies everything.
dump_logs() {
  for f in "$logs"/*.log; do
    echo "::group::$(basename "$f")"
    cat "$f"
    echo "::endgroup::"
  done
}
trap 'dump_logs' ERR

wait_for() {
  local name="$1" url="$2"
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null "$url"; then return 0; fi
    sleep 0.5
  done
  echo "$name did not start listening at $url" >&2
  return 1
}

"$CERBOS" server \
  --set=storage.driver=disk \
  --set=storage.disk.directory="$here/cerbos" \
  --set=server.httpListenAddr=127.0.0.1:3592 \
  --set=server.grpcListenAddr=127.0.0.1:3593 >"$logs/cerbos.log" 2>&1 &
pids+=($!)

"$OPA" run --server --addr 127.0.0.1:8181 "$here/opa" >"$logs/opa.log" 2>&1 &
pids+=($!)
(cd "$PROXY_DIR" && PORT=3000 OPA_URL=http://127.0.0.1:8181 exec node server.js) >"$logs/opa-proxy.log" 2>&1 &
pids+=($!)

"$OPENFGA" run \
  --experimentals=authzen \
  --authzen-base-url=http://127.0.0.1:8080 \
  --playground-enabled=false \
  --http-addr=127.0.0.1:8080 \
  --grpc-addr=127.0.0.1:8081 >"$logs/openfga.log" 2>&1 &
pids+=($!)

wait_for cerbos http://127.0.0.1:3592/_cerbos/health
wait_for opa http://127.0.0.1:8181/health
wait_for opa-proxy http://127.0.0.1:3000/
wait_for openfga http://127.0.0.1:8080/healthz

# OpenFGA keeps policy as a store, a model and tuples behind its API rather
# than in files, and names the store at runtime.
store=$(curl -sf -X POST http://127.0.0.1:8080/stores -d '{"name":"mandatum-interop"}' | jq -er .id)
curl -sf -X POST "http://127.0.0.1:8080/stores/$store/authorization-models" -d @"$here/openfga/model.json" >/dev/null
curl -sf -X POST "http://127.0.0.1:8080/stores/$store/write" -d @"$here/openfga/tuples.json" >/dev/null

# The flags are explained in interop_test.go. Each one records something
# measured about that PDP, and README.md says what.
export MANDATUM_INTEROP_PDPS="\
opa=http://127.0.0.1:3000/access/v1/evaluation,\
cerbos=http://127.0.0.1:3592/access/v1/evaluation;no-request-id;no-context,\
openfga=http://127.0.0.1:8080/stores/$store/access/v1/evaluation;no-request-id"

cd "$here/../.."
go test -count=1 -v -tags interop ./test/interop/
