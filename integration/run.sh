#!/usr/bin/env bash
# Integration test: brings up a local headscale and headscale-sts, exchanges
# an OIDC token for a preauth key through the sts, registers a tailscale node
# (userspace networking) with the minted key, and verifies that the node is
# registered and tagged in headscale.
#
# Required environment:
#   REPOSITORY  expected value of the token's repository claim
# and a token source, one of:
#   - GitHub Actions OIDC (ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN, set by the
#     runner when the job has `id-token: write`)
#   - OIDC_TOKEN (a pre-minted token, e.g. from integration/fakeissuer, for
#     running outside GitHub Actions; optionally OIDC_TOKEN_WRONG_AUDIENCE)
#
# Optional environment:
#   ISSUER     token issuer (default: the GitHub Actions issuer)
#   AUDIENCE   audience to require/request (default: https://headscale-sts.invalid/sts)
#   HEADSCALE, HEADSCALE_STS, TAILSCALE, TAILSCALED  binary paths
set -euo pipefail

ISSUER=${ISSUER:-https://token.actions.githubusercontent.com}
AUDIENCE=${AUDIENCE:-https://headscale-sts.invalid/sts}
REPOSITORY=${REPOSITORY:?set REPOSITORY to the expected token repository claim}
HEADSCALE=${HEADSCALE:-headscale}
HEADSCALE_STS=${HEADSCALE_STS:-./headscale-sts}
TAILSCALE=${TAILSCALE:-tailscale}
TAILSCALED=${TAILSCALED:-tailscaled}

TAG=tag:integration-test
HS_URL=http://127.0.0.1:18080
STS_URL=http://127.0.0.1:18470

DIR=$(mktemp -d)
HS_PID="" STS_PID="" TS_PID=""

cleanup() {
    status=$?
    [[ -n "$TS_PID" ]] && sudo kill "$TS_PID" 2> /dev/null || true
    [[ -n "$STS_PID" ]] && kill "$STS_PID" 2> /dev/null || true
    [[ -n "$HS_PID" ]] && kill "$HS_PID" 2> /dev/null || true
    if [[ $status -ne 0 ]]; then
        for log in headscale sts tailscaled; do
            echo "=== $log log ==="
            cat "$DIR/$log.log" 2> /dev/null || true
        done
    fi
}
trap cleanup EXIT

say() { printf '\n=== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

wait_for() {
    for _ in $(seq 1 60); do
        if curl -fsS -o /dev/null "$1" 2> /dev/null; then return 0; fi
        sleep 0.5
    done
    fail "timeout waiting for $1"
}

expect_status() {
    local expected=$1 method=$2 url=$3 got
    shift 3
    got=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$url" "$@")
    [[ "$got" == "$expected" ]] || fail "$method $url: got HTTP $got, want $expected"
}

say "starting headscale"
cat > "$DIR/policy.json" << EOF
{
  "tagOwners": {"$TAG": []},
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}
EOF
cat > "$DIR/headscale.yaml" << EOF
server_url: $HS_URL
listen_addr: 127.0.0.1:18080
metrics_listen_addr: 127.0.0.1:19090
grpc_listen_addr: 127.0.0.1:15043
noise:
  private_key_path: $DIR/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
database:
  type: sqlite
  sqlite:
    path: $DIR/db.sqlite
derp:
  server:
    enabled: true
    region_id: 999
    region_code: local
    region_name: Local
    stun_listen_addr: 127.0.0.1:13478
    private_key_path: $DIR/derp_private.key
  urls: []
  paths: []
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: $DIR/headscale.sock
policy:
  mode: file
  path: $DIR/policy.json
EOF
"$HEADSCALE" -c "$DIR/headscale.yaml" serve > "$DIR/headscale.log" 2>&1 &
HS_PID=$!
wait_for "$HS_URL/health"

say "creating a headscale API key"
"$HEADSCALE" -c "$DIR/headscale.yaml" apikeys create --expiration 1h > "$DIR/apikey"

say "starting headscale-sts"
cat > "$DIR/sts.yaml" << EOF
listen: "127.0.0.1:18470"
headscale:
  url: "$HS_URL"
  api_key_file: "$DIR/apikey"
trusts:
  - issuer: $ISSUER
    audience: $AUDIENCE
    rules:
      - match:
          repository: $REPOSITORY
        tags: [$TAG]
EOF
"$HEADSCALE_STS" --config "$DIR/sts.yaml" > "$DIR/sts.log" 2>&1 &
STS_PID=$!
wait_for "$STS_URL/sts/healthz"

say "requests without a valid token are rejected"
expect_status 405 GET "$STS_URL/sts/authkey"
expect_status 401 POST "$STS_URL/sts/authkey"
expect_status 401 POST "$STS_URL/sts/authkey" -H "Authorization: Bearer garbage"

say "obtaining OIDC token"
if [[ -n "${OIDC_TOKEN:-}" ]]; then
    TOKEN=$OIDC_TOKEN
else
    : "${ACTIONS_ID_TOKEN_REQUEST_URL:?OIDC_TOKEN not set and not running in GitHub Actions}"
    TOKEN=$(curl -sf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        -G --data-urlencode "audience=$AUDIENCE" "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r .value)
    OIDC_TOKEN_WRONG_AUDIENCE=$(curl -sf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        -G --data-urlencode "audience=$AUDIENCE-wrong" "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r .value)
fi
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || fail "could not obtain an OIDC token"

if [[ -n "${OIDC_TOKEN_WRONG_AUDIENCE:-}" ]]; then
    say "a token with the wrong audience is rejected"
    expect_status 401 POST "$STS_URL/sts/authkey" -H "Authorization: Bearer $OIDC_TOKEN_WRONG_AUDIENCE"
fi

say "minting a preauth key"
KEY=$(curl -sfS -X POST "$STS_URL/sts/authkey" -H "Authorization: Bearer $TOKEN")
[[ -n "$KEY" ]] || fail "empty preauth key"

say "registering a node with the minted key"
mkdir -p "$DIR/ts-state"
sudo "$TAILSCALED" --tun=userspace-networking --socket="$DIR/tailscaled.sock" \
    --statedir="$DIR/ts-state" --port=41642 > "$DIR/tailscaled.log" 2>&1 &
TS_PID=$!
for _ in $(seq 1 60); do
    [[ -S "$DIR/tailscaled.sock" ]] && break
    sleep 0.5
done
sudo "$TAILSCALE" --socket="$DIR/tailscaled.sock" up --login-server="$HS_URL" \
    --auth-key="$KEY" --hostname=integration-node --timeout=60s

say "verifying that the node is registered and tagged"
NODES=$("$HEADSCALE" -c "$DIR/headscale.yaml" nodes list --output json)
echo "$NODES" | grep -q "integration-node" || fail "node not registered: $NODES"
echo "$NODES" | grep -q "$TAG" || fail "node not tagged: $NODES"

say "PASS"
