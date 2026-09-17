# headscale-sts

A small security token service (STS) that federates workload identities into
[headscale](https://github.com/juanfont/headscale) preauth keys.

A workload that already holds an OIDC token from its platform (GitHub
Actions, Buildkite, GitLab, Kubernetes, ...) presents it to this service;
the token is verified against configured trusted issuers and claim rules,
and a freshly minted preauth key (by default single-use, ephemeral, 5 minute
expiry, tagged) is returned. No long-lived credential needs to be stored
with the workload platform.

```
GitHub Actions              headscale-sts                headscale
      │  POST /sts/authkey        │                          │
      │  (Bearer: OIDC token)     │                          │
      ├─────────────────────────► │                          │
      │                          verify                      │
      │                 iss/aud/exp/signature,               │
      │                match claims against rules            │
      │                           │                          │
      │                           │  POST /api/v1/preauthkey │
      │                           ├────────────────────────► │
      │                           │ ◄──────── preauth key ───┤
      │ ◄────── preauth key ──────┤                          │
```

See also [headscale#3303](https://github.com/juanfont/headscale/issues/3303)
which proposes native workload identity federation support; if that lands
this service becomes unnecessary.

## API

`POST /sts/authkey` (also served at `/authkey` for prefix-stripping proxies)
with the OIDC token as a bearer token:

```
Authorization: Bearer <oidc-token>
```

Responses:

- `200` with the preauth key as a `text/plain` body
- `401` if the token is missing or fails verification
- `403` if the token is valid but no rule matches its claims
- `502` if headscale refuses to mint the key

`GET /sts/healthz` (also `/healthz`) returns `200 ok`.

## Configuration

See [config.example.yaml](config.example.yaml). Verification is fully
generic OIDC (discovery, JWKS, `iss`/`aud`/`exp`/signature via
[go-oidc](https://github.com/coreos/go-oidc)); platforms differ only in
which claims to pin in `match`:

| Platform | Typical claims to pin |
| --- | --- |
| GitHub Actions | `repository`, `ref` (or `job_workflow_ref` for tighter pinning) |
| Buildkite | `organization_slug`, `pipeline_slug` |
| GitLab | `project_path`, `ref` |
| Kubernetes | `sub` (`system:serviceaccount:<ns>:<name>`) |

Only scalar claims can be matched (arrays and objects never match). Note
that on GitHub the `sub` format is repo-customizable; prefer explicit claims
like `repository` and `ref`.

Rules must mint tagged keys (`tags` is required): tagged keys are not tied
to a headscale user, and the tag is what ACL policies key on. Requires
headscale >= 0.29 (preauth keys must be tagged or user-owned; this service
only creates tagged keys).

## Workload usage (GitHub Actions)

```yaml
permissions:
  id-token: write

steps:
  - name: Mint tailnet key via OIDC
    id: mint
    run: |
      OIDC=$(curl -sf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://headscale.julialang.org/sts" | jq -r .value)
      KEY=$(curl -sf -X POST https://headscale.julialang.org/sts/authkey \
        -H "Authorization: Bearer $OIDC")
      echo "::add-mask::$KEY"
      echo "authkey=$KEY" >> "$GITHUB_OUTPUT"

  - uses: tailscale/github-action@<pinned>
    with:
      authkey: ${{ steps.mint.outputs.authkey }}
      args: --login-server=https://headscale.julialang.org
```

## Deployment

Run on the headscale host so that the headscale API can stay bound to
localhost and the API key never leaves the machine.

Generate the headscale API key and write it to the key file (the key is
printed once at creation and stored hashed by headscale, so this is the only
chance to capture it):

```sh
headscale apikeys create --expiration 3650d \
    | sudo tee /etc/headscale-sts/apikey > /dev/null
sudo chmod 600 /etc/headscale-sts/apikey
```

If it ever expires (or is expired manually with `headscale apikeys expire`),
headscale-sts starts responding 502; the fix is to repeat the two commands
above and `systemctl restart headscale-sts` (the key is read at startup
only).

Front the service with the existing reverse proxy, e.g. (nginx):

```nginx
location /sts/ {
    proxy_pass http://127.0.0.1:8470;
}
```

Example systemd unit:

```ini
[Unit]
Description=headscale-sts
After=network-online.target headscale.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/headscale-sts --config /etc/headscale-sts/config.yaml
DynamicUser=yes
LoadCredential=apikey:/etc/headscale-sts/apikey
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

With `LoadCredential=`, systemd exposes the key at
`$CREDENTIALS_DIRECTORY/apikey` and `api_key_file` supports environment
variable expansion, so the config becomes:

```yaml
headscale:
  api_key_file: ${CREDENTIALS_DIRECTORY}/apikey
```

(Note that `%d` is a systemd unit-file specifier and cannot be used inside
config.yaml.)

## Build and test

```sh
go build .
go test ./...
```

Tests run fully offline; OIDC verification is tested against a fake issuer
served from `httptest`.
