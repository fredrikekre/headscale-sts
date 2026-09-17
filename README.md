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

The [Makefile](Makefile) deploys everything (privileged commands run with
sudo unless make is invoked as root):

```sh
make install VERSION=v0.1.0
```

which, via individual file targets:

- downloads the release binary for the host architecture, verifies it
  against `SHA256SUMS` and installs it as `/usr/local/bin/headscale-sts`
- installs [headscale-sts.service](headscale-sts.service) (a hardened unit:
  `DynamicUser` and the API key passed via `LoadCredential=`, exposed to the
  service under `$CREDENTIALS_DIRECTORY` which the example config refers to)
- installs a locally created (gitignored) `config.yaml` — start from
  [config.example.yaml](config.example.yaml) — as
  `/etc/headscale-sts/config.yaml` (0644), re-installing it whenever the
  local file changes
- generates the headscale API key with
  `headscale apikeys create --expiration 3650d` into
  `/etc/headscale-sts/apikey` (0600) if missing (the key is printed once at
  creation and stored hashed by headscale, so it can never be re-read later)
- enables and starts the service

The apikey target never overwrites an existing file, so `make install` is
safe to re-run (e.g. to upgrade the binary with a new `VERSION=`, or to push
a config change; follow with `make restart`). To rotate the API key:
`sudo rm /etc/headscale-sts/apikey && make install restart`. If the key ever
expires (or is expired manually with `headscale apikeys expire`),
headscale-sts starts responding 502 and the same rotation fixes it — the
key is read at service startup only.

Front the service with the existing reverse proxy, e.g. (nginx):

```nginx
location /sts/ {
    proxy_pass http://127.0.0.1:8470;
}
```

## Build and test

```sh
go build .
go test ./...
```

or install directly:

```sh
go install github.com/fredrikekre/headscale-sts@latest
```

Pushing a `v*` tag builds static linux amd64/arm64 binaries (stamped with
the version, see `headscale-sts -version`) and publishes them with a
SHA256SUMS file as a GitHub release:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Tests run fully offline; OIDC verification is tested against a fake issuer
served from `httptest`.
