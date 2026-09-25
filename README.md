# OldGrid.io — AMP template

Canonical source of this tree: `deployment/amp-template/` in private `carthorsestudios/poobiverse-classic`.

Public deployment repository: https://github.com/carthorsestudios/poobiverse-classic-amp-template

Private main release publication does **not** automatically push this tree to the public template repository. Synchronize the public repo from the accepted private tree before AMP Fetch/refresh for a new release family.

AMP configuration-repository syntax, from CubeCoders' Generic module documentation (`user/repo:branch`):

`carthorsestudios/poobiverse-classic-amp-template:main`

In AMP: Configuration → Instance Deployment → Configuration Repositories → Add that source → Fetch. Refresh the browser, then create a separate OldGrid.io instance. Do not submit this repository to CubeCoders' community template repo, and do not change the Scratch instance.

Private game source and release assets stay in `carthorsestudios/poobiverse-classic`.

## Contents

AMP manifest, KVP, config, ports, an empty updates list, the pinned Start bootstrap, and the stdlib Python controller. No game source, private binaries, accounts, databases, or tokens.

## Process chain

```
AMP executable
  -> /bin/bash -lc <base64 Start wrapper>
    -> verified control/poobiverse_amp.py
      -> releases/<buildId>/run.sh
        -> runtime/bin/node server/dist/index.js
```

## Fields

| Display name | Field | Env | First value |
|--------------|-------|-----|-------------|
| Web Port | `$WebPort` | `PORT` | `9092` if that port is free inside the container |
| Bind Address | `BindAddress` | `HOST` | `127.0.0.1` for the verified host-Tunnel deployment; use `0.0.0.0` only when container/NAT topology requires it |
| Data Directory | `DataDir` | `POOBIVERSE_DATA_DIR` | external persistent directory, not a release tree |
| Allowed Origins | `AllowedOrigins` | `POOBIVERSE_ALLOWED_ORIGINS` | `https://oldgrid.io,https://www.oldgrid.io` |
| GitHub Release Token | `GitHubToken` | `POOBIVERSE_GITHUB_TOKEN` | fine-grained token, this private repo, Contents: read; enter in AMP only |
| Release Tag Override | `ReleaseTagOverride` | `POOBIVERSE_RELEASE_TAG` | pin the first reviewed tag; later blank means latest |
| Trusted Proxy IPs | `TrustedProxyIps` | `POOBIVERSE_TRUSTED_PROXY_IPS` | empty until the direct cloudflared peer is observed |

The host or container needs Linux x86_64 plus `python3`, `bash`, `base64`, a SHA-256 tool, and `curl`/`wget` or Python urllib. No npm, pip, apt, or host Node on Start.

Routine update: reviewed private `main` → green release → AMP Restart. Rollback is code-only and keeps the external world. Do not delete world data to force a start.

Verified production topology: OldGrid binds `127.0.0.1:9092`, Cloudflare Tunnel targets `http://127.0.0.1:9092`, and the direct trusted proxy peer is `127.0.0.1`. Container/NAT deployments may require a different bind/peer and must re-observe them. Real AMP Stop/Restart remains operator work.
