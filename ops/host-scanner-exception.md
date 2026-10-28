# Host malware scanner exception pack

Use this note when a VPS / host malware product (ImunifyAV, ClamAV, BitNinja, provider panel, and similar) flags DP Security Platform.

## What this host is

DP Security Platform is an authorized security assessment appliance. It intentionally installs and runs open-source recon and vulnerability scanners (SQLMap, Nuclei, Nikto, Commix, Dalfox, WPScan, and others). Host alerts that name those tools, their templates, or raw scan artifacts are expected detections of the tools themselves, not an infected website.

## What to exclude

Do **not** exclude:

- All of `/var/lib/docker`
- The whole home directory or project tree
- Overlay paths under `/var/lib/docker/overlay2/...` (they change on every rebuild)

Do exclude:

1. **Signature / hacktool detections** for the assessment tools listed below (preferred).
2. **One stable volume path** for raw scan output — the named Docker volume `dp-security-platform-scan-data` mounted at `/app/reports` inside the container.

Resolve the host path after deploy (works the same under Dokploy Compose):

```bash
docker volume inspect dp-security-platform-scan-data --format '{{ .Mountpoint }}'
```

That Mountpoint is the only filesystem path that should be ignored for report noise. It survives image rebuilds and Dokploy Autodeploy clones.

Related persist volumes (usually no hacktool signatures, but useful for backups):

- `dp-security-platform-config` → `/app/config`
- `dp-security-platform-logs` → `/app/logs`

Dokploy deploy steps: [dokploy.md](dokploy.md).

## Tool inventory (for hash allowlists)

Inside the running container:

```bash
docker compose exec dp-security-platform /app/docker/tool-inventory.sh
```

Attach the script output to the ticket when the panel wants file hashes. Re-run after every `docker compose build` — binary and template hashes change.

Paths that commonly match hacktool signatures:

| Path | Purpose |
| --- | --- |
| `/usr/bin/sqlmap`, `/usr/share/sqlmap` | SQL injection assessment |
| `/usr/local/bin/nuclei` | Template-based vulnerability scanner |
| `/opt/nuclei-templates` | Nuclei templates (pinned path) |
| `/opt/tools/commix` | Command-injection checks |
| `/opt/tools/nikto` | Web server checks |
| `/usr/local/bin/dalfox` | XSS assessment |
| WPScan gem under `/var/lib/gems` (or similar) | WordPress assessment |

## Suggested ticket wording

> Please allowlist DP Security Platform on this host. It is an authorized security assessment appliance. Alerts for SQLMap, Nuclei templates, Commix, Nikto, Dalfox, and WPScan are the installed tools, not malware. Prefer signature ignores for those hacktool detections. Also exclude only the Docker volume mountpoint for `dp-security-platform-scan-data` (raw scan reports). Do not exclude all of `/var/lib/docker` or overlay2 paths. Hash inventory is attached from `tool-inventory.sh`.

## Operator notes

- Raw scan output lives in the named volume, not in the project folder bind-mounts (`./config`, `./logs` remain on the host).
- Nuclei templates are baked and run from `/opt/nuclei-templates` so allowlists can name one fixed path.
- After migrating from an older bind-mounted `./reports`, delete the old host `./reports` tree once the volume copy is verified; leftover nuclei/sqlmap files on the host keep triggering alerts.
