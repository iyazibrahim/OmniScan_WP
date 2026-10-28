# Dokploy deploy notes

DP Security Platform is meant to run as a **Docker Compose** application in Dokploy (not Stack/Swarm — this compose builds the image).

## Dokploy settings

| Setting | Value |
| --- | --- |
| Type | Docker Compose |
| Compose file | `docker-compose.yml` |
| Domain / port | Point the domain at container port **5000** |
| Environment | Set `DP_SECURITY_PLATFORM_SECRET_KEY` to a long random string |

Optional env:

```bash
UPDATE_NUCLEI_TEMPLATES=0
NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
DP_SECURITY_PLATFORM_SECRET_KEY=<strong-secret>
```

## Why named volumes (not `./config`)

Dokploy Autodeploy runs `git clone` into the app code directory on every deploy and clears that folder. Bind mounts like `./config:/app/config` or `./reports:/app/reports` lose data (or go empty) after the next deploy.

This compose therefore uses Docker named volumes only:

| Volume name | Mount | Purpose |
| --- | --- | --- |
| `dp-security-platform-config` | `/app/config` | Auth, tokens, targets, scan settings |
| `dp-security-platform-scan-data` | `/app/reports` | HTML/JSON reports + raw tool output |
| `dp-security-platform-logs` | `/app/logs` | App / gunicorn logs |

On first create, Docker seeds an empty volume from files already in the image (default JSON under `/app/config`).

Do **not** switch these back to `./…` paths. If you need host-editable files in Dokploy, use Advanced → Mounts with `../files/...` paths instead of repository-relative binds.

## Volume Backups

In Dokploy → Volume Backups, enable backups for:

- `dp-security-platform-config` (credentials / targets)
- `dp-security-platform-scan-data` (reports)

Named volumes are required for that feature; bind mounts are not backed up.

## First deploy after switching from bind mounts

If an older deploy still used `./config` or `./reports` under the Dokploy code directory, copy that data into the volumes once before deleting the old trees:

```bash
# After the new compose is up
docker cp /path/to/old/config/. dp-security-platform:/app/config/
docker cp /path/to/old/reports/. dp-security-platform:/app/reports/
```

Then open the dashboard, confirm login and an existing report, and remove leftover host copies so malware scanners stop matching raw scan files.

## Host malware allowlist

See [host-scanner-exception.md](host-scanner-exception.md). Resolve the reports volume path with:

```bash
docker volume inspect dp-security-platform-scan-data --format '{{ .Mountpoint }}'
docker compose exec dp-security-platform /app/docker/tool-inventory.sh
```
