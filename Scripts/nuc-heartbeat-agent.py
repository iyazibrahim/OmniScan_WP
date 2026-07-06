"""Lightweight heartbeat agent for office NUC or branch hosts.

Usage:
  python Scripts/nuc-heartbeat-agent.py ^
    --server https://example.com ^
    --agent-id office-nuc-01 ^
    --agent-secret <secret> ^
    --site-name HQ ^
    --interval 60
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime


def _collect_metrics() -> dict:
    usage = shutil.disk_usage(os.getcwd())
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "disk_free_mb": round(usage.free / (1024 * 1024), 1),
        "disk_used_mb": round(usage.used / (1024 * 1024), 1),
    }


def _post_heartbeat(server: str, payload: dict) -> tuple[bool, str]:
    request = urllib.request.Request(
        server.rstrip("/") + "/api/monitoring/heartbeat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        return True, str(data.get("message") or "ok")
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send periodic heartbeat updates to DP Security Platform.")
    parser.add_argument("--server", required=True, help="Base URL for DP Security Platform, e.g. https://monitor.example.com")
    parser.add_argument("--agent-id", required=True, help="Heartbeat agent_id configured in monitoring asset metadata")
    parser.add_argument("--agent-secret", required=True, help="Heartbeat secret configured in monitoring asset metadata")
    parser.add_argument("--site-name", default="", help="Optional site name for this NUC or office system")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between heartbeat sends")
    args = parser.parse_args()

    boot_time = datetime.now(UTC).isoformat()
    hostname = socket.gethostname()

    while True:
        payload = {
            "agent_id": args.agent_id,
            "agent_secret": args.agent_secret,
            "hostname": hostname,
            "site_name": args.site_name,
            "sent_at": datetime.now(UTC).isoformat(),
            "boot_time": boot_time,
            "local_ip": socket.gethostbyname(hostname),
            "metrics": _collect_metrics(),
        }
        ok, message = _post_heartbeat(args.server, payload)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{stamp}] {'OK' if ok else 'FAIL'} {message}", flush=True)
        time.sleep(max(15, args.interval))


if __name__ == "__main__":
    sys.exit(main())
