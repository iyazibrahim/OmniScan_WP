#!/usr/bin/env bash
# Print path, sha256, and purpose for signature-heavy assessment tools.
# Attach this output to a host malware-scanner allowlist ticket.
# Re-run after every image rebuild — hashes change when binaries/templates update.
set -euo pipefail

printf '%-60s  %-64s  %s\n' "PATH" "SHA256" "PURPOSE"
printf '%s\n' "----------------------------------------------------------------------------------------------------------------------------------"

hash_one() {
  local path="$1"
  local purpose="$2"
  if [[ ! -e "${path}" ]]; then
    printf '%-60s  %-64s  %s\n' "${path}" "(missing)" "${purpose}"
    return 0
  fi
  if [[ -d "${path}" ]]; then
    # Directory fingerprint: sorted content hashes of regular files (capped).
    local digest
    digest="$(
      find "${path}" -type f -print0 2>/dev/null \
        | sort -z \
        | head -z -n 5000 \
        | xargs -0 sha256sum 2>/dev/null \
        | sha256sum \
        | awk '{print $1}'
    )"
    printf '%-60s  %-64s  %s\n' "${path}/" "${digest:-(empty)}" "${purpose} (dir fingerprint)"
    return 0
  fi
  local digest
  digest="$(sha256sum "${path}" | awk '{print $1}')"
  printf '%-60s  %-64s  %s\n' "${path}" "${digest}" "${purpose}"
}

hash_one "/usr/bin/sqlmap" "SQLMap CLI (apt)"
hash_one "/usr/share/sqlmap" "SQLMap package data"
hash_one "/usr/local/bin/nuclei" "Nuclei scanner binary"
hash_one "/opt/nuclei-templates" "Nuclei vulnerability templates"
hash_one "/usr/local/bin/dalfox" "Dalfox XSS scanner"
hash_one "/opt/tools/commix" "Commix command-injection scanner"
hash_one "/opt/tools/nikto" "Nikto web server scanner"
hash_one "/opt/tools/joomscan" "JoomScan CMS scanner"
hash_one "/opt/tools/CMSmap" "CMSmap CMS scanner"
hash_one "/opt/tools/whatweb" "WhatWeb fingerprinting"
hash_one "/opt/tools/Corsy" "Corsy CORS checker"
hash_one "/usr/local/bin/httpx" "ProjectDiscovery httpx"
hash_one "/usr/local/bin/ffuf" "ffuf fuzzer"
hash_one "/usr/local/bin/feroxbuster" "Feroxbuster content discovery"
hash_one "/usr/local/bin/katana" "Katana crawler"
hash_one "/usr/local/bin/gau" "gau URL discovery"
hash_one "/usr/local/bin/subfinder" "Subfinder subdomain discovery"
hash_one "/usr/local/bin/wapiti" "Wapiti wrapper"
hash_one "/usr/local/bin/wpscan" "WPScan CMS scanner"

# WPScan gem path varies by Ruby version; pick the first match.
wpscan_gem="$(find /var/lib/gems /usr/local/lib/ruby/gems /usr/lib/ruby/gems -type d -path '*/gems/wpscan-*' 2>/dev/null | head -n 1 || true)"
if [[ -n "${wpscan_gem}" ]]; then
  hash_one "${wpscan_gem}" "WPScan Ruby gem"
else
  printf '%-60s  %-64s  %s\n' "(wpscan gem)" "(not found)" "WPScan Ruby gem"
fi

echo
echo "Volume tip: exclude only the named scan-data mount, not all of /var/lib/docker."
echo "  docker volume inspect dp-security-platform-scan-data --format '{{ .Mountpoint }}'"
