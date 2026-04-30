"""Security framework mappings for OmniScan findings enrichment.

Maps vulnerability findings to international security standards:
- OWASP Top 10 (2021)
- MITRE ATT&CK for Enterprise (v14)
- CIS Controls v8
- NIST Cybersecurity Framework (CSF) 2.0
"""

from __future__ import annotations

# ── OWASP Top 10 (2021) ────────────────────────────────────────────────────────

OWASP_TOP10: dict[str, dict] = {
    "A01:2021": {
        "title": "Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "keywords": [
            "access control", "authorization", "privilege escalation", "idor",
            "insecure direct object", "path traversal", "directory traversal",
            "csrf", "cross-site request forgery", "admin access", "unauthorized",
            "missing authorization", "broken access",
        ],
    },
    "A02:2021": {
        "title": "Cryptographic Failures",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "keywords": [
            "tls 1.0", "tls 1.1", "ssl 2", "ssl 3", "sslv2", "sslv3",
            "weak cipher", "cleartext", "plaintext password", "unencrypted",
            "weak crypto", "md5", "sha1", "certificate error", "self-signed",
            "heartbleed", "deprecated cipher",
        ],
    },
    "A03:2021": {
        "title": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
        "keywords": [
            "sql injection", "sqli", "xss", "cross-site scripting",
            "command injection", "os command", "ldap injection", "xpath",
            "template injection", "ssti", "nosql injection",
            "lfi", "rfi", "local file inclusion", "remote file inclusion",
            "code injection", "eval injection",
        ],
    },
    "A04:2021": {
        "title": "Insecure Design",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "keywords": [
            "business logic", "insecure design", "missing rate limit",
            "unrestricted upload", "predictable", "race condition",
        ],
    },
    "A05:2021": {
        "title": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "keywords": [
            "misconfiguration", "debug mode", "default password", "wp_debug",
            "stack trace", "error disclosure", "directory listing", "open port",
            "cors misconfiguration", "xml-rpc", "phpinfo", "exposed endpoint",
            "default credential", "x-frame-options", "content security policy",
            "missing header", "server information", "version disclosure",
        ],
    },
    "A06:2021": {
        "title": "Vulnerable and Outdated Components",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "keywords": [
            "outdated", "deprecated", "vulnerable version", "cve-",
            "plugin vulnerability", "old version", "end of life",
            "unpatched", "known vulnerability", "outdated core",
        ],
    },
    "A07:2021": {
        "title": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "keywords": [
            "brute force", "user enumeration", "weak password", "no lockout",
            "default login", "authentication bypass", "session fixation",
            "missing httponly", "missing secure flag", "jwt", "credential exposure",
        ],
    },
    "A08:2021": {
        "title": "Software and Data Integrity Failures",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "keywords": [
            "deserialization", "insecure deserialization", "update integrity",
            "supply chain", "auto-update", "unsigned package", "integrity check",
        ],
    },
    "A09:2021": {
        "title": "Security Logging and Monitoring Failures",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "keywords": [
            "logging failure", "no audit", "missing log", "log injection",
            "insufficient logging", "audit trail",
        ],
    },
    "A10:2021": {
        "title": "Server-Side Request Forgery",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
        "keywords": [
            "ssrf", "server-side request forgery", "internal network", "metadata service",
            "cloud metadata", "169.254",
        ],
    },
}

# ── MITRE ATT&CK for Enterprise (v14) ─────────────────────────────────────────

MITRE_ATTACK: dict[str, dict] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "keywords": [
            "sql injection", "sqli", "rce", "remote code execution",
            "command injection", "local file inclusion", "remote file inclusion",
            "deserialization", "cve-", "exploit",
        ],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "keywords": [
            "command injection", "remote code execution", "rce",
            "os command", "shell command", "commix",
        ],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "keywords": [
            "brute force", "password spray", "credential stuffing",
            "user enumeration", "xml-rpc amplification", "no lockout",
        ],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/",
        "keywords": [
            "plaintext password", "default credential", "default login",
            "hardcoded credential", "exposed credential", "credentials in url",
            "backup credential",
        ],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "keywords": [
            "directory listing", "directory traversal", "path traversal",
            "file disclosure", "backup file", "sensitive file", "git exposure",
            ".env", "backup.zip",
        ],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "keywords": [
            "ssrf", "server-side request forgery", "open redirect",
        ],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "keywords": [
            "open redirect", "url redirection", "unvalidated redirect",
            "phishing", "clickjacking",
        ],
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1574/",
        "keywords": [
            "arbitrary file upload", "file upload", "webshell", "shell upload",
            "unrestricted upload",
        ],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/",
        "keywords": [
            "privilege escalation", "permission bypass",
            "access control bypass", "broken access control",
        ],
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1203/",
        "keywords": [
            "xss", "cross-site scripting", "dom xss", "stored xss", "reflected xss",
            "dalfox",
        ],
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1539/",
        "keywords": [
            "session hijacking", "session fixation", "cookie theft",
            "missing httponly", "missing secure flag", "cookie without",
        ],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "keywords": [
            "open port", "exposed service", "service discovery",
            "version disclosure", "banner grabbing",
        ],
    },
}

# ── CIS Controls v8 ────────────────────────────────────────────────────────────

CIS_CONTROLS: dict[str, dict] = {
    "CIS-03": {
        "title": "Data Protection",
        "url": "https://www.cisecurity.org/controls/data-protection",
        "keywords": [
            "plaintext password", "unencrypted", "sensitive data",
            "information disclosure", "data exposure", "backup file",
            "cleartext",
        ],
    },
    "CIS-04": {
        "title": "Secure Configuration of Enterprise Assets and Software",
        "url": "https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software",
        "keywords": [
            "misconfiguration", "default password", "debug mode", "wp_debug",
            "phpinfo", "directory listing", "cors misconfiguration",
            "missing header", "server information",
        ],
    },
    "CIS-05": {
        "title": "Account Management",
        "url": "https://www.cisecurity.org/controls/account-management",
        "keywords": [
            "user enumeration", "brute force", "default credential",
            "default login", "authentication failure", "no lockout",
        ],
    },
    "CIS-07": {
        "title": "Continuous Vulnerability Management",
        "url": "https://www.cisecurity.org/controls/continuous-vulnerability-management",
        "keywords": [
            "outdated", "vulnerable version", "cve-", "unpatched",
            "deprecated", "end of life", "plugin vulnerability",
        ],
    },
    "CIS-12": {
        "title": "Network Infrastructure Management",
        "url": "https://www.cisecurity.org/controls/network-infrastructure-management",
        "keywords": [
            "tls 1.0", "tls 1.1", "ssl", "weak cipher",
            "certificate", "open port",
        ],
    },
    "CIS-13": {
        "title": "Network Monitoring and Defense",
        "url": "https://www.cisecurity.org/controls/network-monitoring-and-defense",
        "keywords": [
            "ssrf", "cors", "x-frame-options", "content security policy",
            "missing header", "open redirect",
        ],
    },
    "CIS-16": {
        "title": "Application Software Security",
        "url": "https://www.cisecurity.org/controls/application-software-security",
        "keywords": [
            "sql injection", "sqli", "xss", "cross-site scripting",
            "injection", "file upload", "csrf", "ssti",
            "lfi", "rfi", "deserialization", "command injection",
        ],
    },
    "CIS-18": {
        "title": "Penetration Testing",
        "url": "https://www.cisecurity.org/controls/penetration-testing",
        "keywords": [
            "critical", "rce", "remote code execution", "exploit",
        ],
    },
}

# ── NIST Cybersecurity Framework (CSF) 2.0 ────────────────────────────────────

NIST_CSF: dict[str, dict] = {
    "ID.RA-1": {
        "function": "IDENTIFY",
        "category": "Risk Assessment",
        "description": "Vulnerabilities in assets are identified, validated, and recorded",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/id/id-ra/id-ra-01/",
        "keywords": [
            "outdated", "vulnerable version", "cve-", "plugin vulnerability",
            "exposure", "unpatched",
        ],
    },
    "PR.AA-1": {
        "function": "PROTECT",
        "category": "Identity Management, Authentication, and Access Control",
        "description": "Identities and credentials for authorized users, services, and hardware are managed",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-aa/pr-aa-01/",
        "keywords": [
            "access control", "broken access control", "privilege escalation",
            "authorization bypass", "idor", "user enumeration",
        ],
    },
    "PR.DS-1": {
        "function": "PROTECT",
        "category": "Data Security",
        "description": "The confidentiality, integrity, and availability of data-at-rest are protected",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-ds/pr-ds-01/",
        "keywords": [
            "plaintext password", "unencrypted", "sensitive data",
            "backup file", "information disclosure",
        ],
    },
    "PR.DS-2": {
        "function": "PROTECT",
        "category": "Data Security",
        "description": "The confidentiality, integrity, and availability of data-in-transit are protected",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-ds/pr-ds-02/",
        "keywords": [
            "tls 1.0", "ssl", "weak cipher", "cleartext", "unencrypted",
            "certificate",
        ],
    },
    "PR.PS-2": {
        "function": "PROTECT",
        "category": "Platform Security",
        "description": "Software is maintained, replaced, and removed commensurate with risk",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-ps/pr-ps-02/",
        "keywords": [
            "outdated", "cve-", "unpatched", "deprecated",
            "vulnerable", "old version",
        ],
    },
    "PR.PS-4": {
        "function": "PROTECT",
        "category": "Platform Security",
        "description": "Log records are generated and made available for continuous monitoring",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-ps/pr-ps-04/",
        "keywords": [
            "logging failure", "missing log", "insufficient logging",
        ],
    },
    "PR.IR-1": {
        "function": "PROTECT",
        "category": "Technology Infrastructure Resilience",
        "description": "Networks and environments are protected from unauthorized logical access",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-ir/pr-ir-01/",
        "keywords": [
            "misconfiguration", "directory listing", "debug mode",
            "exposed service", "unnecessary service",
        ],
    },
    "RS.MI-3": {
        "function": "RESPOND",
        "category": "Incident Mitigation",
        "description": "Newly identified vulnerabilities are mitigated or documented as accepted risks",
        "url": "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/rs/rs-mi/rs-mi-03/",
        "keywords": [
            "sql injection", "xss", "rce", "command injection",
            "injection", "critical", "high severity",
        ],
    },
}

# ── Severity-to-SARIF level mapping ───────────────────────────────────────────

SARIF_LEVEL_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


# ── Matching logic ─────────────────────────────────────────────────────────────

def _match_frameworks(search_text: str) -> dict:
    """Return matched framework entries for a given search text (lower-case)."""
    matches: dict = {
        "owasp": [],
        "mitre_attack": [],
        "cis_controls": [],
        "nist_csf": [],
    }

    for cat_id, cat in OWASP_TOP10.items():
        if any(kw in search_text for kw in cat["keywords"]):
            matches["owasp"].append({
                "id": cat_id,
                "title": cat["title"],
                "url": cat["url"],
            })

    for tech_id, tech in MITRE_ATTACK.items():
        if any(kw in search_text for kw in tech["keywords"]):
            matches["mitre_attack"].append({
                "id": tech_id,
                "name": tech["name"],
                "tactic": tech["tactic"],
                "url": tech["url"],
            })

    for ctrl_id, ctrl in CIS_CONTROLS.items():
        if any(kw in search_text for kw in ctrl["keywords"]):
            matches["cis_controls"].append({
                "id": ctrl_id,
                "title": ctrl["title"],
                "url": ctrl["url"],
            })

    for csf_id, csf in NIST_CSF.items():
        if any(kw in search_text for kw in csf["keywords"]):
            matches["nist_csf"].append({
                "id": csf_id,
                "function": csf["function"],
                "category": csf["category"],
                "url": csf["url"],
            })

    return matches


def tag_finding_with_standards(finding: dict) -> dict:
    """Enrich a single finding dict with security framework tags in-place."""
    search_text = (
        f"{finding.get('title', '')} {finding.get('description', '')} "
        f"{finding.get('cve', '')} {finding.get('evidence', '')}"
    ).lower()

    framework_matches = _match_frameworks(search_text)
    finding.setdefault("owasp", framework_matches["owasp"])
    finding.setdefault("mitre_attack", framework_matches["mitre_attack"])
    finding.setdefault("cis_controls", framework_matches["cis_controls"])
    finding.setdefault("nist_csf", framework_matches["nist_csf"])
    return finding


def tag_findings_with_standards(findings: list[dict]) -> list[dict]:
    """Enrich a list of findings with security framework tags in-place."""
    for finding in findings:
        tag_finding_with_standards(finding)
    return findings
