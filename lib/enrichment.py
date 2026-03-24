"""Finding enrichment using the remediation database."""

from pathlib import Path

from lib.config import load_json, REMEDIATION_DB_FILE


def _load_remediation_db() -> dict:
    """Load the remediation database."""
    data = load_json(REMEDIATION_DB_FILE)
    if isinstance(data, dict):
        return data
    return {"categories": {}, "keyword_to_category_map": {}}


def _match_category(finding: dict, keyword_map: dict, categories: dict) -> dict | None:
    """Match a finding to a remediation category by keyword search."""
    search_text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()

    for keyword, cat_key in keyword_map.items():
        if keyword.lower() in search_text:
            cat = categories.get(cat_key)
            if cat:
                return cat
    return None


def enrich_findings(findings: list[dict]) -> list[dict]:
    """Enrich findings with remediation info from the database.

    - Assigns sequential IDs
    - Matches fix steps and references from remediation-db.json
    - Sorts by severity (critical > high > medium > low > info)
    """
    db = _load_remediation_db()
    categories = db.get("categories", {})
    keyword_map = db.get("keyword_to_category_map", {})
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    enriched = []
    for f in findings:
        match = _match_category(f, keyword_map, categories)

        if match:
            # Apply remediation data
            if not f.get("fix") or f["fix"] == "":
                f["fix"] = match.get("fix_summary", "")
            if not f.get("fix_steps"):
                f["fix_steps"] = match.get("fix_steps", [])
            if not f.get("references"):
                f["references"] = match.get("references", [])
            # Upgrade severity if the DB has a higher one
            db_sev = match.get("severity", "info")
            if sev_order.get(db_sev, 4) < sev_order.get(f["severity"], 4):
                f["severity"] = db_sev
        else:
            # No match - provide a generic fix
            if not f.get("fix"):
                f["fix"] = "Review this finding manually and apply appropriate security measures."

        enriched.append(f)

    # Sort by severity
    enriched.sort(key=lambda x: sev_order.get(x["severity"], 4))

    # Assign IDs
    for i, f in enumerate(enriched, 1):
        f["id"] = f"VULN-{i:03d}"

    return enriched
