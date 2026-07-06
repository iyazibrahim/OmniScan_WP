"""Shared branding constants and logo helpers."""

from __future__ import annotations

from pathlib import Path

PRODUCT_NAME = "DP Security Platform"
PRODUCT_SHORT_NAME = "DP Security"
ORGANIZATION_NAME = "Digital Penang"
ORGANIZATION_TEAM = "Digital Penang Cybersecurity Team"
SERVICE_SLUG = "dp-security-platform"
LOG_FILE_NAME = f"{SERVICE_SLUG}.log"
VERSION_LABEL = "v3.0"
REPORT_TITLE = "Security Assessment Report"
REPORT_SUBTITLE = "Formal assessment summary for authorized security testing"
REPORT_TAGLINE = "Securing Our Digital Future"
REPORT_LIGHT_TEXT = "#14345f"

_BASE_DIR = Path(__file__).resolve().parent.parent
WHITE_LOGO_PATH = _BASE_DIR / "web" / "assets" / "dp-logo-white-text.svg"
ICON_LOGO_PATH = _BASE_DIR / "web" / "assets" / "dp-favicon.svg"
FAVICON_HREF = "/assets/dp-favicon.svg"


def _load_logo_source() -> str:
    return WHITE_LOGO_PATH.read_text(encoding="utf-8")


def get_favicon_link_html(*, relative: bool = False) -> str:
    """Return a favicon link tag for HTML pages."""
    href = "assets/dp-favicon.svg" if relative else FAVICON_HREF
    return f'<link rel="icon" href="{href}" type="image/svg+xml">'


def get_logo_svg(variant: str = "white") -> str:
    """Return the Digital Penang SVG for inline embedding."""
    svg = _load_logo_source()
    if variant == "white":
        return svg
    if variant == "dark":
        return svg.replace('fill="white"', f'fill="{REPORT_LIGHT_TEXT}"')
    raise ValueError(f"Unsupported logo variant: {variant}")


def assessment_profile_label(profile: str) -> str:
    profile_map = {
        "auto": "Adaptive Assessment",
        "wordpress": "WordPress Security Assessment",
        "joomla": "Joomla Security Assessment",
        "drupal": "Drupal Security Assessment",
        "webapp": "External Web Application Assessment",
        "api": "API Security Assessment",
    }
    return profile_map.get(str(profile or "").strip().lower(), "Security Assessment")
