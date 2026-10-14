"""Deployment profiles and the region guard.

A profile in config/<name>.yaml can pin the stack to a region. When
region_locked is true, synthesizing for any other region fails unless the
operator passes -c allow_region_override=true, so a public-sector profile
cannot be deployed outside its region by accident.

Only top-level scalar keys and inline lists are read here, so the CDK app needs
no YAML dependency. PyYAML is used when it happens to be installed.
"""

import os
import re
from typing import Any, Dict, Optional

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
DEFAULT_REGION = "us-east-1"


class RegionGuardError(SystemExit):
    """Raised (as a clean CLI exit) when a locked profile targets another region."""


def _scalar(text: str) -> Any:
    text = text.split(" #", 1)[0].strip()
    if text.startswith("[") and text.endswith("]"):
        return [item.strip().strip("'\"") for item in text[1:-1].split(",") if item.strip()]
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    return text.strip("'\"")


def parse_top_level(text: str) -> Dict[str, Any]:
    try:
        import yaml  # optional
        data = yaml.safe_load(text) or {}
        return data if isinstance(data, dict) else {}
    except ImportError:
        pass
    result: Dict[str, Any] = {}
    for line in text.splitlines():
        if not line or line[0] in " \t#":
            continue  # nested keys and comments are not needed by the guard
        match = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
        if match and match.group(2):
            result[match.group(1)] = _scalar(match.group(2))
    return result


def load_profile(name: Optional[str]) -> Dict[str, Any]:
    if not name:
        return {}
    if not re.fullmatch(r"[a-z0-9-]+", name):
        raise RegionGuardError(f"invalid profile name {name!r}")
    path = os.path.join(CONFIG_DIR, f"{name}.yaml")
    if not os.path.exists(path):
        raise RegionGuardError(f"deployment profile not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        profile = parse_top_level(fh.read())
    profile["_name"] = name
    return profile


def resolve_region(profile: Dict[str, Any], requested: Optional[str], allow_override: bool) -> str:
    """Pick the deployment region and enforce a locked profile's region."""
    pinned = profile.get("region")
    region = requested or pinned or DEFAULT_REGION
    if profile.get("region_locked"):
        allowed = profile.get("allowed_regions") or ([pinned] if pinned else [])
        if region not in allowed and not allow_override:
            raise RegionGuardError(
                f"profile {profile.get('_name')!r} is locked to {allowed}; refusing to deploy to {region}. "
                "Pass -c allow_region_override=true only if this is intentional.")
    return region
