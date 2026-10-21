"""Region guard: the public-sector profile cannot deploy outside ca-central-1 by accident."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from deployment_profile import (  # noqa: E402
    DEFAULT_REGION, RegionGuardError, load_profile, parse_top_level, resolve_region,
)


def test_public_sector_profile_pins_canada_central():
    profile = load_profile("public-sector-canada")
    assert profile["region"] == "ca-central-1"
    assert profile["region_locked"] is True
    assert resolve_region(profile, None, False) == "ca-central-1"


def test_other_region_is_refused_without_explicit_override():
    profile = load_profile("public-sector-canada")
    with pytest.raises(RegionGuardError):
        resolve_region(profile, "us-east-1", False)
    assert resolve_region(profile, "us-east-1", True) == "us-east-1"


def test_no_profile_keeps_existing_default():
    assert resolve_region(load_profile(None), None, False) == DEFAULT_REGION


@pytest.mark.parametrize("name", ["../secrets", "PUBLIC", "does-not-exist"])
def test_bad_or_missing_profile_names_fail(name):
    with pytest.raises(RegionGuardError):
        load_profile(name)


def test_fallback_parser_reads_top_level_scalars_and_lists(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_yaml)
    data = parse_top_level("region: ca-central-1  # pinned\nregion_locked: true\n"
                           "allowed_regions: [ca-central-1]\nnested:\n  key: ignored\n")
    assert data == {"region": "ca-central-1", "region_locked": True, "allowed_regions": ["ca-central-1"]}
