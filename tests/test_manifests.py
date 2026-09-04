"""Contract test: every registered module has a complete Learning Manifest.

An under-documented module fails here — enforcing PRD §8.3 ("a module is
incomplete until it explains its traffic, options, output, uncertainty, ...").
"""

import pytest

from reconscope.education.manifest import validate_manifest
from reconscope.modules.registry import list_modules


@pytest.mark.parametrize("module", list_modules(), ids=lambda m: m.module_id)
def test_module_manifest_is_release_ready(module):
    manifest = module.manifest
    assert manifest.module_id == module.module_id
    problems = validate_manifest(manifest)
    assert problems == [], f"{module.module_id}: {problems}"


@pytest.mark.parametrize("module", list_modules(), ids=lambda m: m.module_id)
def test_module_declares_intensity_and_interaction(module):
    assert module.interaction.value in ("passive", "active")
    assert module.intensity.value in ("quiet", "moderate", "loud")
    assert module.accepted_target_types
