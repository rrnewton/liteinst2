"""Fixed scalar recipe identity; no process, loader or native authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from pathlib import Path
import re
from typing import NamedTuple

PREFIX = 'evaluation/ordinary-leaf-set-whole-session/'
OLD = 'evaluation/ordinary-leaf-set-session/'
CATALOG = '68836b6094e77ff46412d18c7f4db6fe24ed12a487e487648edddcdbe6877470'
OLD_CATALOG = '7f2faf14fd394bf6b4a3a40acb116cd03608b2756f6198594e00f03edcbe57ff'
CONTROLS = (
    'test_fixed_bindings_and_default_catalog_are_literal',
    'test_whole_catalog_keeps_all_24_and_120_bytes_and_counts',
    'test_plan_profile_hash_paths_and_policies_before_import',
    'test_table_policy_guard_covers_va_order_and_unselected_last',
    'test_receipt_identity_precedes_custody_release_and_closed_failure',
    'test_bootstrap_deadline_source_locality_and_inventory',
)
SOURCES = tuple(PREFIX + name for name in (
    'reproduce.py', 'produce.py', 'catalog.py', 'profile.py', 'profile_controls.py', 'README.md')) + tuple(
    OLD + name for name in ('reproduce.py', 'produce.py', 'catalog.py', 'output.py'))


class ProfileBinding(NamedTuple):
    identity: str
    catalog_path: str
    catalog_sha256: str
    producer_path: str
    policies: tuple
    status: str

    def fields(self):
        return profile_fields(self)

    def check_plan(self, plan):
        check_plan(self, plan)

    def check_result(self, plan, result):
        check_result(self, plan, result)

    def check_sources(self, root, pins):
        check_sources(self, root, pins)

    def required_sources(self):
        validate(self)
        return SOURCES

    def control_names(self):
        validate(self)
        return CONTROLS


def whole_binding():
    return ProfileBinding('leaf-set-whole-session-v1', PREFIX + 'catalog.py', CATALOG,
                          PREFIX + 'produce.py', ('certified', 'whole', 'whole', 'whole'),
                          'LEAF_SET_WHOLE_FUNCTIONAL_PASS')


def validate(binding):
    assert type(binding) is ProfileBinding and binding == whole_binding()
    assert all(type(getattr(binding, key)) is str for key in (
        'identity', 'catalog_path', 'catalog_sha256', 'producer_path', 'status'))
    assert type(binding.policies) is tuple and all(type(p) is str for p in binding.policies)


def profile_fields(binding):
    validate(binding)
    return dict(profile=binding.identity, catalog_sha256=binding.catalog_sha256,
                policies=list(binding.policies), producer=binding.producer_path)


def check_plan(binding, plan):
    for key, value in profile_fields(binding).items():
        assert type(plan[key]) is type(value) and plan[key] == value


def check_result(binding, plan, result):
    check_plan(binding, plan)
    check_plan(binding, result)


def check_sources(binding, root, pins):
    validate(binding)
    assert isinstance(root, Path) and root.is_absolute() and type(pins) is dict
    def digest(relative):
        value = pins[str(root / relative)]
        if type(value) is dict:
            assert set(value) == {'bytes', 'sha256'} and type(value['bytes']) is int and value['bytes'] >= 0
            value = value['sha256']
        assert type(value) is str and re.fullmatch('[0-9a-f]{64}', value)
        return value
    for relative in SOURCES:
        digest(relative)
    assert digest(binding.catalog_path) == binding.catalog_sha256
    assert digest(OLD + 'catalog.py') == OLD_CATALOG
