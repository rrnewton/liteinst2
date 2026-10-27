"""Exact historical projection for the separate32-instruction native contract.

Only recorder fixtures peel this layer. Fresh qualification requires its actual
named outcome under unchanged defaults; counts or source text cannot grant it.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

import native_fixtures as fixtures
from parsing import require

PRE_ORDINARY_THIRTYTWO_CORPUS_SHA256 = '5088c4e4cc75288a7a7b13498bbcb25846fce920b3379f77b1ce0dbbd79891fb'
CURRENT_ORDINARY_THIRTYTWO_CORPUS_SHA256 = 'bf3808f67ced232b2f72d1b4bbb4fcd68224358d373f79b3cf8d58bf235a08fa'
RUST_METHODS = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests/thirtytwo.rs': ('runtime_ordinary_thirty_two_nops_fit_default_budget_and_retain_exact_history',)}
SOURCE_SHA256 = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/isolation.rs': 'c323e377e67a1ee6f9b2c347d8dea1da2cdf820a8a6786734542307403c4d1cf',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/isolation/tests.rs': 'f6bfa57b93be33f518a6b82e56d186e233ff9bb529cf82dbe204fd45e665caaa',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests.rs': '828598ae114f61df73ce811e2693769afeb383995d037eac5950626bfda6c213',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests/thirtytwo.rs': 'ea474d9f54592ba0b65f2abf52f9c42a1f587ebad31a95d7a905d66e570792ec'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_ordinary_thirtytwo_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected_hash in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "ordinary_thirtytwo_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected_hash,
                "ordinary_thirtytwo_source_inventory_differs")
        if path in RUST_METHODS:
            require(re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
                    == list(RUST_METHODS[path])
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "ordinary_thirtytwo_source_inventory_differs")


def before_ordinary_thirtytwo(declared):
    """Authenticate the full108/737 corpus, then recover the exact107/736 one."""
    require(type(declared) is dict and digest(declared) == CURRENT_ORDINARY_THIRTYTWO_CORPUS_SHA256,
            "ordinary_thirtytwo_inventory_differs")
    rows = declared["native_validation_fixtures"]
    require(type(rows) is list and len(rows) == 108
            and rows[107:] == [fixtures.ORDINARY_THIRTYTWO_ROW],
            "ordinary_thirtytwo_inventory_differs")
    fixtures.catalog(rows)
    for cohort in ("workspace_tests", "serial_launch"):
        observed = declared["harness_test_counts"][cohort][fixtures.UNIT]
        require(observed == {"tests": 737, "ignored": 0}
                and all(type(value) is int for value in observed.values()),
                "ordinary_thirtytwo_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:107]
    for cohort in ("workspace_tests", "serial_launch"):
        previous["harness_test_counts"][cohort][fixtures.UNIT]["tests"] = 736
    require(digest(previous) == PRE_ORDINARY_THIRTYTWO_CORPUS_SHA256,
            "ordinary_thirtytwo_inventory_differs")
    require_current_ordinary_thirtytwo_sources()
    return previous
