"""Exact historical projection for the added in-process crate only.

Production drivers consume the complete corpus. This helper authenticates both
whole corpora, then removes only the new six-test unit and empty doc harnesses.
"""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from core_c7a3e1e_inventory import before_core_c7a3e1e, source_before_core_c7a3e1e

PRE_INPROCESS_CORPUS_SHA256 = 'ccc0d245bd3d006e7ac64f039f1725e8d538aae33c972d49b722626899146b57'
CURRENT_INPROCESS_CORPUS_SHA256 = '25b48766c6213887ac19e799fc0329ef01973d2ade44e2a9cf8e4e722d4fdbd5'
ADDED_HARNESSES = {'unit/liteinst_inprocess/lib': {'ignored': 0, 'tests': 6}, 'doc/liteinst_inprocess': {'ignored': 0, 'tests': 0}}
RUST_TEST_PATH = 'crates/liteinst-inprocess/src/plan/tests.rs'
RUST_TEST_SHA256 = '4a8612179e045aa621cd8d348aff2e86703bc30f7eacec2333c4ff669643ef9e'
RUST_METHODS = ('complete_cross_page_fetch_requires_both_pages', 'boundary_call_fetch_does_not_require_return_page', 'metadata_refuses_unbounded_or_incomplete_extents', 'cross_page_fault_authenticates_saved_head_and_fault_extent', 'data_foreign_and_non_native_faults_never_authenticate', 'complete_byte_comparison_rejects_every_changed_position')
NEW_SOURCE_SHA256 = {RUST_TEST_PATH: RUST_TEST_SHA256, "crates/liteinst-inprocess/Cargo.toml": '4394a131aee87a1a7885d76f25648c506c26fb668cad7723ca2be6ebbd9863c6'}
SOURCE_PROJECTIONS = {'Cargo.toml': {'current_sha256': 'a7df2371afa488062bd99edc3e01da5a5f085925055982e1b124c0f0df2d03f3', 'previous_sha256': 'cc8da284807082bbe47c265a4830ffced4bd173f95a9e2571ecdec6f568130c6', 'current': '"tools/elf-rewrite", "crates/liteinst-inprocess"]', 'previous': '"tools/elf-rewrite"]'}, 'Cargo.lock': {'current_sha256': 'e3a920f1f54ddf4cf91f484e1b795848c7303340964bb62229e299029412afe3', 'previous_sha256': 'd8f447b6869ecbb2638a96a82034e1c6485a00d4e0406ff547715e5d67db51b8', 'current': '[[package]]\nname = "liteinst-inprocess"\nversion = "0.1.0"\ndependencies = [\n "libc",\n "liteinst2",\n]\n\n[[package]]\nname = "liteinst-launch"', 'previous': '[[package]]\nname = "liteinst-launch"'}}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_before_inprocess(path, data, error):
    """Authenticate each exact new Cargo file before its one literal inverse."""
    data = source_before_core_c7a3e1e(path, data, error)
    if path not in SOURCE_PROJECTIONS:
        return data
    row = SOURCE_PROJECTIONS[path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row["current_sha256"], error)
    current, previous = row["current"].encode(), row["previous"].encode()
    require(data.count(current) == 1, error)
    restored = data.replace(current, previous, 1)
    require(hashlib.sha256(restored).hexdigest() == row["previous_sha256"], error)
    return restored


def before_inprocess_baseline(declared):
    require(type(declared) is dict and digest(declared) == CURRENT_INPROCESS_CORPUS_SHA256,
            "inprocess_inventory_differs")
    previous = copy.deepcopy(declared)
    for identity, expected in ADDED_HARNESSES.items():
        require(previous["harness_test_counts"]["workspace_tests"].pop(identity) == expected,
                "inprocess_inventory_differs")
    require(digest(previous) == PRE_INPROCESS_CORPUS_SHA256, "inprocess_inventory_differs")
    root = Path(__file__).resolve().parents[2]
    for path, expected in NEW_SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "inprocess_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected,
                "inprocess_source_inventory_differs")
        if path == RUST_TEST_PATH:
            require(re.findall(r"#\[test\]\s*fn\s+(\w+)\(", source) == list(RUST_METHODS)
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "inprocess_source_inventory_differs")
    return previous


def before_inprocess(declared):
    """Peel the current core addition before the exact historical crate layer."""
    return before_inprocess_baseline(before_core_c7a3e1e(declared))
