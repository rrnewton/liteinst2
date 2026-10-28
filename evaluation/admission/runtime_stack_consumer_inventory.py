"""Closed historical projection for the separate runtime-stack C evaluators.

Synthetic recorder controls only. This module does not alter current corpus
acceptance, execute a feature/native test, or qualify a consumer experiment.
"""

import ast
import copy
import hashlib
import json
from pathlib import Path

from parsing import require
from core_cc846_inventory import peel_python

PRE_RUNTIME_STACK_CONSUMER_CORPUS_SHA256 = 'f6bdba51926d868460764db440f1d084eb5228b3cd32f1cbee52cc6236e8ed24'
OLD_PYTHON305_SHA256 = 'b48c3f3f5c2e33915767d3f31e0032fbd79ccafa23138cfa624e7520adcd8089'
PYTHON_MODULES = {'test_runtime_stack_consumer': ('test_runtime_stack_consumer.RuntimeStackConsumerTests.test_public_summary_exact_kernel_contract', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_public_scope_and_terminal_argument', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_oracle_protocol_roles', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_inspect_closed_path_and_identity', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_oracle_raw_schedule', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_oracle_admitted_separate_inventories', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_oracle_accounting_no_refund', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_oracle_comparison_and_cleanup', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_rows_duplicate_unknown_private_and_mistyped', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_failed_prefix_never_qualifies', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_thirteen_commands_and_late_digest_binding', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_reference_and_outer_cleanup', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_both_prerequisites_require_exact_source_and_environment', 'test_runtime_stack_consumer.RuntimeStackConsumerTests.test_experiment_requires_every_role_and_pin'), 'test_runtime_stack_consumer_inventory': ('test_runtime_stack_consumer_inventory.RuntimeStackConsumerInventoryTests.test_current_corpus_and_methods_reconstruct_exact_old_history', 'test_runtime_stack_consumer_inventory.RuntimeStackConsumerInventoryTests.test_projection_refuses_changed_fields_counts_and_identities', 'test_runtime_stack_consumer_inventory.RuntimeStackConsumerInventoryTests.test_source_census_refuses_missing_extra_or_renamed_methods'), 'test_runtime_stack_feature_controls': ('test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_inventory_is_closed_final_and_source_bound', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_inventory_refuses_native_duplicates_and_default_count_drift', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_source_guard_requires_every_test_exactly', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_capture_requires_exact_named_cohort_and_filtered_count', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_capture_refuses_unknown_duplicate_ignored_nested_and_partial', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_failed_command_never_qualifies_complete_rows', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_receipt_binds_source_environment_limits_and_runner', 'test_runtime_stack_feature_controls.RuntimeStackFeatureControlsTests.test_feature_authentication_replays_actual_hash_bound_capture')}
PYTHON_METHODS = tuple(name for methods in PYTHON_MODULES.values() for name in methods)
CURRENT_RECORDER_TESTS = 330
CURRENT_PYTHON330_SHA256 = 'fb8adb475b7ecbafb984dfa99c674f8a60fdb59fbb5adeb5754482e1136bb3bc'
CURRENT_RUNTIME_STACK_CONSUMER_CORPUS_SHA256 = '5ace8d0218e9872689c6573f5ccd1e8ed137dcd6651a34925c7454e2d244f7da'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_runtime_stack_consumer_python(identities):
    """Authenticate all 25 additions and the entire ordered old 305-name list."""
    identities = peel_python(identities)
    require(type(identities) is list and len(identities) == CURRENT_RECORDER_TESTS
            and all(type(value) is str for value in identities)
            and len(set(identities)) == len(identities)
            and digest(identities) == CURRENT_PYTHON330_SHA256, "runtime_stack_consumer_source_inventory_differs")
    old = [value for value in identities if value.split(".", 1)[0] not in PYTHON_MODULES]
    new = [value for value in identities if value.split(".", 1)[0] in PYTHON_MODULES]
    require(new == list(PYTHON_METHODS) and len(old) == 305
            and digest(old) == OLD_PYTHON305_SHA256, "runtime_stack_consumer_source_inventory_differs")
    return old


def python_source_identities():
    """Read declarations only, preserving the established file/source order."""
    identities = []
    try:
        for path in sorted(Path(__file__).parent.glob("test_*.py")):
            for cls in ast.parse(path.read_text()).body:
                if isinstance(cls, ast.ClassDef):
                    identities.extend(path.stem + "." + cls.name + "." + method.name
                                      for method in cls.body
                                      if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                                      and method.name.startswith("test_"))
    except (OSError, UnicodeError, SyntaxError):
        require(False, "runtime_stack_consumer_source_inventory_differs")
    return peel_python(identities)


def require_current_runtime_stack_consumer_sources():
    before_runtime_stack_consumer_python(python_source_identities())


def before_runtime_stack_consumer(declared):
    """Validate the whole new corpus before exposing the exact old 305 corpus.

    This entry accepts only the current 330 catalog. A second peel, the old
    corpus, a guessed 327 count, or an altered unrelated field must refuse.
    """
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == CURRENT_RECORDER_TESTS,
            "runtime_stack_consumer_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 305
    require(digest(previous) == PRE_RUNTIME_STACK_CONSUMER_CORPUS_SHA256,
            "runtime_stack_consumer_inventory_differs")
    require_current_runtime_stack_consumer_sources()
    return previous
