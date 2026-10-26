"""Exact historical projection for the opt-in launch-cleanup addition.

Used only by recorder regressions. This cannot qualify a run, remove required
native outcomes, or substitute a model receipt for physical cleanup.
"""

import copy
import hashlib
import json

import native_fixtures as fixtures
from parsing import require

PRE_CLEANUP_CORPUS_SHA256 = "148a28bdb2392971e74fd9dd104638c66b50fa6f4940b43d2e074c4d6b4e2f78"
OLD_NATIVE81_SHA256 = "448237140be9269ec468bba858880e457e070f05efe263b96e4491c85338c52d"
OLD_PYTHON296_SHA256 = "36a4f30ff297f697855f32912e5e423b2f430347375a45eea1dda203eb0cffe6"
NATIVE_ROOT = "linux::remote::dynamic::owner::admission::runtime::launch_cleanup_native_tests"
NATIVE_NAMES = (
    "runtime_launch_alias_refusal_retains_pending_cleanup_and_physical_custody",
    "runtime_launch_pre_ready_failure_preserves_original_error_and_cleanup",
)
ROWS = tuple({"cohort": "b3_runtime_launch_cleanup", "harness": fixtures.UNIT,
              "test": NATIVE_ROOT + "::" + name} for name in NATIVE_NAMES)
RUST_METHODS = {
    "crates/liteinst-launch/src/linux/remote/dynamic/launch_cleanup/tests.rs": (
        "runtime_launch_cleanup_not_started_is_not_a_receipt",
        "runtime_launch_cleanup_timeout_preserves_original_receiver_and_error",
        "runtime_launch_cleanup_caches_actual_success_and_failure",
        "runtime_launch_cleanup_disconnect_is_not_complete",
        "runtime_launch_cleanup_rejects_invalid_wait_without_consuming",
        "runtime_launch_cleanup_drop_cancels_without_waiting",
        "runtime_launch_cleanup_provider_panic_observes_prior_cancel",
    ),
    "crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/launch_cleanup_native_tests.rs": NATIVE_NAMES,
}
PYTHON_MODULE = "test_runtime_launch_cleanup"
PYTHON_METHODS = (
    PYTHON_MODULE + ".RuntimeLaunchCleanupTests.test_launch_cleanup_addition_preserves_exact_sources_corpus_and_python_inventory",
    PYTHON_MODULE + ".RuntimeLaunchCleanupTests.test_launch_cleanup_projection_rejects_source_row_count_and_historical_tampering",
    PYTHON_MODULE + ".RuntimeLaunchCleanupTests.test_launch_cleanup_closed_catalog_and_results_preserve_failure_prefix_and_privacy",
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_launch_cleanup(declared):
    """Authenticate every new and old field before returning the prior corpus."""
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 299, "launch_cleanup_inventory_differs")
    rows = declared.get("native_validation_fixtures")
    require(type(rows) is list and len(rows) == 83 and rows[81:] == list(ROWS),
            "launch_cleanup_inventory_differs")
    fixtures.catalog(rows)
    require(digest(rows[:81]) == OLD_NATIVE81_SHA256, "launch_cleanup_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"},
            "launch_cleanup_inventory_differs")
    for name in ("workspace_tests", "serial_launch"):
        require(type(cohorts[name]) is dict
                and cohorts[name].get(fixtures.UNIT) == {"tests": 573, "ignored": 0},
                "launch_cleanup_inventory_differs")
        require(type(cohorts[name][fixtures.UNIT]["tests"]) is int
                and type(cohorts[name][fixtures.UNIT]["ignored"]) is int,
                "launch_cleanup_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 296
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:81]
    for cohort in previous["harness_test_counts"].values():
        cohort[fixtures.UNIT] = {"tests": 564, "ignored": 0}
    require(digest(previous) == PRE_CLEANUP_CORPUS_SHA256, "launch_cleanup_inventory_differs")
    return previous


def before_launch_cleanup_python(identities):
    """Remove only the exact three added source identities, in original order."""
    require(type(identities) is list and len(identities) == 299
            and all(type(value) is str for value in identities)
            and len(set(identities)) == len(identities), "launch_cleanup_source_inventory_differs")
    old = [value for value in identities if not value.startswith(PYTHON_MODULE + ".")]
    new = [value for value in identities if value.startswith(PYTHON_MODULE + ".")]
    require(new == list(PYTHON_METHODS) and len(old) == 296
            and digest(old) == OLD_PYTHON296_SHA256, "launch_cleanup_source_inventory_differs")
    return old


def validate_launch_cleanup_source(path, names):
    require(type(path) is str and path in RUST_METHODS and type(names) is list
            and names == list(RUST_METHODS[path]), "launch_cleanup_source_inventory_differs")
