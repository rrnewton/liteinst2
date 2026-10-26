"""Exact historical projection for the separate compiler-produced consumer.

This helper is imported only by recorder regressions. It cannot qualify a
consumer, remove native outcomes, or relax the actual command parser.
"""

import copy
import hashlib
import json

from parsing import require

PRE_CONSUMER_CORPUS_SHA256 = "ed6e3dc9a9e856f684178083fc56f8f3c665cde6005190f83d5d46bd455479c9"
OLD_PYTHON284_SHA256 = "9c1206d9abe526486c433521ba4924a280cebaf79478b9b25b90d40c75ef95a6"
CONSUMER_MODULE = "test_runtime_kernel_consumer"
CONSUMER_METHODS = (
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_complete_summary_requires_all_exact_fields_and_counts',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_schema_refuses_duplicate_unknown_mistyped_and_private_fields',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_summary_missing_duplicate_trailing_and_protocol_fail_closed',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_failed_command_retains_only_typed_prefix_without_qualification',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_expected_reference_exit_and_cleanup_are_role_specific',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_commands_are_fixed_and_default_test_environment_is_not_reused',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_elf_description_is_complete_static_and_not_head_authority',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_elf_rejects_malformed_dynamic_writable_and_out_of_range_inputs',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_elf_rejects_undefined_relocated_or_missing_start_symbol',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_prerequisite_requires_exact_source_original_environment_and_six_commands',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_whole_experiment_never_qualifies_partial_failed_or_changed_run',
    'test_runtime_kernel_consumer.RuntimeKernelConsumerTests.test_consumer_version_metadata_retains_hash_without_host_path_or_freeform_output',
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_consumer(declared):
    """Validate the full new corpus before recovering the exact prior corpus."""
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 296, "consumer_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 284
    require(digest(previous) == PRE_CONSUMER_CORPUS_SHA256, "consumer_inventory_differs")
    return previous


def before_consumer_python(identities):
    """Remove only the exact twelve additive source method identities."""
    require(type(identities) is list and len(identities) == 296
            and all(type(value) is str for value in identities)
            and len(set(identities)) == len(identities), "consumer_source_inventory_differs")
    old = [value for value in identities if not value.startswith(CONSUMER_MODULE + ".")]
    new = [value for value in identities if value.startswith(CONSUMER_MODULE + ".")]
    require(new == list(CONSUMER_METHODS) and len(old) == 284
            and digest(old) == OLD_PYTHON284_SHA256, "consumer_source_inventory_differs")
    return old
