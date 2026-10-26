"""Named outcomes for the finite dynamic admission fixture cohort.

These rows assert only completion of the reviewed fixture tests. They are not
native instruction samples, syscall-effect measurements or class counters.
The independent aggregate harness parser and whole-run gates remain required.
"""

import copy
import re

from parsing import InvalidEvidence, NAME, harness_id, require


HARNESS = "test/dynamic_admission"


def fixture_results(output, fixtures, successful_command):
    """Require each declared serial fixture once with an explicit terminal ok.

    Read only the announced dynamic harness. Preserve sanitized observations on
    failure, including unobserved rows; diagnostic text never supplies a result.
    Results remain unqualified until the unchanged full protocol succeeds.
    """
    require(isinstance(fixtures, list) and fixtures, "invalid_dynamic_fixture_corpus")
    require(all(isinstance(name, str) and NAME.fullmatch(name) for name in fixtures),
            "invalid_dynamic_fixture_corpus")
    require(len(set(fixtures)) == len(fixtures), "duplicate_dynamic_fixture_corpus")
    require(type(successful_command) is bool, "invalid_dynamic_command_status")
    names = set(fixtures)
    observed = {}
    seen = False
    in_harness = False
    active = None

    def partial():
        return [copy.deepcopy(observed.get(name, {
            "test": name, "status": "not_observed", "test_result": None,
            "command_succeeded": successful_command, "qualified_run": False,
        })) for name in fixtures]

    try:
        for line in output.splitlines():
            identity = harness_id(line)
            if identity:
                if in_harness:
                    require(active is None, "dynamic_fixture_missing_terminal")
                in_harness = identity == HARNESS
                if in_harness:
                    require(not seen, "duplicate_dynamic_fixture_harness")
                    seen = True
                continue
            if re.match(r"\s*(Running |Doc-tests )", line):
                raise InvalidEvidence("unrecognized_harness_header")
            if not in_harness:
                continue
            start = re.fullmatch(r"test ([A-Za-z0-9_]+) \.\.\. (.*)", line)
            if start:
                require(active is None, "dynamic_fixture_missing_terminal")
                name = start[1]
                require(name in names and name not in observed, "dynamic_named_cohort_differs")
                active = name
                observed[name] = {
                    "test": name, "status": "incomplete", "test_result": None,
                    "command_succeeded": successful_command, "qualified_run": False,
                }
                line = start[2]
            elif line.startswith("test ") and not line.startswith("test result:"):
                raise InvalidEvidence("invalid_dynamic_fixture_name")
            terminal = (line if line in ("ok", "FAILED", "ignored") else
                        "ignored" if line.startswith("ignored,") else None)
            if terminal:
                require(active is not None, "dynamic_terminal_without_fixture")
                observed[active]["test_result"] = terminal
                observed[active]["status"] = "complete" if terminal == "ok" else "failed"
                active = None
        require(seen, "missing_dynamic_fixture_harness")
        require(active is None, "dynamic_fixture_missing_terminal")
        require(set(observed) == names, "dynamic_named_cohort_differs")
        require(all(row["test_result"] == "ok" for row in observed.values()),
                "dynamic_fixture_not_passed")
        return partial()
    except InvalidEvidence as error:
        error.partial = partial()
        raise
