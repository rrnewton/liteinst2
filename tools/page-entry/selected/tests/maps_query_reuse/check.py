"""Strict finite oracle result, with no timing or application-success claim."""
import json
from pathlib import Path


def check(stdout, expected_path=None):
    expected_path = expected_path or Path(__file__).with_name('EXPECTED.json')
    expected = json.loads(Path(expected_path).read_bytes())
    actual = json.loads(stdout)
    if (type(actual) is not dict or actual.keys() != expected.keys()
            or any(type(value) is not int for value in actual.values())
            or actual != expected):
        raise ValueError('exact maps-query-reuse oracle result')
    return actual
