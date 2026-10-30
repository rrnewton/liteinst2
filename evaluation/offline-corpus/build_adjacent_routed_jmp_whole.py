#!/usr/bin/env python3
"""Fixed routed-JMP union D01 capture; no candidate execution."""
import hashlib
from pathlib import Path
import sys
import types

assert not sys.flags.optimize, 'assertions required'
path = Path(__file__).resolve().with_name('build_adjacent_whole.py')
with path.open('rb') as stream:
    raw = stream.read(1048577)
assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == '4c0552f2f523edc56d96237c4739ad589f439d7ced0d65ef898fff2c4e34b051'
B = types.ModuleType('authenticated_adjacent_builder'); B.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), B.__dict__)
check_artifact = B.check_artifact


def labels():
    return B.labels(B.ROUTED)


def phase_plan(repo, raw, tools, source):
    return B.phase_plan(repo, raw, tools, source, B.ROUTED)


def main():
    return B.main(B.ROUTED)


if __name__ == '__main__':
    raise SystemExit(main())
