#!/usr/bin/env python3
"""Closed FreeBSD strnlen strip profile; no compiler or native qualification."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import importlib.util
from pathlib import Path

_source = Path(__file__).resolve().parents[1] / 'selected-work' / 'provenance.py'
_spec = importlib.util.spec_from_file_location('strnlen_shared_provenance', _source)
assert _spec is not None and _spec.loader is not None
_shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_shared)

NAME = _shared.STRNLEN_NAME
LABEL = _shared.STRNLEN_LABEL
VERSION_SCRIPT = b'{ local: *; };\n'


def validate(prestrip, final, pre_symbols, final_symbols):
    return _shared.validate_strnlen(prestrip, final, pre_symbols, final_symbols)


def main():
    _shared.main_strnlen()


if __name__ == '__main__':
    main()
