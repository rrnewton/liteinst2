#!/usr/bin/env python3
"""Fixed accuracy callback-state cohorts/collector; no PMU or cadence verdict."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode=True
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent


def main():
    # Authenticate the shared implementation before importing it. Its fixed
    # parser then validates every option before allocating a Run or output.
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--revision',required=True)
    args,_=parser.parse_known_args()
    assert re.fullmatch('[0-9a-f]{40}',args.revision)
    for name in ('accuracy_state.py','sdk_state.py'):
        path=HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size<=1048576
        assert path.read_bytes()==subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',
            args.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    spec=importlib.util.spec_from_file_location('_accuracy_sdk_state',HERE/'sdk_state.py')
    assert spec is not None and spec.loader is not None
    sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)
    return sdk._main(sdk._ACCURACY)


if __name__=='__main__':
    raise SystemExit(main())
