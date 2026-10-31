#!/usr/bin/env python3
"""Fixed legacy/phase Exact37 modes through the unchanged public process owner."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
COMMON = ('phase','revision','reservation-tag','owner','raw','toolchain','user-home','cargo-home','hardware')
BUILD = ('build','build-sha','build-owner','build-owner-sha')
CONTROLS = ('controls','controls-sha','controls-owner','controls-owner-sha')
PREPARE = ('preparation','preparation-sha','preparation-owner','preparation-owner-sha')
EXTRAS = {'accuracy-prepare': BUILD+CONTROLS,
    'accuracy-functional': BUILD+CONTROLS+PREPARE+('geometry','geometry-sha')}
PHASE_EXTRAS = {'phase-prepare': BUILD+CONTROLS+('epoch-phase',),
    'phase-functional': BUILD+CONTROLS+PREPARE+('geometry','geometry-sha','epoch-phase')}
PREPARED_PHASE_EXTRAS = {'prepared-phase-prepare': BUILD+CONTROLS+('epoch-phase',),
    'prepared-phase-functional': BUILD+CONTROLS+PREPARE+('geometry','geometry-sha','epoch-phase')}
SCHEMA = 'selected-accuracy-functional-public-owner-v1'


def extras(phase):
    assert phase in EXTRAS or phase in PHASE_EXTRAS or phase in PREPARED_PHASE_EXTRAS
    return EXTRAS[phase] if phase in EXTRAS else (PHASE_EXTRAS[phase] if phase in PHASE_EXTRAS else PREPARED_PHASE_EXTRAS[phase])



def commands(options, python, script):
    phase = options['phase']
    keys = COMMON+extras(phase)
    assert set(options) == set(keys) and all(type(v) is str and v for v in options.values())
    assert re.fullmatch('[0-9a-f]{40}', options['revision'])
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}', options['reservation-tag'])
    assert 1 <= len(options['hardware']) <= 160 and options['hardware'].isascii() and all(32 <= ord(c) < 127 for c in options['hardware'])
    assert script in ('evaluation/ordinary-selected-session/accuracy_functional_owner.py', str(HERE/'accuracy_functional_owner.py'))
    for key in keys:
        if key.endswith('-sha'):
            assert re.fullmatch('[0-9a-f]{64}', options[key])
        elif key == 'epoch-phase':
            assert options[key] in ('random', 'locked')
        elif key not in ('phase','revision','reservation-tag','hardware'):
            assert Path(options[key]).is_absolute()
    invocation = [python,'-B',script]+[word for key in keys for word in ('--'+key,options[key])]
    child_keys = tuple(key for key in keys if key != 'owner')
    child = [python,'-B',str(HERE/'accuracy_functional.py')]+[word for key in child_keys for word in ('--'+key,options[key])]
    return invocation, child


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=tuple(EXTRAS)+tuple(PHASE_EXTRAS)+tuple(PREPARED_PHASE_EXTRAS), required=True)
    for name in COMMON[1:]:
        parser.add_argument('--'+name, required=True)
    option_names = tuple(dict.fromkeys(k for row in (*EXTRAS.values(), *PHASE_EXTRAS.values(), *PREPARED_PHASE_EXTRAS.values()) for k in row))
    for name in option_names:
        parser.add_argument('--'+name)
    args = parser.parse_args()
    permitted = COMMON+extras(args.phase)
    assert all(getattr(args,k.replace('-','_')) is None for k in set(option_names)-set(permitted))
    options = {k:getattr(args,k.replace('-','_')) for k in permitted}
    python = str(Path(sys.executable).resolve(strict=True))
    invocation, command = commands(options, python, sys.argv[0])
    assert invocation == [python,'-B',sys.argv[0],*sys.argv[1:]]
    checked = ('owner.py','build.py','reproduce.py','accuracy_functional.py','accuracy_produce.py',
        'accuracy_functional_owner.py','accuracy_functional_controls.py')
    for name in checked:
        path = HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576
        assert path.read_bytes() == subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',
            args.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    spec = importlib.util.spec_from_file_location('_accuracy_functional_outer', HERE/'owner.py')
    assert spec is not None and spec.loader is not None
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner._run_owner(args,options,invocation,command,checked,'accuracy_functional_owner.py',SCHEMA)


if __name__ == '__main__':
    raise SystemExit(main())
