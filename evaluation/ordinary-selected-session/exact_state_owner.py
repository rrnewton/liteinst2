#!/usr/bin/env python3
"""Finite Exact37 state phases using the existing public process owner."""
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
SDK = ('sdk-build','sdk-build-sha','sdk-build-owner','sdk-build-owner-sha',
       'sdk-controls','sdk-controls-sha','sdk-controls-owner','sdk-controls-owner-sha')
PREPARED = ('preparation','preparation-sha','preparation-owner','preparation-owner-sha','geometry','geometry-sha')
EXTRAS = {'exact-prepare':BUILD+SDK,'exact-cohort':BUILD+SDK+PREPARED+('cohort',),
          'exact-collect':BUILD+SDK+PREPARED+('cohorts','cohorts-sha')}
COHORTS = ('seed0-lengths01-32','seed0-lengths33-64','seed1-lengths01-32','seed1-lengths33-64')
SCHEMA = 'exact37-accuracy-native-public-owner-v1'
CHECKED = ('owner.py','build.py','reproduce.py','sdk_state.py','sdk_state_controls.py',
           'exact_state.py','exact_state_geometry.py','exact_state_owner.py','exact_state_controls.py')

def commands(options, python, script):
    phase = options['phase']; assert phase in EXTRAS
    keys = COMMON+EXTRAS[phase]
    assert set(options) == set(keys) and all(type(v) is str and v for v in options.values())
    assert re.fullmatch('[0-9a-f]{40}',options['revision'])
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}',options['reservation-tag'])
    assert 1 <= len(options['hardware']) <= 160 and options['hardware'].isascii()
    assert all(32 <= ord(c) < 127 for c in options['hardware'])
    assert script in ('evaluation/ordinary-selected-session/exact_state_owner.py',str(HERE/'exact_state_owner.py'))
    for name in keys:
        if name.endswith('-sha'): assert re.fullmatch('[0-9a-f]{64}',options[name])
        elif name not in ('phase','revision','reservation-tag','hardware','cohort'): assert Path(options[name]).is_absolute()
    if phase == 'exact-cohort': assert options['cohort'] in COHORTS
    invocation = [python,'-B',script]+[w for k in keys for w in ('--'+k,options[k])]
    child = [python,'-B',str(HERE/'exact_state.py')]+[w for k in keys if k != 'owner' for w in ('--'+k,options[k])]
    return invocation,child

def environment(options):
    return dict(HOME=options['user-home'],CARGO_HOME=options['cargo-home'],
        PATH=options['toolchain']+'/bin:/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',LC_ALL='C')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=tuple(EXTRAS),required=True)
    for name in COMMON[1:]: parser.add_argument('--'+name,required=True)
    extras = tuple(dict.fromkeys(k for row in EXTRAS.values() for k in row))
    for name in extras: parser.add_argument('--'+name)
    args = parser.parse_args(); permitted = COMMON+EXTRAS[args.phase]
    assert all(getattr(args,k.replace('-','_')) is None for k in set(extras)-set(permitted))
    options = {k:getattr(args,k.replace('-','_')) for k in permitted}
    python = str(Path(sys.executable).resolve(strict=True))
    invocation,command = commands(options,python,sys.argv[0])
    assert invocation == [python,'-B',sys.argv[0],*sys.argv[1:]]
    for name in CHECKED:
        path = HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576
        assert path.read_bytes() == subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',
            args.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    spec = importlib.util.spec_from_file_location('_exact_state_outer',HERE/'owner.py')
    assert spec is not None and spec.loader is not None
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    return owner._run_owner(args,options,invocation,command,CHECKED,'exact_state_owner.py',SCHEMA)

if __name__ == '__main__':
    raise SystemExit(main())
