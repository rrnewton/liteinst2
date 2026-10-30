#!/usr/bin/env python3
"""Fixed accuracy-state argv adapter for the existing public process owner."""
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
COMMON=('phase','revision','reservation-tag','owner','raw','toolchain','user-home','cargo-home','hardware')
BUILD=('build','build-sha','build-owner','build-owner-sha')
SDK_BUILD=('sdk-build','sdk-build-sha','sdk-build-owner','sdk-build-owner-sha')
SDK_CONTROLS=('sdk-controls','sdk-controls-sha','sdk-controls-owner','sdk-controls-owner-sha')
GEOMETRY=('geometry','geometry-sha')
SDK_EXTRAS={'accuracy-cohort':BUILD+SDK_BUILD+SDK_CONTROLS+GEOMETRY+('cohort',),
    'accuracy-collect':BUILD+SDK_BUILD+SDK_CONTROLS+GEOMETRY+('cohorts','cohorts-sha')}
COHORTS=('unstripped-k10','unstripped-k1000','stripped-k10','stripped-k1000')


def commands(options,python,script):
    phase=options['phase'];assert phase in SDK_EXTRAS
    keys=COMMON+SDK_EXTRAS[phase]
    assert set(options)==set(keys) and all(type(v) is str and v for v in options.values())
    assert re.fullmatch('[0-9a-f]{40}',options['revision'])
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}',options['reservation-tag'])
    assert 1<=len(options['hardware'])<=160 and options['hardware'].isascii() and all(32<=ord(c)<127 for c in options['hardware'])
    assert script in ('evaluation/ordinary-selected-session/accuracy_owner.py',str(HERE/'accuracy_owner.py'))
    for key in keys:
        if key.endswith('-sha'): assert re.fullmatch('[0-9a-f]{64}',options[key])
        elif key not in ('phase','revision','reservation-tag','hardware','cohort'): assert Path(options[key]).is_absolute()
    if phase=='accuracy-cohort': assert options['cohort'] in COHORTS
    invocation=[python,'-B',script]+[word for key in keys for word in ('--'+key,options[key])]
    child_keys=('phase','revision','reservation-tag','raw','toolchain','user-home','cargo-home','hardware')+SDK_EXTRAS[phase]
    child=[python,'-B',str(HERE/'accuracy_state.py')]+[word for key in child_keys for word in ('--'+key,options[key])]
    return invocation,child


def environment(options):
    return dict(HOME=options['user-home'],CARGO_HOME=options['cargo-home'],
        PATH=options['toolchain']+'/bin:/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',LC_ALL='C')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=tuple(SDK_EXTRAS),required=True)
    for name in COMMON[1:]: parser.add_argument('--'+name,required=True)
    extras=tuple(dict.fromkeys(x for row in SDK_EXTRAS.values() for x in row))
    for name in extras: parser.add_argument('--'+name)
    args=parser.parse_args();permitted=COMMON+SDK_EXTRAS[args.phase]
    assert all(getattr(args,k.replace('-','_')) is None for k in set(extras)-set(permitted))
    options={k:getattr(args,k.replace('-','_')) for k in permitted}
    python=str(Path(sys.executable).resolve(strict=True))
    invocation,command=commands(options,python,sys.argv[0])
    assert invocation==[python,'-B',sys.argv[0],*sys.argv[1:]]
    checked=('owner.py','build.py','reproduce.py','sdk_state.py','sdk_state_controls.py',
             'accuracy_owner.py','accuracy_state.py','accuracy_state_controls.py')
    for name in checked:
        path=HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size<=1048576
        assert path.read_bytes()==subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',
            args.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    spec=importlib.util.spec_from_file_location('_accuracy_public_owner',HERE/'owner.py')
    assert spec is not None and spec.loader is not None
    owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
    return owner._run_owner(args,options,invocation,command,checked,
        'accuracy_owner.py','selected-sdk-accuracy-public-owner-v1')


if __name__=='__main__':
    raise SystemExit(main())
