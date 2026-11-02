#!/usr/bin/env python3
"""Run the original hint oracle plus additive backward-refusal controls after installation.

From the repository root, under one reserved CPU and an external 180s wall bound:
  python3 -B target/page-region-next/loop-backward-hint-r1/run.py --expect-revision HEAD40 --output FRESH
FRESH must be inside target/evaluation/inprocess. The installed runtime and binding
leaves are pinned below. A dirty tree is reported and held exactly, not called a
clean revision. Uses the original bounded component process/cleanup owner.
No native application, owner receipt or qualification is produced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import sys

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from page_selected import ENV, fact, need, save
from page_selected_process import invoke

EXPECTED = {'tools/page-entry/selected/persistent_group_source.inc': '6a4310e9eeda65d51a799f45acb60687ee1e0e342538077b4c5f10db292cd899', 'tools/page-entry/selected/persistent_group_runtime.h': '258ca4c99383161f41c2c2893031efe52fdcdf9180f85fa2c722f0ed5da29c53', 'tools/page-entry/selected/persistent_group_controller.inc': '1a5cae3cc44cf01e91d21f725d0fab5ebbab531869936e214e69fab898a3148c', 'tools/page-entry/selected/persistent_loop_negative_hint.h': '9e9b9d253f0321898adfee198427074c3057a56a3cb30cd08a7c20243e1c250e', 'tools/page-entry/selected/persistent_loop_negative_hint.inc': 'df15fa8064cfb9069514f0aaffc1f45e12655baedb4a95557f97d2f779224ed2', 'tools/page-entry/selected/persistent_loop_binding.py': 'a1ec2e8d4b6245b83ab6e1180d5bab75656bc5f3ed4aae1edde8f94d91b80951', 'tools/page-entry/selected/persistent_loop_lifecycle_binding.py': '182a4cf39587fd1a28aa25c779c29d791cafa96955d57ee66ab560ec06f1b81f', 'evaluation/inprocess/persistent_loop_build.py': '466e6e10df655da7141851a6870bc6ed01bc570667a50a3732807e437e9164a7', 'evaluation/inprocess/persistent_loop_lifecycle_build.py': '0a75768536d19df975514bbc4cb672baf79f195b19e5a136998d890b7b6cc011', 'evaluation/inprocess/persistent_loop_owner_build.py': '3aa66abdcb63f0d2c0d03bced9ca60536ada469643664f904278f38efb474237', 'evaluation/inprocess/persistent_loop_performance_build.py': '27d25177cf0bafb5d4bb2dbadecb1f3ce1ef20336c6a7a7fa41ecc06fbb21d8b'}
BOUNDS = {'metadata': [10, 512<<20, 16<<20, 20],
          'build': [30, 512<<20, 64<<20, 60], 'component': [5, 512<<20, 16<<20, 15]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision')
    affinity = sorted(os.sched_getaffinity(0)); need(len(affinity)==1, 'one already-reserved CPU')
    for kind, value in ((resource.RLIMIT_CPU, 180), (resource.RLIMIT_AS, 512<<20),
                        (resource.RLIMIT_FSIZE, 64<<20), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (value, value))
    out = args.output.resolve(); need(out.is_relative_to(ROOT/'target/evaluation/inprocess'), 'private output')
    out.mkdir(exist_ok=False)
    selected = ROOT/'tools/page-entry/selected'
    fixture = HERE/'files/tools/page-entry/selected/tests/loop_backward_hint'
    cc = Path('/usr/bin/cc').resolve(); git = Path('/usr/bin/git').resolve()
    environment = dict(ENV, LI2_CC=str(cc))
    record = dict(schema=1, profile='loop-backward-hint-component-v1', status='failed',
        expected_revision=args.expect_revision, cpu=affinity[0], hardware=dict(zip(
        ('system','node','release','version','machine'), os.uname())), commands=[], inputs={},
        bounds=BOUNDS, inputs_unchanged=False, source_unchanged=False, error=None,
        native_executed=False, owner_validated=False, qualification_credit=False, performance_credit=False)
    inputs = record['inputs']

    def pin(path):
        path = Path(path).resolve(); value = fact(path)
        need(str(path) not in inputs or inputs[str(path)] == value, 'input drift '+str(path))
        inputs[str(path)] = value
        return path

    def stable():
        need(all(fact(path)==value for path,value in inputs.items()), 'whole component inputs unchanged')

    def run(name, argv, profile):
        stable()
        row = dict(name=name, argv=list(map(str,argv)), profile=profile, bounds=BOUNDS[profile],
                   environment=environment, capture_limit=8<<20, expected_exit=0)
        record['commands'].append(row)
        stdout, stderr = invoke(row, out, affinity[0])
        need(row['exit']==0, 'command failed '+name)
        stable()
        return stdout, stderr

    def git_value(name, *args):
        stdout, stderr = run(name, [git,'-C',ROOT,'-c','index.threads=1',
            '-c','core.preloadIndex=false',*args], 'metadata')
        need(not stderr, 'Git metadata stderr'); return stdout

    try:
        for path in (Path(__file__), fixture/'oracle.c', fixture/'build.sh', cc, git, '/bin/sh',
                     selected/'build-persistent-loop.sh'):
            pin(path)
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).resolve().is_relative_to(ROOT): pin(path)
        for name, sha in EXPECTED.items():
            need(fact(pin(ROOT/name))['sha256']==sha, 'installed reviewed source '+name)
        macro = r'-DLI2_[A-Z_0-9]+=1'
        macros = re.findall(macro, (fixture/'build.sh').read_text())
        need(len(macros)==len(set(macros))==47 and macros==re.findall(macro,
             (selected/'build-persistent-loop.sh').read_text()), 'exact whole LOOP release macro roster')
        record['macros'] = macros
        before = git_value('head-before', 'rev-parse', 'HEAD')
        need(before==args.expect_revision.encode()+b'\n', 'actual expected HEAD')
        status = git_value('status-before', 'status', '--porcelain', '--untracked-files=no')
        record['tracked_status'] = status.decode(); record['tracked_clean'] = not status
        version, err = run('cc-version', [cc,'--version'], 'metadata'); need(not err, 'compiler version stderr')
        record['compiler_version_sha256'] = hashlib.sha256(version).hexdigest()
        headers, err = run('headers-before', ['/bin/sh',fixture/'build.sh',selected,out,'headers'], 'metadata')
        need(not err and headers.count(b':')==1, 'complete one-TU compiler-M output')
        target, _, body = headers.replace(b'\\\n',b' ').partition(b':')
        need(target.strip()==b'oracle.o', 'actual oracle compiler-M target')
        dependencies = [Path(x) for x in shlex.split(body.decode())]
        need(len(dependencies)==len(set(dependencies)) and all(p.is_absolute() for p in dependencies),
             'unique absolute compiler inputs')
        for path in dependencies: pin(path)
        need(all((selected/name).resolve() in dependencies for name in
            ('lifecycle_loader.c','lifecycle_loader.h','persistent_group_source.inc',
             'persistent_subentry_source.inc','persistent_cross_pair_source.inc',
             'fetch_loader.inc','span_source.inc','persistent_loop_negative_hint.h',
             'persistent_loop_negative_hint.inc','persistent_group_runtime.h',
             'tests/loop_negative_hint/oracle.c')), 'actual loader and every changed guard compiler input')
        record['headers'] = [str(p) for p in dependencies]
        stdout, stderr = run('build', ['/bin/sh',fixture/'build.sh',selected,out,'build'], 'build')
        need(not stdout and not stderr, 'strict silent component build')
        executable = pin(out/'loop-backward-hint'); record['executable'] = fact(executable)
        stdout, stderr = run('component', [executable], 'component')
        expected = dict(hits=26, misses=87, storage=2, entries=8, owner_entries=0)
        need(not stderr and stdout==b'loop_negative_hint hits=26 misses=87 storage=2 entries=8 owner_entries=0\n' +
             b'loop_backward_hint classifications=24 lookup_hits=6 lookup_misses=16 entries=8 owner_entries=0\n',
             'all literal actual-C hint assertions completed')
        record['component'] = expected
        record['backward_component'] = dict(classifications=24, lookup_hits=6, lookup_misses=16,
            entries=8, owner_entries=0, actual_remember_observed=False)
        after, err = run('headers-after', ['/bin/sh',fixture/'build.sh',selected,out,'headers'], 'metadata')
        need(not err and after==headers, 'complete compiler-M closure')
        need(git_value('head-after','rev-parse','HEAD')==before and
             git_value('status-after','status','--porcelain','--untracked-files=no')==status,
             'unchanged actual revision and tracked status')
        stable(); record.update(inputs_unchanged=True, source_unchanged=True, status='component_passed')
    except BaseException as error:
        record['error'] = type(error).__name__+': '+str(error)
    finally:
        save(out/'receipt.json', record)
    print(json.dumps(dict(status=record['status'], receipt=str(out/'receipt.json'))), flush=True)
    return int(record['status']!='component_passed')


if __name__ == '__main__':
    raise SystemExit(main())
