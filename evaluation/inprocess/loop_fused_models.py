#!/usr/bin/env python3
"""Bound the unchanged rseq and additive saved-PF model checks; no guest runs.

From a clean repository root on one externally reserved CPU:
  python3.12 -B evaluation/inprocess/loop_fused_models.py --expect-revision REV --output FRESH
FRESH must be a new directory below target. Both tests share the original
30 CPU / 60 wall seconds, 512 MiB AS and 16 MiB output limits. This script may
be copied outside the checkout; it always loads the installed tracked models
from the current repository. No captured completion or qualification is proved.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()


def need(ok, why):
    if not ok:
        raise ValueError(why)


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'whole regular source file')
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def history_result(raw):
    need(type(raw) is str and 0 < len(raw.encode()) <= 4096, 'whole bounded history model result')
    def unique(pairs):
        value = dict(pairs)
        need(len(value) == len(pairs), 'no duplicate history model fields')
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    fixed = dict(schema=1, scope='descriptive-model-only', positives=8, near=4, far=4,
        negative_controls=136, subjects=0, actual_completions=0, qualification_credit=False)
    need(type(value) is dict and set(value) == set(fixed) and
         all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items()),
         'all original saved-PF model populations and no-credit fields')
    need(json.dumps(value, sort_keys=True)+'\n' == raw, 'one canonical complete history model row')
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(sys.version_info >= (3, 11) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision and Python assertions')
    cpu, = os.sched_getaffinity(0)
    for kind, value in ((resource.RLIMIT_CPU, 30), (resource.RLIMIT_AS, 512 << 20),
                       (resource.RLIMIT_FSIZE, 16 << 20), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (value, value))
    signal.alarm(60)
    output = args.output.resolve()
    need(output.is_relative_to(ROOT/'target'), 'fresh private target output')
    output.mkdir(parents=True, exist_ok=False)
    record = dict(schema=1, profile='loop-fused-models-v1', status='failed',
        expected_revision=args.expect_revision, cpu=cpu, driver=fact(Path(__file__)),
        bounds=dict(cpu_seconds=30, wall_seconds=60, address_space_bytes=512 << 20, output_bytes=16 << 20),
        inputs={}, native_subjects=0, actual_completions=0, owner_validated=False,
        qualification_credit=False, performance_credit=False, error=None,
        python_version=platform.python_version(), source_unchanged=False, inputs_unchanged=False,
        reproduction_argv=['python3.12', '-B', 'evaluation/inprocess/loop_fused_models.py',
                           '--expect-revision', args.expect_revision, '--output', 'FRESH_TARGET_OUTPUT'])
    original_spec = importlib.util.spec_from_file_location
    def spec(name, location, *a, **kw):
        path = Path(location).resolve()
        need(path.is_relative_to(ROOT), 'repository-owned model import')
        key = str(path.relative_to(ROOT))
        value = fact(path)
        need(key not in record['inputs'] or record['inputs'][key] == value, 'stable whole model import')
        record['inputs'][key] = value
        return original_spec(name, path, *a, **kw)
    started = time.monotonic_ns()
    try:
        importlib.util.spec_from_file_location = spec
        rseq = load('installed_loop_rseq_regression', ROOT/'evaluation/inprocess/loop_rseq_model.py')
        record['revision'] = rseq.git('rev-parse', 'HEAD')
        record['tracked_status'] = rseq.git('status', '--porcelain', '--untracked-files=no')
        need(record['revision'] == args.expect_revision and record['tracked_status'] == '',
             'actual clean exact expected revision')
        record['tracked_clean'] = True
        record['hardware'] = rseq.hardware(cpu)
        focal = load('installed_focal_rseq_model', rseq.TESTS/'persistent_loop_owner/plan.py')
        life = load('installed_lifecycle_rseq_model', rseq.TESTS/'persistent_loop_lifecycle_owner/plan.py')
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            record['rseq'] = rseq.check(focal, life)
        need(stdout.getvalue() == stderr.getvalue() == '', 'unchanged rseq check emits no diagnostics')
        need(tuple(record['rseq'][k] for k in ('bfs_roots', 'focal_graphs', 'lifecycle_graphs',
                                             'whole_decoded_descriptors')) == (28, 28, 6, 806),
             'all original rseq model populations remain mandatory')
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            history = load('installed_fused_history_controls',
                           rseq.TESTS/'persistent_loop_owner/fused_history_controls.py')
            history.main()
        need(stderr.getvalue() == '', 'history model emits no diagnostics')
        record['fused_history'] = history_result(stdout.getvalue())
        need(rseq.git('rev-parse', 'HEAD') == record['revision'] and
             rseq.git('status', '--porcelain', '--untracked-files=no') == record['tracked_status'],
             'whole source revision/status unchanged')
        need(all(fact(ROOT/k) == v for k, v in record['inputs'].items()), 'all whole model imports unchanged')
        need(fact(Path(__file__)) == record['driver'] and os.sched_getaffinity(0) == {cpu},
             'same whole driver and reserved singleton CPU')
        record.update(status='model_regressions_passed', source_unchanged=True, inputs_unchanged=True)
    except BaseException as error:
        record['error'] = type(error).__name__+': '+str(error)
    finally:
        importlib.util.spec_from_file_location = original_spec
        record['validation_duration_ns'] = time.monotonic_ns()-started
        (output/'result.json').write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')
        signal.alarm(0)
    print(json.dumps(dict(status=record['status'], result=fact(output/'result.json'))), flush=True)
    return int(record['status'] != 'model_regressions_passed')


if __name__ == '__main__':
    raise SystemExit(main())
