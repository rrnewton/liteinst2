#!/usr/bin/env python3
"""Run one fixed adjacent-pun native campaign; retain raw artifacts in ignored/."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re


HELPER_SHA256 = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
OUTPUT_BYTES = 8 * 1024 * 1024
# One attempt at every stage. A failed stage prevents its consumers from running.
STAGES = [('target', 30), ('produce', 120), ('verify', 30),
          ('controls', 120), ('run', 900)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--profile', choices=['debug', 'release'], required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    assert Path.cwd() == root
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    out = args.output.resolve()
    assert out.is_relative_to(root / 'ignored') and not out.exists()
    binary = root / 'target' / args.profile / 'examples/adjacent_b2_native'
    assert binary.is_file() and not binary.is_symlink()
    binary_sha = sha(binary.read_bytes())
    helper = root / 'evaluation/admission/processes.py'
    assert sha(helper.read_bytes()) == HELPER_SHA256
    spec = importlib.util.spec_from_file_location('adjacent_native_owner', helper)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    load = lambda: Path('/proc/loadavg').read_text().split()[:3]
    env = dict(os.environ)
    out.mkdir(parents=True)
    logs = root / 'target/evaluation/adjacent-b2-native' / out.name
    logs.mkdir(parents=True, exist_ok=False)
    planned = dict(revision=args.revision, binary_sha256=binary_sha,
                   profile=args.profile, script_sha256=sha(Path(__file__).read_bytes()),
                   helper_sha256=HELPER_SHA256, stages=STAGES, attempts=1,
                   source_guard_seconds=10, source_guards='before each stage and after the last',
                   affinity=sorted(os.sched_getaffinity(0)), load_average=load(),
                   output_limit_bytes=OUTPUT_BYTES, qualification_complete=False,
                   scope='Fixed native correctness campaign; elapsed time is not a performance claim.')
    write_json(out / 'planned.json', planned)
    results = []
    guards = []
    bindings = {}
    custody = True
    failed = False
    failure = None
    current = None

    def checked_command(name, command, limit, records, validate):
        nonlocal custody
        before = load()
        log = logs / (name + '.log')
        row = dict(name=name, command=command, result=None,
                   load_before=before, load_after=None, status='failed')
        records.append(row)
        # An owner exception supplies no custody evidence. Record the attempted
        # command first, and remain unconfirmed until a result actually returns.
        custody = False
        try:
            closed = owner.run_command(command, env, log, limit, OUTPUT_BYTES)
            row['result'] = closed
            custody = closed['cleanup_complete'] is True
            # Owner-internal diagnostic closure is separate from consumer reads.
            # No child artifact or diagnostic is read with uncertain custody.
            if not custody:
                raise RuntimeError('uncertain_child_custody')
            row['load_after'] = load()
            raw = log.read_bytes()
            assert sha(raw) == closed['private_log_sha256'], 'private_log_digest'
            with (out / (name + '.log')).open('xb') as stream:
                stream.write(raw)
            assert closed['exit_code'] == 0, 'command_exit'
            assert closed['termination'] is None, 'command_termination'
            assert closed['reaped_descendants'] == 0, 'adopted_descendant'
            validate(raw, row)
            row['status'] = 'passed'
        except BaseException as error:
            row['failure'] = str(error)
            raise
        finally:
            # Retain the known command outcome even if protocol admission fails.
            write_json(out / (name + '-receipt.json'), row)
            print(json.dumps(dict(name=name, status=row['status'], result=row['result'])), flush=True)

    def guard(index):
        def head(raw, _row):
            assert raw == (args.revision + '\n').encode(), 'revision_changed'

        def clean(raw, row):
            assert not raw, 'unexpected_clean_tree_diagnostic'
            assert binary.is_file() and not binary.is_symlink(), 'binary_shape_changed'
            assert sha(binary.read_bytes()) == binary_sha, 'binary_changed'
            row['binary_sha256'] = binary_sha

        checked_command(f'guard-{index}-head', ['git', 'rev-parse', 'HEAD'], 10, guards, head)
        checked_command(f'guard-{index}-diff',
                        ['git', 'diff', '--quiet', '--no-ext-diff', '--no-textconv', 'HEAD', '--'],
                        10, guards, clean)

    try:
        for index, (name, limit) in enumerate(STAGES):
            current = name
            # These are point-in-time checks, not protection from arbitrary
            # concurrent mutation. The slot and build have one executing owner.
            guard(index)
            destination = out / name
            command = [str(binary), name]
            if name != 'target':
                parent = {'produce': 'target', 'verify': 'produce',
                          'controls': 'verify', 'run': 'verify'}[name]
                command += [str(out / parent), bindings[parent]]
            command += [str(destination)]

            def admit(raw, row):
                # The existing owner merges stdout/stderr. Require exactly one
                # hash across the COMBINED stream, with no other diagnostics;
                # this does not prove which stream supplied those bytes.
                assert re.fullmatch(b'[0-9a-f]{64}\n', raw), 'binding_hash_transcript'
                binding = destination / 'binding.tsv'
                assert binding.is_file() and not binding.is_symlink(), 'binding_shape'
                with binding.open('rb') as stream:
                    data = stream.read(65537)
                assert len(data) <= 65536, 'binding_size'
                actual = sha(data)
                assert actual == raw.decode().strip(), 'binding_digest'
                bindings[name] = actual
                row['binding_sha256'] = actual

            checked_command(name, command, limit, results, admit)
        current = 'final-source-guard'
        guard(len(STAGES))
    except BaseException as error:
        failed = True
        failure = dict(at=current, reason=str(error))
    # Custody failure cannot produce a CLOSED receipt or trigger another command.
    write_json(out / ('closed.json' if custody else 'aborted.json'),
               dict(planned=planned, guards=guards, results=results, failure=failure,
                    unrun_stages=[name for name, _ in STAGES[len(results):]],
                    status='failed' if failed else 'passed',
                    cleanup_complete=custody, qualification_complete=False))
    raise SystemExit(int(failed))


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('assertions required')
    main()
