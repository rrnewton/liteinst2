#!/usr/bin/env python3
"""One prospective verifier build with a complete, restricted Cargo config scope.

The producer's historical build/capture configuration is never changed. Cargo
executes from / with its exact absolute compiler and manifest. Only absent
configuration or the finite offline-neutral net/http grammar below is admitted;
includes, wrappers, aliases and all other settings are refused.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess


def check_config(raw):
    """Strict TOML subset, excluding includes and build-affecting configuration."""
    if len(raw) > 1048576:
        raise ValueError('Cargo configuration size')
    section = None
    seen = set()
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line in ('[net]', '[http]'):
            section = line[1:-1]
            if section in seen:
                raise ValueError('duplicate Cargo configuration section')
            seen.add(section)
            continue
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        identity = (section, key)
        if not separator or identity in seen:
            raise ValueError('Cargo configuration grammar')
        seen.add(identity)
        if identity == ('net', 'git-fetch-with-cli'):
            if value not in ('true', 'false'):
                raise ValueError('Cargo net boolean')
        elif identity == ('http', 'proxy'):
            # JSON strings form a strict subset of one-line TOML basic strings.
            # Restrict escapes further: TOML has no JSON slash escape.
            if '\\/' in value or not value.startswith('"') or not value.endswith('"'):
                raise ValueError('Cargo proxy string')
            decoded = json.loads(value)
            if not isinstance(decoded, str) or any(ord(c) < 32 for c in decoded):
                raise ValueError('Cargo proxy string')
        else:
            raise ValueError('Cargo config outside rooted verifier profile')


def configurations(ctx, captured):
    rows = ctx.B.configuration(Path('/'), Path(captured['env']['CARGO_HOME']))
    for row in rows.values():
        if row['state'] == 'READ':
            pin = row['identity']
            check_config(ctx.read(Path(pin['path']), pin, 1048576))
        elif row['state'] not in ('ABSENT', 'TARGET_ABSENT'):
            raise ValueError('incomplete rooted Cargo configuration')
    return rows


def invocation(ctx, captured):
    root = ctx.ROOT
    return [captured['tools']['python']['path'], '-B',
            str(root / 'evaluation/adjacent-b2/artifact-verifier/cargo_from_root.py'),
            captured['tools']['cargo']['path'],
            str(root / 'evaluation/adjacent-b2/artifact-verifier/Cargo.toml')]


def execute(ctx, request, command, directory):
    ctx.B.write(directory / 'request.json', request)
    ctx.B.write(directory / 'command.json', command)
    parent = dict(wait_returned=False, exit=None, error=None)
    child = None
    try:
        with (directory/'helper.stdout').open('xb') as out, (directory/'helper.stderr').open('xb') as err:
            child = subprocess.Popen(command['argv'], cwd=command['cwd'], env=command['env'],
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            try:
                child.wait(timeout=command['parent_seconds'])
                parent['wait_returned'] = True
            except BaseException as error:
                parent['error'] = type(error).__name__
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait(timeout=command['cleanup_seconds'])
                parent['wait_returned'] = True
                raise
    finally:
        parent['exit'] = child.returncode if child else None
        ctx.B.write(directory/'parent-closed.json', parent)


def main():
    import verify_saved as w
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('capture', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('capture-sha256', 'verifier-lock-sha256'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    ctx, a = w.context(root)
    for name in ('capture_sha256', 'verifier_lock_sha256'):
        pin = getattr(args, name)
        w.need(len(pin) == 64 and all(c in '0123456789abcdef' for c in pin), 'frozen digest')
    w.need(args.capture.is_absolute() and args.capture.resolve(strict=True) == args.capture and
           args.capture.is_relative_to(root/'ignored'), 'canonical capture')
    w.need(args.output.is_absolute() and args.output.is_relative_to(root/'ignored') and
           args.output.parent.resolve(strict=True) == args.output.parent and
           not os.path.lexists(args.output), 'new build directory')
    captured = a.authenticate_capture(ctx, args, {}, a.ROUTED)
    before = configurations(ctx, captured)
    args.output.mkdir(mode=0o700)
    source = {root/w.CRATE/name: pin for name,pin in
              dict(w.VERIFIER_SOURCES, **w.ROOTED_BUILD_SOURCES).items()}
    source[root/w.CRATE/'Cargo.lock'] = args.verifier_lock_sha256
    pins = {str(p): ctx.B.identity(p) for p in source}
    w.need(all(pins[str(p)]['sha256'] == h for p,h in source.items()), 'frozen verifier build source/lock')
    request, command = w.request_and_command(ctx, captured, args.output, invocation(ctx,captured), (120,180,128))
    planned = dict(schema='LI2W01-ROOTED-VERIFIER-PLAN-1', cargo_cwd='/', configurations=before,
        files=pins, request=request, command=command, cpus=sorted(os.sched_getaffinity(0)),
        hardware='AMD EPYC Zen 5 dev host', load_average=Path('/proc/loadavg').read_text().split()[:3])
    ctx.B.write(args.output/'planned.json', planned)
    execute(ctx, request, command, args.output)
    code, streams = ctx.closed(args.output, request)
    w.need(code == 0, 'closed verifier build failed')
    captured['stable']()
    w.need(configurations(ctx,captured) == before and
           all(ctx.B.identity(p) == row for p,row in pins.items()), 'build inputs changed')
    binary = root/'target/release/adjacent-b2-artifact-verifier'
    builder = ctx.load(a.ROUTED.builder, a.ROUTED.builder_sha)
    builder.check_artifact(streams['stdout'], dict(product_name='adjacent-b2-artifact-verifier',
        product_kind='bin', product=str(binary)))
    controls = ('request.json','command.json','parent-closed.json','receipt.json',
                'stdout.txt','stderr.txt','helper.stdout','helper.stderr','planned.json')
    for p in [binary, *(args.output/name for name in controls)]:
        pins[str(p)] = ctx.B.identity(p)
    closed = dict(schema='LI2W01-VERIFIER-BUILD-2', cargo_cwd='/', files=pins,
        lock_sha256=args.verifier_lock_sha256, configuration_complete=True, configurations=before)
    ctx.B.write(args.output/'closed.json', closed)
    args.verifier_build = args.output
    args.verifier_build_sha256 = w.sha((args.output/'closed.json').read_bytes())
    w.verifier_build(ctx,a,args,captured)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
