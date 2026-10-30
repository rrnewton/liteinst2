#!/usr/bin/env python3
"""Build the startup verifier once from the frozen source profile; execute no inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types

MIB = 1048576


def main():
    import verify_saved as legacy
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('output', 'source-profile', 'toolchain', 'cargo-home', 'user-home'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--source-profile-sha256', required=True)
    args = parser.parse_args()
    legacy.need(not sys.flags.optimize, 'assertions required')
    root = Path(__file__).resolve().parents[3]
    ctx, a = legacy.context(root)
    path = root / legacy.CRATE / 'startup_produce.py'
    raw = ctx.read(path, cap=MIB)
    legacy.need(legacy.sha(raw) == legacy.STARTUP_MODULES['startup_produce.py'],
                'exact startup command owner')
    driver = types.ModuleType('_startup_verifier_build_owner'); driver.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), driver.__dict__)
    custody = driver.load_module(ctx, legacy, 'startup_custody.py')
    loader = driver.load_module(ctx, legacy, 'startup_pins.py')
    pins = loader.load(ctx, args.source_profile, args.source_profile_sha256)
    env = driver.environment(root, args.toolchain, args.cargo_home, args.user_home)
    captured = dict(env=env, tools=driver.tools(ctx, env))
    custody.environment(ctx, env, captured['tools'])
    revision = custody.source_profile(ctx, pins, env)
    rooted = legacy.rooted_module(ctx)
    config = rooted.configurations(ctx, captured, profile=rooted.COMMENT_PROFILE)
    captured['configuration_profile'] = rooted.COMMENT_PROFILE
    output = custody.absolute(str(args.output))
    legacy.need(output.is_relative_to(root / 'ignored') and
                output.parent.resolve(strict=True) == output.parent and not os.path.lexists(output),
                'new private verifier build output')
    output.mkdir(mode=0o700)
    store = custody.Store(512 * MIB)
    report = dict(schema='LI2STARTUP-VERIFIER-BUILD-RUN-1', revision=revision,
        source_revision=pins.SOURCE_REVISION, build=None, build_attempts=0,
        verifier_dispatches=0, producer_dispatches=0, native_dispatches=0,
        qualification_complete=False, error=None)
    try:
        source = driver.source_snapshot(ctx, pins, legacy, store)
        source_profile = store.pin(args.source_profile, MIB)
        legacy.need(source_profile['sha256'] == args.source_profile_sha256,
                    'frozen source profile identity')
        directory = output / 'build'
        launcher = root / legacy.CRATE / 'startup_cargo_from_root.py'
        argv = [captured['tools']['python']['path'], '-B', str(launcher),
                captured['tools']['cargo']['path'], str(root), 'verifier']
        driver.write(output / 'planned.json', dict(source_profile=source_profile,
            source_revision=pins.SOURCE_REVISION, revision=revision, env=env,
            tools=captured['tools'], files=source, argv=argv, limits=[120, 180, 128],
            configuration_profile=rooted.COMMENT_PROFILE, configurations=config,
            hardware='AMD EPYC Zen 5 dev host', cpus=sorted(os.sched_getaffinity(0)),
            load_average=Path('/proc/loadavg').read_text().split()[:3], attempts=1))
        def stable():
            store.verify()
            legacy.need(custody.source_profile(ctx, pins, env) == revision,
                        'source changed during verifier build')
            legacy.need(rooted.configurations(ctx, captured, profile=rooted.COMMENT_PROFILE) == config,
                        'rooted Cargo configuration changed')
            for pin in captured['tools'].values():
                legacy.need(ctx.B.identity(pin['path']) == pin, 'tool changed during build')
        stable()
        report['build_attempts'] = 1
        code, streams = driver.execute(ctx, legacy, custody, store, captured, directory,
                                       argv, (120, 180, 128))
        report['build_exit'] = code
        legacy.need(code == 0, 'startup verifier build failed')
        binary = root / 'target/release/adjacent-b2-artifact-verifier'
        builder = ctx.load(a.ROUTED.builder, a.ROUTED.builder_sha)
        builder.check_artifact(streams['stdout'], dict(product_name='adjacent-b2-artifact-verifier',
            product_kind='bin', product=str(binary)))
        stable()
        required = {str(root / name): h for name, h in pins.SOURCE_PINS.items()}
        required[str(root / legacy.CRATE / 'Cargo.lock')] = pins.VERIFIER_LOCK_SHA256
        required[str(launcher)] = legacy.STARTUP_MODULES['startup_cargo_from_root.py']
        for name, h in legacy.ROOTED_BUILD_SOURCES.items():
            required[str(root / legacy.CRATE / name)] = h
        files = {}
        for name, h in required.items():
            data = store.read(Path(name), 16 * MIB)
            legacy.need(hashlib.sha256(data).hexdigest() == h, 'exact verifier source/lock')
            files[name] = store.pin(Path(name), 16 * MIB)
        for path in [binary, *(directory / name for name in custody.CONTROL)]:
            files[str(path)] = store.pin(path, 128 * MIB)
        driver.write(directory / 'closed.json', dict(schema='LI2STARTUP-BUILD-1',
            role='verifier', source_revision=pins.SOURCE_REVISION, files=files,
            configurations=config, configuration_profile=rooted.COMMENT_PROFILE,
            cargo_cwd='/', lock_sha256=pins.VERIFIER_LOCK_SHA256))
        reference = dict(directory=str(directory), sha256=legacy.sha(store.read(directory / 'closed.json', MIB)))
        observed, observed_config = custody.build(ctx, a, legacy, pins, store, 'verifier', reference, captured)
        legacy.need(observed == binary and observed_config == config, 'verifier build reader roundtrip')
        stable()
        report['build'] = reference
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            store.verify()
        except BaseException as error:
            report['error'] = (report['error'] or '') + '; final custody: ' + str(error)
        try:
            store.close()
        except BaseException as error:
            report['error'] = (report['error'] or '') + '; descriptor close: ' + str(error)
        driver.write(output / 'run-closed.json', report)
    print(json.dumps(report))
    return 0 if report['error'] is None and report['build'] is not None else 1


if __name__ == '__main__':
    raise SystemExit(main())
