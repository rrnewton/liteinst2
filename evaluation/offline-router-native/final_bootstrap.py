"""Reconstruct saved main joins and both actual bootstrap builds; never dispatch.

All module arguments are source-authenticated by the fixed final checker. No
callback or reported boolean substitutes for the concrete readers used here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MIB = 1048576
PROGRAMS = ('checksum', 'rle-roundtrip')
CONTROL = ('request.json', 'command.json', 'parent-closed.json', 'receipt.json',
           'stdout.txt', 'stderr.txt', 'helper.stdout', 'helper.stderr')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(a, b):
    return json.dumps(a, sort_keys=True, separators=(',', ':')) == json.dumps(b, sort_keys=True, separators=(',', ':'))


def historical_copy(copy, source, destination):
    """Join the trusted builder's temporal observation, not a replaced pathname."""
    need(set(copy) == {'source_before', 'source_after', 'destination', 'bytes_equal'} and
         copy['bytes_equal'] is True and exact(copy['source_before'], copy['source_after']) and
         exact(copy['destination'], destination), 'exact temporal copy observation')
    old = copy['source_before']
    for pin in (old, destination):
        need(set(pin) == {'path', 'bytes', 'sha256', 'stat'} and type(pin['bytes']) is int and
             0 < pin['bytes'] <= 16*MIB and type(pin['sha256']) is str and
             re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None and
             type(pin['stat']) is list and len(pin['stat']) == 6 and
             all(type(n) is int and n >= 0 for n in pin['stat']) and
             stat.S_ISREG(pin['stat'][2]) and pin['stat'][3] == pin['bytes'], 'bounded regular copy pin')
    need(old['path'] == str(source) and old['path'] != destination['path'] and
         old['stat'][:2] != destination['stat'][:2] and
         old['bytes'] == destination['bytes'] and old['sha256'] == destination['sha256'] and
         stat.S_IMODE(destination['stat'][2]) == 0o400, 'historical built bytes and distinct immutable copy')


def authenticate(ctx, a, legacy, custody, pins, originals, startup, completed_reader,
                 driver, bootstrap, dso, args, store, reference):
    """Return rederived data plus a live stability check, never final authority.

    args is the same frozen-source/capture/producer/verifier/startup-binding
    namespace accepted by startup_completed, with main_joins and its SHA.
    reference is the externally frozen bootstrap run directory and closed SHA.
    """
    need(set(reference) == {'directory', 'sha256'}, 'exact saved bootstrap reference')
    directory = custody.absolute(reference['directory'])
    need(directory.is_relative_to(ctx.ROOT/'ignored'), 'private bootstrap run')
    raw = store.read(directory/'closed.json', MIB)
    need(sha(raw) == custody.digest(reference['sha256']), 'externally frozen bootstrap run')
    run = custody.json_value(raw)
    need(set(run) == {'schema', 'source_revision', 'programs', 'plan', 'producer_dispatches',
         'verifier_dispatches', 'native_dispatches', 'observer_dispatches', 'ordinary_n01_invocations',
         'bootstrap_builds_complete', 'platform_contract_accepted', 'artifact_complete',
         'qualification_complete', 'execution_authorized', 'performance_eligible', 'error',
         'load_average_end'} and run['schema'] == 'LI2STARTUP-BOOTSTRAP-RUN-1' and
         run['source_revision'] == pins.SOURCE_REVISION and run['error'] is None and
         run['bootstrap_builds_complete'] is True and tuple(run['programs']) == PROGRAMS,
         'complete two-build saved run')
    need(all(type(run[k]) is int and run[k] == 0 for k in ('producer_dispatches', 'verifier_dispatches',
         'native_dispatches', 'observer_dispatches', 'ordinary_n01_invocations')) and
         all(run[k] is False for k in ('platform_contract_accepted', 'artifact_complete',
         'qualification_complete', 'execution_authorized', 'performance_eligible')), 'build observations cannot grant execution')
    complete = completed_reader.authenticate(ctx, a, legacy, custody, pins, originals, startup, args, store,
        dict(directory=str(args.main_joins), sha256=args.main_joins_sha256))
    planned_pin = store.pin(directory/'planned.json', MIB)
    need(exact(run['plan'], planned_pin), 'saved prospective plan identity')
    plan = custody.json_value(store.read(directory/'planned.json', MIB, planned_pin))
    need(set(plan) == {'schema', 'revision', 'source_revision', 'source_profile', 'main_joins',
         'startup_binding', 'sources', 'resolver_source', 'lock', 'tools', 'configurations',
         'configuration_profile', 'cargo_cwd', 'builds', 'destination_parents', 'hardware',
         'cpus', 'load_average', 'producer_dispatches', 'verifier_dispatches', 'native_dispatches',
         'qualification_complete'} and plan['schema'] == 'LI2STARTUP-BOOTSTRAP-PLAN-1' and
         re.fullmatch('[0-9a-f]{40}', plan['revision']) is not None, 'whole prospective two-build plan')
    captured = complete['captured']
    custody.source_profile(ctx, pins, captured['env'])
    sources = driver.source_snapshot(ctx, pins, legacy, store)
    package = dso.resolver(ctx)
    resolver = store.pin(ctx.ROOT/dso.PACKAGE, MIB)
    need(resolver['sha256'] == dso.PACKAGE_SHA, 'fixed resolver source')
    lock = store.pin(ctx.ROOT/'crates/liteinst-bootstrap/Cargo.lock', 16*MIB)
    need(lock['sha256'] == pins.SOURCE_PINS['crates/liteinst-bootstrap/Cargo.lock'], 'separate bootstrap lock')
    builds = bootstrap.build_plan(ctx.ROOT, complete, directory)
    source_profile = dict(path=str(args.source_profile), sha256=args.source_profile_sha256)
    parents = {}
    for row in builds.values():
        destination = custody.absolute(row['destination'])
        need(destination.is_relative_to(ctx.ROOT/'ignored'), 'original frozen private destination')
        fd = store.directory(destination.parent)
        try:
            parents[str(destination.parent)] = custody.stamp(os.fstat(fd))[:3]
        finally:
            os.close(fd)
    required = dict(source_revision=pins.SOURCE_REVISION, source_profile=source_profile,
        main_joins=complete['reference'], startup_binding=store.pin(args.startup_binding, MIB),
        sources=sources, resolver_source=resolver, lock=lock, tools=captured['tools'],
        configurations=complete['configurations'], configuration_profile=complete['plan']['configuration_profile'],
        cargo_cwd='/', builds=builds, destination_parents=parents,
        producer_dispatches=0, verifier_dispatches=0, native_dispatches=0, qualification_complete=False)
    need(all(exact(plan[k], v) for k, v in required.items()), 'reconstructed actual source/configuration/build plan')
    joined = {}
    for program in PROGRAMS:
        row = run['programs'][program]
        need(set(row) == {'status', 'attempts', 'build_dispatches', 'error', 'exit', 'destination',
             'copy', 'closure', 'facts'} and row['status'] == 'BUILT_INSPECTED_PENDING_FINAL_PACKAGE' and
             type(row['attempts']) is int and row['attempts'] == 1 and type(row['build_dispatches']) is int and
             row['build_dispatches'] == 1 and type(row['exit']) is int and row['exit'] == 0 and
             row['error'] is None, 'one successful saved build per complete program')
        spec = builds[program]
        attempt = Path(spec['directory'])
        capture = dict(env=spec['env'], tools=captured['tools'])
        request, command = legacy.request_and_command(ctx, capture, attempt, spec['argv'], tuple(spec['limits']))
        code, streams = custody.closed(store, attempt, request, command, ctx.B.HELPER_SHA)
        need(code == 0, 'saved bootstrap raw build refusal')
        source = bootstrap.artifact(streams['stdout'], ctx.ROOT)
        # The first source inode may legitimately have been replaced by the
        # second build. Only the retained destination is read now.
        destination = row['destination']
        need(destination['path'] == spec['destination'], 'pre-frozen copied DSO pathname')
        raw_dso = store.read(Path(destination['path']), 16*MIB, destination)
        copy_pin = store.pin(attempt/'copy.json', MIB)
        need(exact(row['copy'], copy_pin), 'temporal copy receipt identity')
        copy = custody.json_value(store.read(attempt/'copy.json', MIB, copy_pin))
        historical_copy(copy, source, destination)
        inspected = dso.inspect(raw_dso, complete['programs'][program]['product']['catalog.li2boot'], package)
        facts_pin = store.pin(attempt/'linked-facts.json', 16*MIB)
        need(exact(row['facts'], facts_pin) and exact(custody.json_value(store.read(attempt/'linked-facts.json', 16*MIB)), inspected),
             'actual retained DSO reinspected with fixed checker')
        files = {str(attempt/name): store.pin(attempt/name, 128*MIB) for name in CONTROL}
        files[str(attempt/'linked-facts.json')] = facts_pin
        files[str(attempt/'copy.json')] = copy_pin
        closure = dict(schema='LI2STARTUP-BOOTSTRAP-BUILD-1', program=program, revision=plan['revision'], plan=planned_pin,
            source_revision=pins.SOURCE_REVISION, source_profile=source_profile, main_joins=complete['reference'],
            sources=sources, resolver_source=resolver, lock=lock, catalog=spec['catalog'], destination=destination,
            copy=copy, files=files, env=spec['env'], tools=captured['tools'], configurations=complete['configurations'],
            configuration_profile='rooted-offline-neutral-toml-comments-v1', cargo_cwd='/',
            status='BUILT_INSPECTED_PENDING_FINAL_PACKAGE', qualification_complete=False, execution_authorized=False)
        closure_pin = store.pin(attempt/'closed.json', MIB)
        need(exact(row['closure'], closure_pin) and exact(custody.json_value(store.read(attempt/'closed.json', MIB)), closure),
             'complete reconstructed bootstrap closure')
        joined[program] = dict(main=complete['programs'][program], bootstrap_pin=destination,
            bootstrap=raw_dso, linked=inspected, build=closure_pin)
    def stable():
        complete['stable']()
        store.verify()
        custody.source_profile(ctx, pins, captured['env'])
        for tool in captured['tools'].values():
            need(ctx.B.identity(tool['path']) == tool, 'final build tool drift')
    stable()
    return dict(programs=joined, completed=complete, reference=reference, stable=stable)
