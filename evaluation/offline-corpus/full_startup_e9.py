#!/usr/bin/env python3
"""Prepare the fixed matched E9 population from actual saved startup W01 joins.

This is preparation only: no builds, E9, verifier or application dispatch. The
existing bounded command owner executes the eight production requests. Existing
E9 adapter/comparator commands consume those actual closures afterward. Native
execution remains separately admitted; this plan is never execution authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

MIB = 1048576
CRATE = 'evaluation/adjacent-b2/artifact-verifier/'
PROFILE = 'elf-disassembly-null-jumps-static-exec-router-absolute-prerequisites-v1'
PROGRAMS = ('checksum', 'rle-roundtrip')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
DATASETS = ('empty', 'single-zero', 'single-ff', 'all-bytes', 'run-255', 'run-256',
            'runs-boundary', 'mixed-4096', 'long-run', 'long-alternating')
LANES = ('native', 'liteinst', 'stock-algorithm', 'bootstrap-patched-reference')
E9 = {'stock-algorithm': ('stock_frontend', 'stock_backend', 'stock_loader'),
      'bootstrap-patched-reference': ('transport_frontend', 'abi_backend', 'abi_loader')}
CORPUS_SHA = '007e529b3716061d8b7f11f3e33541ee80292027165703663db2f72a81e35b07'
COMPARATOR_SHA = '797b396392ec3459a21a37f4a41b15a47b9f478dfe92c5d2cf436041d282876f'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'


def checked_read(path, expected, cap=MIB):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         'canonical no-symlink input parents')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, 'bounded regular input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(path.parent.resolve(strict=True) == path.parent
             and identity(before) == identity(os.fstat(fd)) == identity(os.stat(path, follow_symlinks=False))
             and len(raw) == before.st_size and sha(raw) == expected, 'whole pinned input')
        return raw
    finally:
        os.close(fd)


def module(path, expected):
    raw = checked_read(path, expected)
    result = types.ModuleType('_full_startup_e9_' + Path(path).stem)
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def preparation(complete, corpus, adapter, tools, output):
    """Same-process seam: complete MUST be startup_completed.authenticate's result.

    A JSON status or user-authored true flag is not accepted by the CLI in place
    of that reader. This pure function generates no success/qualification claim.
    """
    need(complete['plan']['profile'] == PROFILE and tuple(complete['programs']) == PROGRAMS,
         'actual current full-startup producer class and both programs')
    need(adapter.ABSOLUTE_STARTUP_PROFILE == PROFILE, 'explicit matching adapter dispatch')
    data = corpus.datasets()
    need(tuple(data) == DATASETS and tuple(corpus.PROGRAMS) == PROGRAMS
         and all(type(v) is bytes and len(v) <= 65536 for v in data.values()), 'all ten original datasets')
    need(set(tools) == {name for roles in E9.values() for name in roles}, 'exact six pinned E9 roles')
    for lane, roles in E9.items():
        need(tuple(tools[r]['sha256'] for r in roles) == adapter.PRODUCERS[lane], 'unchanged pinned E9 lane')
    files = {'datasets/' + name: raw for name, raw in data.items()}
    programs, commands, rows = {}, [], []
    for program in PROGRAMS:
        item = complete['programs'][program]; product = item['product']
        original, selection = item['original'], product['selection.txt']
        expected_heads, expected_selected = COUNTS[program]
        need((item['row']['expected_heads'], item['row']['expected_selected']) == COUNTS[program]
             and item['row']['candidate_sha256'] == sha(product['candidate.elf']), 'actual independent full-program joins')
        need(sum(line.startswith(b'head ') for line in product['disassembly.txt'].splitlines()) == expected_heads,
             'all independently joined original instruction heads')
        policy = dict(schema=1, original_sha256=sha(original), selection_sha256=sha(selection),
                      e9_revision=adapter.REVISION, instrumentation='null', selection_style='jump-site')
        policy_raw = encode(policy)
        sites, observed = adapter.selection_absolute_startup(selection, original, policy_raw)
        need(observed == policy and len(sites) == expected_selected, 'complete selected jump denominator')
        # These are exactly the current producer's bytes: never a recreated or
        # historical ELF, nor a stripped/rehashed private selection projection.
        for name, raw in (('original.elf', original), ('selection.txt', selection),
                          ('report.tsv', product['report.tsv']), ('policy.json', policy_raw)):
            files[program + '/' + name] = raw
        programs[program] = dict(heads=expected_heads, selected=expected_selected,
            original_sha256=sha(original), selection_sha256=sha(selection),
            candidate_sha256=sha(product['candidate.elf']), policy_sha256=sha(policy_raw),
            report_sha256=sha(product['report.tsv']))
        for lane, roles in E9.items():
            folder = output/program/lane
            common = ['--action=asm=j.*:passthru', '--executable', '--compression=9',
                      '--start=0x401000', '--end=0x403001']
            original_path = str(output/program/'original.elf')
            transport = [tools['transport_frontend']['path'], *common, '--format=json', '--output=-', original_path]
            producer = [tools[roles[0]]['path'], *common, '--format=binary',
                        '--output=' + str(folder/'candidate.elf'), '--backend=' + tools[roles[1]]['path'],
                        '--option=--debug', original_path]
            for phase, argv in (('transport', transport), ('producer', producer)):
                commands.append(dict(program=program, lane=lane, phase=phase,
                    directory=str(folder/phase), argv=argv, limits=[20, 30, 16], attempts=1))
        for name, raw in data.items():
            want = corpus.expected(program, raw)
            need(len(want) == 24 if program == 'checksum' else len(want) <= 196616, 'unchanged exact output bounds')
            files[program + '/expected/' + name] = want
            for lane in LANES:
                rows.append(dict(program=program, dataset=name, lane=lane, status='UNRUN', attempts=0,
                    input_sha256=sha(raw), expected_sha256=sha(want), selected_sites=expected_selected))
    need(sum(p['heads'] for p in programs.values()) == 187 and sum(p['selected'] for p in programs.values()) == 42
         and len(commands) == 8 and len(rows) == 80, 'fixed entire population')
    return files, dict(profile=PROFILE, programs=programs, main_joins=complete['reference'],
        source_revision=complete['plan']['source_revision'], tools=tools, commands=commands, cases=rows,
        execution_tools={name:complete['captured']['tools'][name] for name in ('python','timeout','helper')},
        retained_history=[row['pin'] for row in complete['history']], qualification_complete=False,
        application_outputs_checked=False, native_execution_authorized=False, performance_eligible=False)



def envelope(plan, output, program, lane, adapter, store):
    """After actual production, build the EXISTING adapter's envelope, not a receipt.

    The adapter still reconstructs both command requests, all raw closures,
    producer/loader/RPC/patch ownership and statistics. This function only joins
    their filenames with the already frozen preparation inputs.
    """
    need(plan['profile'] == PROFILE and program in PROGRAMS and lane in E9,
         'one of four exact program/lane products')
    output = Path(output); folder = output/program/lane
    helper_pin = plan['execution_tools']['helper']
    paths = {name:output/program/file for name,file in
             (('original','original.elf'),('selection','selection.txt'),('policy','policy.json'))}
    paths['candidate'] = folder/'candidate.elf'
    for key, role in zip(('frontend','backend','loader'), E9[lane]):
        paths[key] = Path(plan['tools'][role]['path'])
    paths['transport_frontend'] = Path(plan['tools']['transport_frontend']['path'])
    paths['helper'] = Path(helper_pin['path'])
    for phase in ('transport','producer'):
        for key in ('request','receipt','stdout','stderr'):
            paths[phase+'_'+key] = folder/phase/(key+('.json' if key in ('request','receipt') else '.txt'))
    for pin in [*plan['tools'].values(), helper_pin]:
        store.read(pin['path'],16*MIB,pin)
    files = {}
    for name,path in paths.items():
        raw = store.read(path,16*MIB)
        files[name] = dict(path=str(path),bytes=len(raw),sha256=sha(raw))
    for role,key in (('original','original_sha256'),('selection','selection_sha256'),('policy','policy_sha256')):
        need(files[role]['sha256'] == plan['programs'][program][key], 'exact current comparison input')
    need(sha(store.read(output/program/'report.tsv',16*MIB)) == plan['programs'][program]['report_sha256'],
         'exact current independently joined core report')
    common = ['--action=asm=j.*:passthru','--executable','--compression=9','--start=0x401000','--end=0x403001']
    store.verify()
    return dict(schema=1,lane=lane,reference_commit=adapter.REVISION,reference_tree=adapter.TREE,
        archive_sha256=adapter.ARCHIVE,capstone_revision=adapter.CAPSTONE,abi_delta_patch_sha256=adapter.ABI_PATCH,
        common_argv=common,hook=None,files=files)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('root', 'output', 'source-profile', 'capture', 'diagnostic', 'verifier-build',
                 'startup-binding', 'main-joins', 'adapter', 'e9-tools'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-profile-sha256', 'capture-sha256', 'diagnostic-sha256', 'verifier-build-sha256',
                 'verifier-lock-sha256', 'startup-binding-sha256', 'main-joins-sha256', 'adapter-sha256', 'e9-tools-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    need(not sys.flags.optimize, 'assertions required')
    root = args.root
    need(root.is_absolute() and root.resolve(strict=True) == root, 'canonical exact source checkout')
    profile_raw = checked_read(args.source_profile, args.source_profile_sha256)
    adapter = module(args.adapter, args.adapter_sha256)
    profile = adapter.loads(profile_raw)
    # The external source hash authenticates initial imports; the established
    # source-profile loader then checks the COMPLETE inventory/revision/locks.
    def source(name):
        relative = CRATE + name
        return module(root/relative, profile['sources'][relative])
    legacy = source('verify_saved.py'); ctx, a = legacy.context(root)
    custody = source('startup_custody.py')
    pins = source('startup_pins.py').load(ctx, args.source_profile, args.source_profile_sha256)
    completed = source('startup_completed.py'); originals = source('startup_originals.py')
    startup = source('startup_saved.py'); driver = source('startup_produce.py')
    corpus = module(root/'evaluation/offline-corpus/corpus.py', CORPUS_SHA)
    checked_read(root/'tools/elf-rewrite/compare-sites.py', COMPARATOR_SHA)
    store = custody.Store(2 * 1024 * MIB)
    try:
        for path, expected in ((args.adapter, args.adapter_sha256), (args.source_profile, args.source_profile_sha256),
                               (root/'evaluation/offline-corpus/corpus.py', CORPUS_SHA),
                               (root/'tools/elf-rewrite/compare-sites.py', COMPARATOR_SHA)):
            need(sha(store.read(path, MIB)) == expected, 'retained exact preparation source/input')
        complete = completed.authenticate(ctx, a, legacy, custody, pins, originals, startup, args, store,
            dict(directory=str(args.main_joins), sha256=args.main_joins_sha256))
        tool_raw = store.read(args.e9_tools, MIB)
        need(sha(tool_raw) == args.e9_tools_sha256, 'external exact six-tool pathname map')
        paths = adapter.loads(tool_raw)
        need(type(paths) is dict and set(paths) == {n for roles in E9.values() for n in roles}, 'exact E9 tool map')
        tools = {role: store.pin(custody.absolute(path), 16 * MIB) for role, path in paths.items()}
        for role, pin in tools.items():
            need(role.endswith('loader') or pin['stat'][2] & 0o111, 'actual executable E9 tool')
        output = custody.absolute(str(args.output))
        need(output.is_relative_to(root/'ignored') and output.parent.resolve(strict=True) == output.parent
             and not os.path.lexists(output) and all(not output.is_relative_to(p) for p in
             (args.capture, args.diagnostic, args.verifier_build, args.main_joins, args.startup_binding.parent)),
             'new separate private preparation destination')
        files, plan = preparation(complete, corpus, adapter, tools, output)
        plan['source'] = dict(adapter=dict(path=str(args.adapter), sha256=args.adapter_sha256),
            comparator=dict(path=str(root/'tools/elf-rewrite/compare-sites.py'), sha256=COMPARATOR_SHA),
            preparer_sha256=sha(Path(__file__).read_bytes()), corpus_sha256=CORPUS_SHA)
        # All records use the existing bounded-command schema. Nothing runs.
        captured = dict(complete['captured'], env=dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
        for row in plan['commands']:
            request, command = legacy.request_and_command(ctx, captured, Path(row['directory']), row['argv'], row['limits'])
            relative = Path(row['directory']).relative_to(output)
            files[str(relative/'request.json')] = encode(request)
            files[str(relative/'command.json')] = encode(command)
        complete['stable'](); store.verify()
        output.mkdir(mode=0o700)
        for name, raw in files.items():
            path = output/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            driver.write(path, raw)
            store.read(path, 16 * MIB)
        complete['stable'](); store.verify()
        need(len(encode(plan)) <= MIB, 'compact prospective plan')
    finally:
        store.close()
    # No completed preparation plan is published if any read, write, stability
    # check or owner close failed. This is still only a prospective plan.
    driver.write(output/'plan.json', plan)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
