#!/usr/bin/env python3
"""One build phase or one direct original/LiteInst/E9 cat experiment; no retries."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


S, D = sibling('direct_support'), sibling('direct_data')
M = S.M
PRODUCTS = {'full_program_bridge': ('tools/elf-rewrite/Cargo.toml', 'example', 'target/release/examples/full_program_bridge'),
            'disassembly_sites': ('tools/elf-rewrite/Cargo.toml', 'example', 'target/release/examples/disassembly_sites'),
            'elf-exec-oracle': ('Cargo.toml', 'bin', 'target/release/elf-exec-oracle')}
PROFILE = dict(opt_level='3', debuginfo=0, debug_assertions=True, overflow_checks=True, test=False)
PROVIDER = ('target/evaluation/e9-full-address-provider-v1/source/e9tool', 957120, 'af10f5847f332776c0c7ce2a81aea0ce6795982a6d1bcf819f516f25511d2aa2')
BACKEND = ('ignored/a3/upstream/e9patch-pldi2020/e9patch', 93520, '890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb')
CASES = [('empty', [], b'', b''), ('all-bytes-65536', [], bytes(range(256))*256, bytes(range(256))*256),
         ('numbered', ['-n'], b'alpha\n\nbeta\nomega', b'     1\talpha\n     2\t\n     3\tbeta\n     4\tomega')]


def build(r, a):
    r.record['outcomes'] = dict(metadata='UNOBSERVED', release='UNOBSERVED')
    for tool in ('cargo', 'rustc', 'rustdoc'): r.freeze(a.toolchain/'bin'/tool)
    S.save(r.work/'planned.json', r.record); r.capacity('before')
    # The dictionary is serialized as Python literals, with no shell evaluation.
    code = 'import json,subprocess; commands='+repr({'rustc': [str(a.toolchain/'bin/rustc'), '-vV'], 'cargo': [str(a.toolchain/'bin/cargo'), '-V']})+'; print(json.dumps({k:subprocess.check_output(v,stderr=subprocess.STDOUT,timeout=15).decode() for k,v in commands.items()}))'
    row, raw = r.run('metadata', [sys.executable, '-I', '-B', '-c', code], (30, 45, 512*M, 16*M, M))
    r.record['outcomes']['metadata'] = row['status']; assert row['status'] == 'PASS'
    r.record['tool_versions'] = json.loads(raw)
    command = [a.toolchain/'bin/cargo', 'build', '--release', '--locked', '--offline', '-j1', '-p', 'liteinst-rewrite', '-p', 'liteinst2',
               '--example', 'full_program_bridge', '--example', 'disassembly_sites', '--bin', 'elf-exec-oracle', '--message-format=json']
    row, raw = r.run('release', command, (300, 360, 4096*M, 128*M, 8*M))
    r.record['outcomes']['release'] = row['status']; assert row['status'] == 'PASS'
    messages = [json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    assert [m for m in messages if m.get('reason') == 'build-finished'] == [dict(reason='build-finished', success=True)]
    products = {}
    for name, (manifest, kind, path) in PRODUCTS.items():
        found = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == name and m.get('executable')]
        assert len(found) == 1; product = found[0]
        assert product['manifest_path'] == str(r.root/manifest) and product['target']['kind'] == [kind]
        assert product['profile'] == PROFILE and product['features'] == [] and product['executable'] == str(r.root/path)
        products[name] = dict(artifact=r.freeze(r.root/path), cargo=product)
    r.record.update(products=products, subject_executions=0, configuration_scope='Recorded tools, environment and actual Cargo products; no complete sysroot or inaccessible Cargo-config absence claim')
    return True


def functional(r, a):
    stages = {n: dict(status='UNOBSERVED') for n in ('target', 'provider', 'materials', 'policy', 'li2', 'e9')}
    cases = [dict(arm=arm, case=name, status='UNOBSERVED', argv=['cat', *argv], input_bytes=len(data), input_sha256=hashlib.sha256(data).hexdigest(), expected_stdout_sha256=hashlib.sha256(expected).hexdigest(), expected_bytes=len(expected)) for arm in ('original', 'li2', 'e9') for name, argv, data, expected in CASES]
    r.record.update(stages=stages, cases=cases, planned_cases=9, inventory_status='UNOBSERVED', structural={arm: dict(status='UNOBSERVED') for arm in ('li2', 'e9')})
    S.save(r.work/'planned.json', r.record)
    assert a.trusted_complete_code and a.unit
    r.record['scope_before'] = r.scope()
    cat_build, cat_authority = S.closed(a.cat_receipt, a.cat_receipt_sha256, 'READY_BUILT_UNEXECUTED')
    rust_build, rust_authority = S.closed(a.build_receipt, a.build_receipt_sha256, 'READY_BUILT_UNEXECUTED')
    assert sum((q['bytes'], q['sha256']) == (6007136, 'cd328edeac92f6a665de9f323c93b712af1858bc2e0d88f3f7100469470a1b8a') for q in cat_build['inputs'].values()) == 1
    assert rust_build['revision'] == a.revision and rust_build['tree'] == r.record['tree'] and rust_build['subject_executions'] == 0
    cat = Path(cat_build['artifact']['path']); cat_pin = r.freeze(cat, (cat_build['artifact']['bytes'], cat_build['artifact']['sha256']), M)
    assert cat_build['subject_executions'] == 0 and cat_build['artifact']['header_hex'].startswith('7f454c46020101')
    assert int.from_bytes(bytes.fromhex(cat_build['artifact']['header_hex'])[16:18], 'little') == 2
    r.freeze(a.cat_receipt); r.freeze(a.build_receipt)
    products = {}
    for name, (manifest, kind, path) in PRODUCTS.items():
        product = rust_build['products'][name]; q = product['artifact']; cargo = product['cargo']
        assert q['path'] == str(r.root/path) and cargo['manifest_path'] == str(r.root/manifest) and cargo['target']['kind'] == [kind] and cargo['profile'] == PROFILE and cargo['features'] == []
        products[name] = r.root/path; r.freeze(products[name], (q['bytes'], q['sha256']))
    for path, size, digest in (PROVIDER, BACKEND): r.freeze(r.root/path, (size, digest))
    for name in ('libdw.so', 'libelf.so', 'libz.so'): r.freeze(Path('/usr/lib64')/name)
    r.record.update(cat_build_authority=cat_authority, rust_build_authority=rust_authority, original=cat_pin,
                    provider_source='5e098f7920b5b5535f553de599c94ee980e97e29', backend_source='0d5d36e4c4edcac37ca2499694d64302a391136f',
                    policy=dict(domain=7, arena=[16777216, 536870912], preferences=False, records_per_site=3),
                    historical_scope='The earlier 1,035 misses/action pairs and strict full-coverage failures remain unchanged; these are new cat denominators.')
    r.capacity('before')
    def attempt(name, action):
        try:
            if name in r.record['structural']: r.record['structural'][name]['status'] = 'ATTEMPT_UNVERIFIED'
            stages[name]['status'] = 'ATTEMPT_STARTED'; result = action()
            stages[name]['status'] = 'PASS' if result is not None else 'REFUSED'
            return result
        except Exception as error:
            if name in r.record['structural']: r.record['structural'][name]['status'] = 'FAILED_UNVERIFIED'
            stages[name].update(status='FAILED', error=type(error).__name__+': '+str(error)); r.unchanged(); return None
    def command(name, argv, bounds, cwd=None):
        row, raw = r.run(name, argv, bounds, cwd); stages[name]['owner_result'] = name
        return row, raw
    def completed(row):
        assert S.clean_owner(row['owner']) and row['owner']['termination'] is None and row['owner']['exit_code'] in (0, 2)
    def target():
        row, raw = command('target', [products['elf-exec-oracle'], 'target'], (20, 30, 2048*M, 16*M, M))
        assert row['status'] == 'PASS' and re.fullmatch(rb'target xsave64 [0-9]+(?: [0-9]+:[0-9]+:[0-9]+)*\n', raw)
        S.write(r.work/'target.txt', raw); r.freeze(r.work/'target.txt'); return r.work/'target.txt'
    target_path = attempt('target', target)
    def provider():
        row, _ = command('provider', [r.root/PROVIDER[0], '--format=json', '--dump-all', '--plt', '-o', r.work/'provider', cat], (30, 30, 1024*M, 16*M, M))
        assert row['status'] == 'PASS'; path = r.work/'provider.DISASM.csv'; raw = S.payload(path, cap=M)
        assert raw.startswith(b'address,offset,size\n') and raw.endswith(b'\n')
        stages['provider']['csv'] = r.freeze(path, cap=M); return path
    csv_path = attempt('provider', provider)
    sites, rpc_info, material = None, None, r.work/'materials'
    def materials():
        nonlocal sites, rpc_info
        row, _ = command('materials', [products['full_program_bridge'], '--input-profile', 'et-exec-whole-4096-v1', '--original-sha256', cat_pin['sha256'], '--trusted-complete-code', cat, csv_path, r.frozen[str(csv_path)]['sha256'], material], (30, 45, 512*M, 16*M, M))
        completed(row)
        info = D.complete(material, S.payload); stages['materials']['complete'] = info
        assert info['fields']['profile'] == 'et-exec-whole-4096-v1' and info['fields']['original_sha256'] == cat_pin['sha256'] and info['fields']['csv_sha256'] == r.frozen[str(csv_path)]['sha256']
        if 'sites.tsv' in info['files']:
            sites = D.inventory(S.payload(material/'sites.tsv'), cat_pin['sha256'], info['files']['ledger.txt']['sha256'])
            assert int(info['fields']['sites']) == len(sites)
            r.record.update(inventory_status='IMPORTED_COMPLETE_DENOMINATOR', requested_sites=len(sites), complete_inventory=sites)
        if info['fields']['status'] == 'MATERIALS_REFUSED':
            assert row['owner']['exit_code'] == 2; return None
        assert info['fields']['status'] == 'MATERIALS_READY' and row['status'] == 'PASS' and sites is not None
        rpc_info = D.rpc(S.payload(material/'request.jsonl'), cat, sites); r.record['rpc'] = rpc_info
        for name in info['files']: r.freeze(material/name, cap=16*M)
        return material
    if csv_path is not None: attempt('materials', materials)
    def policy():
        rows = r.work/'policy-rows.txt'; S.write(rows, D.uniform_rows(sites)); r.freeze(rows)
        ledger = material/'ledger.txt'; ledger_pin = r.freeze(ledger)
        row, _ = command('policy', [products['full_program_bridge'], '--policy-profile', 'et-exec-whole-bounded-512m-v1', '--trusted-complete-code', cat, cat_pin['sha256'], ledger, ledger_pin['sha256'], target_path, r.frozen[str(target_path)]['sha256'], rows, r.frozen[str(rows)]['sha256'], '7', '16777216', '520093696', 'lowest', 'after-loads', r.work/'policy'], (20, 30, 512*M, 16*M, M))
        completed(row)
        info = D.complete(r.work/'policy', S.payload); stages['policy']['complete'] = info
        assert info['fields']['profile'] == 'et-exec-whole-bounded-512m-v1' and int(info['fields']['complete_jump_count']) == len(sites)
        for name, path in (('original', cat), ('ledger', ledger), ('target', target_path), ('rows', rows)): S.payload(path, info['inputs'][name])
        if info['fields']['status'] == 'POLICY_REFUSED': assert row['owner']['exit_code'] == 2; return None
        assert info['fields']['status'] == 'POLICY_READY' and row['status'] == 'PASS'
        path = r.work/'policy/policy.txt'; r.freeze(path); return path
    policy_path = attempt('policy', policy) if sites is not None and target_path is not None else None
    candidates = {}; r.capacity('before-generation')
    def li2():
        ledger = material/'ledger.txt'
        row, _ = command('li2', [products['disassembly_sites'], '--whole-program-packed-entry-veneer-mixed-neighbors-4096', cat, ledger, r.frozen[str(ledger)]['sha256'], policy_path, r.frozen[str(policy_path)]['sha256'], r.work/'li2'], (180, 240, 3072*M, 64*M, 8*M))
        completed(row)
        info = D.complete(r.work/'li2', S.payload); stages['li2']['complete'] = info; complete = info['fields']['candidate_complete'] == 'true'
        assert info['fields']['candidate_complete'] in ('true', 'false') and info['fields']['observed_original_sha256'] == cat_pin['sha256']
        if 'disassembly-inventory.tsv' in info['files']: assert D.inventory(S.payload(r.work/'li2/disassembly-inventory.tsv'), cat_pin['sha256'], r.frozen[str(ledger)]['sha256']) == sites
        if 'report.tsv' in info['files']: r.record['structural']['li2'] = D.li2_report(S.payload(r.work/'li2/report.tsv'), sites, cat_pin['sha256'], complete)
        r.record['structural']['li2']['status'] = 'PASS' if complete else 'FAILED'
        if not complete: assert row['owner']['exit_code'] == 2; return None
        assert row['status'] == 'PASS' and 'candidate.elf' in info['files'] and 'report.tsv' in info['files']
        assert info['files']['candidate.elf']['bytes'] <= 12120064
        candidates['li2'] = r.work/'li2/candidate.elf'; return candidates['li2']
    if policy_path is not None: attempt('li2', li2)
    r.capacity('after-li2')
    def e9():
        out = r.work/'e9'; out.mkdir(); row, raw = command('e9', [r.root/BACKEND[0], '--debug', '--input', material/'request.jsonl'], (60, 90, 36*1024*M, 64*M, 8*M), out)
        path = out/'a.out'
        assert row['status'] == 'PASS' and path.is_file()
        q = S.pin(path, 64*M); info = D.e9_statistics(raw, rpc_info, cat, cat_pin['bytes'], q['bytes'])
        info['status'] = 'PASS' if info['strict_full'] else 'FAILED'; r.record['structural']['e9'] = info
        candidates['e9'] = path
        return path
    if rpc_info is not None: attempt('e9', e9)
    r.capacity('after-e9')
    original = r.work/'original'; S.write(original, S.payload(cat, cat_pin, M)); candidates['original'] = original
    for arm, path in candidates.items():
        before = S.pin(path, 64*M); os.chmod(path, 0o500); q = r.freeze(path, (before['bytes'], before['sha256']), 64*M)
        r.record.setdefault('executables', {})[arm] = q
    for row in cases:
        if row['arm'] not in candidates: row['reason'] = 'No candidate produced by the single declared rewrite attempt'; continue
        name, argv, data, expected = next(c for c in CASES if c[0] == row['case']); path = candidates[row['arm']]; q = r.frozen[str(path)]
        directory = r.work/(row['arm']+'-'+name); directory.mkdir(); stdin = directory/'stdin'; S.write(stdin, data); inp = r.freeze(stdin)
        intent = [sys.executable, '-I', '-B', Path(__file__).with_name('native_exec.py'), path, str(q['bytes']), q['sha256'], stdin, str(inp['bytes']), inp['sha256'], directory/'stderr', directory/'exec-error.json', 'cat', *argv]
        row.update(status='UNRESOLVED', owner_result=row['arm']+'-'+name)
        result, stdout = r.run(row['arm']+'-'+name, intent, (20, 30, 2048*M, M, 128*1024), directory)
        stderr = S.payload(directory/'stderr', cap=M) if (directory/'stderr').is_file() else None
        row.update(owner_result=result['name'], stdout=result['capture'], stderr=None if stderr is None else S.pin(directory/'stderr'), status='FAILED')
        if (directory/'exec-error.json').is_file(): row['exec_error'] = S.load(directory/'exec-error.json')
        row['exact_stdout'] = stdout == expected; row['empty_stderr'] = stderr == b''
        if result['status'] == 'PASS' and row['exact_stdout'] and row['empty_stderr']: row['status'] = 'PASS'
    r.record['functional_status'] = 'PASS' if all(row['status'] == 'PASS' for row in cases) else 'FAILED'
    r.record['observed_cases'] = sum(row['status'] in ('PASS', 'FAILED') for row in cases)
    return r.record['functional_status'] == 'PASS' and all(r.record['structural'][arm]['status'] == 'PASS' for arm in ('li2', 'e9'))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('phase', choices=('build', 'functional')); parser.add_argument('--revision', required=True); parser.add_argument('--work', type=Path, required=True)
    for name in ('toolchain', 'cargo-home', 'user-home', 'cat-receipt', 'build-receipt'): parser.add_argument('--'+name, type=Path)
    for name in ('cat-receipt-sha256', 'build-receipt-sha256', 'unit'): parser.add_argument('--'+name)
    parser.add_argument('--trusted-complete-code', action='store_true'); a = parser.parse_args(); env = dict(S.BASE_ENV)
    if a.phase == 'build':
        for path in (a.toolchain, a.cargo_home, a.user_home): assert path and path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
        env.update(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(a.toolchain/'bin/rustc'), RUSTDOC=str(a.toolchain/'bin/rustdoc'), CARGO_TARGET_DIR=str(Path.cwd()/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true')
    else:
        for value in (a.cat_receipt_sha256, a.build_receipt_sha256): assert value and re.fullmatch('[0-9a-f]{64}', value)
        assert a.cat_receipt and a.build_receipt
    r = S.Run(a, env, a.phase, (128 if a.phase == 'build' else 160)*M); passed = False
    try: passed = build(r, a) if a.phase == 'build' else functional(r, a)
    except BaseException as error: r.record['error'] = type(error).__name__+': '+str(error)
    return r.finish(passed)


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    raise SystemExit(main())
