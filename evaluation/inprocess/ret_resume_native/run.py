#!/usr/bin/env python3
"""One bounded real-C3/owned-TF ordering observation; no production continuation."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60], 'native': [5, 512 << 20, 16 << 20, 15]}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular whole file: '+str(path))
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'mode': format(stat.S_IMODE(path.stat().st_mode), '04o')}


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), 'no duplicate JSON fields')
    return result


def load(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def dynamic(path):
    """Read actual ELF strings for dependency-closure joins; no loading."""
    b = Path(path).read_bytes()
    need(b[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', b, 18)[0] == 62, 'actual ELF64')
    off = struct.unpack_from('<Q', b, 32)[0]
    size, count = struct.unpack_from('<HH', b, 54)
    need(size == 56 and 0 < count <= 64 and off+size*count <= len(b), 'bounded ELF headers')
    rows = [struct.unpack_from('<IIQQQQQQ', b, off+i*size) for i in range(count)]
    tables = [p for p in rows if p[0] == 2]
    need(len(tables) == 1, 'one actual dynamic table')
    p = tables[0]
    need(p[5] % 16 == 0 and p[2]+p[5] <= len(b), 'whole dynamic table')
    tags = []
    for offset in range(p[2], p[2]+p[5], 16):
        tag, value = struct.unpack_from('<QQ', b, offset)
        if not tag:
            break
        tags.append((tag, value))
    else:
        raise ValueError('terminated dynamic table')
    def one(tag):
        values = [v for t, v in tags if t == tag]
        need(len(values) == 1, 'one string-table field')
        return values[0]
    address, length = one(5), one(10)
    segments = [p for p in rows if p[0] == 1 and p[3] <= address and address+length <= p[3]+p[5]]
    need(len(segments) == 1, 'whole LOAD-owned dynamic strings')
    p = segments[0]
    offset = p[2]+address-p[3]
    strings = b[offset:offset+length]
    need(len(strings) == length, 'whole dynamic strings')
    def name(value):
        need(value < len(strings) and b'\0' in strings[value:], 'bounded dynamic name')
        return strings[value:strings.index(b'\0', value)].decode('ascii')
    needed = [name(v) for t, v in tags if t == 1]
    sonames = [name(v) for t, v in tags if t == 14]
    need(len(sonames) <= 1 and len(set(needed)) == len(needed), 'unambiguous dynamic dependencies')
    need(not any(t in (15, 29, 0x7FFFFFFD, 0x7FFFFFFF, 0x6FFFFEFC, 0x6FFFFEFB) for t, v in tags),
         'no search/filter/audit overrides')
    return {'needed': needed, 'soname': sonames[0] if sonames else None}


def retained(path, wanted, current, pin, environment):
    """Authenticate a closed prerequisite; never execute or substitute its result."""
    prior = load(pin(path))
    need(prior['status'] == wanted['status'] and prior['profile'] == wanted['profile'] and
         prior['revision'] == current['revision'] and prior['source'] == current['source'] and
         prior['cpu'] == current['cpu'] and prior['hardware'] == current['hardware'],
         'exact current prerequisite source and outcome, same actual CPU/hardware')
    need(prior['source_unchanged'] is True and prior['inputs_unchanged'] is True and
         prior['cleanup_complete'] is True and prior['error'] is None and prior['final_errors'] == [] and
         prior['owner_credit'] in (0, False) and prior['qualification_credit'] is False and
         prior['performance_credit'] is False, 'complete closed unqualified prerequisite')
    need([row['name'] for row in prior['commands']] == wanted['commands'] and
         prior['bounds'] == wanted['bounds'], 'whole original prerequisite schedule and bounds')
    for group in ('inputs', 'artifacts'):
        for name, value in prior[group].items():
            need(fact(pin(name)) == value, 'retained whole prerequisite '+group+': '+name)
    for name, target in prior['aliases'].items():
        need(str(pin(name)) == target, 'exact retained prerequisite alias')
    for name, target in prior.get('context_links', {}).items():
        need(Path(name).is_symlink() and os.readlink(name) == target and
             str(pin(name)) == str(Path(target).resolve(strict=True)), 'exact prerequisite context link')
    for name, exists in prior['loader_presence'].items():
        need(Path(name).exists() == exists, 'same prerequisite loader configuration presence')
    directory = Path(path).parent.resolve(strict=True)
    for row in prior['commands']:
        need(row['exit'] == row['expected_exit'] == 0 and row['error'] is None and
             row['timed_out'] is False and row['reaped'] is True and row['cleanup_errors'] == [] and
             all(d['closed'] for d in row['descriptors']) and row['environment'] == environment and
             row['capture_limit'] == 16 << 20 and row['bounds'] in wanted['bounds'].values(),
             'actual prerequisite process success, environment, original bounds and closure')
        need(set(row['captures']) == {'stdout', 'stderr'}, 'both whole prerequisite captures')
        for stream, value in row['captures'].items():
            capture = directory/value['file']
            need(capture.parent == directory and
                 {k: fact(pin(capture))[k] for k in ('bytes','sha256')} ==
                 {k: value[k] for k in ('bytes','sha256')} and
                 fact(capture) == prior['artifacts'][str(capture)], 'whole post-reap prerequisite capture')
    return prior



def ret_compact(observed):
    need(observed['schema'] == 1 and observed['status'] == 'observed_unqualified' and
         observed['native_cases'] == observed['native_lanes'] == 32 and
         observed['ret_continuation_safe'] is None and
         all(observed[k] is False for k in ('production_admission_credit', 'owner_credit',
                                           'qualification_credit', 'performance_credit')),
         'all 32 RET observations only; no replacement authority')
    rows = observed['observations']
    need(len(rows) == 32 and [x['id'] for x in rows] == list(range(32)) and
         [sum(x['group'] == group for x in rows) for group in range(4)] == [20, 4, 6, 2],
         'complete fixed RET population with no skipped category')
    groups = []
    for group, count in enumerate((20, 4, 6, 2)):
        members = [x for x in rows if x['group'] == group]
        need(len(members) == count and all(x['fp_storage_unchanged'] is True and
             x['fs_gs_unchanged'] is True and x['stack_bytes_unchanged'] is True for x in members),
             'all fixed RET full-state and memory checks')
        groups.append(dict(group=group, cases=count,
            signals=dict(sorted(Counter(str(x['signal'])+':'+str(x['si_code']) for x in members).items())),
            rsp_commitment=dict(sorted(Counter(x['observed_rsp_commitment'] for x in members).items()))))
    return dict(status='observed_unqualified', native_cases=32, native_lanes=32,
        groups=groups, raw_source=observed['source'], ret_continuation_safe=None,
        production_admission_credit=False, owner_credit=False,
        qualification_credit=False, performance_credit=False,
        scope='Actual unstepped C3 endpoint/fault observations; no generated replacement, owner or timing credit.')


def public_result(value):
    """Project checked numeric outcomes; all literal frames stay in the private receipt/raw."""
    if value is None:
        return None
    keys = ('id','kind','route','input_flags','owned_tf','signal','si_code','trapno','error','event',
            'target_effect_executed','fp_storage_unchanged','kernel_mask_unchanged','tls_unchanged',
            'raw_record_sha256','full_fp_sha256','stack_before_sha256','stack_after_sha256',
            'private_before_sha256','private_after_sha256')
    result = {k: v for k, v in value.items() if k != 'observations'}
    result['observations'] = [dict({k: row[k] for k in keys},
        logical_rsp_delta=row['logical_rsp']-row['guest_rsp'],
        physical_rsp_delta=row['actual_rsp']-row['physical_operand_rsp'],
        saved_target_equals_original=(row['saved_target']==row['target'] if row['route']==2 else None),
        original_word_changed=row['guest_word_after']!=row['target']) for row in value['observations']]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--ret-receipt', type=Path, required=True)
    parser.add_argument('--ret-receipt-sha256', required=True)
    args = parser.parse_args()
    manifest = load(HERE/'SOURCE.json')
    need(sys.version_info >= (3, 11) and not sys.flags.optimize and os.sched_getaffinity(0) == {args.cpu},
         'pinned Python3.11+, assertions and independently reserved explicit singleton CPU')
    need(re.fullmatch(r'[0-9a-f]{40}', args.expect_revision) is not None,
         'explicit complete source revision; all pinned inputs remain mandatory')
    need(re.fullmatch(r'[0-9a-f]{64}', args.ret_receipt_sha256) is not None,
         'explicit whole public RET prerequisite identity')
    for name, wanted in manifest['files'].items():
        need(fact(ROOT/name) == wanted, 'whole public source input: '+name)
    private = args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and not private.exists(),
         'fresh private attempt')
    cpu = next(iter(os.sched_getaffinity(0)))
    sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
    from checks import source
    from run import hardware
    from page_selected import ENV, save
    from page_selected_process import invoke
    os.chdir(ROOT)
    private.mkdir()
    receipt = private/'receipt.json'
    pins, aliases, artifacts, presence = {}, {}, {}, {}
    r = dict(schema=1, profile='public-ret-resume-native-ordering-v1', status='failed',
             revision=args.expect_revision, cpu=cpu, hardware=hardware(cpu), source=None,
             bounds=BOUNDS, commands=[], result=None, error=None, final_errors=[],
             source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
             ret_continuation_safe=None, native_cases=15, archive_builds=0, archive_copies=0,
             production_continuation=False, portable_recipe=True,
             production_admission_credit=False, owner_credit=False,
             qualification_credit=False, performance_credit=False)

    def pin(path):
        need(path is not None, 'required input path')
        alias = Path(path).absolute()
        resolved = alias.resolve(strict=True)
        value = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved), 'stable input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == value, 'stable complete input')
        aliases[str(alias)], pins[str(resolved)] = str(resolved), value
        return resolved

    def artifact(path):
        path = Path(path)
        need(path.is_relative_to(private), 'artifact stays in this attempt')
        value = fact(path)
        need(str(path) not in artifacts or artifacts[str(path)] == value, 'stable whole artifact')
        artifacts[str(path)] = value

    def closure():
        need(all(fact(p) == f for p, f in pins.items()), 'whole inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'aliases unchanged')
        need(all(fact(p) == f for p, f in artifacts.items()), 'whole artifacts unchanged')
        need(all(Path(p).exists() == v for p, v in presence.items()), 'loader configuration presence')
        need(sorted(os.sched_getaffinity(0)) == [cpu], 'same reserved CPU')

    def run(name, argv, profile='build'):
        closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique command; no retry')
        row = dict(name=name, argv=list(map(str, argv)), bounds=BOUNDS[profile],
                   capture_limit=16 << 20, environment=dict(ENV), expected_exit=0)
        r['commands'].append(row)
        save(receipt, r)
        try:
            out, err = invoke(row, private, cpu)
        finally:
            for stream, f in row.get('captures', {}).items():
                path = private/f['file']
                need({k: fact(path)[k] for k in ('bytes', 'sha256')} ==
                     {k: f[k] for k in ('bytes', 'sha256')}, 'post-reap complete capture')
                artifact(path)
            path = private/(name+'.json')
            if path.is_file():
                artifact(path)
            save(receipt, r)
        need(row['exit'] == 0 and row['error'] is None and not row['timed_out'] and
             row['reaped'] is True and not row['cleanup_errors'] and
             all(d['closed'] for d in row['descriptors']), 'exact bounded command closure: '+name)
        return out, err

    output = private/'ret-resume-native-probe'
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact current clean source')
        pin(HERE/'SOURCE.json')
        for name in manifest['files']:
            pin(ROOT/name)
        for module in tuple(sys.modules.values()):
            name = getattr(module, '__file__', None)
            if name and Path(name).resolve().is_relative_to(ROOT):
                pin(name)
        python = pin(sys.executable)
        r['collector_python'] = str(python)
        fixture = (ROOT/manifest['fixture']).resolve(strict=True)
        need(manifest['matrix'] == dict(chunks=1,fp_bytes_per_frame=65536,frames=30,
             guest_stack_bytes=16384,lanes=15,private_page_bytes=4096,raw_bytes=2879240,
             read_once_poison_cases=5,record_bytes=191928,routes=3,targets=5) and
             manifest['bounds'] == BOUNDS and manifest['production_continuation'] is False,
             'exact published whole-leaf ordering matrix and original finite bounds')
        origin = pin(args.ret_receipt)
        need(fact(origin)['sha256'] == args.ret_receipt_sha256, 'explicit whole public RET receipt')
        old_native = retained(origin,manifest['prerequisite'],r,pin,ENV)
        need(set(old_native['components']) == {'ret_native','ret_dispatch','ret_dispatch_native'} and
             [old_native['components'][n]['status'] for n in ('ret_native','ret_dispatch','ret_dispatch_native')] ==
                 ['observed_unqualified','passed','finite_ret_adapter_observed'] and
             old_native['loaded_miss_resumption'] is False and
             old_native['production_owner_authority'] is False,
             'all prior finite stages remain distinct; no continuation or owner authority')
        for name in ('evaluation/inprocess/ret_dispatch/run.py',
                     'evaluation/inprocess/ret_dispatch/SOURCE.json',
                     'tools/page-entry/selected/tests/ret_native/probe.c',
                     'tools/page-entry/selected/tests/ret_native/probe.S',
                     'tools/page-entry/selected/tests/ret_native/build.sh',
                     'tools/page-entry/selected/tests/ret_native/read.py'):
            actual = pin(ROOT/name)
            need(old_native['inputs'].get(str(actual)) == fact(actual),
                 'exact current public RET32 producer/reader in prior input custody')
        old_ret = old_native['components']['ret_native']
        old_read_rows = [x for x in old_native['commands'] if x['name'] == 'ret_native-reader']
        need(len(old_read_rows) == 1, 'one actual complete RET32 reader')
        old_read = old_read_rows[0]
        need(old_read['name'] == 'ret_native-reader' and old_read['captures']['stderr']['bytes'] == 0,
             'actual original RET32 complete reader')
        old_observed = load(origin.parent/old_read['captures']['stdout']['file'])
        expected_ret = ret_compact(old_observed)
        expected_ret['observations'] = old_observed['observations']
        need(old_ret['result'] == expected_ret, 'whole original RET32 unqualified observation')
        old_rows = [x for x in old_native['commands'] if x['name'] == 'ret_native-native']
        need(len(old_rows) == 1 and old_observed['cpu'] == cpu, 'one original RET32 process on same CPU')
        row = old_rows[0];capture = row['captures']['stdout']
        need(capture['bytes'] == 5879872 and old_observed['source'] ==
             dict(pid=row['pid'],bytes=capture['bytes'],sha256=capture['sha256']) and
             row['bounds'] == BOUNDS['native'] and row['captures']['stderr']['bytes'] == 0,
             'original whole RET32 raw/PID/output/bound joins')
        r['prerequisite'] = dict(receipt=fact(origin),
            revision=old_native['revision'],status=old_native['status'],cases=32,executed_here=False,
            ret_continuation_safe=None)
        need(str(python) == old_native['tools']['python'], 'same actual RET32 Python interpreter')
        tools = {'cc': pin(shutil.which('cc', path=ENV['PATH']))}
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = Path(name).exists()
            if presence[name]:
                pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run('resolve-'+name, [tools['cc'], '-print-prog-name='+name])
            value = out.decode().strip()
            need(value and not err, 'actual compiler subtool')
            tools[name] = pin(value if Path(value).is_absolute() else shutil.which(value, path=ENV['PATH']))
        for name in ('cc', 'cc1', 'collect2', 'as', 'ld'):
            need(str(tools[name]) == old_native['tools'][name] and
                 fact(tools[name]) == old_native['inputs'][str(tools[name])],
                 'same actual whole RET32 compiler subtool')
        tools['objdump'] = pin(shutil.which('objdump',path=ENV['PATH']))
        need(fact(tools['objdump']) == manifest['objdump'], 'exact prebound disassembler tool')
        for name in ('cc', 'as', 'ld','objdump'):
            out, err = run('version-'+name, [tools[name], '--version'])
            need(out and not err, 'actual tool version')
        for name in ('crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'crtbegin.o', 'crtbeginS.o',
                     'crtend.o', 'crtendS.o', 'libgcc.a', 'libgcc_s.so', 'libc.so',
                     'libc_nonshared.a', 'libc.so.6', 'libgcc_s.so.1'):
            out, err = run('link-input-'+name, [tools['cc'], '-print-file-name='+name])
            value = out.decode().strip()
            need(not err and Path(value).is_absolute(), 'actual selected link input')
            selected = pin(value)
            need(str(selected) in old_native['inputs'] and
                 fact(selected) == old_native['inputs'][str(selected)], 'same whole RET32 link input')
        _, err = run('compiler-specs', [tools['cc'], '-dumpspecs'])
        need(not err, 'whole compiler specs')
        r['tools'] = {k: str(v) for k, v in tools.items()}
        recipe = (fixture/'build.sh').read_text().replace('\\\n', ' ')
        lines = [line.strip() for line in recipe.splitlines() if line.strip().startswith('"$cc" ')]
        need(len(lines) == 1, 'one closed literal build recipe')
        substitutions = {'$cc': tools['cc'], '$source_dir': fixture, '$output': output}
        argv = []
        for word in shlex.split(lines[0]):
            for key, value in substitutions.items():
                word = word.replace(key, str(value))
            need('$' not in word and '`' not in word, 'literal compiler argv')
            argv.append(word)
        sources = [str(fixture/'probe.c'), str(fixture/'probe.S')]
        need([x for x in argv if x.endswith(('.c', '.S'))] == sources and
             argv[-2:] == ['-o', str(output)] and '-Werror' in argv and '-no-pie' in argv,
             'exact two-source strict recipe')
        r['recipe'] = {'file': fact(fixture/'build.sh'), 'argv': argv}
        flags = [x for x in argv[1:-2] if x not in sources and not x.startswith('-Wl,')]
        all_headers = set()
        for index, source_path in enumerate(sources):
            out, err = run('headers-'+str(index), [tools['cc'], *flags, '-M', '-MT', 'probe', source_path])
            rule = out.decode().replace('\\\n', ' ')
            need(not err and len(rule.splitlines()) == 1 and rule.startswith('probe: '), 'whole actual compiler-M rule')
            actual = {str(pin(x)) for x in shlex.split(rule.split(':', 1)[1])}
            need(str(Path(source_path).resolve()) in actual, 'actual source included')
            all_headers |= actual
        need(all(name in old_native['inputs'] for name in all_headers-set(sources)),
             'actual opened headers belong to the authenticated RET32 toolchain')
        r['headers'] = sorted(all_headers)
        out, err = run('build', argv)
        need(not out and not err, 'strict compiler captures empty')
        artifact(output)
        need(int(fact(output)['mode'], 8) & 0o111, 'fresh executable')
        out, err = run('emitted-inspection', [python, '-I', '-S', '-B', ROOT/manifest['inspector'], output], 'native')
        need(not err, 'emitted inspection stderr empty')
        inspected = json.loads(out, object_pairs_hook=unique)
        need(inspected['status'] == 'source_bytes_inspected' and
             inspected['elf_sha256'] == fact(output)['sha256'] and inspected['native_execution'] is False and
             inspected['qualification_credit'] is False, 'whole emitted code inspected before subjects')
        r['emitted_inspection'] = inspected
        out, err = run('handler-disassembly',[tools['objdump'],'-d','-w','--insn-width=16',
                       '--disassemble=handler',output],'native')
        need(out and not err, 'whole actual handler disassembly')
        disassembly = private/r['commands'][-1]['captures']['stdout']['file']
        out, err = run('operand-load-inspection',[python,'-I','-S','-B',HERE/'inspect-load.py',
                       output,disassembly],'native')
        need(not err, 'actual operand-load inspection stderr empty')
        inspected_load = json.loads(out,object_pairs_hook=unique)
        need(inspected_load['status'] == 'single_operand_load_inspected' and
             inspected_load['elf_sha256'] == fact(output)['sha256'] and
             inspected_load['disassembly_sha256'] == fact(disassembly)['sha256'] and
             inspected_load['record_bytes'] == 191928 and len(inspected_load['exact_sequence']) == 5 and
             all(inspected_load[k] is False for k in ('native_execution','production_continuation','qualification_credit')),
             'whole actual single target-load sequence passes before any native lane')
        r['operand_load_inspection'] = inspected_load
        interpreter = pin(inspected['interpreter'])
        out, err = run('runtime-dependencies', [interpreter, '--list', output])
        need(not err, 'actual loader dependency inspection')
        objects = {str(output): dynamic(output)}
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):
                continue
            match = re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)', line)
            need(match is not None, 'complete actual loader dependency line')
            resolved = pin(match.group(2))
            need(str(resolved) in old_native['inputs'] and
                 fact(resolved) == old_native['inputs'][str(resolved)], 'same whole RET32 runtime input')
            value = dynamic(resolved)
            requested = match.group(1)
            if requested is not None and requested.startswith('/'):
                need(requested == inspected['interpreter'] and pin(requested) == resolved == interpreter,
                     'exact actual PT_INTERP alias join')
            else:
                need(requested is None or value['soname'] == requested, 'actual SONAME dependency join')
            objects[str(resolved)] = value
        need(str(interpreter) in objects, 'actual interpreter in loader closure')
        sonames = [v['soname'] for v in objects.values() if v['soname'] is not None]
        need(len(sonames) == len(set(sonames)) and
             all(name in sonames for v in objects.values() for name in v['needed']), 'closed exact DT_NEEDED roster')
        r['runtime_objects'] = objects
        out, err = run('native-0', [output, '0'], 'native')
        row = r['commands'][-1]
        need(not err and len(out) == 2879240, 'whole fixed15-lane ordering chunk under original output bound')
        h = struct.unpack_from('<32Q', out)
        need(h[:4] == (0x3153525232494C, 1, 256, 191928) and
             h[10:17] == (15, 0, 0, 15, 15, row['pid'], cpu) and
             h[28:30] == (inspected['reload_address'], inspected['scratch_end_address']),
             'actual collector PID/CPU/ELF-bootstrap and exact single RET chunk')
        capture = private/row['captures']['stdout']['file']
        r['native_chunk'] = dict(chunk=0, pid=row['pid'], cpu=cpu,
            duration_ns=row['duration_ns'], capture=row['captures']['stdout'])
        out, err = run('read-ordering', [python, '-I', '-S', '-B', ROOT/manifest['reader'],
            '--expect-cpu', str(cpu), '--expect-pid', str(row['pid']), capture], 'native')
        need(not err, 'whole independent RET reader stderr empty')
        observed = json.loads(out, object_pairs_hook=unique)
        need(observed['cpu'] == cpu and observed['source'] ==
             dict(pid=r['native_chunk']['pid'], bytes=r['native_chunk']['capture']['bytes'],
                  sha256=r['native_chunk']['capture']['sha256']),
             'whole RET reader input joins actual child capture and PID')
        need([c['name'] for c in r['commands']] == manifest['commands'],
             'complete fixed build/inspection/native/reader schedule; no retry or skipped stage')
        need(observed['status'] == 'hardware_ordering_observed_unqualified' and
             (observed['cases'],observed['targets'],observed['routes']) == (15,5,3) and
             observed['rx_pre_instruction_trace_observed'] is True and
             observed['noncanonical_original_rsp_mapping_observed'] is True and
             observed['saved_word_poison_controls'] == 5 and
             [(x['id'],x['kind'],x['route']) for x in observed['observations']] ==
                 [(i,i//3,i%3) for i in range(15)] and
             all(observed[k] is False for k in ('loaded_miss_continuation_implemented','production_owner_authority',
                 'original_RET32_replaced','original_RET_adapter_cases_replaced','qualification_credit','performance_credit')),
             'complete fixed hardware observation without continuation or qualification credit')
        r['result'] = observed
        r['status'] = 'observed_unqualified'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            if output.exists():
                artifact(output)
        except BaseException as error:
            r['final_errors'].append('partial-artifact: '+type(error).__name__+': '+str(error))
        try:
            closure()
            r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append('input-closure: '+type(error).__name__+': '+str(error))
        try:
            need(source() == r['source'], 'whole current source closure')
            r['source_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append('source-closure: '+type(error).__name__+': '+str(error))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
             all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not all(r[k] for k in
                ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')):
            r['status'] = 'failed'
            r['result'] = None
        r.update(inputs=pins, aliases=aliases, artifacts=artifacts, loader_presence=presence)
        save(receipt, r)
    summary = dict(schema=1,profile=r['profile'],status=r['status'],revision=r['revision'],
        cpu=cpu,hardware=r['hardware'],bounds=BOUNDS,receipt=fact(receipt),
        command_count=len(r['commands']),prerequisite=r.get('prerequisite'),
        result=public_result(r['result']),source_unchanged=r['source_unchanged'],
        inputs_unchanged=r['inputs_unchanged'],cleanup_complete=r['cleanup_complete'],
        error_present=r['error'] is not None,final_error_count=len(r['final_errors']),
        production_continuation=False,owner_credit=False,qualification_credit=False,performance_credit=False)
    save(private/'summary.json',summary)
    print(json.dumps({'status': r['status'], 'receipt': str(receipt), 'error': r['error'],
                      'qualification_credit': False, 'performance_credit': False}, sort_keys=True))
    return 0 if r['status'] == 'observed_unqualified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
