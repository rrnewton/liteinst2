#!/usr/bin/env python3
"""Run RET32, RET671/planner and separate low/high RET16/24 cohorts; no owner qualification."""
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
ROOT = Path(__file__).resolve().parents[3]
SELECTED = ROOT/'tools/page-entry/selected'
BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60],
          'component': [5, 512 << 20, 16 << 20, 15], 'native': [5, 512 << 20, 16 << 20, 15]}
LINK_NAMES = ('crt1.o Scrt1.o crti.o crtn.o crtbegin.o crtbeginS.o crtend.o crtendS.o '
              'libgcc.a libgcc_eh.a libgcc_s.so libgcc_s.so.1 libc.so libc_nonshared.a '
              'libc.so.6 libdl.a libpthread.a libm.so libm.so.6 libmvec.so.1').split()
CASES = {'ret_native': {'recipe_sha256': '740c5a7a68180a84f303dc9fdca05adff1a7b8c7bc8f4012dec42a1e995a140a', 'units': ['tests/ret_native/probe.c', 'tests/ret_native/probe.S'], 'headers': [], 'stdout': None, 'kind': 'ret32'}, 'ret_dispatch': {'recipe_sha256': '3a9f92fd91f943308e6c8d1e1f59563bc9d0c97fffa5fde6f88f1675e115b887', 'units': ['tests/ret_dispatch/oracle.c', 'tests/ret_dispatch/model.c', 'linked_ret_dispatch.c', 'tests/decoder/support.c'], 'headers': ['linked_ret_dispatch.h', 'tests/ret_dispatch/model.h', 'persistent_group_plan.h'], 'stdout': 'ret-dispatch descriptors=15 decoded=795 models=671 forms=512 arguments=6 bindings=16 corruptions=20 interiors=459 geometry=4 recovery_controls=16 far_models=4 literal_controls=12 relocations=6\n', 'kind': 'component'}, 'ret_dispatch_plan': {'recipe_sha256': '91db34f0fc34df963610ec494142f837f5c1a1866d54b159317b9bbc8e2864c0', 'units': ['tests/ret_dispatch_plan/oracle.c', 'tests/ret_dispatch/model.c', 'persistent_group_plan.c', 'persistent_group_compact.c', 'linked_ret_dispatch.c', 'linked_call_dispatch.c', 'linked_jmp_dispatch.c', 'linked_direct_dispatch.c', 'linked_mov_guard.c', 'tests/decoder/support.c'], 'headers': ['persistent_group_plan.h', 'persistent_group_compact.h', 'linked_ret_dispatch.h', 'linked_call_dispatch.h', 'linked_jmp_dispatch.h', 'linked_direct_dispatch.h', 'linked_mov_guard.h', 'tests/ret_dispatch/model.h'], 'stdout': 'ret-dispatch-plan plans=8 models=924 refusals=6 geometry=9 capacities=4 corruptions=36 interiors=459 landings=4098 compact_recoveries=167772 loaded_recoveries=528 rows=53 arguments=24 far_plans=2 far_corruptions=24\n', 'kind': 'component'}, 'ret_dispatch_native': {'recipe_sha256': 'd7e719e5cdc915910c33fb2e31b05646d00af4788ca932d73b790b4a85db6f48', 'units': ['tests/ret_dispatch_native/probe.c', 'tests/ret_dispatch_native/probe.S', 'linked_ret_dispatch.c', 'tests/decoder/support.c'], 'headers': ['linked_ret_dispatch.h', 'linked_jmp_domain.h', 'decoder.h'], 'stdout': None, 'kind': 'adapter'}}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular whole file: '+str(path))
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=digest(data), mode=format(stat.S_IMODE(path.stat().st_mode), '04o'))


def elf(path):
    """Read the actual ELF interpreter, SONAME and every DT_NEEDED entry."""
    data = Path(path).read_bytes()
    def take(at, count):
        need(0 <= at <= len(data) and 0 <= count <= len(data)-at, 'whole bounded ELF range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\2\1\1' and h[1] in (2, 3) and h[2:4] == (62, 1)
         and h[8:10] == (64, 56) and 0 < h[10] <= 128, 'actual bounded x86-64 ELF')
    ph = [struct.unpack('<IIQQQQQQ', take(h[5]+56*i, 56)) for i in range(h[10])]
    for p in ph:
        take(p[2], p[5])
        need(p[5] <= p[6], 'file-backed program extent')
    interpreter = [take(p[2], p[5]) for p in ph if p[0] == 3]
    need(len(interpreter) <= 1, 'at most one actual interpreter')
    if interpreter:
        name = interpreter[0]
        need(name.startswith(b'/') and name.endswith(b'\0') and b'\0' not in name[:-1], 'whole interpreter spelling')
        interpreter = os.fsdecode(name[:-1])
    else:
        interpreter = None
    dynamic = [p for p in ph if p[0] == 2]
    need(len(dynamic) == 1 and dynamic[0][5] % 16 == 0, 'one complete dynamic table')
    tags = []
    for at in range(dynamic[0][2], dynamic[0][2]+dynamic[0][5], 16):
        tag, value = struct.unpack('<QQ', take(at, 16))
        if tag == 0:
            break
        tags.append((tag, value))
    else:
        raise ValueError('unterminated dynamic table')
    addresses, sizes = ([v for t, v in tags if t == key] for key in (5, 10))
    need(len(addresses) == len(sizes) == 1, 'one actual dynamic string table')
    loads = [p for p in ph if p[0] == 1 and p[3] <= addresses[0]
             and sizes[0] <= p[3]+p[5]-addresses[0]]
    need(len(loads) == 1, 'whole strings in one file-backed LOAD')
    names = take(loads[0][2]+addresses[0]-loads[0][3], sizes[0])
    def string(at):
        need(at < len(names) and b'\0' in names[at:], 'bounded dynamic name')
        name = names[at:names.index(b'\0', at)].decode('ascii')
        need(name and '/' not in name, 'plain runtime SONAME')
        return name
    sonames = [string(v) for t, v in tags if t == 14]
    needed = [string(v) for t, v in tags if t == 1]
    need(len(sonames) <= 1 and len(set(needed)) == len(needed), 'unique SONAME/dependency identities')
    return dict(interpreter=interpreter, soname=sonames[0] if sonames else None, needed=needed)


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), 'duplicate manifest field')
    return result


def load(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def compact(observation):
    need(observation['status'] == 'observed_unqualified' and observation['matrix_pairs'] == 217 and
         observation['native_lanes'] == 434 and observation['call_push_equivalence'] is None and
         all(observation[k] is False for k in ('production_admission_credit', 'owner_credit',
                                              'qualification_credit', 'performance_credit')),
         'observation-only reader result')
    pairs = observation['pairs']
    need(len(pairs) == 217 and [p['id'] for p in pairs] == list(range(217)), 'all ordered pairs')
    groups = []
    for group, count in enumerate((16, 128, 16, 35, 16, 6)):
        rows = [p for p in pairs if p['call']['group'] == group]
        need(len(rows) == count and all(p['push']['group'] == group for p in rows), 'complete fixed group')
        result = {'group': group, 'pairs': count,
                  'after_greg_difference_pairs': sum(bool(p['after_greg_differences']) for p in rows)}
        for key in ('call', 'push'):
            lanes = [p[key] for p in rows]
            result[key] = {
                'signals': dict(sorted(Counter(str(p['signal'])+':'+str(p['si_code']) for p in lanes).items())),
                'stack_changed_bytes_distribution': dict(sorted(Counter(str(p['stack_changed_bytes']) for p in lanes).items())),
                'fp_storage_changed': sum(not p['fp_storage_unchanged'] for p in lanes),
                'fs_gs_changed': sum(not p['fs_gs_unchanged'] for p in lanes)}
        groups.append(result)
    return {'status': 'observed_unqualified', 'matrix_pairs': 217, 'native_lanes': 434,
            'groups': groups, 'call_push_equivalence': None,
            'production_admission_credit': False, 'owner_credit': False,
            'qualification_credit': False, 'performance_credit': False,
            'scope': 'Complete actual native observations; differences are not general equivalence or production admission.'}


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


def native_compact(observed):
    need(observed['schema'] == 1 and observed['status'] == 'finite_ret_adapter_observed' and
         observed['cases'] == 16 and observed['native_lanes'] == 24 and
         tuple(observed[k] for k in ('matched_hit_pairs','matched_load_fault_pairs','typed_loaded_misses',
             'before_load_misses','post_load_mutations')) == (6,2,4,2,2) and
         observed['observed_trace_events'] == [45,35] and observed['observed_unique_boundaries'] == [38,35] and
         len(observed['observed_boundary_union']) == len(set(observed['observed_boundary_union'])) == 38 and
         observed['component_all53_boundaries_separate'] is True and
         all(observed[k] is False for k in ('loaded_miss_resumption','production_owner_authority',
             'qualification_credit','performance_credit','old_RET32_replaced','old_component671_replaced')),
         'complete fixed RET adapter observations; no resumed miss/owner/performance credit')
    pairs,rows = observed['pairs'],observed['observations']
    need([x['id'] for x in pairs] == [0,1,2,3,4,5,12,13] and
         [x['kind'] for x in pairs] == ['hit']*6+['load_fault']*2 and
         all(x['full_state_stack_equal'] is True for x in pairs), 'all eight exact full-state pairs')
    expected = [(i,w) for i in range(16) for w in ((0,1) if i<6 or 12<=i<14 else (1,))]
    need([(x['id'],x['which']) for x in rows] == expected and
         [sum(x['kind']==k for x in rows) for k in range(5)] == [12,4,2,4,2],
         'all24 actual lanes in fixed order; no omitted or substituted case')
    return observed


def retained(path, wanted, current, pin, environment):
    """Authenticate a closed prerequisite; never execute or substitute its result."""
    prior = load(pin(path))
    need(prior['status'] == wanted['status'] and prior['profile'] == wanted['profile'] and
         prior['revision'] == current['revision'] and prior['source'] == current['source'] and
         prior['cpu'] == current['cpu'] and prior['hardware'] == current['hardware'],
         'exact prerequisite source, CPU, hardware and outcome')
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



CALL217 = {'bounds': {'build': [30, 536870912, 16777216, 60], 'native': [5, 536870912, 16777216, 15]}, 'commands': ['resolve-cc1', 'resolve-collect2', 'resolve-as', 'resolve-ld', 'version-cc', 'version-as', 'version-ld', 'link-input-crt1.o', 'link-input-Scrt1.o', 'link-input-crti.o', 'link-input-crtn.o', 'link-input-crtbegin.o', 'link-input-crtbeginS.o', 'link-input-crtend.o', 'link-input-crtendS.o', 'link-input-libgcc.a', 'link-input-libgcc_s.so', 'link-input-libc.so', 'link-input-libc_nonshared.a', 'link-input-libc.so.6', 'link-input-libgcc_s.so.1', 'compiler-specs', 'headers-0', 'headers-1', 'build', 'emitted-inspection', 'runtime-dependencies', 'native-0', 'native-1', 'native-2', 'native-3', 'native-4', 'native-5', 'native-6', 'read-all-chunks'], 'profile': 'call-push-native-diagnostic-v1', 'status': 'observed_unqualified'}

def public_result(value):
    """Keep private raw/state complete; publish each checked outcome and its exact raw digest."""
    if value is None: return None
    result = json.loads(json.dumps(value))
    rows = result.get('observations', [])
    if result.get('native_cases') == 32:
        keys = ('id','group','group_case','input_rflags','signal','si_code','trapno','error_code',
                'observed_rsp_commitment','rsp_delta_mod64','fp_storage_unchanged','fs_gs_unchanged',
                'stack_bytes_unchanged','stack_operand_present','raw_record_sha256','fp_sha256',
                'source_sha256','stack_sha256')
        result['observations'] = [{key: row[key] for key in keys} for row in rows]
    else:
        for row in rows:
            row['rsp_delta'] = row.pop('actual_rsp')-row.pop('original_rsp')
    return result


def native_dynamic(path):
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


def main():
    sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
    from page_selected_maps_sources import historical, bind as bind_maps_sources
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--archive', required=True, type=Path)
    ap.add_argument('--call217-receipt', required=True, type=Path)
    ap.add_argument('--call217-receipt-sha256', required=True)
    ap.add_argument('--archive-sha256', required=True)
    ap.add_argument('--cpu', required=True, type=int)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    need(sys.version_info >= (3, 11) and not sys.flags.optimize, 'Python3.11+ with assertions enabled')
    need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'one externally reserved CPU matching --cpu')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', args.archive_sha256) and
         re.fullmatch('[0-9a-f]{64}', args.call217_receipt_sha256), 'explicit full source and archive identities')
    private = args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and not private.exists(),
         'fresh private attempt below target/evaluation/inprocess')
    sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
    from checks import source
    from run import hardware
    from page_selected import ENV, save
    from page_selected_process import invoke
    os.chdir(ROOT)
    private.mkdir()
    receipt = private/'receipt.json'
    pins, aliases, artifacts, presence = {}, {}, {}, {}
    r = dict(schema=1, profile='experimental-ret-components-native-v1', status='failed',
             revision=args.expect_revision, source=None, cpu=args.cpu, hardware=hardware(args.cpu), bounds=BOUNDS,
             commands=[], components={}, prerequisite=None, source_unchanged=False, inputs_unchanged=False,
             cleanup_complete=False, archive_builds=0, archive_source_provenance_verified=False,
             generated_execution=0, native_execution=0, loaded_miss_resumption=False, production_owner_authority=False, owner_credit=False, qualification_credit=False,
             performance_credit=False, error=None, final_errors=[])
    stage = 'preflight'

    def pin(path):
        need(path is not None, 'required input/tool')
        alias = Path(path).absolute(); resolved = alias.resolve(strict=True); value = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved), 'stable input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == value, 'stable whole input')
        aliases[str(alias)] = str(resolved); pins[str(resolved)] = value
        return resolved

    def artifact(path):
        path = Path(path)
        need(path.is_relative_to(private), 'private artifact containment')
        value = fact(path)
        need(str(path) not in artifacts or artifacts[str(path)] == value, 'immutable completed artifact')
        artifacts[str(path)] = value
        return value

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'all whole inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'all aliases unchanged')
        need(all(fact(p) == v for p, v in artifacts.items()), 'all completed artifacts unchanged')
        need(all(Path(p).exists() == v for p, v in presence.items()), 'loader configuration presence unchanged')
        need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'same reserved CPU')

    def run(name, argv, kind='build'):
        nonlocal stage
        stage = name; closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique stage, no retry')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV), bounds=BOUNDS[kind],
                   capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row); save(receipt, r)
        try:
            out, err = invoke(row, private, args.cpu)
        finally:
            for v in row.get('captures', {}).values():
                actual = artifact(private/v['file'])
                need(all(actual[k] == v[k] for k in ('bytes', 'sha256')), 'whole post-reap capture')
            if (private/(name+'.json')).is_file():
                artifact(private/(name+'.json'))
            save(receipt, r)
        need(row['exit'] == 0 and row['error'] is None and row['timed_out'] is False and
             row['reaped'] is True and row['cleanup_errors'] == [] and
             all(d['closed'] for d in row['descriptors']), 'exact successful reaped command: '+name)
        return out, err

    def runtime(label, program, allowed=None):
        image = elf(program); spelling = image['interpreter']
        need(spelling is not None, 'one actual executable interpreter')
        loader = pin(spelling)
        if allowed is not None:
            need(str(loader) in allowed, 'actual interpreter was bound before link')
        out, err = run(label+'-dependencies', [loader, '--list', program])
        need(not err, 'whole loader dependency listing stderr')
        dependencies = set()
        for line in out.decode().splitlines():
            line = line.strip()
            if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line): continue
            alias = re.fullmatch(r'(/[^ ]+) => (/[^ ]+) \(0x[0-9a-f]+\)', line)
            if alias:
                need(alias[1] == spelling and alias[2] == str(loader) and pin(alias[1]) == pin(alias[2]) == loader,
                     'only the exact actual interpreter alias/target')
                path = loader
            else:
                match = re.fullmatch(r'(?:[^ /]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)', line)
                need(match is not None, 'complete resolved runtime dependency grammar'); path = pin(match[1])
            if allowed is not None:
                need(str(path) in allowed, 'runtime dependency bound before link')
            dependencies.add(str(path))
        need(str(loader) in dependencies, 'complete actual loader closure')
        dynamic = {p: elf(p) for p in sorted(dependencies)}; sonames = {}
        for p, info in dynamic.items():
            if info['soname']:
                need(info['soname'] not in sonames, 'one actual file per runtime SONAME'); sonames[info['soname']] = p
        need('libc.so.6' in sonames and all(n in sonames for info in [image, *dynamic.values()] for n in info['needed']),
             'every actual DT_NEEDED edge closes over the bound runtime objects')
        return image, dynamic

    try:
        pin('/usr/bin/git')
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'clean exact expected source revision')
        pin(__file__); pin(Path(__file__).with_name('README.md')); pin(sys.executable)
        bind_maps_sources(pin)
        manifest = load(pin(Path(__file__).with_name('SOURCE.json')))
        for name, wanted in manifest['files'].items():
            need(historical(ROOT/name,wanted,fact(pin(ROOT/name))) == wanted, 'whole public source leaf: '+name)
        origin = pin(args.call217_receipt)
        need(fact(origin)['sha256'] == args.call217_receipt_sha256, 'explicit whole CALL217 prerequisite')
        prior = retained(origin, CALL217, r, pin, ENV)
        reader_row = prior['commands'][-1]
        need(reader_row['name'] == 'read-all-chunks' and reader_row['captures']['stderr']['bytes'] == 0,
             'actual old217 whole reader completed')
        old_observed = load(origin.parent/reader_row['captures']['stdout']['file'])
        old_result = compact(old_observed)
        old_result['raw_sources'] = old_observed['sources']
        need(old_result == prior['result'] and prior['call_push_equivalence'] is None and
             prior['production_admission_credit'] is False, 'whole old217 reader result and every original population')
        chunks = [row for row in prior['commands'] if re.fullmatch(r'native-[0-6]',row['name'])]
        need(len(chunks) == len(old_observed['sources']) == 7 and old_observed['cpu'] == args.cpu,
             'all seven actual old217 chunks')
        for i,(row,observed) in enumerate(zip(chunks,old_observed['sources'])):
            capture = row['captures']['stdout']
            need(observed == dict(chunk=i,pid=row['pid'],bytes=capture['bytes'],sha256=capture['sha256']) and
                 row['bounds'] == BOUNDS['native'] and row['captures']['stderr']['bytes'] == 0,
                 'whole old217 reader inputs join actual original process rows')
        need(str(Path(sys.executable).resolve()) == prior['collector_python'], 'same actual old217 Python interpreter')
        r['prerequisite'] = dict(receipt=fact(origin), status=prior['status'], matrix_pairs=217, native_lanes=434, executed_here=False)
        for module in tuple(sys.modules.values()):
            name = getattr(module, '__file__', None)
            if name and Path(name).is_file():
                pin(name)
        maps = Path('/proc/self/maps').read_bytes()
        (private/'python-maps.txt').write_bytes(maps); artifact(private/'python-maps.txt')
        mapped = set()
        for line in maps.decode().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                need(not fields[5].endswith(' (deleted)'), 'live Python mapped input')
                mapped.add(str(pin(fields[5])))
        r['python_mapped_inputs'] = sorted(mapped)
        archive = pin(args.archive)
        need(fact(archive)['sha256'] == args.archive_sha256 and archive.read_bytes().startswith(b'!<arch>\n'),
             'explicit supplied static archive identity')
        r['archive'] = fact(archive)
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc', 'nm')}
        tools['python'] = pin(sys.executable)
        tools['git'] = pin('/usr/bin/git')
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = Path(name).exists()
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        r['tool_runtime'] = {name: runtime('tool-'+name, tools[name])[1] for name in ('cc', 'nm', 'python', 'git')}
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run('resolve-'+name, [tools['cc'], '-print-prog-name='+name]); value = out.decode().strip()
            need(value and not err, 'actual compiler subtool')
            tools[name] = pin(value if Path(value).is_absolute() else shutil.which(value, path=ENV['PATH']))
            r['tool_runtime'][name] = runtime('tool-'+name, tools[name])[1]
        for name in ('cc', 'as', 'ld', 'nm', 'python', 'git'):
            out, err = run('version-'+name, [tools[name], '--version'])
            need(out and not err, 'actual tool version')
        r['tools'] = {name: str(p) for name, p in tools.items()}
        link_inputs = {str(archive)}
        for name in LINK_NAMES:
            out, err = run('link-'+name, [tools['cc'], '-print-file-name='+name]); value = out.decode().strip()
            need(not err and Path(value).is_absolute(), 'prebound compiler-selected link input')
            link_inputs.add(str(pin(value)))
        pending = list(link_inputs)
        while pending:
            path = Path(pending.pop()); data = path.read_bytes()
            if data.startswith((b'\x7fELF', b'!<arch>')): continue
            need(len(data) < 4096 and b'GNU ld script' in data, 'bounded recognized GNU linker script')
            for name in re.findall(r'/[^\s()]+', re.sub(r'/\*.*?\*/', '', data.decode(), flags=re.S)):
                name = str(pin(name))
                if name not in link_inputs: link_inputs.add(name); pending.append(name)
        _, err = run('compiler-specs', [tools['cc'], '-dumpspecs']); need(not err, 'compiler specifications stderr')
        out, err = run('archive-exports', [tools['nm'], '-g', '--defined-only', archive]); need(not err, 'whole archive census stderr')
        required = ('li2_decoder_decode', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint',
                    'li2_decoder_span_describe', 'li2_decoder_region_describe', 'li2_decoder_link_none', 'li2_decoder_mov_store')
        names = [m[1] for line in out.decode().splitlines()
                 if (m := re.fullmatch(r'[0-9a-fA-F]+ T (\S+)', line))]
        need(all(names.count(name) == 1 for name in required), 'all exact decoder component providers')

        for name, case in CASES.items():
            fixture = SELECTED/'tests'/name; recipe = pin(fixture/'build.sh')
            need(fact(recipe)['sha256'] == case['recipe_sha256'], 'unchanged complete component recipe')
            output_dir = private/name; output_dir.mkdir(); output = output_dir/'component'
            units = [str(SELECTED/x) for x in case['units']]
            for p in units: pin(p)
            text = recipe.read_text().replace('\\\n', ' ')
            lines = [line.strip() for line in text.splitlines() if line.strip().startswith(('"$cc_bin" ', '"$cc" '))]
            need(len(lines) == 1, 'one exact compiler recipe')
            replacements = {'$cc_bin': tools['cc'], '$fixture': fixture, '$selected': SELECTED,
                            '$archive': archive, '$output': output, '$source_dir': fixture, '$cc': tools['cc']}
            argv = []
            for word in shlex.split(lines[0]):
                for key, value in replacements.items(): word = word.replace(key, str(value))
                need('$' not in word and '`' not in word, 'closed literal compiler argument'); argv.append(word)
            need([x for x in argv if x.endswith(('.c', '.S'))] == units and
                 [x for x in argv if x.endswith('.a')] == ([] if case['kind'] == 'ret32' else [str(archive)]) and argv[-2:] == ['-o', str(output)],
                 'all component translation units, single archive and exact output')
            flags = [x for x in argv[1:-2] if x not in units and x != str(archive) and not x.startswith(('-Wl,', '-l'))]
            out, err = run(name+'-headers', [tools['cc'], *flags, '-M', '-MT', 'ret_component', *units])
            rules = out.decode().replace('\\\n', ' ').splitlines()
            need(not err and len(rules) == len(units) and all(x.startswith('ret_component: ') for x in rules),
                 'every complete actual compiler-M rule')
            headers = {str(pin(x)) for line in rules for x in shlex.split(line.split(':', 1)[1])}
            need({str(Path(x).resolve()) for x in units} |
                 {str((SELECTED/x).resolve()) for x in case['headers']} <= headers, 'complete typed component header closure')
            additions = ['-save-temps=obj', '-Wl,--trace'] if case['kind'] == 'component' else []
            out, err = run(name+'-build', argv[:-2]+additions+argv[-2:])
            need(not err, 'strict original -Werror compiler/linker stderr')
            if case['kind'] == 'component':
                objects = {str(output_dir/('component-'+Path(p).stem+'.o')) for p in units}
                for p in units:
                    for suffix in ('.i', '.s', '.o', '.su'):
                        artifact(output_dir/('component-'+Path(p).stem+suffix))
                trace = out.decode().splitlines()
                need(trace and all(Path(x).is_absolute() for x in trace), 'whole absolute actual linker trace')
                linked = {str(Path(x).resolve(strict=True)) for x in trace}
                need(objects | {str(archive)} <= linked <= link_inputs | objects,
                     'all generated objects and only prebound link inputs')
            else:
                need(not out, 'unchanged exact native recipe stdout empty')
                linked = set()  # Exact native recipe has no linker trace; no inferred object census.
            binary = artifact(output); need(int(binary['mode'], 8) & 0o111, 'actual executable component')
            image, dynamic = runtime(name, output, link_inputs)
            if case['kind'] != 'component':
                for p, expected in [(str(output), image), *dynamic.items()]:
                    actual = native_dynamic(p)
                    need(actual == {k: expected[k] for k in ('needed','soname')},
                         'whole native dynamic tags and no search/filter/audit overrides')
            r['components'][name] = dict(status='not_run', recipe=fact(recipe), original_argv=argv,
                diagnostic_only_additions=additions, headers=sorted(headers), link_inputs=sorted(linked),
                runtime_objects=dynamic, elf=image, binary=binary, result=None)
            if case['kind'] == 'component':
                out, err = run(name+'-component', [output], 'component')
                need(not err and out == case['stdout'].encode(), 'exact complete component population and stdout')
                r['components'][name].update(status='passed', result={k: int(v) for k, v in
                    (word.split('=') for word in case['stdout'].split()[1:])})
                continue
            inspector = pin(ROOT/'evaluation/inprocess/call_push_native/inspect.py')
            reader = pin(fixture/'read.py')
            if case['kind'] == 'adapter': pin(fixture/'frame.py')
            out, err = run(name+'-inspection', [tools['python'], '-I', '-S', '-B', inspector, output], 'native')
            inspected = json.loads(out, object_pairs_hook=unique)
            need(not err and inspected['status'] == 'source_bytes_inspected' and
                 inspected['elf_sha256'] == binary['sha256'] and inspected['native_execution'] is False and
                 inspected['qualification_credit'] is False and inspected['interpreter'] == image['interpreter'],
                 'whole actual native bootstrap and return inspection before execution')
            r['components'][name]['emitted_inspection'] = inspected
            for address_model in (('low','high') if case['kind'] == 'adapter' else ('original',)):
                run_name = name+'_high' if address_model == 'high' else name
                if address_model == 'high':
                    r['components'][run_name] = dict(r['components'][name], status='not_run', result=None,
                        address_model='high-cluster-low-window', executable_reused_from=name)
                out, err = run(run_name+'-native', [output,'0'] if case['kind'] == 'ret32' else [output,*(['--high'] if address_model == 'high' else [])], 'native'); child = r['commands'][-1]
                expected_bytes, magic, record, cases, lanes, end = (
                    (5879872,0x3154455232494c,183736,32,32,0x3145455232494c) if case['kind'] == 'ret32' else
                    (8845632,0x314e524432494c,368544,16,24,0x3145524432494c))
                need(not err and len(out) == expected_bytes < 16 << 20, 'whole exact fixed native chunk')
                h = struct.unpack_from('<64Q' if case['kind'] == 'adapter' else '<32Q', out)
                need(h[:4] == (magic,1,256 if case['kind'] == 'ret32' else 512,record) and h[10:17] == (cases,0,0,cases,lanes,child['pid'],args.cpu) and
                     h[28:30] == (inspected['reload_address'],inspected['scratch_end_address']) and
                     struct.unpack_from('<8Q',out,len(out)-64) == (end,1,lanes,len(out),0,0,0,0),
                     'actual PID/CPU/ELF-bootstrap and complete fixed chunk/footer joins')
                raw_path = private/child['captures']['stdout']['file']
                out, err = run(run_name+'-reader', [tools['python'],'-I','-S','-B',reader,
                    '--expect-cpu',str(args.cpu),'--expect-pid',str(child['pid']),
                    *(['--expect-address-model','high'] if address_model == 'high' else []),raw_path], 'native')
                need(not err, 'complete native reader stderr empty')
                observed = json.loads(out, object_pairs_hook=unique)
                expected_source = dict(pid=child['pid'],bytes=expected_bytes,sha256=child['captures']['stdout']['sha256'])
                if case['kind'] == 'adapter': expected_source['cpu'] = args.cpu
                else: need(observed['cpu'] == args.cpu, 'actual RET32 reader CPU')
                need(observed['source'] == expected_source, 'reader joins exact actual raw chunk/PID/CPU')
                result = ret_compact(observed) if case['kind'] == 'ret32' else native_compact(observed)
                if case['kind'] == 'ret32': result['observations'] = observed['observations']
                if address_model == 'high':
                    expected_geometry = dict(model='high-cluster-low-window',cluster=h[21],cluster_bytes=24*4096,
                        window=h[34],loaded_miss=h[34]+128,generated=h[30],loaded_jump_offset=190,
                        loaded_jump_bytes=6,landing_literal_offset=504,
                        signed_distance=h[34]+128-(h[30]+196),beyond_rel32=True)
                    need(observed['address_geometry'] == expected_geometry and expected_geometry['signed_distance'] < -(1<<31),
                         'actual high cluster/low window joins raw chunk and exceeds signed32 reach')
                elif case['kind'] == 'adapter':
                    need('address_geometry' not in observed, 'original low cohort remains separately identified')
                r['components'][run_name].update(status=observed['status'], result=result)
                r['native_execution'] += lanes
                if case['kind'] == 'adapter': r['generated_execution'] += 16
        need(list(r['components']) == [*CASES,'ret_dispatch_native_high'] and
             [v['status'] for v in r['components'].values()] ==
             ['observed_unqualified','passed','passed','finite_ret_adapter_observed','finite_ret_adapter_observed'] and
             r['native_execution'] == 80 and r['generated_execution'] == 32,
             'all five separate complete finite results, original low cohort and mandatory high cohort; no scope promotion')
        r['status'] = 'finite_experiments_passed'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        for name in CASES:
            directory = private/name
            if directory.is_dir():
                for p in directory.iterdir():
                    if p.is_file() and not p.is_symlink():
                        try: artifact(p)
                        except BaseException as error: r['final_errors'].append('partial-artifact: '+repr(error))
        try: closure(); r['inputs_unchanged'] = True
        except BaseException as error: r['final_errors'].append('inputs: '+repr(error))
        try:
            need(source() == r['source'], 'whole tracked source before/after equality'); r['source_unchanged'] = True
        except BaseException as error: r['final_errors'].append('source: '+repr(error))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not all(r[k] for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')):
            r['status'] = 'failed'
        r.update(inputs=pins, aliases=aliases, artifacts=artifacts, loader_presence=presence)
        save(receipt, r)

    # A shareable projection, never raw command lines, loader paths or failure text.
    host = dict(r['hardware']); host.pop('runner_euid', None); flags = host.pop('isa_flags')
    host['isa_flags_count'] = len(flags); host['isa_flags_sha256'] = digest(canonical(flags))
    summary = dict(schema=1, profile=r['profile'], status=r['status'], source=r['source'], cpu=args.cpu,
        hardware=host, bounds=BOUNDS, archive=r.get('archive'), archive_builds=0,
        archive_source_provenance_verified=False, generated_execution=r['generated_execution'], native_execution=r['native_execution'],
        prerequisite=r['prerequisite'], loaded_miss_resumption=False, production_owner_authority=False,
        owner_credit=False, qualification_credit=False, performance_credit=False,
        pending=['authenticated RET owner execution and single-consumption loaded-miss continuation', 'whole392/522 qualification', 'real-program completion and performance'],
        source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'], cleanup_complete=r['cleanup_complete'],
        failed_stage=stage if r['status'] == 'failed' else None, final_error_count=len(r['final_errors']), receipt=fact(receipt),
        tools={n: pins[p] for n, p in r.get('tools', {}).items()},
        inventories={n: dict(count=len(v), sha256=digest(canonical(v))) for n, v in
            (('inputs', pins), ('aliases', aliases), ('artifacts', artifacts), ('tool_runtime', r.get('tool_runtime', {})),
             ('python_mapped_inputs', r.get('python_mapped_inputs', [])))},
        components={n: dict(status=v['status'], result=public_result(v['result']), binary=v['binary'], recipe=v['recipe'],
            headers=dict(count=len(v['headers']), sha256=digest(canonical(v['headers']))),
            link_inputs=dict(count=len(v['link_inputs']), sha256=digest(canonical(v['link_inputs']))),
            runtime_objects=dict(count=len(v['runtime_objects']), sha256=digest(canonical(v['runtime_objects']))))
            for n, v in r['components'].items()},
        commands=[dict(name=c['name'], exit=c.get('exit'), duration_ns=c.get('duration_ns'), bounds=c['bounds'],
            reaped=c.get('reaped', False), timed_out=c.get('timed_out', False), cleanup_errors=len(c.get('cleanup_errors', [])),
            argv_sha256=digest(canonical(c['argv'])), captures={n: {k: v[k] for k in ('bytes', 'sha256')}
                for n, v in c.get('captures', {}).items()}) for c in r['commands']])
    payload = json.dumps(summary, indent=2, sort_keys=True)+'\n'
    need(str(ROOT) not in payload and str(private) not in payload and '/home/' not in payload, 'public projection excludes private paths')
    (private/'summary.json').write_text(payload)
    print(json.dumps(dict(status=r['status'], components={n: v['result'] for n, v in r['components'].items()},
                         qualification_credit=False, summary=str((private/'summary.json').relative_to(ROOT))), sort_keys=True))
    return int(r['status'] != 'finite_experiments_passed')


if __name__ == '__main__':
    raise SystemExit(main())
