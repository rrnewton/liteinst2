#!/usr/bin/env python3
"""Canonical all-register LOCK CMPXCHG oracle, actual-before footprint queries and32 failed RMW controls."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save, elf
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/lock_cmpxchg_register'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '2dc559eb1067a4cb2a43057702e48f57ef122335bf5f98008a536562a552d3ff', 'exact reviewed independent register/effect catalogue')
    declared = json.loads((FIXTURE/'CASES.json').read_bytes())
    names = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split()
    source_values = [0xfaceb00cdeadbeef ^ (i*0x11111111) for i in range(16)]
    source_values[4] = 0x100011800
    aliases = [(0,0),(0,7),(13,0),(4,7),(13,4),(2,2),(13,13),(13,7)]
    modes = ['no-access-match','read-only-match','no-access-mismatch','read-only-mismatch']
    forms = []
    for source_reg in range(16):
        for base in range(16):
            # Independent bit-field derivation; no import of the product matcher.
            rex = (4 if source_reg >= 8 else 0) | (1 if base >= 8 else 0)
            m = (source_reg%8)*8
            address = [m+4,0x24] if base%8 == 4 else [m+0x45,0] if base%8 == 5 else [m+base%8]
            raw = bytes([0xf0]+([0x40+rex] if rex else [])+[0x0f,0xb1]+address)
            forms.append([source_reg,base,raw.hex()])
    rows, faults = [], []
    for source_reg in range(16):
        for mismatch in (0,1):
            for base in range(16):
                raw = bytes.fromhex(forms[16*source_reg+base][2])
                tail = 1+(source_reg+base)%(len(raw)-1) if mismatch else len(raw)
                rows.append(literal(source_reg,base,raw,tail,mismatch,0x100011100,
                    names[source_reg]+'-'+names[base]+'-'+('mismatch' if mismatch else 'match'),source_values))
    for source_reg,base in aliases:
        for mode in modes:
            r = literal(source_reg,base,bytes.fromhex(forms[16*source_reg+base][2]),1,
                int(mode.endswith('mismatch')),0x100012100,names[source_reg]+'-'+names[base]+'-'+mode,source_values)
            r['readonly'] = int(mode.startswith('read-only'));faults.append(r)
    raw_digest = lambda value: hashlib.sha256((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
    need(declared == dict(schema=1,code=2075,data_target=0x100011100,fault_target=0x100012100,
        groups=32,new_per_group=16,source_values=source_values,forms=forms,
        group_columns=['source','mismatch'],group_rows=[[s,m] for s in range(16) for m in (0,1)],
        fault_aliases=[list(x) for x in aliases],fault_modes=modes,ending=256,crossing=256,
        geometry='match: tail=length; mismatch: tail=1+(source+base)%(length-1)',
        row_sha256=raw_digest(rows),fault_rows_sha256=raw_digest(faults)),
        'complete literal all-register/effect and geometry recipe')
    parsed = []
    for line in path.read_text().splitlines():
        if re.match(r' \{[0-9]',line):
            match = re.fullmatch(r' \{(\d+),(\d+),(\d+),\{([^}]*)\}\},',line)
            need(match is not None,'closed C opcode row')
            raw = bytes(int(x,0) for x in match[4].split(','))
            need(len(raw) == int(match[3]),'literal C instruction length')
            parsed.append([int(match[1]),int(match[2]),raw.hex()])
    need(parsed == forms,'all256 literal C opcodes match independent field derivation')
    values = re.findall(r'^ UINT64_C\(0x([0-9a-f]{16})\),$',path.read_text(),re.M)
    need([int(x,16) for x in values] == source_values,'all literal source input seeds')
    need(len(rows)==512 and len(faults)==32 and forms[16*13+7][2]=='f0440fb12f',
         'complete matrix and actual observed source form')
    for length in (4,5,6):
        need({r['tail'] for r in rows if r['length']==length} == set(range(1,length+1)),
             'each instruction length covers every cut collectively')
    summary = dict(source=binding,counts=dict(new_pairs=512,success_pairs=256,failure_pairs=256,
        page_ending_pairs=256,crossing_pairs=256,bases=16,sources=16,forms=256,protected_fault_commands=32),
        rows_sha256=digest(rows),fault_rows_sha256=digest(faults))
    return summary, rows, faults


def literal(source_reg,base,raw,tail,mismatch,target,name,source_values):
    rax = target if base == 0 else 0xa5a5a5a500000001-mismatch
    source_value = target if source_reg == base else rax if source_reg == 0 else source_values[source_reg]
    memory = (target & 0xffffffff)+mismatch if base == 0 else 1
    a = rax & 0xffffffff
    difference = (a-memory) & 0xffffffff
    signed_a = a if a < 1 << 31 else a-(1 << 32)
    signed_m = memory if memory < 1 << 31 else memory-(1 << 32)
    flags = (int(a < memory) | (int((difference & 255).bit_count()%2 == 0) << 2) |
             (int((a & 15) < (memory & 15)) << 4) | (int(difference == 0) << 6) |
             ((difference >> 31) << 7) | (int(not -(1 << 31) <= signed_a-signed_m < 1 << 31) << 11))
    need((a != memory) == bool(mismatch) and flags == (0x95 if mismatch else 0x44), 'literal alias-aware subtraction')
    return dict(name=name,source=source_reg,base=base,length=len(raw),tail=tail,mismatch=mismatch,
        rax=rax,source_value=source_value,rax_after=memory if mismatch else rax,input=memory,
        output=memory if mismatch else source_value & 0xffffffff,flags=flags,hex=raw.hex())


def fault_trailer(data, expected):
    need(len(data) == 16512, 'complete fixed failed-operand trailer')
    fields = list(struct.unpack_from('<16Q', data))
    need(fields[:3] == [0x314b434f4c32494c, 1, 16512], 'exact trailer identity')
    if expected is None:
        need(not any(data[24:]), 'positive has no fabricated failed-operand observation')
        return dict(bytes=len(data), observed=False)
    prot, error = (1,7) if expected['readonly'] else (0,6)
    need(fields[3:] == [1,0x100012100,0x100012000,prot,expected['input'],prot,prot,prot,prot,1,1,error,error],
         'actual fixed operand/protection/error prefix and both independent observations')
    page = bytearray((i*13+0x5b)&255 for i in range(4096))
    page[256:260] = expected['input'].to_bytes(4,'little')
    need(all(data[128+4096*i:128+4096*(i+1)] == page for i in range(4)),
         'all actual pre/post native/step failed-operand bytes unchanged')
    return dict(bytes=len(data), observed=True, memory_bytes_per_snapshot=4096,
                snapshots=4, protection=prot, native_error=error, stepped_error=error,
                base=expected['base'],source=expected['source'],comparison_would_match=not expected['mismatch'])


def record_layout(path,symbols):
    names = {'result','samples','negative_sample','refused_last','lock_fault','lock_queries'}
    found = {}; _,_,segments = elf(path)
    for line in symbols.decode('ascii').splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[3] not in names: continue
        address,size,kind,name = fields
        need(name not in found and re.fullmatch('[0-9a-fA-F]+',address) and
             re.fullmatch('[0-9a-fA-F]+',size) and kind in ('b','B'),'unique actual fixture BSS symbol')
        address,size = int(address,16),int(size,16)
        need(size > 0 and sum(p[0] == 1 and p[1] == 6 and p[3] <= address < address+size <= p[3]+p[6]
             for p in segments) == 1,'whole actual record symbol in writable NX ELF load')
        found[name] = dict(address=address,bytes=size)
    need(set(found) == names,'all six actual record symbols')
    intervals = sorted((x['address'],x['address']+x['bytes']) for x in found.values())
    need(all(a[1] <= b[0] for a,b in zip(intervals,intervals[1:])),'disjoint actual record objects')
    sizes = {k:v['bytes'] for k,v in found.items()}
    need(sizes['result'] == 136 and sizes['samples'] == 21*sizes['negative_sample'] and
         sizes['refused_last'] == 40 and sizes['lock_fault'] == 16512 and sizes['lock_queries'] == 9920 and
         sum(sizes.values()) < 16 << 20,'actual21-slot full record and both trailers below unchanged cap')
    return dict(symbols=found,sample_bytes=sizes['negative_sample'],bytes=sum(sizes.values()))


def query_trailer(data,record,header,layout,group,rows,fault):
    need(len(data) == 9920,'complete fixed query trailer')
    qh = struct.unpack_from('<8Q',data)
    count = 1 if fault is not None else 16
    need(qh == (0x315942514c32494c,1,9920,group,256,count,count,0),'actual complete query prefix')
    selected = {21:fault} if fault is not None else {i+1:r for i,r in enumerate(rows[group*16:group*16+16])}
    indices = [13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7] # Linux x86-64 greg ABI, checked by C's real frames.
    for slot in range(22):
        sample = header['header_bytes']+slot*header['sample_bytes']
        expected = selected.get(slot)
        prior = None
        for lane in (0,1):
            raw = data[64+(2*slot+lane)*224:64+(2*slot+lane+1)*224]
            if expected is None:
                need(not any(raw),'unused query slots are literal zero');continue
            attempted,result,sample_id,base = struct.unpack_from('<4Q',raw)
            expected_id = 3000+fault['index'] if fault is not None else 2000+16*group+slot-1
            need((attempted,result,sample_id,base) == (1,0,expected_id,expected['base']),'actual query identity')
            before = struct.unpack_from('<18Q',raw,32)
            at = sample+layout['sample']['step_before' if lane else 'native_before']
            greg_at = at+layout['state']['frame']+layout['frame']['greg']
            need(before[:16] == tuple(struct.unpack_from('<Q',record,greg_at+8*i)[0] for i in indices) and
                 before[16:] == tuple(struct.unpack_from('<Q',record,at+layout['state'][x])[0] for x in ('fs','gs')),
                 'every actual query register/base equals independently retained NX before-frame')
            if prior is not None:need(before == prior,'native/step actual input registers identical')
            prior = before
            target = 0x100012100 if fault is not None else 0x100011100
            need(before[base] == target and before[0] == expected['rax'] and before[expected['source']] == expected['source_value'],
                 'literal actual RAX/source/base alias input')
            actual_pc = struct.unpack_from('<Q',record,sample+layout['sample']['pc'])[0]
            actual_id = struct.unpack_from('<I',record,sample+layout['sample']['id'])[0]
            actual_target = struct.unpack_from('<Q',record,sample+layout['sample']['target'])[0]
            need(actual_id == expected_id and actual_target == target,'query belongs to actual complete sample')
            pc,next_pc,first,end,abi,policy,code,length = struct.unpack_from('<4Q4I',raw,176)
            need((pc,next_pc,first,end,abi,policy,code,length) ==
                 (actual_pc,actual_pc+expected['length'],target,target+4,1,2,2075,expected['length']),
                 'full before-state write RANGE independent of comparison outcome')
    return dict(bytes=9920,typed_acceptances=256,native_queries=count,stepped_queries=count,
                actual_before_frames_joined=2*count,write_bytes_per_query=4)


def publish(path, record, receipt):
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds', 'elf')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        cases_sha256=digest(record['cases']), inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts={name: {k: value[k] for k in ('bytes', 'sha256')}
                         for name, value in build.get('artifacts', {}).items()},
        fixtures=record.get('fixtures'), catalogue=record.get('catalogue'),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        native_commands=[{'name': c['name'], 'exit': c.get('exit'), 'expected_exit': c['expected_exit'],
                          'duration_ns': c.get('duration_ns'), 'reaped': c.get('reaped'),
                          'timed_out': c.get('timed_out'),
                          'cleanup_error_count': len(c.get('cleanup_errors', [])),
                          'environment_delta': {k: v for k, v in c['environment'].items() if ENV.get(k) != v},
                          'captures': {n: {k: v[k] for k in ('bytes', 'sha256')}
                                       for n, v in c.get('captures', {}).items()}}
                         for c in record['commands'] if c['profile'] == 'native'],
        cases=[{'name': c['name'], 'accepted': c['accepted'], 'process_outcome': c['process_outcome'],
                'actual_exit': c.get('actual_exit'), 'operation_completed': c.get('operation_completed'),
                'verified_memory_fault': c.get('verified_memory_fault'),
                'header': c.get('header'), 'record': c.get('record'), 'fault_trailer': c.get('fault_trailer'), 'query_trailer': c.get('query_trailer')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/lock_cmpxchg_register/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['lock-cmpxchg-register']]*64,
            'exact_commands_and_environment_deltas': 'tools/page-entry/selected/tests/lock_cmpxchg_register/OUTCOMES.json',
            'group_variable': 'LI2_LOCK_CMPXCHG_REGISTER_GROUP',
            'control_variable': 'LI2_LOCK_CMPXCHG_REGISTER_CONTROL',
            'actual_commands': 'Complete ordered argv, environments and captures are retained privately and bound by commands_sha256.'})
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    markers = (str(Path.home()), str(REPO), platform.node(), '/home/')
    need(not any(x and len(x) > 1 and x in text for x in markers), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(sys.flags.optimize == 0, 'Python assertions must remain enabled')
    need(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision), 'exact revision')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-lock-cmpxchg-register-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-lock-cmpxchg-register-oracle-v1', 'status': 'failed',
        'scope': 'Exactly256 canonical dword [base],r32 forms, original-PC execution.32 bounded groups retain512 full native/TF comparisons plus32startup;32 genuine protected RMW failures remain failed operations. Every source/base combination has match and mismatch, ending and one crossing; all cuts are covered collectively, not every cut of every encoding. Actual before-state4B footprint ranges and complete records retained. Old EDX-base/R13/RIP/generic suites remain separately required. No split-lock/concurrent, real-program, performance or full-B2/B3 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'promoted_acceptance_checks': 0, 'lock_cmpxchg_register_pairs': 0,
                   'comparison_success_pairs': 0, 'comparison_failure_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0, 'typed_acceptance_checks': 0, 'actual_before_footprint_queries': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_lock_cmpxchg_register.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries, aliases = {}, {}, {}
    fixtures = {'lock-cmpxchg-register': private/'lock-cmpxchg-register'}
    build = None

    def pin(path):
        lexical = Path(path).absolute()
        path = lexical.resolve(strict=True)
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(path), 'input alias changed')
        aliases[str(lexical)] = str(path)
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'pinned input changed')
        pins[str(path)] = value
        return path

    def binary(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value
        return path

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'input alias changed before command')
        need(all(fact(p) == v for p, v in pins.items()), 'input changed before command')
        need(all(fact(p) == v for p, v in binaries.items()), 'artifact changed before command')
        native = profile == 'native'
        row = {'name': label, 'argv': list(map(str, argv)), 'bounds': PROFILES[profile],
               'expected_exit': expected, 'profile': profile,
               'capture_limit': 8192 if native else 1024*1024,
               'environment': dict(ENV, **(env or {}))}
        record['commands'].append(row)
        out, err = invoke(row, private, cpu, record=native, step=native)
        need(row['exit'] == expected, 'exact process exit: '+label)
        return row, out, err

    try:
        record['source'] = source()
        need(record['source']['revision'] == args.expect_revision, 'revision differs')
        record['hardware'] = hardware(cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'],
                                        cwd=REPO, timeout=5).split(b'\0')
        for value in paths:
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(REPO/os.fsdecode(value))
        build = Build(record, private, pin, binary, run)
        products = build.prepare()
        build.tools['gdb'] = pin(shutil.which('gdb',path=ENV['PATH']))
        gdb_environment = dict(build.environment, XDG_CACHE_HOME=str(private/'gdb-cache'))
        _,out,err = run('version-gdb',[build.tools['gdb'],'--version'],profile='metadata',env=gdb_environment)
        need(out and not err,'actual file-only GDB identity')
        record['build']['versions']['gdb'] = out.decode().strip()
        record['build']['tools']['gdb'] = dict(path=str(build.tools['gdb']),**fact(build.tools['gdb']))
        layouts = {}
        selected = REPO/'tools/page-entry/selected'
        dependency_rows = []
        for index, unit in enumerate((selected/'step_owner.c',selected/'lifecycle_loader.c',
                selected/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',selected/'tests/generic/fixture.S')):
            _,out,err = run('fixture-dependencies-'+str(index),[build.tools['cc']]+(['-std=gnu11'] if unit.suffix=='.c' else [])+['-M','-MT','li2_fixture',
                '-I'+str(selected/'tests/generic'),'-I'+str(selected),'-I'+str(selected.parent),unit],
                profile='metadata',env=build.environment)
            need(not err,'actual fixture compiler dependency stderr')
            dependencies = out.decode().replace('\\\n',' ').split(':',1)
            need(len(dependencies)==2 and dependencies[0]=='li2_fixture','exact fixture dependency target')
            paths = shlex.split(dependencies[1])
            need(paths and str(unit) in paths,'actual fixture dependency root')
            for dependency in paths:pin(dependency)
            dependency_rows.append(dict(unit=str(unit),dependencies=paths))
        record['fixture_dependencies'] = dependency_rows
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        record['fixtures'], record['elf'] = {}, {}
        for fixture_name, fixture in fixtures.items():
            binary(fixture)
            record['fixtures'][fixture_name] = fact(fixture)
            record['elf'][fixture_name] = plain_executable(fixture)
            _, out, err = run(fixture_name+'-undefined', [build.tools['nm'], '-u', fixture],
                              profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
            _,out,err = run(fixture_name+'-symbols',[build.tools['nm'],'-S','--defined-only',fixture],profile='inspect',env=build.environment)
            need(not err,'actual retained symbols stderr')
            actual = record_layout(fixture,out)
            _,out,err = run(fixture_name+'-dwarf',[build.tools['gdb'],'-q','-nx','-batch',
                '-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off',
                '-iex','maintenance set worker-threads 1','--readnow','--se='+str(fixture),
                '-x',pin(REPO/'evaluation/inprocess/page_selected_lock_base_dwarf.py')],profile='metadata',env=gdb_environment)
            need(not err,'file-only actual DWARF stderr')
            layout = json.loads(out)
            need(layout['sample_bytes'] == actual['sample_bytes'] and layout['query_bytes'] == 9920 and
                 layout['greg_count'] == 23,'actual record symbols and DWARF agree')
            actual['dwarf'] = layout;layouts[fixture_name] = actual
        record['layouts'] = layouts
        record['catalogue'], rows, faults = catalogue()
        for index,entry in enumerate(faults):entry['index'] = index
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        need(len(names) == 17 and len(outcomes['commands']) == 64, 'complete finite64-command canonical-register protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] == ['group'+str(i) for i in range(32)]+[x['name'] for x in faults] and
             [c['exit'] for c in outcomes['commands']] == [0]*32+[125]*32 and
             [c['argv'] for c in outcomes['commands']] == [['lock-cmpxchg-register']]*64 and
             [c['environment_delta'] for c in outcomes['commands']] == [{'LI2_LOCK_CMPXCHG_REGISTER_GROUP':str(i)} for i in range(32)]+[
                 {'LI2_LOCK_CMPXCHG_REGISTER_GROUP':'0','LI2_LOCK_CMPXCHG_REGISTER_CONTROL': x['name']} for x in faults] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact LOCK CMPXCHG names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             'b92a3a6fd1cb41e7172822fda277bc3cc0999609c06d423b79c6fa481aad6200',
             'exact reviewed64-command outcomes')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'verified_memory_fault': False}
            record['cases'].append(result)
            row, out, err = run(name, [fixtures[case['argv'][0]], *case['argv'][1:]], case['exit'],
                                env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            actual = layouts[case['argv'][0]]
            need(header['sample_bytes'] == actual['sample_bytes'] and len(data) == actual['bytes'] and
                 len(data) == header['header_bytes']+22*header['sample_bytes']+40+16512+9920 and len(data) < 16 << 20,
                 'complete actual retained-ELF record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            positive = name in ['group'+str(i) for i in range(32)]
            group = int(name[5:]) if positive else 0
            fault = None if positive else next(x for x in faults if x['name'] == name)
            used = 17 if positive else 1
            result['fault_trailer'] = fault_trailer(data[-26432:-9920],fault)
            result['query_trailer'] = query_trailer(data[-9920:],data,header,actual['dwarf'],group,rows,fault)
            record['totals']['typed_acceptance_checks'] += 256
            record['totals']['actual_before_footprint_queries'] += 32 if positive else 2
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['lock_cmpxchg_register_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['comparison_success_pairs'] += sum(not x['mismatch'] for x in rows[16*group:16*group+16])
                record['totals']['comparison_failure_pairs'] += sum(x['mismatch'] for x in rows[16*group:16*group+16])
                record['totals']['new_page_ending_pairs'] += sum(x['tail'] == x['length'] for x in rows[16*group:16*group+16])
                record['totals']['new_crossing_pairs'] += sum(x['tail'] < x['length'] for x in rows[16*group:16*group+16])
                record['totals'].update(supplied_refusal_encodings=83,
                    old_refusal_encodings=47, new_refusal_encodings=36)
            else:
                need(any(data[end:end+header['sample_bytes']]), 'retain actual failed-operation sample')
                # The authenticated C path requires actual native #PF and the
                # stepped unexpected frame, revoke/sync, unchanged state and
                # retained failed borrow before emitting this exact outcome.
                # Its full retained sample is not a successful continuation.
                result['verified_memory_fault'] = True
                record['totals']['verified_memory_fault_commands'] += 1
                record['totals']['actual_native_failed_operations'] += 1
                record['totals']['actual_stepped_failed_operations'] += 1
                record['totals']['additional_negative_command_selftests'] += 1
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=544,generic_pairs=512,lock_cmpxchg_register_pairs=512,
                 positive_selftest_pairs=32,supplied_refusal_encodings=83,old_refusal_encodings=47,
                 new_refusal_encodings=36,comparison_success_pairs=256,comparison_failure_pairs=256,
                 new_page_ending_pairs=256,new_crossing_pairs=256,verified_memory_fault_commands=32,
                 actual_native_failed_operations=32,actual_stepped_failed_operations=32,
                 additional_negative_command_selftests=32,executed_refusal_checks=5312,
                 promoted_acceptance_checks=0,typed_acceptance_checks=16384,actual_before_footprint_queries=1088) and
             len(record['cases']) == 64 and all(c['accepted'] for c in record['cases']),
             'complete256-form native/TF/footprint cohort and32 genuine failed atomic operations')
        record['status'] = 'passed'
    except BaseException as exc:
        record['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if build is not None:
            try:
                record['final_errors'].extend(build.finish())
                if record['status'] == 'passed':
                    need(record['build']['status'] == 'passed', 'build closure did not pass')
            except BaseException as exc:
                record['final_errors'].append('build closure: '+repr(exc))
        for fixture_name, fixture in fixtures.items():
            try:
                if fixture.is_file():
                    value = fact(fixture)
                    record.setdefault('fixtures_after', {})[fixture_name] = value
                    record.setdefault('fixtures', {}).setdefault(fixture_name, value)
                    binary(fixture)
            except BaseException as exc:
                record['final_errors'].append('fixture retention '+fixture_name+': '+repr(exc))
        record['input_aliases'] = aliases
        for lexical, resolved in aliases.items():
            try:
                need(str(Path(lexical).resolve(strict=True)) == resolved, 'final input alias identity')
            except BaseException as exc:
                record['final_errors'].append('input alias '+lexical+': '+repr(exc))
        record['inputs_before'], record['binaries_before'] = pins, binaries
        for key, before in (('inputs_after', pins), ('binaries_after', binaries)):
            after = record[key] = {}
            for path, expected in before.items():
                try:
                    after[path] = fact(path)
                    need(after[path] == expected, 'final byte identity')
                except BaseException as exc:
                    record['final_errors'].append(path+': '+repr(exc))
        try:
            record['source_unchanged'] = source() == record['source']
            need(record['source_unchanged'], 'source changed')
        except BaseException as exc:
            record['final_errors'].append('source: '+repr(exc))
        if record['final_errors']:
            record['status'] = 'failed'
            if record['error'] is None:
                record['error'] = 'FinalObservationError: input/source/artifact closure failed'
        receipt = private/'receipt.json'
        save(receipt, record)
        publish(public, record, receipt)
    print(json.dumps({'status': record['status'], 'totals': record['totals'],
                      'failure_type': (record['error'] or '').split(':')[0] or None}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
