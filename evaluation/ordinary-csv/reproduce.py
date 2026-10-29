#!/usr/bin/env python3
"""One release CSV functional qualification; no retries or performance claim.

Run from a clean checkout inside a one-core cpuset reservation. Output must be
new and under ignored/. Private compiler logs and ELF captures stay there.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
ROOT = Path.cwd()
HEADER = 'id,length,expected,original,installed,return_offset,ordinal,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,ack,ack_ordinal'
COUNTS = [1,1,3,2,3,2,2,1,1,2,3,2,1,2,4,3]
LENGTHS = [0, 1, 5, 1, 2, 2, 2, 2, 5, 7, 9, 8, 4, 5, 24, 29]


def caller_geometry(disassembly):
    """Accept this example's straight-line CALL/store/RET, or refuse its shape."""
    names = re.findall(r'^([0-9a-f]+) <liteinst_csv_call_and_store>:$', disassembly, re.M)
    assert len(names) == 1
    start = int(names[0],16); instructions = []
    for line in disassembly.splitlines():
        if not re.match(r'^\s+[0-9a-f]+:',line):
            continue
        parts = line.split('\t'); assert len(parts) == 3
        address = int(parts[0].strip()[:-1],16)
        encoded = bytes.fromhex(parts[1]); assembly = parts[2].strip()
        assert 1 <= len(encoded) <= 15
        assert assembly.split()[0] in ('push','pop','mov','lea','add','sub','call','ret','nop')
        instructions.append((address,encoded,assembly))
    assert instructions and instructions[0][0] == start
    for left,right in zip(instructions,instructions[1:]):
        assert left[0] + len(left[1]) == right[0]
    calls = [i for i,item in enumerate(instructions) if item[2].startswith('call ')]
    assert len(calls) == 1 and calls[0]+1 < len(instructions)
    call = instructions[calls[0]]; following = instructions[calls[0]+1]
    assert re.fullmatch(r'call\s+r(?:ax|bx|cx|dx|si|di|sp|bp|[89]|1[0-5])',call[2])
    assert re.fullmatch(r'mov\s+QWORD PTR \[r(?:ax|bx|cx|dx|si|di|sp|bp|[89]|1[0-5])\],rax',following[2])
    assert [i for i,item in enumerate(instructions) if item[2].split()[0]=='ret'] == [len(instructions)-1]
    assert instructions[-1][2] == 'ret'
    return dict(elf_va=start, length=instructions[-1][0]+len(instructions[-1][1])-start,
        continuation_offset=following[0]-start, call_bytes=call[1].hex(), store_bytes=following[1].hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--cargo-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    out = args.output.resolve()
    assert out.is_relative_to(ROOT / 'ignored') and not out.exists()
    assert subprocess.check_output(['git','rev-parse','HEAD']).decode().strip() == args.revision
    assert subprocess.check_output(['git','status','--porcelain','--untracked-files=no']) == b''
    affinity = sorted(os.sched_getaffinity(0)); assert len(affinity) == 1
    out.mkdir(parents=True)
    logs = ROOT/'target/evaluation'/out.name
    logs.mkdir(parents=True, exist_ok=False)
    tc = args.toolchain.resolve(strict=True)
    env = dict(HOME=os.environ['HOME'], PATH=str(tc/'bin')+':/usr/bin:/bin',
        RUSTC=str(tc/'bin/rustc'), RUSTDOC=str(tc/'bin/rustdoc'),
        CARGO_HOME=str(args.cargo_home.resolve(strict=True)), CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_TERM_COLOR='never', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', LANG='C.UTF-8', LC_ALL='C.UTF-8',
        PYTHONDONTWRITEBYTECODE='1', LITEINST_EVALUATION='1')
    helper = ROOT/'evaluation/admission/processes.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
    spec = importlib.util.spec_from_file_location('csv_process_owner', helper)
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    stanzas = [dict(line.split(':',1) for line in stanza.splitlines() if ':' in line)
        for stanza in Path('/proc/cpuinfo').read_text().split('\n\n') if stanza.strip()]
    stanzas = [{k.strip():v.strip() for k,v in stanza.items()} for stanza in stanzas]
    selected = [stanza for stanza in stanzas if stanza.get('processor') == str(affinity[0])]
    assert len(selected) == 1
    cpu = {k:v for k,v in selected[0].items() if k in
        ('processor','vendor_id','cpu family','model','model name','stepping','microcode')}
    result = dict(revision=args.revision, status='FAILED', attempts=1, retries=0,
        observed_cpu=cpu, affinity=affinity,
        load_before=list(os.getloadavg()), commands=[], native_status='UNRUN')
    sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    def step(name, argv, wall=180):
        argv = list(map(str, argv)); log = logs/(name+'.log')
        closed = owner.run_command(argv, env, log, wall, 1048576)
        result['commands'].append(dict(name=name, argv=argv, closed=closed))
        data = log.read_bytes(); (out/log.name).write_bytes(data)
        assert hashlib.sha256(data).hexdigest() == closed['private_log_sha256']
        assert closed['exit_code'] == 0 and closed['termination'] is None
        assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        return log.read_text()
    try:
        step('release-build', [tc/'bin/cargo','build','-p','rapid-profiler','--bin','ordinary-interval','--release'])
        candidate = out/'csv_fields.so'; trusted = out/'trusted_csv_fields.so'
        c = ROOT/'tools/rapid-profiler/normal-work/csv_fields.c'
        assert sha(c) == 'f8f98cc0550cf3ba72d2f2558f45057d2889870e804b51f599d4050ffb37cddd'
        step('csv-build', ['/usr/bin/gcc','-O2','-fno-tree-vectorize','-fno-if-conversion','-fno-if-conversion2',
            '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-stack-protector',
            '-fcf-protection=none','-fPIC','-nostdlib','-shared','-Wl,--build-id=none,-z,now','-o',candidate,c])
        shutil.copyfile(candidate, trusted)
        assert candidate.stat().st_ino != trusted.stat().st_ino and candidate.read_bytes() == trusted.read_bytes()
        symbols = step('csv-symbols', ['/usr/bin/readelf','--wide','--syms',trusted], 30)
        rows = [line.split() for line in symbols.splitlines() if line.split() and line.split()[-1]=='csv_fields']
        assert len(rows) == 2 and all(r[3:6] == ['FUNC','GLOBAL','DEFAULT'] for r in rows)
        extents = {(int(r[1],16),int(r[2])) for r in rows}; assert len(extents) == 1
        va,length = extents.pop(); assert va > 0 and 1 <= length <= 256
        step('csv-disassembly', ['/usr/bin/objdump','-d','-M','intel','--disassemble=csv_fields',trusted],30)
        binary = ROOT/'target/release/ordinary-interval'
        caller = caller_geometry(step('caller-disassembly', ['/usr/bin/objdump','-d','-M','intel','--disassemble=liteinst_csv_call_and_store',binary],30))
        caller_symbols = step('caller-symbols', ['/usr/bin/bash','-o','pipefail','-c',
            '/usr/bin/readelf --wide --syms "$1" | /usr/bin/rg \' liteinst_csv_call_and_store$\'',
            'csv-caller-symbols',binary],30)
        rows = [line.split() for line in caller_symbols.splitlines()]
        assert 1 <= len(rows) <= 2 and all(len(r)==8 and r[3:6]==['FUNC','GLOBAL','DEFAULT']
            and r[7]=='liteinst_csv_call_and_store' and r[6].isdecimal() for r in rows)
        assert {(int(r[1],16),int(r[2])) for r in rows} == {(caller['elf_va'],caller['length'])}
        assert caller['length'] > 0
        result['caller'] = caller
        result.update(elf_va=va, length=length, subject_sha256=sha(candidate), binary_sha256=sha(binary), source_sha256=sha(c))
        request = dict(argv=[str(binary),'normal-csv-work',str(candidate),str(trusted),str(va),str(length)],
            cwd=str(ROOT),env=env,stdout=str(out/'stdout.txt'),stderr=str(out/'stderr.txt'),
            cpu_seconds=20,wall_seconds=30,file_bytes=1048576)
        request_bytes = (json.dumps(request,indent=2)+'\n').encode()
        with (out/'request.json').open('xb') as stream: stream.write(request_bytes)
        bounded = ROOT/'tools/unwind-oracle/bounded_command.py'
        bounded_sha = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
        assert sha(bounded) == bounded_sha
        result['native_status'] = 'FAILED'
        step('native-owner', [sys.executable,'-B',ROOT/'tools/unwind-oracle/bounded_command.py',
            '--request',out/'request.json','--receipt',out/'native.json'],55)
        native = json.loads((out/'native.json').read_text())
        assert native['exit'] == 0 and native['absence_proof'] == 'ECHILD'
        assert not native['wall_timeout'] and not native['unexpected_descendants'] and not native['cleanup_events']
        assert native['aborted'] is None and native['cleanup_error'] is None and native['inputs_unchanged']
        assert native['request_sha256'] == hashlib.sha256(request_bytes).hexdigest() == sha(out/'request.json')
        assert native['helper_sha256'] == bounded_sha == sha(bounded)
        assert native['stdout_sha256'] == sha(out/'stdout.txt') and native['stderr_sha256'] == sha(out/'stderr.txt')
        raw = (out/'stdout.txt').read_bytes(); assert len(raw) <= 8192
        text = raw.decode('ascii'); assert text.endswith('\n') and text.count('\n') == 18 and '\r' not in text
        assert (out/'stderr.txt').read_bytes() == b''
        lines = text.splitlines(); assert len(lines) == 18 and lines[0] == HEADER
        fields = HEADER.split(',')
        assert all(len(line.split(',')) == len(fields) for line in lines[1:17])
        table = [dict(zip(fields,line.split(','))) for line in lines[1:17]]; assert len(table) == 16
        fields = lines[-1].split(); assert fields[:2] == ['normal-csv-work','CSV_FUNCTIONAL_PASS']
        pairs = [f.split('=') for f in fields[2:]]; assert all(len(p)==2 for p in pairs)
        assert ' '.join(fields) == lines[-1]
        assert all(re.fullmatch('0|[1-9][0-9]*',v) and int(v)<2**64 for k,v in pairs)
        terminal = {k:int(v) for k,v in pairs}; assert len(terminal) == len(pairs)
        fixed = dict(originals=16, installed=16, fields_per_leg=33, batches=1, events=32,
            records=16, actions=2, journal_words=512, entered=16, ret_observed=16,
            confirmed=16, completed=16, unsampled=0, next_entry=15, checkpoints=1,
            install=0x63737601, function=1, registration=1)
        assert list(terminal) == ['originals','installed','fields_per_leg','batches','events',
            'records','actions','journal_words','entered','ret_observed','confirmed','completed',
            'unsampled','next_entry','checkpoints','declared_returns','observed_returns','pid','tid',
            'cpu','generation','entry','caller_entry','length','install','function','registration']
        assert all(terminal[k] == v for k,v in fixed.items())
        assert terminal['generation'] > 0 and 0 < terminal['entry'] < 2**64-length
        assert terminal['pid'] == terminal['tid'] and 0 < terminal['pid'] < 2**32
        assert terminal['cpu'] == affinity[0] < 1024 and terminal['length'] == length
        expected_word = terminal['caller_entry'] + caller['continuation_offset']
        assert 0 < terminal['caller_entry'] < expected_word < 2**64
        for i,row in enumerate(table):
            assert all(re.fullmatch('0|[1-9][0-9]*',v) and int(v)<2**64 for v in row.values())
            r = {k:int(v) for k,v in row.items()}
            assert r['id'] == r['ordinal'] == i+1 and r['invocation'] == i and r['history_prefix'] == 1
            assert r['length'] == LENGTHS[i]
            assert r['expected'] == r['original'] == r['installed'] == COUNTS[i]
            assert r['ack'] == (2 if i==15 else 1) and r['ack_ordinal'] == (0 if i==15 else i+2)
            assert 0 < r['return_offset'] < length and r['entry_rsp'] % 16 == 8 and r['return_word'] == expected_word
            assert r['start_aux'] == r['end_aux'] < 2**32 and r['start_ticks'] <= r['end_ticks']
        assert 1 <= terminal['declared_returns'] <= 4
        assert terminal['declared_returns'] == terminal['observed_returns'] == len({r['return_offset'] for r in table})
        (out/'results.csv').write_text('\n'.join(lines[:17])+'\n')
        assert sha(candidate) == sha(trusted) == result['subject_sha256'] and sha(binary) == result['binary_sha256']
        assert subprocess.check_output(['git','status','--porcelain','--untracked-files=no']) == b''
        assert subprocess.check_output(['git','rev-parse','HEAD']).decode().strip() == args.revision
        result.update(native_status='PASS', status='PASS', terminal=terminal, rows=len(table))
    finally:
        result['load_after'] = list(os.getloadavg())
        (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'], original_calls=16, installed_calls=16, rows=result['rows'])))

if __name__ == '__main__':
    main()
