#!/usr/bin/env python3
"""Separate E9 zero-hook capture audit; original strict comparator unchanged."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python disables capture checks")
HERE = Path(__file__).resolve().parent
sha = lambda data: hashlib.sha256(data).hexdigest()
from state_mapping_identity import backing_identity, require_mapping_identity
from state_ownership_audit import audit_ownership
from state_ledger_schema import CASES_HEADER, PAGES_HEADER, exact_rows
REGISTER_KEYS = set('r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs logical_pc'.split())
DEBUGGER_FLAGS = (1 << 8) | (1 << 16)

def tsv(path):
    rows = [line.split('\t') for line in path.read_text().splitlines()]
    assert all(len(row) == 2 for row in rows)
    result = dict(rows)
    assert len(result) == len(rows)
    return result

def audit(captures, input_inventory):
    assert captures.is_dir()
    inputs = json.loads(input_inventory.read_text())
    assert inputs['actual_emitted_files'] == 6
    assert inputs['status'] == 'ACTUAL_E9_COMMON_INPUTS_STATE_PENDING'
    assert inputs['required_traces'] == [48, 48, 48]
    assert inputs['required_points'] == 360 and inputs['expected_file_pages'] == 768
    assert inputs['required_hook_witnesses'] == 0 and inputs['manual_fixture_load'] is True
    assert len(inputs['fixtures']) == 6
    assert inputs['retained_module_instances'] == 12 and inputs['reservation_roots'] == 16
    assert inputs['body_owned_bytes'] == 425984 and inputs['data_stack_owned_bytes'] == 884736
    complete = tsv(captures / 'complete.tsv')
    expected = dict(actual_output_files='6', retained_module_instances='12', reservation_roots='16', body_owned_bytes='425984', data_stack_owned_bytes='884736', original_traces='48', rewritten_comparisons='48', restored_original_comparisons='48', passthru_hook_events='0', manual_fixture_load='true', loader_admission='false', qualification_complete='false')
    assert complete.keys() == expected.keys() | {'observed_distinct_biases'}
    for key, value in expected.items(): assert complete[key] == value, key
    cases = exact_rows((captures / 'cases.tsv').read_text(), CASES_HEADER)
    assert len(cases) == 12
    assert all(set(row) == {'fixture','bias_index','bias','source','image','restored_head','terminal'} for row in cases)
    assert len({(row['fixture'], row['bias_index']) for row in cases}) == 12
    assert int(complete['observed_distinct_biases']) == len({int(row['bias']) for row in cases}) >= 2
    hashes = {}
    def bind(path):
        assert path.is_file() and not path.is_symlink()
        relative = str(path.relative_to(captures))
        assert relative not in hashes
        hashes[relative] = sha(path.read_bytes())
    bind(captures / 'complete.tsv'); bind(captures / 'cases.tsv')
    totals = dict(traces=0, points=0, hook_witnesses=0, file_pages=0)
    fixture_names = set()
    instance_roots = {}
    for item in inputs['fixtures']:
        name = item['name']; fixture_names.add(name)
        rows = [row for row in cases if row['fixture'] == name]
        assert len(rows) == 2 and {row['bias_index'] for row in rows} == {'0', '1'}
        assert rows[0]['bias'] != rows[1]['bias']
        for row in rows:
            bias = int(row['bias']); selected = bias + item['source_pc']
            image = bias + item['image_pc']
            restored = bias + item['restored_boundary']; terminal = bias + item['source_page'] + 2048
            assert {key:int(row[key]) for key in ['source','image','restored_head','terminal']} == dict(source=selected,image=image,restored_head=restored,terminal=terminal)
            base = captures / name / f"bias-{row['bias_index']}"
            for phase in ['original', 'rewritten', 'restored-original']:
                phase_dir = base / phase
                maps_path = phase_dir / 'maps.txt'; bind(maps_path)
                assert maps_path.stat().st_size > 0
                pages_path = phase_dir / 'pages.tsv'; bind(pages_path)
                pages = exact_rows(pages_path.read_text(), PAGES_HEADER)
                file_path = item['output_path'] if phase == 'rewritten' else item['original_path']
                data = Path(file_path).read_bytes()
                assert sha(data) == item['output_sha256' if phase == 'rewritten' else 'original_sha256']
                loads = item['output_loads' if phase == 'rewritten' else 'original_loads']
                actual_pages = {}
                mapped = []
                for line in maps_path.read_text().splitlines():
                    fields = line.split(maxsplit=5)
                    assert len(fields) in (5, 6)
                    low, high = (int(value, 16) for value in fields[0].split('-'))
                    mapped.append((low, high, fields))
                for backing_name in ['backing.tsv','fdinfo.txt','mountinfo.txt','backing-path.txt']: bind(phase_dir/backing_name)
                file_stat = Path(file_path).stat()
                backing = backing_identity(tsv(phase_dir/'backing.tsv'), (phase_dir/'fdinfo.txt').read_text(), (phase_dir/'mountinfo.txt').read_text(), (phase_dir/'backing-path.txt').read_text(), str(Path(file_path).resolve()), file_stat.st_dev, file_stat.st_ino, file_stat.st_size, sha(data))
                for load in loads:
                    start = load['vaddr'] & ~4095
                    stop = (load['vaddr'] + load['memory_size'] + 4095) & ~4095
                    file_page = load['offset'] & ~4095
                    for offset in range(0, stop - start, 4096):
                        raw = data[file_page + offset:file_page + offset + 4096].ljust(4096, b'\0')
                        assert len(raw) == 4096
                        address = bias + start + offset
                        assert address not in actual_pages
                        actual_pages[address] = raw
                        owners = [(low, high, fields) for low, high, fields in mapped if low <= address and address + 4096 <= high]
                        assert len(owners) == 1
                        low, _, fields = owners[0]
                        assert len(fields) == 6 and fields[5] == str(Path(file_path).resolve())
                        assert fields[1] == {4:'r--p',5:'r-xp',6:'rw-p'}[load['flags']]
                        assert int(fields[2],16) + address - low == file_page + offset
                        major, minor = (int(value,16) for value in fields[3].split(':'))
                        require_mapping_identity(backing, major, minor, int(fields[4]))
                ownership_path = phase_dir / 'ownership.tsv'; bind(ownership_path)
                roots = audit_ownership(ownership_path, item, bias, phase, mapped, actual_pages)
                key = (name, row['bias_index'])
                if key in instance_roots: assert instance_roots[key] == roots
                else:
                    assert all(end <= low or high <= start for start,end in roots for prior in instance_roots.values() for low,high in prior)
                    instance_roots[key] = roots
                assert len(pages) == len(actual_pages)
                assert {int(page['address']) for page in pages} == actual_pages.keys()
                for page in pages:
                    assert page['bytes'] == '4096' and page['sha256'] == sha(actual_pages[int(page['address'])])
                for entry in range(2):
                    for seed in range(2):
                        directory = phase_dir / f'entry-{entry}-seed-{seed}'
                        points = [selected, selected + 5, terminal][entry:]
                        calls = 0  # This separately declared passthru RPC has no hook.
                        expected_complete = dict(points=str(len(points)), hook_calls=str(calls), manual_fixture_load='true', qualification_complete='false')
                        assert tsv(directory / 'complete.tsv') == expected_complete
                        bind(directory / 'complete.tsv')
                        assert set(path.name for path in (directory / 'file-pages').iterdir()) == {f'{address:016x}.bin' for address in actual_pages}
                        for address, raw in actual_pages.items():
                            path = directory / 'file-pages' / f'{address:016x}.bin'
                            assert path.read_bytes() == raw
                            bind(path); totals['file_pages'] += 1
                        for point_index, logical_pc in enumerate(points):
                            point = directory / f'point-{point_index:02}'
                            assert {path.name for path in point.iterdir()} == {'registers.tsv','xstate.bin','application-data.bin','application-stack-redzone.bin'}
                            regs = {key:int(value) for key,value in tsv(point / 'registers.tsv').items()}
                            assert regs.keys() == REGISTER_KEYS and regs['logical_pc'] == logical_pc
                            assert regs['rip'] == (restored if phase == 'rewritten' and logical_pc == selected else logical_pc)
                            assert (point / 'application-data.bin').stat().st_size == 4096
                            assert (point / 'application-stack-redzone.bin').stat().st_size == 4232
                            canonical = (point / 'xstate.bin').read_bytes()
                            # Exact old canonical format: 363 fixed x87/MXCSR/XMM
                            # bytes, then complete (bit:u32,size:u64,bytes) records.
                            assert len(canonical) >= 363
                            offset = 363; prior_bit = 1
                            while offset < len(canonical):
                                assert offset + 12 <= len(canonical)
                                bit = int.from_bytes(canonical[offset:offset+4],'little')
                                size = int.from_bytes(canonical[offset+4:offset+12],'little')
                                assert prior_bit < bit < 64 and size > 0
                                assert offset + 12 + size <= len(canonical)
                                prior_bit = bit; offset += 12 + size
                            assert offset == len(canonical)
                            for path in point.iterdir(): bind(path)
                            if phase != 'original':
                                original = base / 'original' / f'entry-{entry}-seed-{seed}' / f'point-{point_index:02}'
                                old_regs = {key:int(value) for key,value in tsv(original/'registers.tsv').items()}
                                for key in REGISTER_KEYS - {'rip','eflags'}: assert regs[key] == old_regs[key], key
                                assert regs['eflags'] & ~DEBUGGER_FLAGS == old_regs['eflags'] & ~DEBUGGER_FLAGS
                                for filename in ['xstate.bin','application-data.bin','application-stack-redzone.bin']:
                                    assert (point/filename).read_bytes() == (original/filename).read_bytes(), filename
                            totals['points'] += 1
                        expected_names = {'complete.tsv','file-pages'} | {f'point-{index:02}' for index in range(len(points))}
                        # A hook capture, extra point, or other unexpected file
                        # is rejected by the exact directory inventory below.
                        assert {path.name for path in directory.iterdir()} == expected_names
                        totals['traces'] += 1
                assert {path.name for path in phase_dir.iterdir()} == {'maps.txt','pages.tsv','backing.tsv','fdinfo.txt','mountinfo.txt','backing-path.txt','ownership.tsv'} | {f'entry-{entry}-seed-{seed}' for entry in range(2) for seed in range(2)}
            assert {path.name for path in base.iterdir()} == {'original','rewritten','restored-original'}
        assert {path.name for path in (captures/name).iterdir()} == {'bias-0','bias-1'}
    assert {path.name for path in captures.iterdir()} == fixture_names | {'complete.tsv','cases.tsv'}
    assert totals == dict(traces=144,points=360,hook_witnesses=0,file_pages=768)
    assert len(instance_roots) == 12
    assert sum(len(roots) for roots in instance_roots.values()) == 16
    assert sum(end-start for roots in instance_roots.values() for start,end in roots) == 416*1024
    assert len(hashes) == 2606  # Exact old 2570 plus 36 phase ownership ledgers.
    return dict(status='EXACT_CAPTURE_AUDIT_PASS',manual_fixture_load=True,loader_admission=False,qualification_complete=False,totals=totals,source_inventory_sha256=sha(input_inventory.read_bytes()),captured_sha256=hashes)

# Invocation is through the source-authenticated package entry, which pins the
# actual six-output freeze, exact capture path and separate audit receipt.
