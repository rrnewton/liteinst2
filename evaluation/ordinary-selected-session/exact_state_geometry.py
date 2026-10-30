"""Actual Exact37 ELF/caller facts; external acceptance is never generated here."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
from pathlib import Path
import re

MIB = 1048576
BODY = bytes.fromhex('31c04c8d04370fb60f83f15a4801c848ffc74c39c772ef48ba157c4a7fb979379e4831d0c3')
HEADS = [0,2,6,9,12,15,18,21,23,33,36]
CALLER = bytes.fromhex('534889cb4889f84889f74889d6ffd04889035bc3')
CALLER_HEADS = [0,1,4,7,10,13,15,18,19]
PREMISES = ('complete_symbol_extent','complete_cfg_and_return','complete_elf_and_source_page',
    'complete_copied_machine_caller','immutable_path_and_object_lifetime','scalar_sysv_abi_and_readable_inputs',
    'termination_no_hidden_calls_or_exits','sole_worker_no_reentry_or_concurrency','cet_and_signal_preconditions')

def instructions(raw, address, body, heads):
    assert type(raw) is bytes and 0 < len(raw) <= 4*MIB
    rows = []
    for line in raw.decode('ascii').splitlines():
        if not re.match(r'^\s+[0-9a-f]+:',line): continue
        fields = line.split('\t'); assert len(fields) >= 3
        pc = int(fields[0].strip()[:-1],16)
        encoded = bytes.fromhex(fields[1]); assert 1 <= len(encoded) <= 15
        rows.append((pc,encoded))
    assert [pc-address for pc,_ in rows] == heads
    assert b''.join(code for _,code in rows) == body
    assert all(pc+len(code) == nxt for (pc,code),(nxt,_) in zip(rows,rows[1:]))
    assert rows[-1][0]+len(rows[-1][1]) == address+len(body)

def source_page(raw, fixture):
    selection = fixture.describe(raw)
    assert fixture.CODE == BODY and selection['length'] == 37
    assert selection['head_offsets'] == HEADS and selection['return_offsets'] == [36]
    parsed = fixture.elf.elf(raw); va = selection['elf_va']; page_va = va & ~4095
    assert 0 < va < 2**64-37 and va%4096+37 <= 4096
    owners = [p for p in parsed['loads'] if p[1] == 5 and p[3] <= va and va+37 <= p[3]+p[5]]
    assert len(owners) == 1
    p = owners[0]; offset = (p[2] & ~4095)+(page_va-(p[3] & ~4095))
    page = fixture.elf.extent(raw,offset,4096)
    assert len(page) == 4096 and page[va-page_va:va-page_va+37] == BODY
    return selection,dict(elf_va=page_va,file_offset=offset,**fixture.elf.digest(page)),parsed

def facts(run, recipe, driver, fixture, build, sdk, directory):
    trusted = directory/'exact-final.so'; candidate = directory/'exact-candidate.so'
    raw = driver.raw_pin(run,recipe,trusted,cap=MIB)
    selection,page,parsed = source_page(raw,fixture)
    declared = driver.read_json(run,recipe,directory/'selection.json')
    assert declared == dict(selection,revision=run.a.revision)
    fixture.authenticate(candidate,trusted,selection['elf_va'],37,directory/'selection.json',
        run.retained[str(directory/'selection.json')]['sha256'])
    driver.raw_pin(run,recipe,candidate,recipe.pin(raw),MIB)
    disassembly = driver.raw_pin(run,recipe,directory/'exact-disassembly-io/stdout.txt',cap=MIB)
    instructions(disassembly,selection['elf_va'],BODY,HEADS)
    driver.raw_pin(run,recipe,directory/'exact-elf-io/stdout.txt',cap=MIB)
    build_dir = run.a.build.parent
    caller_capture = build_dir/'ordinary-interval-disassembly/stdout'
    caller_disassembly = driver.raw_pin(run,recipe,caller_capture,cap=4*MIB)
    shape = run.m['csv'].caller_geometry(caller_disassembly.decode('ascii'))
    assert shape['length'] == 20 and shape['continuation_offset'] == 15
    assert len(bytes.fromhex(shape['call_bytes'])) == 2
    instructions(caller_disassembly,shape['elf_va'],CALLER,CALLER_HEADS)
    symbols_path = build_dir/'ordinary-interval-elf/stdout'
    symbols = driver.raw_pin(run,recipe,symbols_path,cap=4*MIB).decode('ascii')
    selected = '\n'.join(line for line in symbols.splitlines()
        if len(line.split()) == 8 and line.split()[-1] == 'liteinst_csv_call_and_store')
    run.m['module'].caller_symbols(selected,shape)
    caller = build_dir/'products/ordinary-interval'
    driver.raw_pin(run,recipe,caller,build['products']['ordinary-interval'],128*MIB)
    # The Rust Artifact reader independently joins the copied caller to this ELF.
    # Here the complete ELF and closed readelf/objdump products are review inputs.
    pins = {str(path):run.retained[str(path)] for path in (trusted,candidate,directory/'selection.json',
        directory/'exact-elf-io/stdout.txt',directory/'exact-disassembly-io/stdout.txt',caller_capture,symbols_path,caller)}
    for product in sdk['products'].values():
        path = Path(product['path']); pin = {k:product[k] for k in ('bytes','sha256')}
        driver.raw_pin(run,recipe,path,pin,128*MIB); pins[str(path)] = pin
    return dict(revision=run.a.revision,selection=selection,source_page=page,
        elf_metadata_sha256=driver.sha(recipe.canonical(parsed)),program_headers=[list(p) for p in parsed['ph']],
        table=[dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=selection['elf_va'],extent=37,returns=[36])],
        caller=dict(elf_va=shape['elf_va'],extent=20,heads=CALLER_HEADS,call=13,continuation=15,outer_ret=19,
            subject_rsp_delta=16,stack_bytes=152,body_sha256=driver.sha(CALLER)),
        trusted=str(trusted),candidate=str(candidate),application=str(caller),pins=pins)

def acceptance(value, facts, preparation, build, sdk_build, revision, profile):
    assert type(value) is dict and set(value) == {'kind','status','scope','revision','preparation','build','sdk_build',
        'facts','premises','review','supporting_pins','native_state','qualification'}
    assert value['kind'] == 'exact37-accuracy-copied-geometry-acceptance-v1'
    assert value['status'] == 'INDEPENDENTLY_ACCEPTED_FOR_FIXED_EXACT37_COPIED_ACCURACY_STATE'
    assert value['scope'] == profile and value['revision'] == revision
    assert value['preparation'] == preparation and value['build'] == build and value['sdk_build'] == sdk_build
    assert value['facts'] == facts and facts['revision'] == revision
    assert value['native_state'] == 'UNRUN_SEPARATE_REQUIRED'
    assert value['qualification'] == dict(pmu_metric=False,cadence=False,performance=False)
    assert all(flag is False for flag in value['qualification'].values())
    assert set(value['premises']) == set(PREMISES) and all(value['premises'][key] is True for key in PREMISES)
    assert type(value['review']) is str and 1 <= len(value['review']) <= 16384
    assert type(value['supporting_pins']) is dict and 1 <= len(value['supporting_pins']) <= 64
    for path,pin in value['supporting_pins'].items():
        assert Path(path).is_absolute() and set(pin) == {'bytes','sha256'}
        assert type(pin['bytes']) is int and 0 < pin['bytes'] <= 128*MIB
        assert re.fullmatch('[0-9a-f]{64}',pin['sha256'])
    # External unsafe premises remain explicit. Equality and source hashes do
    # not establish the machine ABI, signal/CET state or immutable lifetime.
