#!/usr/bin/env python3
"""W01 only: independently join immutable saved D01 artifacts; never rerun a producer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types

assert not sys.flags.optimize, 'assertions required'
MIB = 1048576
MAX_MEMBERS = 262
FRAMING_BYTES = (MAX_MEMBERS + 2) * 256
TRANSPORT_BYTES = 70 * MIB + FRAMING_BYTES
REPRODUCER = 'cd01ee97b046a382fcb2881a4b642836d9c6b0d2dd60273ba27b1432536c9c2f'
DIAGNOSTIC = 'b8e61360056220b1e2a60f93f32844b36e483d08a354bccbf6b03f1a8288c4a3'
PROGRAMS = ('checksum', 'rle-roundtrip')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
CRATE = 'evaluation/adjacent-b2/artifact-verifier'
# Filled with the exact reviewed Rust/manifest bytes when this source packet closes.
VERIFIER_SOURCES = {'Cargo.toml': '3c1d5a89b9779529772e080011bf480be89d68969047e207cebe5a87fae01f7b', 'src/main.rs': 'fc32fdb0437339a22a86e0d77b5643e6ff0378eed1577ac261d2ae63f09738ee', 'src/startup_transport.rs': '35b6346e79c5c0f827e87c39f1ced572ec5a3ec5372ab5df055cf76825bf010e', 'src/transport_tests.rs': 'd8f5c6b7998b0048ff5d4a426405ea8da71bfad0b56dffbd3e65465051ca6323', 'src/verify/association.rs': '4f5fa3b5a5d1dc8fc0c67a71e99117f8f7fa899c630467dc0ae37f8985bae169', 'src/verify/candidate.rs': 'b6015031b5dec52c3fc059ed05c4f8966c589fd63ce3769ed0f48dabecfa1677', 'src/verify/candidate_tests.rs': '26be1e9dda4817bc9a12d6374ddfa1362522419b126b7458e3beb4417d9f37de', 'src/verify/ledger.rs': '32f2d3a62e33d2eaf68f74d30ba69cd5f9fba43b3d6cbdea4926aa5c4907af07', 'src/verify/startup/catalog.rs': 'a1f3eaa41eae0416d10f1d4c2284e836c9c48e665a4dde93aa0242025e7c9f92', 'src/verify/startup/dependencies.rs': 'a6743d24e22c92c749012a9c38b309f79f305fa4985dec3f267ea87fb2e39208', 'src/verify/startup/layout.rs': '9392bdde69c3def9171c9631548be21ee416a9fa9be9dad49e0dfe5f8c84b17c', 'src/verify/startup/tests.rs': 'e5bfc7c66d2bcf69995c46831ed6bc619de37e2d2e50119eb67a44e1ad9da6a4', 'src/verify/startup.rs': '097176575c5481984e66c29547d3faa5bb2bd6337f4215b8010f1f23c96b2a85', 'src/verify/tests.rs': '5d031626803a3890ded56c7a33178e91462a53949c9c3f6f81261a4cc51d8f32', 'src/verify.rs': '6f84826ad4045eba942bda9611ef9ca23bd9fa3377f34ab1ac1cc745c8ef90ec'}
# Separate additive startup modules, bound to exact closed source packets.
STARTUP_MODULES = {'startup_cargo_from_root.py': 'd9189f38057a1167f74de2c93ce22b361cdcd2ca10e6bf68862c8281f2c4aa89', 'startup_custody.py': '6c236204101fb5950f955eb0540a51756bcf27d0a09860a9feab5f041d51f8c5', 'startup_originals.py': 'fe1c9bc33800a8216a9c3bc12a33be3579d92e07c5dbc1c10bd0ea75566bd03c', 'startup_pins.py': 'b11f1d05d80a604cb63e1f13288933b14ada1ec28f0d1034928901d4fa4ede3a', 'startup_produce.py': '42d97f0fe862ad43ac16531c854707db260960a66858ce28050e64a768009eb0', 'startup_saved.py': 'f9b888833e907af4bef59848ea94472f5d5f968134dd55686ff906baef5f9c0b', 'startup_target_from_root.py': '81ef52660559ee2f4088d02470eddbe64b981d16625392cbd0481123dd63312d'}
ROOTED_BUILD_SOURCES = {'cargo_from_root.py': '515060bdbff75aba566cd2778636772adf942a2277e6ef34d6bdfab094139a5c', 'rooted_build.py': '812fe73a6b31551d828177c4e7597f4367fab29a3eadc39f7a248b44e291a468'}
sha = lambda b: hashlib.sha256(b).hexdigest()


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def context(root):
    path = root / 'evaluation/offline-corpus/reproduce_whole.py'
    with path.open('rb') as stream:
        raw = stream.read(MIB + 1)
    need(len(raw) <= MIB and sha(raw) == REPRODUCER, 'exact D01 reproducer before import')
    module = types.ModuleType('_w01_checked_reproducer'); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    a = module.load('adjacent_whole.py', DIAGNOSTIC)
    ctx = types.SimpleNamespace(B=module.B, H=module.H, D=module.D, ROOT=module.ROOT,
        HERE=module.HERE, PINS=module.PINS, read=module.read, closed=module.closed,
        load=module.load, reproducer_file=str(path), invoke=module.invoke)
    need(ctx.ROOT == root, 'one unchanged producer checkout')
    return ctx, a


def expected_files(ctx, a, program, inputs, material):
    """All complete text comes from checked original/authored facts, before Product reads."""
    d = ctx.D
    image, obj, sizes = d.ownership(inputs['original'], inputs['object'], program)
    heads = d.head_transport(program, inputs['heads'], inputs['original'], inputs['object'], sizes)
    d.code_and_relocations(image, obj, heads, program)
    startup, labels = d.source_roster()
    kernel = d.C.instructions(program)
    regions = {role: (d.BASES['.text.' + role], sizes[role]) for role in d.ROLES}
    cuts = {pc for base, size in regions.values() for pc in (base, base + size)}
    # This is the closed authored instruction inventory, not a second decoder.
    # Every non-Next instruction in these exact sources is enumerated here.
    for instruction, (off, code) in zip(startup, heads['start']):
        op = instruction.split()[0]; pc = 0x401000 + off
        if op.startswith('j') or op in ('call', 'syscall', 'ud2'):
            cuts.add(pc + len(code))
        if op.startswith('j'):
            cuts.add(0x401000 + heads['start'][labels[instruction.split()[1]]][0])
        elif op == 'call':
            need(instruction == 'call kernel', 'closed direct-call population')
            cuts.add(0x402000)
    for row in kernel:
        if row['target'] is not None:
            cuts.update((row['pc'] + len(row['code']), row['target']))
        elif row['code'] == b'\xc3':
            cuts.add(row['pc'] + 1)
    cuts.add(0x403001)
    selected = a.selected_rows(program, material)
    need(len(selected) == COUNTS[program][1], 'immutable selected denominator')
    ledger, policy = material['ledger.txt'], material['policy.txt']
    p = policy.decode('ascii').splitlines()
    need(p[0] == 'LI2DISASM-POLICY 6' and p[3:8] == [
        'neighbor-victims short-only', 'neighbor-ownership inherited-t3',
        'pending-selected full-instruction-ownership', 'adjacent-pairs original-geometry-jcc-or-routed-jmp-v1',
        'adjacent-pair-budgets 2 1 2'], 'independent v6 declarations')
    s = ['LI2TOOL 1', 'original ' + sha(inputs['original']), *p[3:8], *p[8:12],
         'hook 1 4206592 1 ' + sha(b'\xc3')]
    inventory = [['LI2DISASSEMBLY-INVENTORY', '1'], ['profile', a.ROUTED.importer], *a.family(a.ROUTED),
        ['original_sha256', sha(inputs['original'])], ['ledger_sha256', sha(ledger)],
        ['complete_jump_count', str(len(selected))], ['qualification_complete', 'false'],
        ['id', 'pc', 'length', 'file_offset', 'region_pc', 'region_length', 'block_pc', 'block_length']]
    for sid, pc_text, length, offset in selected:
        pc = int(pc_text)
        owners = [role for role, (base, size) in regions.items() if base <= pc < base + size]
        need(len(owners) == 1, 'independent region ownership')
        role = owners[0]; base, size = regions[role]
        start = max(c for c in cuts if base <= c <= pc)
        end = min(c for c in cuts if pc < c <= base + size)
        s += [f'site {sid} {pc} {length} {offset} {base} {size} {base} {size} {start} {end-start} 1 observe original-decode',
              'entries ' + sid + ' complete ' + sha(ledger) + ''.join(f' {base+off}:0' for off, _ in heads[role]),
              'resumes ' + sid + ' none']
        inventory.append([sid, pc_text, length, offset, str(base), str(size), str(start), str(end-start)])
    s += p[13:]
    selection = ('\n'.join(s) + '\n').encode('ascii')
    profile = [['LI2PLANNING', '1'], ['profile', a.ROUTED.importer], *a.family(a.ROUTED),
        ['adjacent_upper', '2'], ['adjacent_lower', '1'], ['adjacent_joint', '2'],
        ['scope', 'artifact-code-regions-not-functions'], ['entries', 'all-verified-instruction-heads'],
        ['original_sha256', sha(inputs['original'])], ['ledger_sha256', sha(ledger)],
        ['policy_sha256', sha(policy)], ['selection_sha256', sha(selection)],
        ['complete_jump_count', str(len(selected))], ['qualification_complete', 'false']]
    encode = lambda rows: ('\n'.join('\t'.join(row) for row in rows) + '\n').encode('ascii')
    files = {'disassembly-inventory.tsv': encode(inventory), 'disassembly-policy.txt': policy,
             'disassembly.txt': ledger, 'planning-profile.tsv': encode(profile), 'selection.txt': selection}
    need(all(len(v) <= MIB for v in files.values()), 'full expected-text bound')
    return files


def material_inputs(ctx, a, args, captured, program):
    streams, pins = captured['streams'], captured['captured']['files']
    need(all(program + '-' + suffix in streams for suffix in
        ('as', 'ld', 'disassemble-_start', 'disassemble-kernel', 'disassemble-null_hook')), 'all original build/head captures')
    inputs = {key: ctx.read(args.capture / program / name,
        pins[str(args.capture / program / name)], MIB) for key, name in (('original', 'original'), ('object', 'subject.o'))}
    inputs.update(source=ctx.read(ctx.HERE / (program + '.S'), pins[str(ctx.HERE / (program + '.S'))], MIB),
        linker=ctx.read(ctx.HERE / 'layout.ld', pins[str(ctx.HERE / 'layout.ld')], MIB), target=streams['target']['stdout'])
    objdump = {role: streams[program + '-disassemble-' + symbol]['stdout'] for role, symbol in ctx.H.SYMBOLS.items()}
    inputs['heads'] = ctx.H.capture(program, inputs['original'], inputs['object'], objdump)
    expected_hashes = {key: sha(value) for key, value in inputs.items()}
    result = captured['material_adapter'].attempt_adjacent_routed_jmp(program, inputs, expected_hashes, upper=2, lower=1, joint=2)
    material = result['files']
    need(a.check_material(program, result, material, inputs['original'], a.ROUTED) is not None, 'independent materials unsatisfied')
    expected = expected_files(ctx, a, program, inputs, material)
    return inputs, objdump, result, material, expected


def request_and_command(ctx, captured, directory, argv, limits):
    cpu, wall, mib = limits
    request = dict(argv=argv, cwd=str(ctx.ROOT), env=captured['env'],
        stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'),
        cpu_seconds=cpu, wall_seconds=wall, file_bytes=mib * MIB)
    t = captured['tools']
    command = dict(argv=[t['timeout']['path'], '--signal=TERM', '--kill-after=10s', str(wall+10)+'s',
        t['python']['path'], '-B', t['helper']['path'], '--request', str(directory / 'request.json'),
        '--receipt', str(directory / 'receipt.json')], env=captured['env'], cwd=str(ctx.ROOT),
        parent_seconds=wall+25, cleanup_seconds=10)
    return request, command


def rooted_module(ctx):
    modules = {}
    for name, digest in ROOTED_BUILD_SOURCES.items():
        path = ctx.ROOT / CRATE / name
        raw = ctx.read(path, cap=MIB)
        need(sha(raw) == digest, 'exact rooted build source')
        module = types.ModuleType('_w01_' + name[:-3]); module.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        modules[name] = module
    return modules['rooted_build.py']


def verifier_build(ctx, a, args, captured):
    """Verify a separately frozen build. This function never invokes Cargo."""
    directory = args.verifier_build
    raw = ctx.read(directory / 'closed.json', cap=MIB)
    need(sha(raw) == args.verifier_build_sha256, 'root-frozen verifier build')
    closed = a.json_value(raw)
    commented = closed.get('schema') == 'LI2W01-VERIFIER-BUILD-3'
    rooted = commented or closed.get('schema') == 'LI2W01-VERIFIER-BUILD-2'
    keys = {'schema', 'files', 'lock_sha256', 'configuration_complete'}
    if rooted:
        keys |= {'cargo_cwd', 'configurations'}
    if commented:
        keys.add('configuration_profile')
    need(set(closed) == keys and
        closed['schema'] in ('LI2W01-VERIFIER-BUILD-1', 'LI2W01-VERIFIER-BUILD-2', 'LI2W01-VERIFIER-BUILD-3') and
        closed['configuration_complete'] is True and
        closed['lock_sha256'] == args.verifier_lock_sha256, 'separate build/lock declaration')
    module = rooted_module(ctx) if rooted else None
    if rooted:
        if commented:
            need(closed['configuration_profile'] == module.COMMENT_PROFILE, 'exact rooted comment profile')
        configurations = module.configurations(ctx, captured, profile=module.COMMENT_PROFILE) if commented else module.configurations(ctx, captured)
        need(closed['cargo_cwd'] == '/' and
            closed['configurations'] == configurations,
            'exact complete rooted Cargo configuration')
    manifest = ctx.ROOT / CRATE / 'Cargo.toml'
    binary = ctx.ROOT / 'target/release/adjacent-b2-artifact-verifier'
    argv = [captured['tools']['cargo']['path'], 'build', '--release', '--locked', '--offline',
            '--manifest-path', str(manifest), '--bin', 'adjacent-b2-artifact-verifier', '--message-format=json']
    if rooted:
        argv = module.invocation(ctx, captured)
    request, command = request_and_command(ctx, captured, directory, argv, (120,180,128))
    control = {'request.json','command.json','parent-closed.json','receipt.json','stdout.txt','stderr.txt','helper.stdout','helper.stderr'}
    sources = dict(VERIFIER_SOURCES)
    if rooted:
        control.add('planned.json')
        sources.update(ROOTED_BUILD_SOURCES)
    source = {str(ctx.ROOT / CRATE / name): digest for name, digest in sources.items()}
    need(bool(source), 'reviewed verifier source pins required')
    lock = ctx.ROOT / CRATE / 'Cargo.lock'
    required = set(source) | {str(lock),str(binary)} | {str(directory / name) for name in control}
    need(set(closed['files']) == required, 'exact separate build member closure')
    for path, pin in closed['files'].items():
        ctx.read(Path(path), pin, 128*MIB)
    need(all(closed['files'][path]['sha256'] == digest for path,digest in source.items()) and
        closed['files'][str(lock)]['sha256'] == args.verifier_lock_sha256, 'exact source and separately approved lock')
    need(a.json_value(ctx.read(directory / 'command.json', cap=MIB)) == command, 'exact verifier build command')
    code, streams = ctx.closed(directory, request)
    need(code == 0, 'verifier build closed unsuccessfully')
    builder = ctx.load(a.ROUTED.builder, a.ROUTED.builder_sha)
    builder.check_artifact(streams['stdout'], dict(product_name='adjacent-b2-artifact-verifier', product_kind='bin', product=str(binary)))
    return binary


EXPECTED_NAMES = ('disassembly-inventory.tsv', 'disassembly-policy.txt', 'disassembly.txt', 'planning-profile.tsv', 'selection.txt')


def pack_sizes(program, original, expected, product):
    need(program in PROGRAMS and set(expected)==set(EXPECTED_NAMES), 'exact transport input roster')
    leaf=lambda n: type(n) is str and 1<=len(n)<=128 and n not in ('.','..') and all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for c in n)
    need(len(product)<=256 and all(leaf(n) for n in product), 'transport product member names/count')
    need(type(original) is int and 0<=original<=MIB and
         all(type(n) is int and 0<=n<=MIB for n in expected.values()) and
         all(type(n) is int and 0<=n<=16*MIB for n in product.values()) and
         sum(product.values())<=64*MIB, 'unchanged transport body bounds')
    return original+sum(expected.values())+sum(product.values())


def pack(path, program, original, expected, product):
    body=pack_sizes(program,len(original),{n:len(b) for n,b in expected.items()},{n:len(b) for n,b in product.items()})
    files = {'input/original': original, **{'expected/'+k:v for k,v in expected.items()},
             **{'product/'+k:v for k,v in product.items()}}
    headers=[f'LI2W01-INPUT\t1\t{program}\t{len(files)}\n'.encode('ascii')]
    headers.extend(f'{name}\t{len(data)}\t{sha(data)}\n'.encode('ascii') for name,data in sorted(files.items()))
    headers.append(b'END\n')
    need(all(len(h)<=256 for h in headers) and body+sum(map(len,headers))<=TRANSPORT_BYTES, 'checked framing overhead')
    digest = hashlib.sha256()
    with path.open('xb') as stream:
        def write(data):
            need(stream.write(data)==len(data), 'complete transport write');digest.update(data)
        write(headers[0])
        for header,(_,data) in zip(headers[1:-1],sorted(files.items())):
            write(header);write(data)
        write(headers[-1])
    return digest.hexdigest()


def result_row(a, program, raw, stderr, code, candidate):
    need(code == 0 and stderr == b'', 'structural verifier refusal or stderr')
    rows = a.table(raw); heads, selected = COUNTS[program]
    need(len(rows)==10 and rows[:3]==[['LI2W01-PROGRAM','1'],['program',program],['selected',str(selected)]] and
        rows[3][0]=='images' and len(rows[3])==2 and 1<=a.uint(rows[3][1])<=32 and
        rows[4:]==[['candidate_sha256',sha(candidate)],['structural_joins_complete','true'],
        ['qualification_complete','false'],['classification_complete','false'],
        ['native_correctness_complete','false'],['performance_eligible','false']], 'exact verifier response')
    return dict(status='STRUCTURAL_JOINS_COMPLETE', expected_heads=heads, expected_selected=selected,
                candidate_sha256=sha(candidate), verifier_calls=1)


def runtime_handoff(a, raw, selection):
    """Extract only after Rust accepted these exact ledger bytes; never grants execution."""
    need(len(raw)<=16*MIB and len(selection)<=MIB, 'bounded verified handoff')
    selected={}
    for line in selection.decode('ascii').splitlines():
        f=line.split()
        if f and f[0]=='site':
            need(len(f)==14 and a.uint(f[1]) not in selected, 'handoff selected roster')
            selected[a.uint(f[1])]=(a.uint(f[2]),a.uint(f[11]))
    steps={};images={};requirements={}
    for f in a.table(raw):
        if f[0]=='step':
            need(len(f)==8, 'handoff step arity');owner,local=a.uint(f[1]),a.uint(f[2])
            need(owner in selected and local<2 and (owner,local) not in steps, 'handoff step ownership')
            steps[owner,local]=dict(logical_pc=a.uint(f[4]),physical_pc=a.uint(f[5]),routes=[])
        elif f[0]=='allocation':
            need(len(f)==6 and a.uint(f[5])==4096, 'handoff page allocation')
            step=steps[a.uint(f[1]),a.uint(f[2])];need('allocation' not in step, 'handoff unique allocation')
            step['allocation']=(a.uint(f[3]),a.uint(f[4]))
        elif f[0]=='entry-router-required':
            need(len(f)==5, 'handoff route arity')
            steps[a.uint(f[1]),a.uint(f[2])]['routes'].append((a.uint(f[3]),a.uint(f[4])))
        elif f[0]=='image':
            need(len(f)==7 and len(images)<32, 'handoff image arity/count')
            iid,owner,entry,size=map(a.uint,f[1:5])
            need(iid==len(images) and owner in selected and size>0 and len(f[5])==64 and all(c in '0123456789abcdef' for c in f[5]), 'handoff image identity')
            images[iid]=dict(image_id=iid,selected_id=owner,entry_pc=entry,bytes=size,sha256=f[5]);requirements[iid]=[]
        elif f[0]=='unmet-requirement':
            need(len(f)==4, 'handoff requirement arity')
            requirements[a.uint(f[1])].append((a.uint(f[2]),a.uint(f[3])))
    need(selected and {owner for owner,_ in steps}==set(selected) and len(steps)==len(images), 'handoff complete selected and auxiliary images')
    used=set();routes=[];out=[]
    routed_owners={owner for (owner,_),s in steps.items() if s['routes']}
    for iid,image in images.items():
        extent=(image['entry_pc']&~4095,(image['entry_pc']+image['bytes']+4095)&~4095)
        matches=[(key,s) for key,s in steps.items() if key[0]==image['selected_id'] and s.get('allocation')==extent]
        need(len(matches)==1 and matches[0][0] not in used, 'handoff unique step/image allocation association')
        (owner,local),step=matches[0];used.add((owner,local))
        chosen=step['logical_pc']==selected[owner][0]
        expected=[(1,0),(2,0),(3,0),(4,0),(7,0),(8,0)]+([(5,selected[owner][1])] if chosen else [])+([(6,0)] if owner in routed_owners else [])
        need(requirements[iid]==expected, 'handoff complete unresolved requirements')
        out.append(dict(image,step=local,logical_pc=step['logical_pc'],physical_pc=step['physical_pc'],role='selected' if chosen else 'auxiliary',
                        unresolved_requirements=[dict(code=c,hook=h) for c,h in expected],
                        live_prerequisites_not_receipts=dict(quiescent=True,sync_core=True,sigill_router=bool(step['routes']))))
        need(len(step['routes'])<=187, 'handoff route count')
        for original,target in step['routes']:
            need(image['entry_pc']<=target<image['entry_pc']+image['bytes'], 'handoff route target image')
            routes.append(dict(selected_id=owner,step=local,image_id=iid,original_pc=original,target_pc=target))
    return dict(plan_ledger_sha256=sha(raw),images=out,entry_router_required=routes,
                unresolved_global=['declared-entry-completeness-not-proven','loader-abi-cpu-unwind-cet'],
                required_routes_empty=not routes,execution_authorized=False,N01='UNRUN')


def check_saved(ctx, a, args, captured, program, saved, binary, retain):
    need(saved['status'] in ('UNRUN','FAILED','MATERIALS_REFUSED','PRODUCER_FAILED','PRODUCER_REFUSED','PRODUCER_COMPLETE_UNVERIFIED'), 'known retained producer status')
    if saved['status'] not in ('PRODUCER_REFUSED','PRODUCER_COMPLETE_UNVERIFIED'):
        return dict(status=saved['status'],expected_heads=COUNTS[program][0],expected_selected=COUNTS[program][1],
                    verifier_calls=0,original_diagnostic=saved,artifact_reason='retained producer did not supply a complete artifact')
    inputs, objdump, result, material, expected = material_inputs(ctx,a,args,captured,program)
    # Expected full manifests/wrappers are now closed; no Product facts helped.
    class FullReader(a.OutputReader):
        def read(self, relative, cap=a.FILE_BYTES, keep=0):
            return super().read(relative, cap, cap)
    need(saved['output_membership_complete'] is True and saved['output_stability']=='VERIFIED', 'saved full custody required')
    try:
        reader = FullReader(args.diagnostic / program); retain.append((program,reader,saved))
        reader.verify_retained(saved['output_directories'])
        for name,pin in saved['output_files'].items():
            observed=reader.read(name)
            need({k:observed[k] for k in ('bytes','sha256','stat')}==pin, 'saved output content/identity')
    except Exception as error:
        raise a.CustodyFailure('saved-output-custody',str(error)) from error
    need(reader.bytes('heads.txt')==inputs['heads'] and
        a.json_value(reader.bytes('input-hashes.json'))=={k:sha(v) for k,v in inputs.items()} and
        a.json_value(reader.bytes('raw-input-hashes.json'))==dict(inputs={k:sha(v) for k,v in inputs.items() if k!='heads'},objdump={k:sha(v) for k,v in objdump.items()}), 'raw capture/head binding')
    retained={k:v for k,v in result.items() if k!='files'}
    need(a.json_value(reader.bytes('materials.json'))==dict(retained,files={n:dict(bytes=len(b),sha256=sha(b)) for n,b in material.items()}), 'independent full material result')
    for name,data in material.items():
        need(reader.bytes(name)==data, 'independent material bytes')
    need(saved['producer_dispatches']==1 and saved['material_calls']==1, 'exact original attempt counts')
    argv=a.importer_arguments(captured['binary'],args.capture/program/'original',args.diagnostic/program,material)
    request,command=request_and_command(ctx,captured,args.diagnostic/program/'importer',argv,(20,30,16))
    code,streams=a.check_closed(reader,request,ctx.B.HELPER_SHA,command)
    a.check_stdout(streams['stdout']['data'],streams['stderr']['data'],code,a.ROUTED)
    declaration=a.check_product(reader,program,inputs['original'],material,code,a.ROUTED)
    need(saved['producer_exit']==code and saved['producer_candidate_complete'] is (code==0) and
        saved['selection_sha256']==declaration.get('selection_sha256') and saved['producer_roster_join'] is declaration['producer_roster_join'],
        'retained producer declarations agree with raw closure')
    reader.verify_retained(saved['output_directories'])
    if code!=0:
        need(saved['status']=='PRODUCER_REFUSED', 'preserve original producer refusal label')
        return dict(status='PRODUCER_REFUSED',expected_heads=COUNTS[program][0],expected_selected=COUNTS[program][1],
                    producer_exit=code,verifier_calls=0,original_diagnostic=saved)
    need(saved['status']=='PRODUCER_COMPLETE_UNVERIFIED' and saved['diagnostic_capture_complete'] is True,
         'no relabeling of producer failure')
    product={name:reader.bytes('importer/product/'+name,a.FILE_BYTES) for name in reader.names('importer/product')}
    directory=args.output/program;directory.mkdir(mode=0o700)
    transport=directory/'transport.bin';transport_hash=pack(transport,program,inputs['original'],expected,product)
    # The only dispatch target in W01 is this separately authenticated verifier.
    captured['stable']();reader.verify_retained(saved['output_directories'])
    attempt=directory/'verifier';attempt.mkdir(mode=0o700)
    try:
        code,streams=ctx.invoke(attempt,[str(binary),str(transport),transport_hash],captured['env'],captured['tools'])
    except Exception as error:
        raise a.CustodyFailure('verifier-closure',str(error)) from error
    try:
        need(sha(ctx.read(transport,cap=TRANSPORT_BYTES))==transport_hash, 'transport unchanged after verification')
    except Exception as error:
        raise a.CustodyFailure('transport-custody',str(error)) from error
    captured['stable']();reader.verify_retained(saved['output_directories'])
    row=result_row(a,program,streams['stdout'],streams['stderr'],code,product['candidate.elf'])
    row['runtime_handoff']=runtime_handoff(a,product['plan-ledger.tsv'],expected['selection.txt'])
    row.update(original_diagnostic=saved,transport_sha256=transport_hash,expected_files={k:dict(bytes=len(v),sha256=sha(v)) for k,v in expected.items()})
    return row


def aggregate(report):
    need(tuple(report['programs'])==PROGRAMS and (report['expected_programs'],report['expected_heads'],report['expected_selected'])==(2,187,42), 'immutable full aggregation roster')
    complete=report['configuration_complete'] is True and report['custody_complete'] is True and 'error' not in report and all(
        row['status']=='STRUCTURAL_JOINS_COMPLETE' and (row['expected_heads'],row['expected_selected'])==COUNTS[name]
        for name,row in report['programs'].items())
    report.update(W01=complete,artifact_complete=complete,independent_artifact_verified=complete,
        qualification_complete=False,classification_complete=False,native_correctness_complete=False,
        corpus_success_claimed=False,performance_eligible=False,N01='UNRUN')
    report['required_routes_empty']=complete and all(row.get('runtime_handoff',{}).get('required_routes_empty') is True for row in report['programs'].values())
    report['execution_authorized']=False
    return 0 if complete else 1


def run(args,ctx,a):
    report=dict(schema='LI2W01-SAVED-1',expected_programs=2,expected_heads=187,expected_selected=42,
        configuration_complete=False,custody_complete=False,producer_dispatches=0,expected_datasets_per_program=10,N01_program_dataset_pairs=20,N01_invocations=40,
        programs={p:dict(status='UNRUN',expected_heads=COUNTS[p][0],expected_selected=COUNTS[p][1],verifier_calls=0) for p in PROGRAMS})
    retain=[];diagnostic=None
    try:
        need(args.output.is_absolute() and args.output.is_relative_to(ctx.ROOT/'ignored') and
            not os.path.lexists(args.output) and args.output.parent.resolve(strict=True)==args.output.parent and
            not args.output.is_relative_to(args.capture) and not args.output.is_relative_to(args.diagnostic), 'new separate W01 output')
        args.output.mkdir(mode=0o700)
        captured=a.authenticate_capture(ctx,args,report,a.ROUTED)  # unchanged producer Rust/Cargo/source guard
        diagnostic=a.OutputReader(args.diagnostic)
        raw=diagnostic.bytes('closed.json');need(sha(raw)==args.diagnostic_sha256,'root-frozen D01 closure')
        saved=a.json_value(raw)
        need(saved['milestone']=='D01_FULL_ROSTER_PRODUCER_DIAGNOSTIC' and
            (saved['placement_profile'],saved['capture_profile'],saved['importer_profile']) ==
            (a.ROUTED.material,a.ROUTED.capture,a.ROUTED.importer) and
            [saved[k] for k in ('adjacent_upper','adjacent_lower','adjacent_joint')]==[2,1,2] and
            saved['aggregate_output_read_bytes_per_program']==64*MIB and saved['capture']==str(args.capture) and
            saved['capture_sha256']==args.capture_sha256 and tuple(saved['programs'])==PROGRAMS and
            (saved['expected_programs'],saved['expected_heads'],saved['expected_selected'])==(2,187,42) and
            all(saved[k] is False for k in a.FALSE_FLAGS), 'exact D01 identity and no promotion')
        need(saved['configuration_complete'] is report['configuration_complete'] and
            all(ctx.B.identity(path)==pin for path,pin in saved['first_pins'].items()), 'saved global input custody')
        if 'error' in saved:
            raise a.CustodyFailure('saved-diagnostic-global-failure',str(saved['error']))
        frozen=diagnostic.seal();binary=verifier_build(ctx,a,args,captured)
        stable=captured['stable']
        def all_stable():
            try:
                stable();diagnostic.verify_retained(frozen)
                for _,reader,row in retain:
                    reader.verify_retained(row['output_directories'])
            except Exception as error:
                raise a.CustodyFailure('W01-custody',str(error)) from error
        captured['stable']=all_stable
        for program in PROGRAMS:
            all_stable()
            try:
                report['programs'][program]=check_saved(ctx,a,args,captured,program,saved['programs'][program],binary,retain)
            except a.CustodyFailure:
                raise
            except Exception as error:
                report['programs'][program].update(status='UNSATISFIED',error=type(error).__name__,detail=str(error),original_diagnostic=saved['programs'][program])
        all_stable();report['custody_complete']=True
    except Exception as error:
        report['error']=dict(type=type(error).__name__,detail=str(error))
    except BaseException as error:
        report['error']=dict(type=type(error).__name__,detail=str(error))
        report['custody_complete']=False
        raise
    finally:
        readers=[reader for _,reader,_ in retain] + ([diagnostic] if diagnostic is not None else [])
        for reader in readers:
            try:
                reader.close()
            except BaseException as error:
                report['custody_complete']=False
                report.setdefault('close_errors',[]).append(dict(type=type(error).__name__,detail=str(error)))
                report['error']=dict(type='CustodyCloseFailure',detail='one or more retained descriptors failed to close')
        code=aggregate(report)
        if args.output.is_dir():
            ctx.B.write(args.output/'closed.json',report)
    return code


def startup_modules(ctx):
    """Authenticate new-profile modules before executing their source text."""
    required = {'startup_pins.py','startup_custody.py','startup_saved.py',
                'startup_cargo_from_root.py','startup_originals.py','startup_target_from_root.py',
                'startup_produce.py'}
    need(set(STARTUP_MODULES) == required, 'startup module profile UNBOUND')
    raw_files = {}
    for name,digest in STARTUP_MODULES.items():
        path = ctx.ROOT / CRATE / name
        raw = ctx.read(path,cap=MIB)
        need(type(digest) is str and len(digest)==64 and sha(raw)==digest, 'exact startup module source')
        raw_files[name] = raw
    modules = {}
    for name,raw in raw_files.items():
        path = ctx.ROOT / CRATE / name
        module = types.ModuleType('_w01_' + name[:-3]); module.__file__ = str(path)
        exec(compile(raw,str(path),'exec'),module.__dict__)
        modules[name] = module
    return modules


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('capture','diagnostic','verifier-build','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('capture-sha256','diagnostic-sha256','verifier-build-sha256','verifier-lock-sha256'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--startup-binding',type=Path)
    parser.add_argument('--startup-binding-sha256')
    parser.add_argument('--source-profile',type=Path)
    parser.add_argument('--source-profile-sha256')
    args=parser.parse_args();root=Path(__file__).resolve().parents[3]
    need((args.startup_binding is None) == (args.startup_binding_sha256 is None), 'paired explicit startup binding flags')
    need((args.source_profile is None) == (args.source_profile_sha256 is None) and
         (args.source_profile is None) == (args.startup_binding is None), 'startup source profile is required only with explicit startup binding')
    for name in ('capture','diagnostic','verifier_build'):
        path=getattr(args,name)
        if name=='verifier_build' and args.startup_binding is not None and not os.path.lexists(path):
            # A failed saved producer needs no verifier build. Success still
            # requires the exact complete new-profile build closure in run().
            need(path.is_absolute() and path.parent.resolve(strict=True)==path.parent and path.is_relative_to(root/'ignored'), 'canonical prospective startup verifier directory')
        else:
            need(path.is_absolute() and path.resolve(strict=True)==path and path.is_relative_to(root/'ignored'), 'canonical saved input directory')
    for name in ('capture_sha256','diagnostic_sha256','verifier_build_sha256','verifier_lock_sha256'):
        value=getattr(args,name);need(len(value)==64 and all(c in '0123456789abcdef' for c in value), 'frozen digest')
    ctx,a=context(root)
    if args.startup_binding is not None:
        path=args.startup_binding
        need(path.is_absolute() and path.resolve(strict=True)==path and path.is_relative_to(root/'ignored'), 'canonical startup binding file')
        value=args.startup_binding_sha256
        need(len(value)==64 and all(c in '0123456789abcdef' for c in value), 'frozen startup binding digest')
        modules=startup_modules(ctx)
        pins=modules['startup_pins.py'].load(ctx,args.source_profile,args.source_profile_sha256)
        return modules['startup_saved.py'].run(args,ctx,a,sys.modules[__name__],
            modules['startup_custody.py'],pins,modules['startup_originals.py'])
    return run(args,ctx,a)


if __name__=='__main__':
    raise SystemExit(main())
