"""Explicit saved-startup main joins only. No producer, build, or native dispatch.

The only possible child command is the independently authenticated verifier,
--startup, once per program. Package acceptance and execution remain separate.
"""
import hashlib
import json
import os
from pathlib import Path
import re

MIB = 1048576
PROFILE = 'elf-disassembly-null-jumps-static-exec-router-bootstrap-v1'
RUNTIME_PROFILE = 'linux-x86-64-static-exec-router-bootstrap-v1'
PROGRAMS = ('checksum', 'rle-roundtrip')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
EXPECTED = ('disassembly-inventory.tsv', 'disassembly-policy.txt', 'disassembly.txt',
            'planning-profile.tsv', 'selection.txt', 'startup-policy.txt')
MAX_MEMBERS = 279
BODY_BYTES = 198*MIB + 65536
FRAMING_BYTES = (MAX_MEMBERS+2)*256
TRANSPORT_BYTES = BODY_BYTES + FRAMING_BYTES
FALSE_FLAGS = ('W01', 'artifact_complete', 'independent_artifact_verified',
    'startup_package_joins_complete', 'qualification_complete', 'classification_complete',
    'native_correctness_complete', 'corpus_success_claimed', 'performance_eligible', 'execution_authorized')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uint(value):
    need(type(value) is str and re.fullmatch('0|[1-9][0-9]{0,19}', value) is not None, 'canonical decimal')
    n = int(value)
    need(n <= (1 << 64)-1, 'decimal overflow')
    return n


def lines(raw, cap=MIB):
    need(type(raw) is bytes and len(raw) <= cap and raw.endswith(b'\n') and
         re.fullmatch(rb'[\x20-\x7e\t\n]+', raw) is not None, 'bounded canonical ASCII/LF text')
    return raw.decode('ascii')[:-1].split('\n')


def table(raw):
    return [line.split('\t') for line in lines(raw)]


def encode(rows):
    return ('\n'.join('\t'.join(row) for row in rows) + '\n').encode('ascii')


def policy(raw, program, original, ledger, planning, custody):
    rows = lines(raw, 65536)
    need(12 <= len(rows) <= 27 and all('\t' not in row for row in rows), 'startup policy cardinality/spacing')
    def fields(index, tag, count):
        result = rows[index].split(' ')
        need(len(result) == count and result[0] == tag and all(result), 'startup policy fields/order')
        return result[1:]
    need(rows[:3] == ['LI2BOOTSTRAP-POLICY 1', 'profile '+RUNTIME_PROFILE, 'program '+program], 'startup policy profile/program')
    for index, tag, raw_input in ((3,'original',original),(4,'disassembly',ledger),(5,'planning-policy',planning)):
        need(fields(index,tag,2) == [sha(raw_input)], 'startup policy independent input identity')
    interpreter = str(custody.absolute(fields(6,'interpreter',2)[0]))
    bootstrap = str(custody.absolute(fields(7,'bootstrap',2)[0]))
    need(tuple(map(uint,fields(8,'app-stack',3))) == (0x446000,65536), 'authored file-backed application stack')
    contract = custody.digest(fields(9,'qualification-contract',2)[0])
    need(contract != '0'*64, 'named external qualification contract')
    caps = tuple(map(uint,fields(10,'startup-limits',9)))
    ceiling = (4096,4096,4097,112,16384,4096,65536,1048576)
    need(all(n <= limit for n,limit in zip(caps,ceiling)) and
         caps[0] >= len(interpreter)+1 and caps[1] >= len(bootstrap)+1 and
         caps[2] >= len(bootstrap)+2 and caps[3] == 112, 'unchanged startup resource ceilings')
    dependencies = []
    for index in range(11,len(rows)):
        path, identity = fields(index,'dependency',3)
        custody.absolute(path); custody.digest(identity)
        need(identity != '0'*64 and path != bootstrap and
             (not dependencies or dependencies[-1][0] < path), 'sorted unique dependency roster')
        dependencies.append((path,identity))
    need(1 <= len(dependencies) <= 16 and interpreter in dict(dependencies), 'interpreter dependency required')
    return dict(interpreter=interpreter,bootstrap=bootstrap,dependencies=dependencies,contract=contract,caps=caps)


def dependency_roster(policy_value, data):
    need(len(data) == len(policy_value['dependencies']), 'dependency byte roster')
    rows = []
    for (path,expected),raw in zip(policy_value['dependencies'],data):
        need(sha(raw) == expected, 'full pinned dependency bytes')
        rows.append([path,str(len(raw)),sha(raw)])
    return encode(rows)


def pack_sizes(program, original, expected, product, dependencies):
    need(program in PROGRAMS and set(expected) == set(EXPECTED), 'exact startup input roster')
    leaf = lambda n: type(n) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',n) is not None and n not in ('.','..')
    need(len(product) <= 256 and all(leaf(n) for n in product) and
         'original.elf' not in product and 'COMPLETE' not in product, 'startup product roster/count')
    bounded = lambda n,cap: type(n) is int and 0 <= n <= cap
    need(bounded(original,MIB) and all(bounded(n,65536 if name=='startup-policy.txt' else MIB) for name,n in expected.items()) and
         all(bounded(n,16*MIB) for n in product.values()) and sum(product.values()) <= 64*MIB,
         'unchanged original/expected/product bounds')
    need(1 <= len(dependencies) <= 16 and all(bounded(n,16*MIB) for n in dependencies) and
         sum(dependencies) <= 128*MIB, 'independent dependency bounds')
    body = original+sum(expected.values())+sum(product.values())+sum(dependencies)
    need(body <= BODY_BYTES and 1+len(expected)+len(product)+len(dependencies) <= MAX_MEMBERS, 'startup body/member ceiling')
    return body


def pack(path, program, original, expected, product, dependencies):
    body = pack_sizes(program,len(original),{n:len(b) for n,b in expected.items()},
                      {n:len(b) for n,b in product.items()},list(map(len,dependencies)))
    files = {'input/original': original}
    files.update(('expected/'+n,b) for n,b in expected.items())
    files.update(('product/'+n,b) for n,b in product.items())
    files.update(('dependency/%04d'%i,b) for i,b in enumerate(dependencies))
    ordered = sorted(files.items())
    headers = [('LI2W01-INPUT\t2\t%s\t%s\t%d\n'%(PROFILE,program,len(files))).encode('ascii')]
    headers += [('%s\t%d\t%s\n'%(name,len(raw),sha(raw))).encode('ascii') for name,raw in ordered]
    headers.append(b'END\n')
    need(all(len(h) <= 256 for h in headers) and sum(map(len,headers)) <= FRAMING_BYTES and
         body+sum(map(len,headers)) <= TRANSPORT_BYTES, 'separate framing byte bound')
    digest = hashlib.sha256()
    with path.open('xb') as stream:
        def write(raw):
            need(stream.write(raw) == len(raw), 'complete startup transport write')
            digest.update(raw)
        write(headers[0])
        for header,(_,raw) in zip(headers[1:-1],ordered):
            write(header); write(raw)
        write(headers[-1])
        stream.flush(); os.fsync(stream.fileno())
    return digest.hexdigest()


def result_row(program, raw, stderr, code, product, dependency_hash):
    need(code == 0 and stderr == b'', 'startup verifier raw refusal/stderr')
    rows = table(raw)
    heads, selected = COUNTS[program]
    need(len(rows) == 15 and rows[:5] == [['LI2W01-PROGRAM','2'],['profile',PROFILE],
         ['program',program],['original_heads',str(heads)],['selected',str(selected)]] and
         len(rows[5]) == 2 and rows[5][0] == 'images' and 1 <= uint(rows[5][1]) <= 32 and
         rows[6:] == [['candidate_sha256',sha(product['candidate.elf'])],
         ['catalog_sha256',sha(product['catalog.li2boot'])],['startup_policy_sha256',sha(product['startup-policy.txt'])],
         ['dependency_roster_sha256',dependency_hash],['structural_joins_complete','true'],
         ['qualification_complete','false'],['classification_complete','false'],
         ['native_correctness_complete','false'],['performance_eligible','false']], 'exact startup 15-row response')
    actual_images = sum(re.fullmatch('image-[0-9]{4}\\.bin',name) is not None for name in product)
    need(uint(rows[5][1]) == actual_images, 'verifier exact image denominator')
    return dict(status='STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE', expected_heads=heads,
        expected_selected=selected,images=actual_images,candidate_sha256=sha(product['candidate.elf']),
        catalog_sha256=sha(product['catalog.li2boot']),startup_policy_sha256=sha(product['startup-policy.txt']),
        dependency_roster_sha256=dependency_hash,verifier_calls=1)


def publication(store, a, frozen, originals, expected, policies):
    need(frozen is not None and set(frozen) == {'path','directory','files'}, 'complete actual flat publication')
    root = Path(frozen['path'])
    need(store.members(root) == frozen['directory'] and
         set(frozen['files']) == set(frozen['directory']['members']) and 'COMPLETE' in frozen['files'], 'exact retained flat membership')
    need(len(frozen['files']) <= 513 and sum(pin['bytes'] for name,pin in frozen['files'].items() if name!='COMPLETE') <= 256*MIB, 'producer outer member/byte caps')
    allowed_prefix = lambda name: any(name.startswith(p+'-') and len(name)>len(p)+1 for p in PROGRAMS)
    need(all(name == 'COMPLETE' or allowed_prefix(name) for name in frozen['files']), 'unknown/cross-prefix/failure member')
    full = {}
    for name,pin in frozen['files'].items():
        cap = MIB if name == 'COMPLETE' or name.endswith('-original.elf') else 65536 if name.endswith('-startup-policy.txt') else 16*MIB
        full[name] = store.read(root/name,cap,pin)
    prefix = [['LI2BOOTSTRAP-DIRECTORY','1'],['profile',PROFILE],
        ['checksum_original_sha256',sha(originals['checksum'])],['rle_original_sha256',sha(originals['rle-roundtrip'])],
        ['required_original_heads','187'],['required_selected_sites','42'],['candidate_complete','true'],
        ['qualification_complete','false'],['execution_authority','none']]
    marker = encode(prefix+[['file',name,str(len(raw)),sha(raw)] for name,raw in sorted(full.items()) if name!='COMPLETE'])
    need(full['COMPLETE'] == marker, 'exact actual startup COMPLETE bytes')
    result = {}
    for program in PROGRAMS:
        product = {name[len(program)+1:]:raw for name,raw in full.items() if name.startswith(program+'-')}
        need(product.pop('original.elf',None) == originals[program], 'independent original snapshot in flat output')
        images = sorted(name for name in product if re.fullmatch('image-[0-9]{4}\\.bin',name))
        need(1 <= len(images) <= 32 and images == ['image-%04d.bin'%i for i in range(len(images))], 'contiguous bounded image roster')
        required = (a.PRODUCT-{'adjacent-b2-evidence.txt'} | {a.ROUTED.evidence} | a.COMPLETE_ONLY |
                    {'startup-policy.txt','startup-profile.tsv','catalog.li2boot'} |
                    {'site-%d.diagnostics.txt'%i for i in range(1,COUNTS[program][1]+1)} | set(images))
        need(set(product) == required, 'exact complete per-program startup Product roster')
        need(len(product) <= 256 and sum(map(len,product.values())) <= 64*MIB, 'unchanged per-program Product caps')
        bundle = [['LI2BUNDLE','1'],['original_sha256',sha(originals[program])],['qualification_complete','false'],
                  ['consumer_action','RuntimeScan-while-gated-until-qualified']]
        bundle += [['file',name,str(len(raw)),sha(raw)] for name,raw in sorted(product.items()) if name!='bundle-index.tsv']
        need(product['bundle-index.tsv'] == encode(bundle), 'actual nested bundle-index, no synthesized COMPLETE')
        need(all(product[name] == data for name,data in expected[program].items()), 'independent full expected bytes')
        startup_profile = [['LI2STARTUP-PRODUCER','1'],['profile',PROFILE],['runtime_profile',RUNTIME_PROFILE],
            ['planning_profile',a.ROUTED.importer],['program',program],['original_heads',str(COUNTS[program][0])],
            ['selected_sites',str(COUNTS[program][1])],['runtime_policy_sha256',sha(product['startup-policy.txt'])],
            ['qualification_complete','false'],['execution_authority','none']]
        need(product['startup-profile.tsv'] == encode(startup_profile), 'exact additive startup profile')
        result[program] = product
    store.verify()
    need(store.members(root) == frozen['directory'], 'flat output changed during join')
    return result


def aggregate(report):
    need(tuple(report['programs']) == PROGRAMS and
         (report['expected_programs'],report['expected_heads'],report['expected_selected']) == (2,187,42), 'immutable startup aggregation roster')
    complete = (report['configuration_complete'] is True and report['custody_complete'] is True and
        report['producer']['status'] == 'PRODUCER_COMPLETE_UNVERIFIED' and 'error' not in report and all(
        row['status'] == 'STARTUP_MAIN_JOINS_COMPLETE_PENDING_PACKAGE' and
        (row['expected_heads'],row['expected_selected']) == COUNTS[p] and row['verifier_calls'] == 1
        for p,row in report['programs'].items()))
    report.update(dict.fromkeys(FALSE_FLAGS,False))
    report.update(startup_main_joins_complete=complete,N01='UNRUN',producer_dispatches=0,
        required_routes_empty=complete and all(row.get('runtime_handoff',{}).get('required_routes_empty') is True for row in report['programs'].values()))
    return 0 if complete else 1


def load_binding(store, args, custody):
    raw = store.read(args.startup_binding,MIB)
    need(sha(raw) == custody.digest(args.startup_binding_sha256), 'frozen startup binding')
    bound = custody.json_value(raw)
    need(set(bound) == {'schema','profile','plan','producer_controls','publication','failure_history','input_after'} and
         bound['schema'] == 'LI2STARTUP-SAVED-BINDING-1' and bound['profile'] == PROFILE, 'explicit new startup binding schema')
    plan_raw = store.read(bound['plan']['path'],MIB,bound['plan'])
    plan = custody.json_value(plan_raw)
    need(set(plan) == {'schema','profile','capture','source_revision','env','tools','configuration_profile',
        'configurations','producer_build','inputs','dependencies','producer_directory','output','source_profile'} and
        plan['schema'] == 'LI2STARTUP-SAVED-PLAN-1' and plan['profile'] == PROFILE, 'explicit prospective startup plan')
    need(plan['source_profile'] == dict(path=str(args.source_profile),sha256=args.source_profile_sha256), 'frozen source profile authority')
    need(plan['capture'] == dict(directory=str(args.capture),sha256=args.capture_sha256) and
         plan['producer_directory'] == str(args.diagnostic), 'frozen capture/attempt identities')
    need(set(bound['producer_controls']) == set(custody.CONTROL) and
         args.diagnostic_sha256 == bound['producer_controls']['receipt.json']['sha256'], 'startup diagnostic means exact raw producer receipt')
    for name,pin in bound['producer_controls'].items():
        need(pin['path'] == str(args.diagnostic/name), 'producer control pathname')
        store.read(pin['path'],16*MIB if name.endswith(('.txt','.stdout','.stderr')) else MIB,pin)
    need(type(bound['failure_history']) is list and len(bound['failure_history']) <= 64 and
         len({p['path'] for p in bound['failure_history']}) == len(bound['failure_history']), 'bounded retained failure history')
    history = []
    for pin in bound['failure_history']:
        raw = store.read(pin['path'],MIB,pin)
        history.append(dict(pin=pin,original=custody.json_value(raw)))
    return bound,plan,history


def verify_program(ctx, a, legacy, custody, store, captured, verifier, output_root, program,
                   original, expected, product, dependencies, dependency_hash, row, stable):
    """Exactly one authenticated verifier attempt, with no producer capability."""
    need(program in PROGRAMS and row['verifier_calls'] == 0, 'one verifier call per program')
    directory = output_root/program; directory.mkdir(mode=0o700)
    transport = directory/'transport.bin'
    transport_hash = pack(transport,program,original,expected,product,dependencies)
    transport_pin = store.pin(transport,TRANSPORT_BYTES)
    need(transport_pin['sha256'] == transport_hash, 'observed transport write identity')
    attempt = directory/'verifier'; attempt.mkdir(mode=0o700)
    stable()
    row['verifier_calls'] = 1
    argv = [str(verifier),'--startup',str(transport),transport_hash]
    try:
        ctx.invoke(attempt,argv,captured['env'],captured['tools'])
        request,command = legacy.request_and_command(ctx,captured,attempt,argv,(20,30,16))
        exit_code,streams = custody.closed(store,attempt,request,command,ctx.B.HELPER_SHA)
    except Exception as error:
        raise a.CustodyFailure('startup-verifier-closure',str(error)) from error
    stable()
    try:
        row.update(result_row(program,streams['stdout'],streams['stderr'],exit_code,product,dependency_hash))
        row['runtime_handoff'] = legacy.runtime_handoff(a,product['plan-ledger.tsv'],expected['selection.txt'])
        row['transport_sha256'] = transport_hash
        row['expected_files'] = {n:dict(bytes=len(b),sha256=sha(b)) for n,b in expected.items()}
    except Exception as error:
        row.update(status='VERIFIER_REFUSED',verifier_exit=exit_code,error=type(error).__name__,detail=str(error))
    return row



def create_output(path, store):
    """Own only a directory this invocation actually created, retaining its fd."""
    parent = store.directory(path.parent)
    output = None
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        created = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        identity = (created.st_dev, created.st_ino, created.st_mode)
        output = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        opened = os.fstat(output)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(identity == (opened.st_dev, opened.st_ino, opened.st_mode) ==
             (current.st_dev, current.st_ino, current.st_mode), 'created output directory changed')
        return output, identity
    except BaseException:
        if output is not None:
            os.close(output)
        raise
    finally:
        os.close(parent)


def write_output(path, output, identity, report):
    """Publish exclusively through the retained directory, never a replacement."""
    def retained():
        opened = os.fstat(output)
        current = os.lstat(path)
        need(path.parent.resolve(strict=True) == path.parent and
             identity == (opened.st_dev, opened.st_ino, opened.st_mode) ==
             (current.st_dev, current.st_ino, current.st_mode), 'owned output directory changed')
    retained()
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('utf-8')
    closure = os.open('closed.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=output)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(closure, raw[offset:])
            need(written > 0, 'short owned output write')
            offset += written
        os.fsync(closure)
    finally:
        os.close(closure)
    retained()
    os.fsync(output)


def run(args, ctx, a, legacy, custody, pins, originals_module):
    report = dict(schema='LI2STARTUP-SAVED-1',profile=PROFILE,expected_programs=2,expected_heads=187,expected_selected=42,
        expected_datasets_per_program=10,N01_program_dataset_pairs=20,N01_invocations=40,
        configuration_complete=False,custody_complete=False,producer=dict(status='UNRUN'),
        programs={p:dict(status='UNRUN',expected_heads=COUNTS[p][0],expected_selected=COUNTS[p][1],verifier_calls=0) for p in PROGRAMS})
    store = custody.Store(2*1024*MIB)
    output = None
    try:
        need(args.output.is_absolute() and args.output.is_relative_to(ctx.ROOT/'ignored') and
             args.output.parent.resolve(strict=True) == args.output.parent and not os.path.lexists(args.output) and
             all(not args.output.is_relative_to(p) for p in (args.capture,args.diagnostic,args.verifier_build,args.startup_binding.parent)), 'new separate startup verifier output')
        output, output_identity = create_output(args.output, store)
        bound,plan,history = load_binding(store,args,custody)
        report['retained_history'] = history
        report['original_producer_receipt'] = custody.json_value(store.read(args.diagnostic/'receipt.json',MIB))
        report['original_producer_parent'] = custody.json_value(store.read(args.diagnostic/'parent-closed.json',MIB))
        need(bound['input_after'] == plan['inputs'], 'eight before-after snapshot identities')
        copy_directory = Path(bound['plan']['path']).parent/'inputs'
        need(all(Path(pin['path']).parent == copy_directory for group in plan['inputs'].values() for pin in group.values()), 'actual eight pre-attempt copy paths')
        frozen = custody.frozen_inputs(store,plan)
        captured = dict(env=plan['env'],tools=plan['tools'])
        custody.environment(ctx,captured['env'],captured['tools'])
        current = custody.source_profile(ctx,pins,captured['env'])
        need(plan['source_revision'] == pins.SOURCE_REVISION, 'exact prospective new source profile')
        module = legacy.rooted_module(ctx)
        config = module.configurations(ctx,captured,profile=module.COMMENT_PROFILE)
        need(plan['configuration_profile'] == module.COMMENT_PROFILE and plan['configurations'] == config,
             'pre-frozen complete rooted new configuration')
        args.startup_custody = custody; args.startup_pins = pins
        original_capture = originals_module.authenticate(ctx,a,legacy,args,store,plan['capture'])
        report['original_facts_capture'] = original_capture['summary']
        # This is a new independently observed build. Historical capture/D01
        # flags remain verbatim in retained_history and are never overwritten.
        producer, producer_config = custody.build(ctx,a,legacy,pins,store,'producer',plan['producer_build'],captured)
        need(producer_config == config, 'complete observed producer build configuration')
        report['configuration_complete'] = True
        report['source_revision'] = pins.SOURCE_REVISION; report['current_revision'] = current
        need(bound['publication'] is None or bound['publication']['path'] == plan['output'], 'sole prospective output pathname')
        def stable():
            original_capture['stable']()
            store.verify()
            need(all(ctx.B.identity(path) == pin for path,pin in ctx.PINS.items()), 'retained source/tool/input identity')
            need(module.configurations(ctx,captured,profile=module.COMMENT_PROFILE) == config, 'rooted configuration changed')
            if bound['publication'] is not None:
                need(store.members(Path(plan['output'])) == bound['publication']['directory'], 'retained flat membership changed')
        argv = custody.producer_argv(producer,plan)
        request, command = legacy.request_and_command(ctx,captured,args.diagnostic,argv,(20,30,16))
        code, streams = custody.closed(store,args.diagnostic,request,command,ctx.B.HELPER_SHA)
        producer_status = 'PRODUCER_COMPLETE_UNVERIFIED' if code == 0 else 'PRODUCER_REFUSED' if code == 2 else 'PRODUCER_FAILED'
        report['producer'] = dict(status=producer_status,exit=code,producer_dispatches=1,argv=argv,
            stdout_sha256=sha(streams['stdout']),stderr_sha256=sha(streams['stderr']),control_pins=bound['producer_controls'])
        if code != 0:
            for row in report['programs'].values():
                row['status'] = producer_status
            # Even a complete-looking marker from failed fsync/publication never
            # permits verifier dispatch. Retain every observed member identity.
            report['retained_failed_publication'] = bound['publication']
            if bound['publication'] is not None:
                saved_output = bound['publication']
                need(set(saved_output['files']) == set(saved_output['directory']['members']) and
                     len(saved_output['files']) <= 513 and
                     sum(pin['bytes'] for name,pin in saved_output['files'].items() if name!='COMPLETE') <= 256*MIB, 'failed publication complete bounded custody')
                for name,pin in saved_output['files'].items():
                    store.read(Path(plan['output'])/name,MIB if name=='COMPLETE' else 16*MIB,pin)
            stable(); report['custody_complete'] = True
            return 1
        want = ('profile=%s candidate_complete=true qualification_complete=false required_programs=2 required_heads=187 required_selected=42\n'%PROFILE).encode('ascii')
        need(streams['stdout'] == want and streams['stderr'] == b'', 'exact successful producer response')
        verifier, verifier_config = custody.build(ctx,a,legacy,pins,store,'verifier',
            dict(directory=str(args.verifier_build),sha256=args.verifier_build_sha256),captured)
        need(verifier_config == config and args.verifier_lock_sha256 == pins.VERIFIER_LOCK_SHA256, 'new build configuration/lock joins')
        report['configuration_complete'] = True
        report['source_revision'] = pins.SOURCE_REVISION; report['current_revision'] = current
        expected, policies, originals = {}, {}, {}
        material_adapter = ctx.load('adjacent_routed_jmp_material.py',a.MATERIAL_SHA)
        for program in PROGRAMS:
            inputs = original_capture['inputs'][program]
            material_result = material_adapter.attempt_adjacent_routed_jmp(program,inputs,{k:sha(v) for k,v in inputs.items()},upper=2,lower=1,joint=2)
            material = material_result['files']
            need(a.check_material(program,material_result,material,inputs['original'],a.ROUTED) is not None, 'independent original materials ready')
            need(frozen[program]['original'] == inputs['original'] and frozen[program]['ledger'] == material['ledger.txt'] and
                 frozen[program]['policy'] == material['policy.txt'], 'three planning snapshots derive from independent original facts')
            originals[program] = inputs['original']
            expected[program] = legacy.expected_files(ctx,a,program,inputs,material)
            expected[program]['startup-policy.txt'] = frozen[program]['startup']
            policies[program] = policy(frozen[program]['startup'],program,inputs['original'],material['ledger.txt'],material['policy.txt'],custody)
        need(policies[PROGRAMS[0]]['bootstrap'] != policies[PROGRAMS[1]]['bootstrap'], 'distinct pre-frozen bootstrap pathnames')
        roster = {}
        for p in PROGRAMS:
            for path,h in policies[p]['dependencies']:
                need(path not in roster or roster[path] == h, 'shared dependency identity')
                roster[path] = h
        need(list(plan['dependencies']) == sorted(roster), 'complete pre-frozen union dependency roster')
        dependencies = {}
        for p in PROGRAMS:
            dependencies[p] = []
            charged = 0
            for path,h in policies[p]['dependencies']:
                pin = plan['dependencies'][path]
                need(pin['path'] == path and pin['sha256'] == h and type(pin['bytes']) is int and
                     0 <= pin['bytes'] <= 16*MIB and pin['bytes'] <= 128*MIB-charged, 'independent dependency cap/identity')
                charged += pin['bytes']
                dependencies[p].append(store.read(path,16*MIB,pin))
        products = publication(store,a,bound['publication'],originals,expected,policies)
        for program in PROGRAMS:
            stable()
            row = report['programs'][program]
            verify_program(ctx,a,legacy,custody,store,captured,verifier,args.output,program,
                originals[program],expected[program],products[program],dependencies[program],
                sha(dependency_roster(policies[program],dependencies[program])),row,stable)
        stable(); report['custody_complete'] = True
    except Exception as error:
        report['error'] = dict(type=type(error).__name__,detail=str(error))
    except BaseException as error:
        report['error'] = dict(type=type(error).__name__,detail=str(error)); report['custody_complete'] = False
        raise
    finally:
        try:
            store.close()
        except Exception as error:
            report['custody_complete'] = False
            report['error'] = dict(type='CustodyCloseFailure',detail=str(error))
        code = aggregate(report)
        if output is not None:
            try:
                write_output(args.output, output, output_identity, report)
            except Exception as error:
                report['custody_complete'] = False
                report['error'] = dict(type='OutputClosureFailure', detail=str(error))
                code = aggregate(report)
            finally:
                os.close(output)
    return code
