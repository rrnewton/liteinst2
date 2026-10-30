"""Read actual completed new-profile main joins. No subprocess dispatch API."""
import hashlib
from pathlib import Path

MIB = 1048576
PROGRAMS = ('checksum', 'rle-roundtrip')


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def transport(program, original, expected, product, dependencies, startup, *, profile=None):
    """Reconstruct the complete bounded wire bytes, without creating any file."""
    profile = startup.PROFILE if profile is None else startup.checked_profile(profile)
    body = startup.pack_sizes(program,len(original),{n:len(v) for n,v in expected.items()},
        {n:len(v) for n,v in product.items()},[len(v) for v in dependencies])
    files = {'input/original':original}
    files.update(('expected/'+n,v) for n,v in expected.items())
    files.update(('product/'+n,v) for n,v in product.items())
    files.update(('dependency/%04d'%i,v) for i,v in enumerate(dependencies))
    ordered = sorted(files.items())
    header = ('LI2W01-INPUT\t2\t%s\t%s\t%d\n'%(profile,program,len(files))).encode('ascii')
    headers = [('%s\t%d\t%s\n'%(name,len(raw),sha(raw))).encode('ascii') for name,raw in ordered]
    framing = len(header)+sum(map(len,headers))+4
    need(all(len(row)<=256 for row in [header,*headers,b'END\n']) and framing<=startup.FRAMING_BYTES,
         'exact bounded startup transport framing')
    need(body+framing<=startup.TRANSPORT_BYTES,'unchanged startup transport bound')
    out = bytearray(header)
    for row,(_,raw) in zip(headers,ordered):
        out.extend(row);out.extend(raw)
    out.extend(b'END\n')
    need(len(out)==body+framing,'whole transport byte count')
    return bytes(out)


def authenticate(ctx,a,legacy,custody,pins,originals_module,startup,args,store,reference):
    """Join saved raw verifier controls and independently reconstructed inputs.

    The caller supplies exact externally frozen main-output closure identity.
    Claimed booleans are never authority; both real verifier closures must match.
    """
    directory = custody.absolute(reference['directory'])
    need(directory.is_relative_to(ctx.ROOT/'ignored'),'private completed-main capture')
    closed_raw = store.read(directory/'closed.json',MIB)
    need(sha(closed_raw)==custody.digest(reference['sha256']),'externally frozen main closure')
    closed = custody.json_value(closed_raw)
    bound,plan,history = startup.load_binding(store,args,custody)
    profile = plan['profile']
    need(bound['input_after']==plan['inputs'],'all eight input after-identities')
    copies = Path(bound['plan']['path']).parent/'inputs'
    need(all(Path(pin['path']).parent==copies for group in plan['inputs'].values() for pin in group.values()),
         'eight actual pre-attempt copies')
    frozen = custody.frozen_inputs(store,plan)
    captured = dict(env=plan['env'],tools=plan['tools'])
    custody.environment(ctx,captured['env'],captured['tools'])
    custody.source_profile(ctx,pins,captured['env'])
    need(plan['source_revision']==pins.SOURCE_REVISION,'main source revision')
    rooted = legacy.rooted_module(ctx)
    configs = rooted.configurations(ctx,captured,profile=rooted.COMMENT_PROFILE)
    need(plan['configuration_profile']==rooted.COMMENT_PROFILE and plan['configurations']==configs,
         'main rooted build configuration')
    args.startup_custody=custody;args.startup_pins=pins
    facts = originals_module.authenticate(ctx,a,legacy,args,store,plan['capture'])
    custody.join_stability(facts['stability'],ctx,pins,store,captured,configs,rooted.COMMENT_PROFILE)
    producer,pc = custody.build(ctx,a,legacy,pins,store,'producer',plan['producer_build'],captured)
    verifier,vc = custody.build(ctx,a,legacy,pins,store,'verifier',
        dict(directory=str(args.verifier_build),sha256=args.verifier_build_sha256),captured)
    need(pc==vc==configs and args.verifier_lock_sha256==pins.VERIFIER_LOCK_SHA256,'separate actual producer/verifier builds')
    argv = custody.producer_argv(producer,plan)
    request,command = legacy.request_and_command(ctx,captured,args.diagnostic,argv,(20,30,16))
    code,streams = custody.closed(store,args.diagnostic,request,command,ctx.B.HELPER_SHA)
    want = ('profile=%s candidate_complete=true qualification_complete=false required_programs=2 required_heads=187 required_selected=42\n'%profile).encode('ascii')
    need(code==0 and streams['stdout']==want and streams['stderr']==b'','exact successful full producer raw closure')
    need(bound['publication'] is not None and bound['publication']['path']==plan['output'],
         'only prospective producer publication')
    originals,expected,policies = {},{},{}
    for program in PROGRAMS:
        inputs = facts['inputs'][program]
        result = facts['materials'](program)
        material = result['files']
        need(result['status']=='MATERIALS_READY','full unchanged material roster')
        need(frozen[program]['original']==inputs['original'] and frozen[program]['ledger']==material['ledger.txt']
             and frozen[program]['policy']==material['policy.txt'],'independent original/planning snapshots')
        originals[program]=inputs['original']
        expected[program]=legacy.expected_files(ctx,a,program,inputs,material)
        expected[program]['startup-policy.txt']=frozen[program]['startup']
        policies[program]=startup.policy(frozen[program]['startup'],program,inputs['original'],material['ledger.txt'],material['policy.txt'],custody,profile=profile)
    need(policies[PROGRAMS[0]]['bootstrap']!=policies[PROGRAMS[1]]['bootstrap'],'distinct frozen bootstrap destinations')
    roster = {}
    for policy in policies.values():
        for path,h in policy['dependencies']:
            need(path not in roster or roster[path]==h,'consistent dependency union')
            roster[path]=h
    need(list(plan['dependencies'])==sorted(roster),'exact dependency union')
    dependencies = {}
    for program in PROGRAMS:
        rows=[];charged=0
        for path,h in policies[program]['dependencies']:
            pin=plan['dependencies'][path]
            need(pin['path']==path and pin['sha256']==h and type(pin['bytes']) is int
                 and 0<=pin['bytes']<=16*MIB and pin['bytes']<=128*MIB-charged,'unchanged dependency identity/bound')
            charged+=pin['bytes'];rows.append(store.read(path,16*MIB,pin))
        dependencies[program]=rows
    products = startup.publication(store,a,bound['publication'],originals,expected,policies,profile=profile)
    need(closed['schema']=='LI2STARTUP-SAVED-1' and closed['profile']==profile
         and closed['source_revision']==pins.SOURCE_REVISION and closed['configuration_complete'] is True
         and closed['custody_complete'] is True and 'error' not in closed,'completed main capture shape')
    need(all(closed[key] is False for key in startup.FALSE_FLAGS) and closed['N01']=='UNRUN'
         and closed['producer_dispatches']==0,'main facts cannot claim final admission or new producer calls')
    need(closed['expected_programs']==2 and closed['expected_heads']==187 and closed['expected_selected']==42
         and closed['expected_datasets_per_program']==10 and closed['N01_program_dataset_pairs']==20
         and closed['N01_invocations']==40 and tuple(closed['programs'])==PROGRAMS,'unchanged complete population')
    joined={}
    for program in PROGRAMS:
        product=products[program]
        wire=transport(program,originals[program],expected[program],product,dependencies[program],startup,profile=profile)
        transport_path=directory/program/'transport.bin'
        need(store.read(transport_path,startup.TRANSPORT_BYTES)==wire,'actual full independent verifier transport bytes')
        wire_sha=sha(wire)
        attempt=directory/program/'verifier'
        argv=[str(verifier),startup.verifier_flag(profile),str(transport_path),wire_sha]
        request,command=legacy.request_and_command(ctx,captured,attempt,argv,(20,30,16))
        code,streams=custody.closed(store,attempt,request,command,ctx.B.HELPER_SHA)
        dependency_sha=sha(startup.dependency_roster(policies[program],dependencies[program]))
        row=startup.result_row(program,streams['stdout'],streams['stderr'],code,product,dependency_sha,profile=profile)
        handoff=legacy.runtime_handoff(a,product['plan-ledger.tsv'],expected[program]['selection.txt'])
        recorded=closed['programs'][program]
        need(all(recorded.get(k)==v for k,v in row.items()) and recorded['runtime_handoff']==handoff
             and recorded['transport_sha256']==wire_sha and recorded['expected_files']==
             {n:dict(bytes=len(v),sha256=sha(v)) for n,v in expected[program].items()},'actual main result/transport/handoff join')
        joined[program]=dict(row=row,policy=policies[program],product=product,original=originals[program],
            catalog_pin=bound['publication']['files'][program+'-catalog.li2boot'],
            main_pin=bound['publication']['files'][program+'-candidate.elf'],transport_pin=store.pin(transport_path,startup.TRANSPORT_BYTES))
    def stable():
        custody.join_stability(facts['stability'],ctx,pins,store,captured,configs,rooted.COMMENT_PROFILE)
        # Same Store/source/config predicates, checked afresh by the original
        # callback. No producer, verifier, write or external dispatch intervenes.
        revision = facts['stable']()
        need(store.members(Path(plan['output']))==bound['publication']['directory'],'completed publication drift')
        return revision
    stable()
    return dict(programs=joined,plan=plan,captured=captured,configurations=configs,history=history,
        reference=reference,stable=stable,stability=facts['stability'])
