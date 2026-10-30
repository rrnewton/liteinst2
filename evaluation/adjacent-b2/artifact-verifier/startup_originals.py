"""Fresh authored originals only. authenticate never executes a command.

The legacy twelve-command profile builds only the target-query binary, asks its
target mode once, and assembles/links/disassembles both unchanged authored programs.
The explicit readonly-headerpad profile adds one metadata-only assembler command;
it changes neither program assembly nor the complete instruction/head roster.
No old producer, bootstrap, original program, or candidate is executed here.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import types

MIB = 1048576
SCHEMA = 'LI2STARTUP-ORIGINALS-1'
PLAN_SCHEMA = 'LI2STARTUP-ORIGINALS-PLAN-1'
PROFILE = 'startup-original-facts-rooted-v1'
READONLY_PROFILE = 'startup-original-facts-readonly-headerpad-v1'
PROGRAMS = ('checksum', 'rle-roundtrip')
CONTROL = ('request.json', 'command.json', 'parent-closed.json', 'receipt.json',
           'stdout.txt', 'stderr.txt', 'helper.stdout', 'helper.stderr')
CRATE = 'evaluation/adjacent-b2/artifact-verifier'


def need(value, detail):
    if not value:
        raise ValueError(detail)


def linker_relative(profile):
    need(profile in (PROFILE, READONLY_PROFILE), 'explicit original capture profile')
    return ('evaluation/offline-corpus/layout.ld' if profile == PROFILE else
            CRATE + '/startup_layout.ld')


def capture_profile(plan, closed):
    profile = plan['profile']
    linker_relative(profile)
    need(closed['profile'] == profile, 'same original capture profile before and after')
    return profile


def material_module(ctx, pins):
    relative = CRATE + '/startup_material.py'
    raw = ctx.read(ctx.ROOT/relative, cap=MIB)
    need(relative in pins.SOURCE_PINS and hashlib.sha256(raw).hexdigest() == pins.SOURCE_PINS[relative],
         'exact startup material source from complete frozen profile')
    module = types.ModuleType('_startup_original_material'); module.__file__ = str(ctx.ROOT/relative)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def phases(repo, directory, tools, *, profile=PROFILE):
    repo, directory = Path(repo), Path(directory)
    source = repo/'evaluation/offline-corpus'
    linker = repo/linker_relative(profile)
    phases = [dict(name='build-target', dependencies=[], limits=[120,180,128],
        argv=[tools['python']['path'],'-B',str(repo/CRATE/'startup_target_from_root.py'),
              tools['cargo']['path'],str(repo)],
        product=str(repo/'target/release/elf-exec-oracle'),product_name='elf-exec-oracle',product_kind='bin'),
        dict(name='target',dependencies=['build-target'],limits=[20,30,16],
             argv=[str(repo/'target/release/elf-exec-oracle'),'target'])]
    if profile == READONLY_PROFILE:
        phases.append(dict(name='header-pad-as',dependencies=[],limits=[60,90,128],
            argv=[tools['as']['path'],'--64',str(repo/CRATE/'startup_header_pad.S'),
                  '-o',str(directory/'header-pad.o')],outputs=[str(directory/'header-pad.o')]))
    for program in PROGRAMS:
        obj, original = directory/program/'subject.o', directory/program/'original'
        phases += [dict(name=program+'-as',dependencies=[],limits=[60,90,128],
                       argv=[tools['as']['path'],'--64',str(source/(program+'.S')),'-o',str(obj)],outputs=[str(obj)]),
                   dict(name=program+'-ld',dependencies=[program+'-as']+(['header-pad-as'] if profile == READONLY_PROFILE else []),limits=[60,90,128],
                       argv=[tools['ld']['path'],'-static','-nostdlib','--build-id=none','-z','noexecstack',
                             '-T',str(linker),str(obj)]+([str(directory/'header-pad.o')] if profile == READONLY_PROFILE else [])+['-o',str(original)],outputs=[str(original)])]
        for symbol in ('_start','kernel','null_hook'):
            phases.append(dict(name=program+'-disassemble-'+symbol,dependencies=[program+'-ld'],limits=[20,30,16],
                argv=[tools['objdump']['path'],'-d','-w','--insn-width=16','--disassemble='+symbol,str(original)]))
    need(len(phases)==(13 if profile == READONLY_PROFILE else 12), 'fixed original-facts command denominator')
    return phases


def source_inputs(ctx, pins, *, profile=PROFILE):
    # The same independently reviewed source map feeds the build and reader.
    # The freeze owner must include all source/module/manifest files before use.
    paths = {str(ctx.ROOT/relative) for relative in pins.SOURCE_PINS}
    paths |= {str(ctx.ROOT/'Cargo.lock'),str(ctx.ROOT/CRATE/'startup_originals.py'),
              str(ctx.ROOT/CRATE/'startup_target_from_root.py'),
              str(ctx.ROOT/linker_relative(profile)),*(str(ctx.HERE/(p+'.S')) for p in PROGRAMS)}
    if profile == READONLY_PROFILE:
        paths.add(str(ctx.ROOT/CRATE/'startup_header_pad.S'))
    return paths


def terminal(store, directory, code):
    expected = dict(exit=code,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=code==0)
    need(store.read(directory/'helper.stdout',16*MIB)==(json.dumps(expected)+'\n').encode(),
         'exact original-facts helper terminal response')


def authenticate(ctx, a, legacy, args, store, reference):
    """Read one new-profile closure and all raw facts; never use legacy capture."""
    custody = args.startup_custody
    pins = args.startup_pins
    directory = custody.absolute(reference['directory'])
    need(directory.is_relative_to(ctx.ROOT/'ignored'), 'private fresh original capture')
    raw = store.read(directory/'closed.json',MIB)
    need(custody.sha(raw)==custody.digest(reference['sha256']), 'original-facts closure identity')
    closed = custody.json_value(raw)
    plan = custody.json_value(store.read(directory/'planned.json',MIB,closed['planned']))
    profile = capture_profile(plan, closed)
    need(set(closed)=={'schema','profile','planned','source_revision','revision','results','files',
                       'configuration_complete','configurations','error','qualification_complete'}
         and closed['schema']==SCHEMA and closed['profile']==profile
         and closed['qualification_complete'] is False, 'new original-facts closure shape')
    need(set(plan)=={'schema','profile','source_revision','revision','env','tools','inputs','phases',
                     'configuration_profile','configurations','hardware','affinity','load_average',
                     'qualification_complete'}
         and plan['schema']==PLAN_SCHEMA and plan['profile']==profile
         and plan['qualification_complete'] is False, 'new original-facts plan shape')
    need(plan['source_revision']==closed['source_revision']==pins.SOURCE_REVISION
         and plan['revision']==closed['revision'], 'exact original-facts source revisions')
    custody.environment(ctx,plan['env'],plan['tools'])
    custody.source_profile(ctx,pins,plan['env'])
    captured = dict(env=plan['env'],tools=plan['tools'])
    rooted = legacy.rooted_module(ctx)
    configs = rooted.configurations(ctx,captured,profile=rooted.COMMENT_PROFILE)
    need(plan['configuration_profile']==rooted.COMMENT_PROFILE
         and plan['configurations']==closed['configurations']==configs
         and closed['configuration_complete'] is True, 'complete actual rooted Cargo configuration')
    expected = phases(ctx.ROOT,directory,plan['tools'],profile=profile)
    need(plan['phases']==expected and set(closed['results'])=={p['name'] for p in expected},
         'all exact original-facts phases for the explicit capture profile')
    required_inputs = source_inputs(ctx,pins,profile=profile)
    need(set(plan['inputs'])==required_inputs, 'exact original-facts source file roster')
    files = dict(plan['inputs'])
    streams = {}
    for phase in expected:
        row=closed['results'][phase['name']]
        need(set(row)=={'status','exit','error'}, 'original-facts phase outcome shape')
        need(row['status'] in ('PASS','FAILED','UNRUN'), 'original-facts outcome label')
        if row['status']=='UNRUN':
            need(row['exit'] is None, 'unrun phase cannot have exit')
            continue
        d=directory/phase['name']
        request,command=legacy.request_and_command(ctx,captured,d,phase['argv'],phase['limits'])
        code,observed=custody.closed(store,d,request,command,ctx.B.HELPER_SHA)
        terminal(store,d,code)
        need(row['exit']==code, 'original-facts exact recorded exit')
        for name in CONTROL:
            files[str(d/name)]=store.pin(d/name,128*MIB if name.endswith(('.txt','.stdout','.stderr')) else MIB)
        if row['status']=='PASS':
            need(code==0 and row['error'] is None
                 and all(closed['results'][dep]['status']=='PASS' for dep in phase['dependencies']),
                 'original-facts PASS closure/dependencies')
            if 'product' in phase:
                builder=ctx.load(a.ROUTED.builder,a.ROUTED.builder_sha)
                builder.check_artifact(observed['stdout'],phase)
                files[phase['product']]=store.pin(Path(phase['product']),128*MIB)
            else:
                need(observed['stderr']==b'', 'original-facts tool stderr')
            for path in phase.get('outputs',[]): files[path]=store.pin(Path(path),MIB)
            streams[phase['name']]=observed
    need(set(closed['files'])==set(files), 'whole original-facts retained file roster')
    for path,pin in closed['files'].items():
        store.read(Path(path),128*MIB,pin)
        need(pin==files[path], 'original-facts exact source/control/output identities')
    need(closed['error'] is None and len(streams)==len(expected), 'incomplete original-facts capture retained as failure')
    inputs={}
    for program in PROGRAMS:
        original=store.read(directory/program/'original',MIB,closed['files'][str(directory/program/'original')])
        obj=store.read(directory/program/'subject.o',MIB,closed['files'][str(directory/program/'subject.o')])
        objdump={role:streams[program+'-disassemble-'+symbol]['stdout'] for role,symbol in ctx.H.SYMBOLS.items()}
        inputs[program]=dict(original=original,object=obj,
            source=store.read(ctx.HERE/(program+'.S'),MIB,closed['files'][str(ctx.HERE/(program+'.S'))]),
            linker=store.read(ctx.ROOT/linker_relative(profile),MIB,closed['files'][str(ctx.ROOT/linker_relative(profile))]),
            target=streams['target']['stdout'],heads=ctx.H.capture(program,original,obj,objdump))
        if profile == READONLY_PROFILE:
            seed=ctx.ROOT/CRATE/'startup_header_pad.S'
            obj=directory/'header-pad.o'
            inputs[program].update(header_pad_source=store.read(seed,MIB,closed['files'][str(seed)]),
                                   header_pad_object=store.read(obj,MIB,closed['files'][str(obj)]))
    material = material_module(ctx,pins)
    def materials(program):
        return material.derive(ctx,a,profile,program,inputs[program])
    def stable():
        return custody.verify_stability(ctx,pins,store,captured,rooted,configs)
    stable()
    return dict(inputs=inputs,materials=materials,capture_profile=profile,summary=dict(schema=SCHEMA,
        profile=profile,linker=str(ctx.ROOT/linker_relative(profile)),source_revision=closed['source_revision'],
        revision=closed['revision'],phase_count=len(expected),phases_passed=len(expected),configuration_complete=True,
        configurations=configs,artifact_producer_dispatches=0,native_dispatches=0,
        qualification_complete=False,closure_sha256=reference['sha256']),stable=stable,
        stability=custody.stability_inputs(ctx,pins,store,captured,configs,rooted.COMMENT_PROFILE))
