#!/usr/bin/env python3
"""Reproducible six-subject feasibility diagnostic. No qualification or speedup credit.

Build two fresh release bridges from the exact baseline tree and the reviewed
hint candidate. Build one fresh shared decoder archive and retain every attempt,
including timeout/CPU kills. Never import an
owner reader to synthesize protected observations for the release-only fixture.
"""
import argparse, csv, hashlib, importlib.util, io, json, os, re, shlex
import subprocess, sys, types
from pathlib import Path
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCRIPT = 'evaluation/inprocess/linked_hint_experiment.py'
BASELINE = 'a005a22fb174768f5822c57789a21a830efbcf1c'
UNCHANGED_FIXTURE = {
    'tools/page-entry/selected/tests/linked_epoch_reuse_app/'+name
    for name in ('build.sh','main.c','pure.c','pure.ld','machine.S','app.h','read.py')} | {
    'tools/page-entry/selected/tests/linked_epoch_app/launch.py'}
EXPECTED = {'tools/page-entry/selected/lifecycle_loader.c': {'bytes': 48238, 'sha256': 'aaee0fb94c8cf00240732138f057e781d584e08aa5e8778695a672e493c4b01a'}, 'tools/page-entry/selected/linked_controller.inc': {'bytes': 53142, 'sha256': '13b2eafc1b30551785d5df2b53bb73d3e9fc387015cfbb94ceaaf2e61f54a017'}, 'tools/page-entry/selected/linked_native_hint.h': {'bytes': 2308, 'sha256': '132be173a2db3a87a975712f352c0a1860ef816abc4e83f5196b68017de82149'}, 'tools/page-entry/selected/linked_native_hint.inc': {'bytes': 8649, 'sha256': '07fba0c98d4710e3592fab534443fb1dfc79a5c3c7b169bb2189f13ea8d149ea'}, 'tools/page-entry/selected/native_pair_controller.inc': {'bytes': 2296, 'sha256': '28ab4a43648cc4bbdf9245b18f235a7e24ea84f431da95ec11e7d0cd13a2a951'}, 'tools/page-entry/selected/native_pair_lifecycle.inc': {'bytes': 16405, 'sha256': 'dbbe727d688559b4ed02ad93a2a6a6adeaebd30791207003a80b0d2144828b77'}, 'tools/page-entry/selected/linked_epoch_binding.py': {'bytes': 3026, 'sha256': '73cec3f2ea6906edbdd9adecbcd6d4df16d1b2695f3ed6e881ebaeffa8eb087e'}, 'evaluation/inprocess/linked_epoch_build.py': {'bytes': 16696, 'sha256': '9a28416d97136a53fee4e8740ba430376ce61fb10485fd8d4e227aa2935b6d6b'}, 'tools/page-entry/selected/build-linked-epoch-native-hint.sh': {'bytes': 3214, 'sha256': '35c9ea90f467bcf5b2a06811ec9ef68d29f57c3a65d7a142c66e175dc9687197'}}
PROGRAM = [30, 512 << 20, 16 << 20, 60]
SHORT = [5, 512 << 20, 16 << 20, 15]
ORDER = ('baseline-ls', 'hint-ls', 'hint-true', 'baseline-true',
         'native-reuse65', 'hint-reuse65')
H = lambda b: hashlib.sha256(b).hexdigest()
D = lambda value: H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())


def need(ok, why):
    if not ok:
        raise ValueError(why)


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=H(data))


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args],
                                   env=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'),
                                   timeout=15)


def git_bytes(revision, paths):
    """One bounded read-only Git batch, retaining exact complete blob bytes."""
    paths=sorted(paths)
    request=''.join(revision+':'+p+'\n' for p in paths).encode()
    data=subprocess.check_output(['/usr/bin/git','-C',str(ROOT),'cat-file','--batch'],
        input=request,env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=15)
    need(len(data)<=96<<20,'bounded source snapshot')
    cursor=0;result={}
    for path in paths:
        end=data.index(b'\n',cursor);header=data[cursor:end].split()
        need(len(header)==3 and header[1]==b'blob','actual complete committed source blob')
        size=int(header[2]);cursor=end+1
        need(size<=len(data)-cursor-1 and data[cursor+size:cursor+size+1]==b'\n','whole Git blob boundary')
        result[path]=data[cursor:cursor+size];cursor+=size+1
    need(cursor==len(data),'no unconsumed Git source output')
    return result


def source_paths(revision):
    paths=git('ls-tree','-r','--name-only',revision,'--','tools/page-entry',
              'evaluation/inprocess','evaluation/admission','evaluation/precontext/verify.py').decode().splitlines()
    code={p for p in paths if (p.endswith('.py') and not p.startswith('evaluation/inprocess/results/')) or
          (p.endswith('.json') and str(Path(p).parent) in ('evaluation/inprocess','evaluation/admission'))}
    compile_sources={p for p in paths if p.startswith('tools/page-entry/') and
        ((str(Path(p).parent) in ('tools/page-entry','tools/page-entry/selected') and
          Path(p).suffix in ('.c','.h','.inc','.S','.sh','.py')) or
         p.startswith('tools/page-entry/selected/decoder/') and Path(p).suffix in ('.rs','.toml','.lock'))}
    return code,compile_sources


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def counters(stderr, hint):
    """Canonical raw numeric extraction only, not a release acceptance gate."""
    def pairs(items):
        need(len(items) == len(dict(items)), 'no duplicate terminal keys')
        return dict(items)
    result = {}
    for label in ('LI2_LINKED_EPOCH', 'LI2_LINKED_NATIVE_HINT', 'LI2_MAPS_VIEW', 'LI2_NATIVE'):
        prefix = (label + ' ').encode()
        lines = [x for x in stderr.splitlines() if x.startswith(prefix)]
        if label == 'LI2_LINKED_NATIVE_HINT' and not hint:
            need(not lines, 'baseline must not emit hint counters')
            continue
        need(len(lines) == 1 and len(lines[0]) <= 4096, 'one complete ' + label)
        value = json.loads(lines[0][len(prefix):], object_pairs_hook=pairs)
        need(type(value) is dict and value and all(type(x) is int and 0 <= x < 1 << 64
             or type(x) is list and all(type(y) is int and 0 <= y < 1 << 64 for y in x)
             for x in value.values()), 'unsigned actual terminal values')
        need(prefix + json.dumps(value, separators=(',', ':'), allow_nan=False).encode() == lines[0],
             'canonical whole numeric terminal row')
        result[label] = value
    native=result['LI2_NATIVE']
    need(native.get('version')==1 and native.get('status')==native.get('failure_code')==0,
         'observed exit-zero native terminal outcome')
    linked = result['LI2_LINKED_EPOCH']
    need(linked.get('version') == 1 and linked.get('status') == 0 and
         linked.get('failure_code') == linked.get('first_error') == 0,
         'observed exit-zero linked terminal outcome')
    need(type(linked.get('signals')) is list and len(linked['signals']) == 5 and
         type(linked.get('refusals')) is list and len(linked['refusals']) == 4,
         'actual five event buckets and four refusal classes')
    need(('graph_refaults' in linked) is hint, 'distinct actual hint report domain')
    if hint:
        row=result['LI2_LINKED_NATIVE_HINT']
        need(row.get('version')==1 and row.get('status')==row.get('failure_code')==row.get('errors')==0,
             'observed exit-zero hint terminal outcome')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline-revision', required=True)
    parser.add_argument('--candidate-revision', required=True)
    a = parser.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1,
         'assertions and exactly one externally reserved CPU')
    need(Path(__file__).resolve()==ROOT/SCRIPT and a.baseline_revision==BASELINE and
         re.fullmatch('[0-9a-f]{40}',a.candidate_revision) is not None and
         git('rev-parse','HEAD').decode().strip()==a.candidate_revision,
         'canonical committed script and exact baseline/candidate revisions')
    need(git('diff','--name-only',a.candidate_revision,'--','tools/page-entry',
             'evaluation/inprocess','evaluation/admission','evaluation/precontext/verify.py')==b'',
         'no tracked code/data edits against exact candidate commit')
    code,compiled=source_paths(a.candidate_revision)
    _,base_compiled=source_paths(a.baseline_revision)
    actual=git_bytes(a.candidate_revision,code|compiled|UNCHANGED_FIXTURE)
    baseline=git_bytes(a.baseline_revision,base_compiled|UNCHANGED_FIXTURE)
    facts=lambda rows:{p:dict(bytes=len(b),sha256=H(b)) for p,b in rows.items()}
    current=facts(actual);before=facts(baseline)
    changed={p for p in compiled|base_compiled if current.get(p)!=before.get(p)}
    need(changed=={p for p in EXPECTED if p.startswith('tools/page-entry/')},
         'exact reviewed source/build delta between committed snapshots')
    need(all(current.get(p)==v for p,v in EXPECTED.items()),'all nine exact reviewed runtime/build leaves')
    need(all(actual[p]==baseline[p] and (ROOT/p).read_bytes()==actual[p] for p in UNCHANGED_FIXTURE),
         'all eight actual reuse65 workload/reader/launcher sources equal whole baseline Git bytes')
    # Validate all possible local Python/import-time data inputs before importing
    # any repository module. The collector itself is joined to this actual Git
    # commit; no ignored source packet supplies executable code.
    for path in current:
        need(fact(ROOT/path)==current[path],'exact committed local code/data/source: '+path)
    need((ROOT/SCRIPT).read_bytes()==actual[SCRIPT],'whole actual committed collector')
    manifest=dict(driver=current[SCRIPT],baseline_revision=a.baseline_revision,
        candidate_revision=a.candidate_revision,code={p:current[p] for p in code},
        candidate_source=EXPECTED,unchanged_fixture={p:current[p] for p in sorted(UNCHANGED_FIXTURE)},
        snapshots=dict(baseline={p:before[p] for p in base_compiled},hint={p:current[p] for p in compiled}))
    out = a.output.resolve()
    out.relative_to(ROOT / 'target/page-region-next')
    out.mkdir(mode=0o700)
    cpu = next(iter(os.sched_getaffinity(0)))
    sys.path[:0] = [str(ROOT / 'evaluation/inprocess'), str(ROOT / 'tools/page-entry')]
    from page_selected import ENV, save
    from page_selected_process import invoke
    from page_selected_generic_build import Build, PROFILES
    from page_selected_oneshot_build import before_default
    from page_native_pair_performance import program_invoke
    from page_selected_register_time_build import recipe, expand, headers, bridge_check
    import page_native_pair_performance as pair
    import scalar_span_trace_build as span_build
    import linked_epoch as finite
    import namespace
    from run import hardware
    r = dict(schema=1, scope='UNQUALIFIED_NATIVE_HINT_FEASIBILITY_ONLY',
        qualification_credit=False, timing_credit=False, aggregate_credit=False,
        source_revision=a.candidate_revision, baseline_revision=manifest['baseline_revision'],
        candidate_source=manifest['candidate_source'], cpu=cpu, hardware=hardware(cpu),
        bounds=dict(PROFILES,metadata=PROGRAM,build_metadata=PROFILES['metadata'],
                    program=PROGRAM,release_build=PROGRAM,finite=SHORT,seed=SHORT),
        commands=[], cases=[dict(name=x, status='not_run', qualification_credit=False) for x in ORDER],
        inputs={}, artifacts={}, aliases={}, namespace_aliases={}, error=None,
        final_errors=[], source_unchanged=False, cleanup_complete=False,
        seed_prerequisite=dict(status='unexecuted', planned=1, launched=False,
                               expected_exit=0, bounds=SHORT))

    def pin(path):
        alias = Path(os.path.abspath(path)); path = alias.resolve(strict=True)
        value = fact(path)
        need(str(alias) not in r['aliases'] or r['aliases'][str(alias)] == str(path), 'stable input alias')
        need(str(path) not in r['inputs'] or r['inputs'][str(path)] == value, 'stable input bytes')
        r['aliases'][str(alias)] = str(path); r['inputs'][str(path)] = value
        return path

    def binary(path):
        path = pin(path); value = dict(fact(path), mode=path.stat().st_mode & 0o7777)
        need(str(path) not in r['artifacts'] or r['artifacts'][str(path)] == value, 'stable artifact')
        r['artifacts'][str(path)] = value
        return path

    def imports():
        # Include dynamically loaded modules referenced by module objects, not
        # just sys.modules: checks.admission is loaded through exec_module().
        queue = [v for v in sys.modules.values() if isinstance(v, types.ModuleType)]
        seen = set()
        while queue:
            module = queue.pop()
            if id(module) in seen: continue
            seen.add(id(module)); need(len(seen) <= 8192, 'bounded module closure')
            queue.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))
            p = getattr(module, '__file__', None)
            if not p or not Path(p).is_file(): continue
            p = Path(p).resolve()
            if p == ROOT / SCRIPT:
                need(fact(p) == manifest['driver'], 'executed diagnostic identity')
                pin(p)
                continue
            if p.is_relative_to(ROOT):
                rel = str(p.relative_to(ROOT))
                need(rel in manifest['code'] and fact(p) == manifest['code'][rel],
                     'actual executed local module is in baseline closure: ' + rel)
            pin(p)

    def stable():
        imports()
        need(all(Path(k).resolve(strict=True) == Path(v) for k,v in r['aliases'].items()), 'all aliases unchanged')
        need(all(fact(p) == v for p,v in r['inputs'].items()), 'whole input byte closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o7777) == v
                 for p,v in r['artifacts'].items()), 'whole artifact byte/mode closure')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p,value in
                 r['namespace_aliases'].items()), 'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False, step=False):
        stable(); need(name not in [x['name'] for x in r['commands']], 'unique retained command')
        subject = name in ORDER
        row = dict(name=name, argv=list(map(str,argv)), profile=profile,
            bounds=r['bounds'][profile], expected_exit=expected, capture_limit=16 << 20,
            environment=dict(ENV if env is None else env))
        r['commands'].append(row)
        try:
            stdout, stderr = (program_invoke if subject else invoke)(row,out,cpu,record=record,step=step)
        finally:
            for value in row.get('captures',{}).values(): binary(out / value['file'])
            save(out / 'receipt.json', r)
        need(type(row['exit']) is int and (expected is None or row['exit'] == expected),
             'actual required command outcome: ' + name)
        return row, stdout, stderr

    def attempt(case, argv, validate, *, record=False):
        case['status'] = 'failed'
        start = len(r['commands'])
        try:
            row, stdout, stderr = run(case['name'], argv, profile='program', expected=None,
                                      env=ENV if 'reuse65' in case['name'] else pair.PROGRAM_ENV,
                                      record=record)
            need(row['exit'] == 0, 'actual diagnostic subject must exit zero')
            validate(row, stdout, stderr)
            case['status'] = 'observed_unqualified'
        except Exception as error:
            case['error'] = type(error).__name__ + ': ' + str(error)
            actual = r['commands'][start:]
            need(len(actual) == 1 and actual[0]['name'] == case['name'] and
                 actual[0].get('reaped') is True and actual[0].get('cleanup_errors') == [] and
                 all(x.get('closed') is True for x in actual[0].get('descriptors',[])),
                 'continue only after sole actual attempt is fully reaped and closed')
        finally:
            if len(r['commands']) > start:
                row = r['commands'][start]
                case.update({k:row.get(k) for k in ('pid','exit','process_ns','duration_ns','timed_out','reaped')})
                case['captures'] = row.get('captures',{})
            save(out / 'receipt.json',r)
            print(json.dumps(dict(name=case['name'],status=case['status'],exit=case.get('exit'))),flush=True)

    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,r['aliases'],run,r)
        return run(name,argv,profile='build_metadata' if profile=='metadata' else profile,
                   env=env,expected=expected)

    builder=Build(r,out,pin,binary,build_run,extra_decoder_sources=('region.rs',),
                  scalar_span=True,linked_epoch=True)
    try:
        pin(ROOT/SCRIPT)
        save(out/'source-manifest.json',manifest);binary(out/'source-manifest.json')
        for path in manifest['code']: pin(ROOT/path)
        for path in UNCHANGED_FIXTURE: pin(ROOT/path)
        products=builder.prepare()
        need(builder.decoder_features==('scalar-region','scalar-span','linked-epoch'),
             'one fresh exact linked-epoch decoder feature closure')
        archive=binary(products['archive']);tools=builder.tools
        r['archive']=fact(archive)
        bridges={};compiler_commands={};r['builds']={}
        for lane in ('baseline','hint'):
            directory=out/lane;directory.mkdir(); selected=directory/'tools/page-entry/selected'
            snapshot={p:baseline[p] for p in base_compiled} if lane=='baseline' else {p:actual[p] for p in compiled}
            for path,data in snapshot.items():
                target=directory/path;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(data);pin(target)
            release=directory/'release';release.mkdir()
            def labelled(name,*args,**kwargs): return run(lane+'-'+name,*args,**kwargs)
            labelled('binding',[tools['python'],'-B',selected/'linked_epoch_binding.py',selected,archive,release,
                                *(['native-hint'] if lane=='hint' else [])])
            for p in release.iterdir(): binary(p)
            recipe_path=selected/('build-linked-epoch-native-hint.sh' if lane=='hint' else 'build-linked-epoch.sh')
            rows=recipe(recipe_path,'"$cc_bin"')
            need(len(rows)==1,'one exact source-owned compiler command')
            argv=expand(rows[0],{'$cc_bin':tools['cc'],'$selected_dir':selected,
                '$parent_dir':selected.parent,'$archive':archive,'$output':release})
            need(not any('CAPTURE' in x for x in argv),'release-only; no incompatible protected capture')
            compiler_commands[lane]=argv
            if lane=='hint':
                need([x.replace(str(directory),str(out/'baseline')) for x in argv
                      if x!='-DLI2_LINKED_NATIVE_HINT=1']==compiler_commands['baseline'],
                     'only hint macro and private source/output paths differ in compiler argv')
            state=r['builds'][lane]=dict(argv=argv,revision=a.baseline_revision if lane=='baseline' else a.candidate_revision)
            binding=json.loads((release/'linked_epoch_binding.json').read_bytes())
            need(binding['archive']==fact(archive),'binding to actual fresh retained archive')
            binder=__import__('ast').parse((selected/'linked_epoch_binding.py').read_bytes())
            names={n.targets[0].id:__import__('ast').literal_eval(n.value) for n in binder.body
                   if isinstance(n,__import__('ast').Assign) and isinstance(n.targets[0],__import__('ast').Name)
                   and n.targets[0].id in ('LEAVES','HINT_LEAVES')}
            paths=names['LEAVES']+(names['HINT_LEAVES'] if lane=='hint' else ())
            values=[dict(path=p,**fact(selected/p)) for p in paths]
            policy=H(json.dumps(values,sort_keys=True,separators=(',',':')).encode())
            literal=lambda x:'{'+','.join('0x'+x[i:i+2] for i in range(0,64,2))+'}'
            header=('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
                '#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(fact(archive)['sha256'])+
                '\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
            need((release/'linked_epoch_config.h').read_bytes()==header and binding==dict(version=1,
                 archive=fact(archive),policy_sha256=policy,sources=values,header_sha256=H(header)),
                 'whole independent archive/hint policy/header derivation')
            state['binding']=binding
            units=[x for x in argv if x.endswith(('.c','.S'))]
            need(len(units)==21,'exact unchanged21-TU linked recipe')
            headers(lane+'-headers',argv,units,archive,builder,pin,r['aliases'],run,state)
            for name in ('linked_native_hint.h','linked_native_hint.inc'):
                need((str(selected/name) in state['headers'])==(lane=='hint'),'actual compiler sees hint iff enabled')
            labelled('link',argv,profile='release_build',env=builder.environment)
            bridge=binary(argv[-1]);state['bridge']=fact(bridge);state['elf']=bridge_check(bridge)
            _,stdout,stderr=labelled('undefined',[tools['nm'],'-u',bridge],profile='inspect')
            need(stdout==stderr==b'','no unresolved release imports')
            bridges[lane]=bridge
        # The actual header is identical in both snapshots. The mandatory
        # unchanged oracle uses that exact header, not a substituted byte model.
        for lane in ('baseline','hint'):
            need(fact(out/lane/'tools/page-entry/selected/span_fast_bytes.h')==fact(ROOT/'tools/page-entry/selected/span_fast_bytes.h'), 'same actual oracle header')
        r['fast_byte_build']={}
        span_build.fast_bytes(builder,out,pin,binary,r['aliases'],run,r['fast_byte_build'])
        (out/'external-inputs').mkdir(); states={}
        for lane in ('baseline','hint'):
            for kind,path,args in (('ls','/bin/ls',['-d','.']),('true','/bin/true',[])):
                states[lane,kind]=pair.prepare_workload(lane+'-'+kind,path,args,bridges[lane],builder,out,pin,binary,run,r,namespace)
        for key in ('system_inputs','namespace_plans','external_inputs'):
            for kind in ('ls','true'): need(r[key]['baseline-'+kind]==r[key]['hint-'+kind],'identical program/interpreter/dependency inputs')
        for case in r['cases'][:4]:
            lane,kind=case['name'].split('-'); state=states[lane,kind]; ns=out/(case['name']+'-namespace')
            argv=[tools['python'],'-B',state['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
                  '--namespace',ns,state['carrier'],state['original'],'--',*state['argv']]
            def validate(row,stdout,stderr):
                need(stdout==(b'.\n' if kind=='ls' else b''),'exact full real-program stdout')
                pair.namespace_join(state,ns,binary,r,namespace)
                case['raw_counters']=counters(stderr,lane=='hint')
            attempt(case,argv,validate)
        # Fresh unchanged application, seed, native-policy and actual native
        # reference on this CPU. No existing owner predicate is relaxed/called.
        fixture=ROOT/'tools/page-entry/selected/tests/linked_epoch_reuse_app'
        appdir=out/'reuse65';appdir.mkdir();appstate={}
        def app_run(name,*args,**kwargs):return run('reuse-'+name,*args,**kwargs)
        original=finite.compile_subject(builder,appdir,pin,binary,app_run,appstate,fixture)
        # Keep the original reader_support body but load only its app reader:
        # policy source remains the exact unchanged original full-page policy.
        reader=load('hint_diagnostic_reuse_app',pin(fixture/'read.py'))
        import ctypes
        policy=appdir/'native-policy.so';unit=pin(ROOT/'tools/page-entry/selected/native_policy.c')
        pargv=[tools['cc'],'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared',unit,'-o',policy]
        _,po,pe=app_run('policy-headers',[tools['cc'],'-M','-MT','li2_policy',unit])
        need(not pe and po.startswith(b'li2_policy: '),'whole actual policy headers')
        for x in shlex.split(po.decode().replace('\\\n',' ').split(':',1)[1]):pin(x)
        app_run('policy-link',pargv,profile='release_build');binary(policy)
        lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
        layout=reader.elf(original.read_bytes(),lambda data:lib.li2_native_policy(data,len(data)))
        seed=finite.seed_prerequisite(builder,appdir,pin,binary,run,r)
        interp,roots,objects,description,images,raws,carrier=finite.prepare_inputs(original,bridges['hint'],builder,appdir,pin,binary,app_run,appstate)
        r['reuse65_build']=appstate; observations={}
        for case in r['cases'][4:]:
            role='native' if case['name'].startswith('native') else 'gated';directory=appdir/case['name'];directory.mkdir()
            argv=[tools['python'],'-B',ROOT/'tools/page-entry/selected/tests/linked_epoch_app/launch.py',
                  '--root',ROOT,'--role',role,'--mode','6','--control','0','--refault-control','0',
                  '--original',original,'--preparation',directory/'preparation.json']
            for p in roots:argv+=['--library-root',p]
            if role=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
            def validate(row,stdout,stderr):
                finite.preparation(dict(lane=role,mode=6,control=0,refault_control=0),row,directory,
                    original,roots,objects,description,carrier,out,binary,r)
                result=reader.read(stdout,6,role=='native',row['exit'],layout,row['pid'],cpu,seed)
                need(len(result['observations'])==65,'all65 actual unchanged invocations')
                observations[role]=result;case['application_invocations']=65
                if role=='native':need(stderr==b'','native reference stderr empty')
                else:
                    need(row['captures']['record']['bytes']==0,'release cannot fabricate protected owner wire')
                    case['raw_counters']=counters(stderr,True)
                    need('native' in observations,'fresh actual native reference must succeed')
                    n=observations['native'];g=result
                    need(n['header'][8:19]==g['header'][8:19]and n['hardware']==g['hardware']and
                         all(n[k]==g[k] for k in ('seed','source','stack','data','rsp','predecessor')),
                         'identical actual source/seed/hardware inputs')
                    for nr,gr in zip(n['observations'],g['observations'],strict=True):
                        need(all(nr[k]==gr[k] for k in ('before','after','live')),
                             'all65 complete application-visible state including actual AF')
                    case['application_only_pair']=dict(invocations=65,owner_credit=False,
                        protected_frames_credit=False,retirement_credit=False)
            attempt(case,argv,validate,record=role=='gated')
    except BaseException as error:
        r['error']=type(error).__name__+': '+str(error)
    finally:
        try:r['final_errors'].extend(builder.finish())
        except BaseException as error:r['final_errors'].append('build finish: '+type(error).__name__+': '+str(error))
        try:
            stable()
            need(all(fact(ROOT/path)==value for path,value in manifest['code'].items()), 'baseline local code/data unchanged')
            need(git('rev-parse','HEAD').decode().strip()==a.candidate_revision,'invocation revision unchanged')
            need(all(fact(ROOT/path)==value for path,value in current.items()),'all committed source inputs unchanged')
            r['source_unchanged']=True
        except BaseException as error:r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete']=all(c.get('reaped') is True and c.get('cleanup_errors')==[] and
            all(d.get('closed') is True for d in c.get('descriptors',[])) for c in r['commands'])
        r['status']=('complete_unqualified' if r['error'] is None and not r['final_errors'] and
            r['cleanup_complete'] and all(c['status']=='observed_unqualified' for c in r['cases']) else 'failed')
        save(out/'receipt.json',r)
        # Small numeric-only public-shaped output stays private. Failed subjects
        # retain their real outcome; missing/partial terminal counters stay null.
        rows=[]
        for c in r['cases']:
            raw=c.get('raw_counters',{});le=raw.get('LI2_LINKED_EPOCH',{});hint=raw.get('LI2_LINKED_NATIVE_HINT',{})
            view=raw.get('LI2_MAPS_VIEW',{});native=raw.get('LI2_NATIVE',{})
            rows.append(dict(name=c['name'],status=c['status'],exit=c.get('exit'),process_ns=c.get('process_ns'),
                timed_out=c.get('timed_out'),events=le.get('events'),traps=le.get('signals',[None]*5)[1],
                offers=le.get('offers'),entries=le.get('entries'),refaults=le.get('refaults'),
                graph_refaults=le.get('graph_refaults'),hint_hits=hint.get('hits'),
                maps_queries=view.get('queries'),maps_hits=view.get('hits'),
                maps_refreshes=view.get('refreshes'),maps_comparisons=view.get('comparisons'),
                maps_updates=view.get('updates'),maps_invalidations=view.get('invalidations'),
                maps_unexplained=view.get('unexplained'),
                maps_fresh=(view['refreshes']+view['comparisons']) if view else None,
                hint_admitted=hint.get('admitted'),hint_refused=hint.get('refused'),
                total_native_attempts=native.get('attempts'),total_native_admissions=native.get('admissions'),
                total_native_closed=native.get('closed'),
                application_invocations=c.get('application_invocations')))
        hw=dict(r['hardware']);flags=hw.pop('isa_flags')
        hw.update(isa_flags_count=len(flags),isa_flags_sha256=D(flags))
        summary=dict(scope=r['scope'],status=r['status'],source_revision=r['source_revision'],
            baseline_revision=a.baseline_revision,candidate_revision=a.candidate_revision,cpu=cpu,hardware=hw,
            bounds=r['bounds'],qualification_credit=False,timing_credit=False,aggregate_credit=False,rows=rows,
            reproduction_argv=['python3','-B',SCRIPT,'--baseline-revision',a.baseline_revision,
                               '--candidate-revision',a.candidate_revision,'--output','${PRIVATE_OUTPUT}'],
            reproduction_environment='One externally reserved CPU; original resource profiles are enforced for every child.',
            driver=manifest['driver'],source_manifest=fact(out/'source-manifest.json'),
            archive=r.get('archive'),input_count=len(r['inputs']),inputs_sha256=D(r['inputs']),
            artifact_count=len(r['artifacts']),artifacts_sha256=D(r['artifacts']),
            command_count=len(r['commands']),commands_sha256=D(r['commands']),
            count_scope='Actual whole-process terminal counters only. Physical fresh maps are refreshes plus comparisons. No qualification, ratio, aggregate, or saved-event inference.',
            cleanup_complete=r['cleanup_complete'],source_unchanged=r['source_unchanged'],receipt=fact(out/'receipt.json'))
        text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader();writer.writerows(rows)
        need(len(text.encode())<=16<<10 and len(stream.getvalue().encode())<=8<<10 and
             all(x not in text+stream.getvalue() for x in (str(ROOT),str(Path.home()),'/home/')), 'bounded numeric summary without private paths')
        (out/'summary.json').write_text(text);(out/'summary.csv').write_text(stream.getvalue())
    return int(r['status']!='complete_unqualified')


if __name__=='__main__':
    raise SystemExit(main())
