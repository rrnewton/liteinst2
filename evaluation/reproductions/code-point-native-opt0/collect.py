#!/usr/bin/env python3
"""Project three independently reviewed closed native attempts; executes no subject."""
import argparse,csv,hashlib,io,json,os,re,stat,sys
from pathlib import Path
def sha(data):
    return hashlib.sha256(data).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def loads(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def csv_bytes(rows, fields):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    writer.writerows({k: r.get(k) for k in fields} for r in rows)
    return output.getvalue().encode()

def read(path):
    assert path.is_absolute() and '..' not in path.parts and path.parent.resolve(strict=True) == path.parent
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 16 * 1024 * 1024
        data = stream.read(before.st_size + 1)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(before) == fields(os.fstat(stream.fileno())) == fields(path.lstat()) and len(data) == before.st_size
    return data

ATTEMPTS=(
 ('v1','dd94a43b7986509f70635896ab759659fbd81ba4','683005bfb3ef5dcf157703ba5913ac6b649548484090c8ce044095091641ae3d',0,1,12),
 ('v2','5403fdf53bbf21b8d3890a9a13d6f6f0f3d1c41a','a1d48e52232b900e805e03bf9228528e63bb5464ce1169c54b0c736b906b02ea',0,1,12),
 ('v3','4fe20da702222651894501f297123e367312544c','18dd8f0fe755b852d3043b4bf35ab685fa9559e9fc26b218d588dc7c9617ced2',8,1,4))
REASONS={'v1':'fixture required private RX but the allocator provides shared RX; rejected',
 'v2':'fixture expected PC in the generic terminal-value field whose existing contract stores invocation; rejected',
 'v3':'old-reservation-seed-0 exhausted the unchanged 20000-step oracle bound'}
CASES_SHA='16878c690a95f52845968272354d7f692ac2ff03776b589d2df4373df852de1f'
HELPER_SHA='c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'

def main():
    if sys.flags.optimize:raise SystemExit('assertions required')
    ap=argparse.ArgumentParser();ap.add_argument('--inputs',type=Path,required=True);ap.add_argument('--inputs-sha256',required=True);ap.add_argument('--new-output',type=Path,required=True);args=ap.parse_args()
    ib=read(args.inputs);assert sha(ib)==args.inputs_sha256;spec=loads(ib)
    assert set(spec)=={'schema','repo','attempts','cases','files','roles','privacy_literals'}and spec['schema']==1
    repo=Path(spec['repo']);out=args.new_output;assert repo.resolve(strict=True)==repo
    assert out.is_absolute()and out.is_relative_to(repo/'ignored')and out.parent.resolve(strict=True)==out.parent and not out.exists()
    assert len(spec['attempts'])==3 and [a['id']for a in spec['attempts']]==[a[0]for a in ATTEMPTS]
    facts={}
    def bound(value):
        path=Path(value);assert path.is_relative_to(repo/'ignored')and not path.is_relative_to(out)
        assert not path.is_relative_to(repo/'target')
        pin=spec['files'][str(path)];assert set(pin)=={'sha256','bytes'}
        data=read(path);assert pin==dict(sha256=sha(data),bytes=len(data));facts[str(path)]=pin;return data
    def obj(path):return loads(bound(path))
    catalog=obj(spec['cases']);assert sha(bound(spec['cases']))==CASES_SHA
    assert len(catalog['commands'])==13 and catalog['totals']==dict(actual_completed=0,candidate_children=52,children=75,commands=13,full_state_comparisons=130,original_children=20,output_files=130,refusal_children=3)
    roles=spec['roles'];assert roles['${REPO}']==str(repo)and 1<=len(roles)<=32 and len(set(roles.values()))==len(roles)
    assert all(re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}',k)and type(v)is str and v.startswith('/')for k,v in roles.items())
    tokens=re.compile('|'.join(re.escape(k)for k in roles));locations=re.compile('|'.join(re.escape(v)for v in sorted(roles.values(),key=len,reverse=True)));inverse={v:k for k,v in roles.items()}
    def norm(value):
        if isinstance(value,str):
            assert not tokens.search(value);new=locations.sub(lambda m:inverse[m[0]],value);assert tokens.sub(lambda m:roles[m[0]],new)==value;return new
        if isinstance(value,list):return[norm(x)for x in value]
        if isinstance(value,dict):
            new={norm(k):norm(v)for k,v in value.items()};assert len(new)==len(value);return new
        assert value is None or type(value)in(bool,int,float);return value
    contexts=[];inverses=[];reports=[];rows=[];exports={};sources=[]
    def context(name,value):
        public=norm(value);contexts.append(dict(id=name,context=public));inverses.append(dict(id=name,original=value,normalized=public));return name
    for a,(identifier,revision,review_sha,passed,failed,unrun)in zip(spec['attempts'],ATTEMPTS):
        assert set(a)=={'id','raw','parent','activation','build','build_parent','build_source','build_parent_source','constructor_source','construction','review'}
        raw,parent,activation,build,build_parent,review=(Path(a[k])for k in('raw','parent','activation','build','build_parent','review'))
        for root in(raw,parent,activation,build,build_parent,review):assert not out.is_relative_to(root)and not root.is_relative_to(out)
        rb=obj(review/'binding.json');assert sha(bound(review/'binding.json'))==review_sha and rb['findings']==[]and rb['qualification_complete']is False
        for name,pin in rb['files'].items():assert pin==dict(sha256=sha(bound(review/name)),bytes=len(bound(review/name)))
        assert rb['references_sha256']==sha(bound(review/'references.json'))
        if identifier=='v1':assert rb['original_child_completed']is True and rb['candidate_completion_credit']is False
        elif identifier=='v2':assert rb['closed_child_records']==2 and rb['source_attested_live_comparisons_in_closed_prefix']==3
        else:assert rb['closed_child_records']==65 and rb['passing_case_children']==64 and rb['passing_case_source_attested_live_comparisons']==120 and rb['failed_case_closed_originals']==1 and rb['failed_case_candidate_completion']is False
        raw_map=obj(review/'raw-records.json');summary=obj(raw/'summary.json');binding=obj(raw/'binding.json')
        assert summary['revision']==revision and summary['status']=='FAILED'and (summary['passed'],summary['failed'],summary['unrun'])==(passed,failed,unrun)
        assert summary['whole_A4']is summary['qualification_complete']is summary['independent_saved_state_audit']is False
        assert summary['final_source_tools_configs_product_runtime_equal']is True and summary['final_error']is None
        assert [x['id']for x in summary['cases']]==[x['id']for x in catalog['commands']]
        assert [x['status']for x in summary['cases']]==['PASS']*passed+['FAILED']+['UNRUN']*unrun
        assert summary['attempted']==passed+1 and summary['planned_children']==75 and summary['planned_full_state_comparisons']==130
        assert obj(raw/'planned.json')['cases']==catalog['commands']
        before=bound(raw/'inputs-before.json');assert before==bound(raw/'inputs-after.json');snapshot=loads(before)
        assert snapshot['source']['revision']==revision and len(snapshot['source']['files'])==2189 and snapshot['metadata']==binding['files']
        hw=obj(raw/'hardware.json');assert set(hw)=={'host_label','architecture','cpu_model','kernel_release','libc','affinity'}and hw['host_label']=='AMD EPYC Zen 5 dev host'and hw['affinity']==[0,1,2,3]
        caller=bound(activation/'run.py');parent_bytes=bound(activation/'launch.py');assert sha(caller)==binding['caller_sha256']
        assert bound(activation/'binding.json')==bound(raw/'binding.json')
        outer=obj(parent/'command.json');closed=obj(parent/'closed.json');started=obj(parent/'started.json')
        assert closed['exit']==1 and closed['parent_wait_returned']is True and closed['parent_error']is None and closed['pid']==started['pid']
        assert outer['caller_sha256']==sha(caller)and outer['binding_sha256']==sha(bound(raw/'binding.json'))and outer['parent_source_sha256']==sha(parent_bytes)
        assert outer['parent_timeout_seconds']==1200 and outer['parent_failure_cleanup_seconds']==10
        for stream in('stdout','stderr'):assert sha(bound(parent/(stream+'.txt')))==closed[stream+'_sha256']
        assert obj(parent/'stdout.txt')==summary and bound(parent/'stderr.txt')==b''
        campaign_id=context(identifier+'/campaign',outer)
        for case,result in zip(catalog['commands'],summary['cases']):
            row=dict(attempt=identifier,revision=revision,case=case['id'],status=result['status'],attempted=result['attempted'],planned_children=case['children'],planned_comparisons=case['full_state_comparisons'],completed_case_children=result.get('completed_children'),source_attested_live_comparisons=result.get('source_attested_full_state_comparisons'),native_exit=None,helper_absence=None,seconds=None,command_context=None,parent_context=None,qualification_complete=False)
            if result['status']=='UNRUN':assert result['attempted']is False;rows.append(row);continue
            d=raw/case['id'];assert result==obj(d/'summary.json')and result['source_tools_configs_product_runtime_equal']is True
            assert bound(d/'inputs-before.json')==bound(d/'inputs-after.json')==before
            request=obj(d/'request.json');command=obj(d/'command.json');receipt=obj(d/'receipt.json');cc=obj(d/'closed.json');ss=obj(d/'started.json')
            assert request['argv']==[str(repo/'target/debug/frontend-native-point'),case['mode'],case.get('member',case.get('control')),str(case['seed_index']),str(d/'output')]
            assert (request['cpu_seconds'],request['wall_seconds'],request['file_bytes'])==(20,30,1048576)
            assert request['cwd']==command['cwd']==str(repo)and request['env']==command['env']==dict(LANG='C.UTF-8',LC_ALL='C.UTF-8',PATH='/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',TMPDIR=str(d/'tmp'))
            assert request['stdout']==str(d/'stdout.txt')and request['stderr']==str(d/'stderr.txt')
            assert command['argv']==['/usr/bin/timeout','--signal=TERM','--kill-after=10s','40s','/usr/bin/python3.9','-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')]
            assert command['caller_sha256']==sha(caller)and command['binding_sha256']==sha(bound(raw/'binding.json'))
            assert set(receipt)=={'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
            success=result['status']=='PASS';assert receipt['exit']==(0 if success else 101)and receipt['absence_proof']=='ECHILD'and receipt['wall_timeout']is False and receipt['inputs_unchanged']is True
            assert receipt['request_sha256']==command['request_sha256']==sha(bound(d/'request.json'))and receipt['helper_sha256']==HELPER_SHA
            assert receipt['unexpected_descendants']==receipt['cleanup_events']==[]and receipt['cleanup_error']is receipt['aborted']is None
            assert cc['exit']==(0 if success else 1)and cc['parent_wait_returned']is True and cc['parent_error']is None and cc['pid']==ss['pid']
            assert command['parent_timeout_seconds']==55 and command['parent_failure_cleanup_seconds']==10 and command['affinity']==[0,1,2,3]
            for stream in('stdout','stderr'):
                assert sha(bound(d/(stream+'.txt')))==receipt[stream+'_sha256']
                assert sha(bound(d/('helper.'+stream)))==cc[stream+'_sha256']
            assert obj(d/'helper.stdout')==dict(exit=receipt['exit'],wall_timeout=False,absence_proof='ECHILD',descendants=0,success=success)and bound(d/'helper.stderr')==b''
            if success:
                assert result['fatal']is None and result['completed_children']==case['children']and result['source_attested_full_state_comparisons']==case['full_state_comparisons']and bound(d/'stderr.txt')==b''
                native=obj(d/'stdout.txt');assert native==dict(mode=case['mode'],member=case['member'],seed_index=case['seed_index'],children=case['children'],full_state_comparisons=case['full_state_comparisons'],status='PASS')
                index=obj(d/'output-files.json');assert len(index)==case['output_files']
                assert all(raw_map[str(d/'output'/name)]==pin for name,pin in index.items())
            else:assert result.get('completed_children')is None and result.get('source_attested_full_state_comparisons')is None and bound(d/'stdout.txt')==b''
            row.update(native_exit=receipt['exit'],helper_absence='ECHILD',seconds=receipt['elapsed_seconds'],command_context=context(identifier+'/'+case['id']+'/native',request),parent_context=context(identifier+'/'+case['id']+'/parent',command));rows.append(row)
        build_command=obj(build/'command.json');build_summary=obj(build/'summary.json');build_result=obj(build/'process-result.json');build_closed=obj(build_parent/'closed.json');build_outer=obj(build_parent/'command.json')
        assert build_command['source_revision']==build_summary['revision']==revision and build_summary['status']=='PASS'and build_summary['source_tools_configs_equal']is True and build_summary['command']==build_result
        assert build_result['exit_code']==0 and build_result['cleanup_complete']is True and build_result['termination']is None and build_result['reaped_descendants']==0
        assert bound(build/'inputs-before.json')==bound(build/'inputs-after.json')and loads(bound(build/'inputs-before.json'))['source']==snapshot['source']
        assert build_closed['exit']==0 and build_closed['parent_error']is None and build_closed['parent_wait_returned']is True and build_closed['pid']==obj(build_parent/'started.json')['pid']
        assert build_command['argv']==['cargo','build','-p','rapid-profiler','--bin','frontend-native-point','--message-format=json']
        assert build_command['timeout_seconds']==180 and build_command['max_log_bytes']==8388608 and build_command['affinity']==[0,1,2,3]
        assert build_outer['parent_timeout_seconds']==240 and build_outer['parent_cleanup_seconds']==10
        assert sha(bound(build/'command.log'))==build_result['private_log_sha256']
        driver=bound(a['build_source']);bp=bound(a['build_parent_source']);assert build_command['caller_sha256']==sha(driver)==build_outer['source_sha256']and build_outer['parent_source_sha256']==sha(bp)
        for stream in('stdout','stderr'):assert sha(bound(build_parent/(stream+'.txt')))==build_closed[stream+'_sha256']
        assert obj(build_parent/'stdout.txt')==build_summary and bound(build_parent/'stderr.txt')==b''
        build_id=context(identifier+'/build',build_command);build_parent_id=context(identifier+'/build-parent',build_outer)
        construction=Path(a['construction']);constructor=bound(a['constructor_source'])
        if identifier=='v1':
            cq=obj(construction/'construct-command.json');cz=obj(construction/'construct-result.json');stream_paths=[construction/'construct.stdout',construction/'construct.stderr'];constructor_parent_authority=False
        else:
            cq=obj(construction/'command.json');cz=obj(construction/'result.json');stream_paths=[construction/'stdout.txt',construction/'stderr.txt'];constructor_parent_authority=True
            assert cz['parent_wait_returned']is True and cz['error']is None and cz['pid']==obj(construction/'started.json')['pid']
        assert cq['source_sha256']==sha(constructor)and cz['exit']==0
        for stream,path in zip(('stdout','stderr'),stream_paths):assert sha(bound(path))==cz[stream+'_sha256']
        assert bound(stream_paths[1])==b''and obj(stream_paths[0])==obj(activation/'constructed.json')
        construct_id=context(identifier+'/construct',cq)
        product=obj(build/'product.json');profile=product['artifact']['profile'];assert profile==dict(debug_assertions=True,debuginfo=0,opt_level='0',overflow_checks=True,test=False)
        assert product['revision']==revision and product['artifact']['executable']==str(repo/'target/debug/frontend-native-point')
        assert (raw/'summary.json').as_posix()in raw_map and raw_map[str(raw/'summary.json')]['sha256']==sha(bound(raw/'summary.json'))
        reports.append(dict(attempt=identifier,revision=revision,status='FAILED',cases=dict(planned=13,attempted=passed+1,passed=passed,failed=failed,unrun=unrun),profile=profile,hardware=hw,failure=REASONS[identifier],campaign_context=campaign_id,build_context=build_id,build_parent_context=build_parent_id,construction_context=construct_id,constructor_direct_parent_recorded=constructor_parent_authority,campaign_parent_seconds=closed['seconds'],source_files=2189,source_map_sha256=sha(encode(snapshot['source']['files'])),review_sha256=review_sha,raw_summary_sha256=sha(bound(raw/'summary.json')),source_attested_live_comparisons_in_passing_cases=120 if identifier=='v3'else 0,closed_prefix_extra=dict(completed_children=1 if identifier!='v2'else 2,source_attested_live_comparisons=3 if identifier=='v2'else 0),independent_saved_state_audit=False,qualification_complete=False))
        reports[-1].update(tools=norm(snapshot['tools']),compiler_tools=norm(snapshot['compiler_tools']),selected_runtime_owners=norm(snapshot['selected_runtime']),selected_runtime_scope='selected-host owners only; no complete loader/process mapping closure',product=norm(snapshot['product']),configuration_observation_sha256=sha(encode(snapshot['configurations'])),source_materials={p:snapshot['source']['files'][p]for p in('tests/support/native_interval_oracle.rs','tests/support/native_point.rs','tools/rapid-profiler/Cargo.toml','tools/rapid-profiler/native-point/main.rs')})
        for name,data in [('run.py',caller),('build.py',driver),('construct-historical.py',constructor),('native-parent.py.template',parent_bytes),('build-parent.py.template',bp)]:
            text=data.decode();normalized=norm(text);key=identifier+'/'+name;exports[key]=normalized.encode();inverses.append(dict(id=identifier+'/source/'+name,original=text,normalized=normalized))
            sources.append(dict(attempt=identifier,file=key,original_sha256=sha(data),public_sha256=sha(exports[key]),transformation='exact bytes'if data==exports[key]else'invertible private-path roles',historical_source_only=True))
    assert len(rows)==39 and len(contexts)==34 and len(sources)==15
    assert set(facts)==set(spec['files'])
    summary=dict(schema=1,attempts=reports,attempts_aggregated_as_unique_tests=False,qualification_complete=False,whole_A4=False,independent_saved_state_audit=False,durations='operational observations, not performance measurements',planned_per_attempt=dict(cases=13,children=75,full_state_comparisons=130),unimplemented_modes=[r['mode']for r in catalog['modes']if r['status']=='UNIMPLEMENTED'],input_sha256=sha(ib))
    payload={'summary.json':encode(summary),'cases.json':encode(rows),'cases.csv':csv_bytes(rows,tuple(rows[0])),'contexts.json':encode(contexts),'recipe-sources.json':encode(sources),'records.json':encode(norm(facts))}
    literals=spec['privacy_literals'];assert type(literals)is list and literals and all(type(x)is str and x for x in literals)
    for data in list(payload.values())+list(exports.values()):
        text=data.decode();assert '/home/'not in text and '/tmp/'not in text
        for literal in literals:assert literal not in text and literal.encode().hex()not in text.lower()
        for value in roles.values():assert value not in text and value.encode().hex()not in text.lower()
    # Revalidate only admitted saved metadata/source files; never dereference their member maps.
    for path in tuple(facts):bound(path)
    out.mkdir();(out/'public').mkdir();(out/'private').mkdir();(out/'public/historical').mkdir()
    for name,data in payload.items():(out/'public'/name).write_bytes(data)
    for name,data in exports.items():
        p=out/'public/historical'/name;p.parent.mkdir(exist_ok=True);p.write_bytes(data)
    (out/'private/command-and-source-inverses.json').write_bytes(encode(inverses));(out/'private/roles.json').write_bytes(encode(roles));(out/'private/read-records.json').write_bytes(encode(facts))
    public={str(p.relative_to(out/'public')):dict(sha256=sha(p.read_bytes()),bytes=p.stat().st_size)for p in(out/'public').rglob('*')if p.is_file()}
    (out/'collection.json').write_bytes(encode(dict(schema=1,input_sha256=sha(ib),collector_sha256=sha(Path(__file__).read_bytes()),files=public,attempts=3,cases=39,contexts=34,historical_source_exports=15,qualification_complete=False)))
if __name__=='__main__':main()
