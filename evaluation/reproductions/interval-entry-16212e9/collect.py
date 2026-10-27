#!/usr/bin/env python3
"""Summarize one reviewed closed validation cohort. Executes no validation."""
import argparse,csv,hashlib,io,json,os,re,stat,sys
from pathlib import Path
REVISION='16212e9ab00a18ce003a305f7265bce8633e1c0e'
DRIVER='a819f578148b1a0d8031b8add0b1dd6a0461b8d277fc7b75a9a6799d04a75ec4'
PARENT='d563fe8b5c867c1b6a1a212ff4ed14860f2a442978fe0eb3928e6c55066755d0'
PHASES=('targeted-profiler','required','serial','parallel-library','parallel-prefixed','parallel-neighbor')
COUNT_KEYS=('passed','failed','ignored','measured','filtered_out')
HARDWARE='AMD EPYC Zen 5 dev host'


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

def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    ap=argparse.ArgumentParser();ap.add_argument('--inputs',type=Path,required=True);ap.add_argument('--inputs-sha256',required=True);ap.add_argument('--new-output',type=Path,required=True)
    args=ap.parse_args();ib=read(args.inputs);assert sha(ib)==args.inputs_sha256;spec=loads(ib)
    assert set(spec)=={'schema','repo','raw','driver','launcher','review','files','roles','privacy_literals'} and spec['schema']==1
    repo=Path(spec['repo']);raw=Path(spec['raw']);review=Path(spec['review']);out=args.new_output
    assert repo.resolve(strict=True)==repo and raw.is_relative_to(repo/'ignored') and review.is_relative_to(repo/'ignored')
    assert out.is_relative_to(repo/'ignored') and out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink()
    assert not out.is_relative_to(raw) and not out.is_relative_to(review)
    facts={}
    def bound(value):
        path=Path(value);assert not path.is_relative_to(repo/'target')
        expected=spec['files'][str(path)];assert set(expected)=={'sha256','bytes'}
        data=read(path);assert expected==dict(sha256=sha(data),bytes=len(data));facts[str(path)]=expected;return data
    def obj(value):return loads(bound(value))
    driver=bound(spec['driver']);parent_source=bound(spec['launcher']);assert sha(driver)==DRIVER and sha(parent_source)==PARENT
    binding=obj(review/'binding.json');complete=obj(review/'complete.json')
    assert binding['verdict']=='CLOSED_SIX_VALIDATION_PHASES_AND_COMPLETE_TEST_INVENTORIES_VERIFIED' and binding['findings']==[]
    assert binding['revision']==complete['revision']==REVISION and binding['phases']==list(PHASES)
    for name,pin in binding['files'].items():
        data=bound(review/name);assert pin==dict(sha256=sha(data),bytes=len(data))
    assert binding['references_sha256']==sha(bound(review/'references.json'))
    assert binding['source_files']==complete['source_files']==2191 and complete['saved_source_tools_configs_equal_across_all_six_phases'] is True
    assert binding['native_campaign_review'] is binding['qualification_complete'] is False
    assert binding['prior_cases_retained']==2256 and complete['prior_complete_identities_and_statuses_retained'] is True
    assert binding['new_workspace_cases']==complete['new_workspace_cases']==23 and complete['prior_revision']=='dd94a43b7986509f70635896ab759659fbd81ba4'
    assert complete['counts_aggregated_across_commands'] is complete['nested_passes_aggregated'] is False
    roles=spec['roles'];assert roles['${REPO}']==str(repo) and roles['${RAW}']==str(raw)
    assert 2<=len(roles)<=16 and len(set(roles.values()))==len(roles)
    assert all(re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}',k) and type(v)is str and v.startswith('/') for k,v in roles.items())
    token=re.compile('|'.join(re.escape(k)for k in roles));locations=re.compile('|'.join(re.escape(v)for v in sorted(roles.values(),key=len,reverse=True)));inverse={v:k for k,v in roles.items()}
    def normalize(value):
        if isinstance(value,str):
            assert not token.search(value);new=locations.sub(lambda m:inverse[m[0]],value);assert token.sub(lambda m:roles[m[0]],new)==value;return new
        if isinstance(value,list):return [normalize(x)for x in value]
        if isinstance(value,dict):
            new={normalize(k):normalize(v)for k,v in value.items()};assert len(new)==len(value);return new
        assert value is None or type(value)in(bool,int,float);return value
    rows=[];contexts=[];private=[];cases=[];source_files=None;hardware=None;tool_versions=None;rustc_version=None;accounting={};native_build_profile=None
    def context(identifier,value):
        public=normalize(value);contexts.append(dict(id=identifier,context=public));private.append(dict(id=identifier,original=value,normalized=public));return identifier
    for phase in PHASES:
        d=raw/phase;launch=raw/(phase+'-launch');p=review/'v1'/phase
        inventory=obj(p/'binding.json');checks=obj(p/'checks.json');groups=obj(p/'test-groups.json');records=obj(p/'record-checks.json')
        assert inventory['revision']==checks['revision']==records['revision']==REVISION and inventory['findings']==checks['findings']==[]
        for name,pin in inventory['files'].items():
            data=bound(p/name);assert pin==dict(sha256=sha(data),bytes=len(data))
        command=obj(d/'command.json');result=obj(d/'process-result.json');summary=obj(d/'summary.json');outer=obj(launch/'command.json');closed=obj(launch/'closed.json');started=obj(launch/'started.json')
        assert records['command']==command and records['result']==summary['command']==result and records['parent']==closed
        assert summary['revision']==command['source_revision']==outer['source_revision']==REVISION and summary['status']=='PASS'
        assert result['exit_code']==closed['exit']==0 and result['termination'] is None and result['cleanup_complete'] is True and result['reaped_descendants']==0
        assert closed['parent_wait_returned'] is True and closed['parent_error'] is None and started['pid']==closed['pid']
        assert command['caller_sha256']==DRIVER and outer['source_sha256']==DRIVER and outer['parent_source_sha256']==PARENT
        for stream in ('stdout','stderr'):assert sha(bound(launch/(stream+'.txt')))==closed[stream+'_sha256']
        assert bound(launch/'stderr.txt')==b'' and obj(launch/'stdout.txt')==summary
        log=bound(d/'command.log');assert sha(log)==result['private_log_sha256']
        before=obj(d/'inputs-before.json');assert bound(d/'inputs-before.json')==bound(d/'inputs-after.json') and summary['source_tools_configs_equal'] is True
        assert before['source']['revision']==REVISION and len(before['source']['files'])==2191
        if source_files is None:source_files=before['source']['files'];tool_versions=before['tools'];rustc_version=command['rustc']
        else:assert source_files==before['source']['files'] and tool_versions==before['tools'] and rustc_version==command['rustc']
        hw=obj(d/'hardware.json');assert hw['host_label']==HARDWARE
        if hardware is None:hardware=hw
        else:assert hardware==hw
        expected=complete['phases'][phase];assert expected['status']=='PASS'
        counts=checks['outer_counts'];assert counts==expected['counts'] and len(groups)==(checks['outer_groups']or 0)
        if phase=='native-build':
            assert counts is None and groups==[] and checks['product_bytes_independently_read'] is False
            native_build_profile=checks['cargo_target']['profile'];assert native_build_profile==dict(debug_assertions=True,debuginfo=0,opt_level='0',overflow_checks=True,test=False)
        else:
            count=dict.fromkeys(COUNT_KEYS,0)
            for group in groups:
                observed={'ok':0,'FAILED':0,'ignored':0}
                for name,value in group['cases'].items():
                    observed[value['status']]+=1;cases.append(dict(phase=phase,group=group['identity'],name=name,status=value['status'],raw_status=value.get('raw_status',value['status'])))
                assert group['summary'][1]==[observed['ok'],observed['FAILED'],observed['ignored'],0,0]
                for k,v in zip(COUNT_KEYS,group['summary'][1]):count[k]+=v
            assert count==counts and sum(count[k]for k in ('passed','failed','ignored'))==checks['outer_named_cases']
            assert checks['nested_passes_aggregated'] is False
        accounting[phase]={k:expected[k]for k in ('groups','named_cases','nested_completed_summaries','extra_child_starts','bare_terminals','ordinary_main_harnesses','serial_split_terminals')}
        accounting[phase]['ordinary_main']=[dict(identity=x['identity'],controls=x['controls'],records=[r['record']for r in x['records']],libtest_pass_credit=x['libtest_pass_credit'])for x in checks.get('ordinary_main_controls',[])]
        command_id=context(phase,dict(command=command,result=result,parent=closed));parent_id=context(phase+'/parent',outer)
        rows.append(dict(id=phase,scope='dispatch' if phase=='required' else 'validation',status='PASS',exit=0,seconds=result['seconds'],parent_seconds=closed['seconds'],cpus=len(command['affinity']),timeout_seconds=command['timeout_seconds'],log_sha256=sha(log),counts=None if phase=='required' else counts,groups=None if phase=='required' else checks['outer_groups'],command_context=command_id,parent_context=parent_id,cleanup_complete=True,reaped_descendants=0))
        if phase=='required':
            gate_source=bound(repo/'evaluation/required-gates.py');assert sha(gate_source)==before['source']['files']['evaluation/required-gates.py']['sha256']=='6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b'
            assert gate_source.decode().splitlines().count("env=dict(os.environ,CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_TARGET_DIR=str(ROOT/'target'),RUST_TEST_THREADS='4',CARGO_NET_OFFLINE='true',TMPDIR=str(OUT))")==1
            gate_env=dict(command['env'],CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_TARGET_DIR=str(repo/'target'),RUST_TEST_THREADS='4',CARGO_NET_OFFLINE='true',TMPDIR=str(d/'gates'))
            gate=obj(d/'gates/commands.json');assert gate['head']==REVISION and gate['records']==[{k:v for k,v in x.items()if k!='status'}for x in records['gate_results']]
            assert [(x['name'],x['exit'])for x in gate['records']]==[('fmt',0),('clippy',0),('test',0),('check',0)]
            for record in gate['records']:
                gate_log=bound(repo/record['log']);assert sha(gate_log)==record['sha256'];identifier='required/'+record['name']
                if record['name']=='test':assert checks['raw_log_sha256']==sha(gate_log)
                context_id=context(identifier,dict(argv=record['argv'],cwd=command['cwd'],env=gate_env,affinity=command['affinity'],timeout_seconds=record['timeout_seconds'],env_authority=dict(kind='source-derived from saved outer env and exact gate-source assignment',source=str(repo/'evaluation/required-gates.py'),sha256=sha(gate_source),independently_saved_env=False)))
                rows.append(dict(id=identifier,scope='validation',status='PASS',exit=record['exit'],seconds=record['seconds'],parent_seconds=None,cpus=4,timeout_seconds=record['timeout_seconds'],log_sha256=record['sha256'],counts=counts if record['name']=='test' else None,groups=checks['outer_groups'] if record['name']=='test' else None,command_context=context_id,parent_context=parent_id,cleanup_complete=None,reaped_descendants=None))
    assert len(rows)==10 and len(contexts)==16
    assert len(cases)==3822 and sum(x['status']=='ok'for x in cases)==3817 and sum(x['status']=='ignored'for x in cases)==5
    assert set(facts)==set(spec['files'])
    source_map=[dict(path=name,**{k:pin[k]for k in ('sha256','bytes','mode')})for name,pin in sorted(source_files.items())]
    summary=dict(schema=1,revision=REVISION,hardware=hardware,phases=PHASES,inventory_accounting=accounting,native_build_profile=native_build_profile,all_six_phases_passed=True,validation_commands=9,required_dispatches=1,rows=rows,workspace=dict(groups=95,passed=2275,failed=0,ignored=4,prior_identities_statuses_retained=2256,new_workspace_cases=23,doc_identity_relocations=0,allocation_regressions_passed=3),repeated_case_observations=len(cases),case_observation_counts=dict(passed=3817,failed=0,ignored=5),unique_tests_not_summed=True,nested_passes_aggregated=False,native_build_included=False,native_build_is_not_native_execution=True,interval_entry_model_only=True,native_campaign_review=False,qualification_complete=False,durations='operational observations, not performance measurements',source_files=2191,driver_sha256=DRIVER,actual_parent_sha256=PARENT,review_sha256=sha(bound(review/'binding.json')),input_sha256=sha(ib))
    versions=dict(rustc=rustc_version,tools={name:{k:value[k]for k in ('sha256','bytes')}for name,value in tool_versions.items()},other_tool_version_strings_recorded=False)
    payload={'summary.json':encode(summary),'commands.csv':csv_bytes([dict(r,counts=json.dumps(r['counts'],sort_keys=True)if r['counts']is not None else '')for r in rows],('id','scope','status','exit','seconds','parent_seconds','cpus','timeout_seconds','log_sha256','counts','groups','command_context','parent_context','cleanup_complete','reaped_descendants')),'contexts.json':encode(contexts),'cases.csv':csv_bytes(cases,('phase','group','name','status','raw_status')),'source-files.json':encode(source_map),'tool-versions.json':encode(versions)}
    for name,data in payload.items():
        text=data.decode();assert '/home/'not in text and '/tmp/'not in text
        for literal in spec['privacy_literals']:assert literal not in text,(name,literal)
    for name,pin in facts.items():
        data=read(Path(name));assert pin==dict(sha256=sha(data),bytes=len(data))
    out.mkdir();public=out/'public';public.mkdir()
    for name,data in payload.items():
        with (public/name).open('xb') as f:f.write(data)
    with (out/'private-inverses.json').open('xb') as f:f.write(encode(dict(roles=roles,contexts=private)))
    with (out/'used-inputs.json').open('xb') as f:f.write(encode(facts))
    with (out/'result.json').open('xb') as f:f.write(encode(dict(status='REPORT_PROJECTED',public_files={name:dict(sha256=sha(data),bytes=len(data))for name,data in payload.items()},commands=10,contexts=16,native_executions=0,qualification_complete=False)))
    print(json.dumps(dict(status='REPORT_PROJECTED',commands=10,contexts=16,public_files=len(payload),qualification_complete=False),sort_keys=True))
if __name__=='__main__':main()
