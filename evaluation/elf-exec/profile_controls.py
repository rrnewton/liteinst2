#!/usr/bin/env python3
"""Pure synthetic-record controls for exact normal-ELF profile guards only."""
import argparse,ast,copy,hashlib,json,stat,sys
from pathlib import Path
from types import SimpleNamespace
if sys.flags.optimize: raise SystemExit('assertions required')
PINS={'reproduce.py':'907d30099d2febee4f534f10e1f0eb90f74df9add78b81916f40605e77bc8319',
      'reproduce_tactics.py':'ba95fc8171a3151a02b25b308a78001567bcae46b4226fa92f00299fca914b36'}
H=lambda b:hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--repo',type=Path,required=True);p.add_argument('--sources',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 assert a.repo.is_absolute() and a.repo.resolve(strict=True)==a.repo
 assert a.sources.is_absolute() and a.sources.resolve(strict=True)==a.sources
 assert a.out.is_absolute() and not a.out.exists() and a.out.parent.resolve(strict=True)==a.out.parent and a.out.is_relative_to(a.repo/'ignored')
 trees={};paths={};source={}
 for name,pin in PINS.items():
  path=a.sources/name;assert path.is_file() and not path.is_symlink();data=path.read_bytes();assert H(data)==pin
  trees[name]=ast.parse(data);paths[name]=str(path);source[name]=data
 b1=next(n for n in trees['reproduce.py'].body if isinstance(n,ast.FunctionDef) and n.name=='main')
 tactics=next(n for n in trees['reproduce_tactics.py'].body if isinstance(n,ast.FunctionDef) and n.name=='main')
 def is_profile(n):return isinstance(n,ast.If) and ast.dump(n.test)==ast.dump(ast.parse("args.build_profile == 'legacy'",mode='eval').body)
 marker=next(n for n in tactics.body if is_profile(n))
 b1_guard=next(n for n in ast.walk(b1) if is_profile(n))
 tactics_guard=next(n for n in ast.walk(tactics) if is_profile(n) and n is not marker)
 env_guard=next(n for n in ast.walk(tactics) if isinstance(n,ast.If) and ast.dump(n.test)==ast.dump(ast.parse("row['name'] in ('required', 'native-compile', 'codec-compile')",mode='eval').body))
 archived=next(n for n in tactics.body if isinstance(n,ast.For) and ast.dump(n.iter)==ast.dump(ast.parse('binaries.items()',mode='eval').body)).body[1:]
 assert len(archived)==3 and isinstance(archived[0],ast.Assign) and all(isinstance(n,ast.Assert) for n in archived[1:])
 readers=[next(n for n in tactics.body if isinstance(n,ast.FunctionDef) and n.name==name) for name in ('retain','prior_json')]
 constants=[n for n in trees['reproduce.py'].body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('DEBUG0_BUILD_PROFILE','DEBUG0_PROFILE','DEBUG0_ENV')]
 assert len(constants)==3
 for n in constants:
  peer=next(v for v in trees['reproduce_tactics.py'].body if isinstance(v,ast.Assign) and isinstance(v.targets[0],ast.Name) and v.targets[0].id==n.targets[0].id)
  assert ast.dump(n)==ast.dump(peer)
 env_assignment=next(n for n in b1.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='env')
 parts={'marker':([marker],'reproduce_tactics.py'),'env':([env_guard],'reproduce_tactics.py'),'archived':(archived,'reproduce_tactics.py'),'b1':([b1_guard],'reproduce.py'),'tactics':([tactics_guard],'reproduce_tactics.py')}
 def code(nodes,name):return compile(ast.Module(body=nodes,type_ignores=[]),paths[name],'exec')
 codes={name:code(nodes,file) for name,(nodes,file) in parts.items()}
 global_scope={'hashlib':hashlib,'json':json,'stat':stat}
 exec(code(constants,'reproduce.py'),global_scope)
 profile=global_scope['DEBUG0_PROFILE'];debug_env=global_scope['DEBUG0_ENV'];legacy=dict(profile,debuginfo=2)
 a.out.mkdir(mode=0o700);fixture=a.out/'synthetic-inputs';fixture.mkdir()
 args=SimpleNamespace(user_home=fixture/'home',cargo_home=fixture/'cargo',build_profile=None)
 env_scope=dict(global_scope,args=args,repo=fixture,tool=fixture/'toolchain/bin')
 exec(code([env_assignment],'reproduce.py'),env_scope);base_env=env_scope['env']
 names=('elf-exec-oracle','liteinst-rewrite','verify_elf_exec');stages=('required','native-compile','codec-compile')
 def valid(which):
  explicit=which=='dev-debug0-v1';cp=profile if explicit else legacy;env=dict(base_env,**(debug_env if explicit else {}))
  return dict(profile=which,marker=dict(schema=1,build_profile='dev-debug0-v1',cargo_profile=copy.deepcopy(profile),cargo_env=copy.deepcopy(debug_env)) if explicit else None,
   envs={stage:copy.deepcopy(env) for stage in stages},archived={name:dict(artifact=dict(profile=copy.deepcopy(cp))) for name in names},
   b1=[dict(profile=copy.deepcopy(cp)) for _ in names],tactics=[dict(profile=copy.deepcopy(cp)) for _ in range(2)])
 observations=[];active=None;active_code=None;scope=None
 def invoke(which,case):
  nonlocal active,active_code,scope
  directory=fixture/which;directory.mkdir();marker_path=directory/'build-profile.json'
  if case['marker'] is not None:marker_path.write_text(json.dumps(case['marker'],sort_keys=True)+'\n')
  args.build_profile=case['profile'];expected_env=dict(base_env,**(debug_env if args.build_profile=='dev-debug0-v1' else {}))
  scope=dict(global_scope,args=args,b1=directory,prerequisite={},env=expected_env)
  exec(code(readers,'reproduce_tactics.py'),scope)
  def run(name):
   nonlocal active,active_code
   active=name;active_code=codes[name];exec(active_code,scope)
  run('marker')
  for stage in stages:
   scope['row']=dict(name=stage,env=dict(case['envs'][stage],TMPDIR=str(directory/stage/'tmp')));run('env')
  for row in case['archived'].values():scope['row']=row;run('archived')
  for item in case['b1']:scope['item']=item;run('b1')
  for item in case['tactics']:scope['item']=item;run('tactics')
 def observe(label,case,expected=None):
  try:invoke(label,case)
  except (AssertionError,FileNotFoundError) as error:
   assert expected is not None,'valid complete record must pass'
   stage,line,kind=expected;assert active==stage and type(error) is kind
   frames=[];tb=error.__traceback__
   while tb is not None:frames.append(tb);tb=tb.tb_next
   own=[tb for tb in frames if tb.tb_frame.f_code.co_filename in paths.values()]
   assert own and any(tb.tb_frame.f_code is active_code for tb in own)
   if kind is FileNotFoundError:
    assert own[-1].tb_frame.f_code is scope['retain'].__code__ and error.filename==str(fixture/label/'build-profile.json')
   else:assert own[-1].tb_frame.f_code is active_code
   assert own[-1].tb_lineno==line
   observations.append(dict(label=label,accepted=False,expected_acceptance=False,guard=stage,line=line,exception=kind.__name__))
  else:
   assert expected is None,'mutated record unexpectedly admitted'
   observations.append(dict(label=label,accepted=True,expected_acceptance=True))
 observe('valid-legacy',valid('legacy'));observe('valid-debug0',valid('dev-debug0-v1'))
 def mutate(label,change,expected,which='dev-debug0-v1'):
  case=valid(which);change(case);observe(label,case,expected)
 marker_equal=marker.orelse[1].lineno;marker_type=marker.orelse[2].lineno;marker_profile_type=marker.orelse[3].lineno
 mutate('marker-wrong-profile',lambda c:c['marker'].__setitem__('build_profile','other'),('marker',marker_equal,AssertionError))
 mutate('marker-missing',lambda c:c.__setitem__('marker',None),('marker',readers[0].body[0].lineno,FileNotFoundError))
 mutate('legacy-caller-debug0-marker',lambda c:c.__setitem__('profile','legacy'),('marker',marker.body[0].lineno,AssertionError))
 mutate('marker-bool-schema',lambda c:c['marker'].__setitem__('schema',True),('marker',marker_type,AssertionError))
 mutate('marker-cross-debug',lambda c:c['marker']['cargo_profile'].__setitem__('debuginfo',2),('marker',marker_equal,AssertionError))
 mutate('marker-bool-debuginfo',lambda c:c['marker']['cargo_profile'].__setitem__('debuginfo',False),('marker',marker_profile_type,AssertionError))
 mutate('marker-altered-environment',lambda c:c['marker']['cargo_env'].__setitem__('CARGO_PROFILE_TEST_DEBUG','2'),('marker',marker_equal,AssertionError))
 for i,key in enumerate(debug_env):
  stage=stages[i%len(stages)]
  mutate('environment-'+key,lambda c,key=key,stage=stage:c['envs'][stage].__setitem__(key,'2' if key.endswith(('DEBUG','OPT_LEVEL')) else 'false'),('env',env_guard.body[0].lineno,AssertionError))
 for name in names:
  for value,suffix,node in ((2,'debug2',archived[1]),(False,'bool',archived[2])):
   mutate('archive-'+name+'-'+suffix,lambda c,name=name,value=value:c['archived'][name]['artifact']['profile'].__setitem__('debuginfo',value),('archived',node.lineno,AssertionError))
 for group,guard in (('b1',b1_guard),('tactics',tactics_guard)):
  for value,suffix,node in ((2,'debug2',guard.orelse[0]),(False,'bool',guard.orelse[1])):
   mutate(group+'-compiler-'+suffix,lambda c,group=group,value=value:c[group][0]['profile'].__setitem__('debuginfo',value),(group,node.lineno,AssertionError))
 for group,guard in (('b1',b1_guard),('tactics',tactics_guard)):
  mutate('legacy-'+group+'-debug0',lambda c,group=group:c[group][0]['profile'].__setitem__('debuginfo',0),(group,guard.body[0].lineno,AssertionError),'legacy')
 mutate('legacy-archive-debug0',lambda c:c['archived'][names[0]]['artifact']['profile'].__setitem__('debuginfo',0),('archived',archived[1].lineno,AssertionError),'legacy')
 assert len(observations)==30 and sum(r['accepted'] for r in observations)==2
 assert all(r['accepted'] is r['expected_acceptance'] for r in observations)
 result=dict(schema=1,status='PASS',scope='pure synthetic profile records and exact AST-extracted admission guards',observations=observations,valid_complete_records=2,expected_refusals=28,source_sha256=PINS,extracted_guard_ast_sha256={name:H(ast.dump(ast.Module(body=nodes,type_ignores=[])).encode()) for name,(nodes,_) in parts.items()},compiler_or_native_execution=False,subject_recipe_main_executed=False,literal_profile_guards_executed=True,legacy_predicates_modified=False,native_or_corpus_credit=False)
 with (a.out/'results.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({k:v for k,v in result.items() if k!='observations'},sort_keys=True))
if __name__=='__main__':main()
