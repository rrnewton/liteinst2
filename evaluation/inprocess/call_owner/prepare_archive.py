#!/usr/bin/env python3
"""Run the unchanged committed decoder Build preparation only; no native or owner subject."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(Path(__file__).resolve().parent)]
from custody import fact, load, need
from checks import source
from run import hardware
from page_selected import ENV, save
from page_selected_generic_build import Build, PROFILES
from page_selected_process import invoke


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--cpu',type=int,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    need(not sys.flags.optimize and sys.version_info>=(3,11) and
         sorted(os.sched_getaffinity(0))==[args.cpu],'assertions, Python3.11+ and one reserved CPU')
    private=args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and
         not private.exists(),'new contained private archive preparation')
    os.chdir(ROOT);private.mkdir();receipt=private/'receipt.json'
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='call-decoder-archive-v1',status='failed',revision=args.expect_revision,
        source=None,cpu=args.cpu,hardware=hardware(args.cpu),bounds=PROFILES,commands=[],
        source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,
        archive_builds=1,subjects=0,owner_credit=False,qualification_credit=False,performance_credit=False,
        error=None,final_errors=[])
    def pin(path):
        need(path is not None,'required source/tool')
        alias=Path(path).absolute();q=alias.resolve(strict=True);value=fact(q)
        need(str(alias) not in aliases or aliases[str(alias)]==str(q),'stable alias')
        need(str(q) not in pins or pins[str(q)]==value,'stable complete source/tool input')
        aliases[str(alias)]=str(q);pins[str(q)]=value;return q
    def binary(path):
        q=Path(path).resolve(strict=True)
        need(q.is_relative_to(private) and not Path(path).is_symlink(),'private regular produced artifact')
        value=fact(q);need(str(q) not in artifacts or artifacts[str(q)]==value,'stable whole artifact')
        artifacts[str(q)]=value;return q
    def imports():
        for m in tuple(sys.modules.values()):
            name=getattr(m,'__file__',None)
            if name and Path(name).is_file():pin(name)
    def closure():
        need(all(fact(p)==v for p,v in pins.items()),'all input bytes and full modes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all input aliases unchanged')
        need(all(fact(p)==v for p,v in artifacts.items()),'all retained artifacts unchanged')
        need(all(Path(p).exists()==v for p,v in presence.items()),'loader presence unchanged')
        need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved CPU')
    def run(name,argv,profile='metadata',env=None,expected=0):
        closure();argv=list(map(str,argv));pin(argv[0])
        need(profile in PROFILES and expected==0 and not any(x['name']==name for x in r['commands']),
             'original Build bounds and unique fixed command, no retry')
        row=dict(name=name,argv=argv,bounds=PROFILES[profile],environment=dict(ENV if env is None else env),
                 expected_exit=0,capture_limit=16<<20)
        r['commands'].append(row);save(receipt,r)
        try:out,err=invoke(row,private,args.cpu)
        finally:
            for v in row.get('captures',{}).values():
                q=binary(private/v['file']);need(all(fact(q)[k]==v[k] for k in ('bytes','sha256')),
                                              'whole reaped command capture')
            save(receipt,r)
        need(row['exit']==0 and row['reaped'] is True and row['timed_out'] is False and
             row['error'] is None and not row['cleanup_errors'] and
             all(x['closed'] is True for x in row['descriptors']),'complete original bounded Build command')
        return row,out,err
    builder=None
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean source revision')
        manifest=load(Path(__file__).with_name('SOURCE.json'))
        for directory,names in manifest['source_roster'].items():
            for name in names:pin(ROOT/directory/name)
        for name in ('prepare_archive.py','custody.py','SOURCE.json'):pin(Path(__file__).with_name(name))
        pin(sys.executable);imports()
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=Path(name).exists()
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        builder=Build(r,private,pin,binary,run,('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
        paths=builder.prepare()
        need(not builder.finish(),'complete source-owned build finalization')
        r['archive']=fact(paths['archive'])
        exports=next(x for x in r['commands'] if x['name']=='archive-text-exports')['captures']['stdout']
        r['exports']={k:exports[k] for k in ('bytes','sha256')}
        imports();closure();r['status']='passed'
    except BaseException as e:r['error']=repr(e)
    finally:
        if builder is not None and r['status']!='passed':
            try:r['final_errors'].extend(builder.finish())
            except BaseException as e:r['final_errors'].append('build finalization: '+repr(e))
        for label,action in (('imports',imports),('whole closure',closure)):
            try:action()
            except BaseException as e:r['final_errors'].append(label+': '+repr(e))
        try:
            r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'same complete source')
        except BaseException as e:r['final_errors'].append('source: '+repr(e))
        r['inputs_unchanged']=not r['final_errors']
        r['cleanup_complete']=all(x.get('reaped') is True and not x.get('cleanup_errors') and
            all(d['closed'] is True for d in x.get('descriptors',[])) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']:r['status']='failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts,loader_presence=presence);save(receipt,r)
    print(json.dumps(dict(status=r['status'],receipt=str(receipt.relative_to(ROOT)),archive=r.get('archive'),
        subjects=0,qualification_credit=False,performance_credit=False),sort_keys=True))
    return int(r['status']!='passed')


if __name__=='__main__':raise SystemExit(main())
