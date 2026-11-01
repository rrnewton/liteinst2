"""Offline complete native, gated, owner and pair audit for one installed D3 observation."""
import sys
sys.dont_write_bytecode=True
import argparse,json,os,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import save
from call_owner.custody import check_archive
from resident_three.audit_semantics import need,load,whole,fact,check


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receipt',type=Path,required=True);p.add_argument('--receipt-sha256',required=True)
    p.add_argument('--cpu',type=int,required=True);p.add_argument('--expect-revision',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.absolute()
    need(sorted(os.sched_getaffinity(0))==[a.cpu],'exact selected CPU affinity before offline audit')
    need(not sys.flags.optimize and out.parent==ROOT/'target/evaluation/inprocess'and not out.exists(),
         'fresh direct offline audit child with assertions enabled')
    out.mkdir();r=dict(schema=1,profile='resident-three-offline-audit-v1',status='failed',commands=[],
        child_processes=0,subject_executions=0,builds=0,qualification_credit=False,performance_credit=False,
        equivalence_credit=False,source=source(),hardware=hardware(a.cpu),cpu=a.cpu,
        inputs={},aliases={},inputs_unchanged=False,source_unchanged=False,cleanup_complete=False,
        error=None,final_errors=[])
    def pin(path,expected=None):
        alias=Path(path).absolute();q=alias.resolve(strict=True);v=whole(q)
        need(str(q)not in r['inputs']or r['inputs'][str(q)]==v,'stable complete input')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(q),'stable actual alias')
        if expected is not None:
            need({'bytes','sha256'}<=set(expected)and all(v[k]==expected[k]for k in ('bytes','sha256'))and
                 ('mode'not in expected or v['mode']==expected['mode'])and
                 ('resolved'not in expected or str(q)==expected['resolved']),'exact whole declared input')
        r['inputs'][str(q)]=v;r['aliases'][str(alias)]=str(q);return q
    def capture(directory,row,kind):
        c=row['captures'][kind];need(Path(c['file']).name==c['file'],'one contained capture filename')
        return pin(directory/c['file'],c).read_bytes()
    def closed(row,exit_status=None,bounds=None):
        need(row['reaped']is True and row['timed_out']is False and row['error']is None and row['cleanup_errors']==[]and
             all(v['closed']is True for v in row['descriptors'])and row['capture_limit']==16<<20,'actual process/reap/descriptor closure')
        if exit_status is not None:need(row['exit']==exit_status and row['expected_exit']==0,'actual expected successful exit')
        if bounds is not None:need(row['bounds']==bounds,'unchanged actual process bounds')
    try:
        r['revision']=r['source']['revision']
        need(r['source']['revision']==a.expect_revision and a.cpu>=0,'explicit clean current source/CPU')
        path=pin(a.receipt);need(fact(path)['sha256']==a.receipt_sha256,'explicit actual full receipt hash')
        old=load(path)
        need(old['profile']=='resident-three-observation-v1'and old['status']=='bounded_subjects_completed'and
             all(old[k]is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete'))and
             old['error']is None and old['final_errors']==[]and old['source']==r['source']and old['hardware']==r['hardware']and
             old['cpu']==a.cpu and old['native_subjects']==old['gated_subjects']==1 and
             all(old[k]is False for k in ('qualification_credit','performance_credit','equivalence_credit'))and
             old['result']==dict(independent_semantic_audit_pending=True,native_subjects=1,gated_subjects=1,
                 app_bytes=341960,owner_bytes=2063104,qualification_credit=False,performance_credit=False,equivalence_credit=False),
             'one complete same-source finite native/gated observation; no prefix promotion')
        for table in ('inputs','artifacts'):
            for q,v in old[table].items():pin(q,v)
        for alias,target in old['aliases'].items():need(str(pin(alias))==target,'actual retained alias')
        need(not old.get('namespace_aliases',{})and not old.get('context_links',{}),'natural fixed no-needed fixture has no hidden namespace/context aliases')
        for row in old['commands']:
            for kind in row['captures']:capture(path.parent,row,kind)
        prior=old['archive_prerequisite'];archive_path=pin(prior['path'],prior)
        archive,_,_,_,ar=check_archive(archive_path,prior['sha256'],r,pin)
        need(old['archive']==dict(receipt=whole(archive_path),revision=ar['revision'],archive=whole(archive)),
             'entire same-source archive validator and exact fresh decoder bytes')
        check(ROOT,HERE,r,path,old,pin,capture,closed)
        r['receipt']=dict(path=str(path),**whole(path));r['status']='observed_unqualified'
    except Exception as e:r['error']=repr(e);r['status']='failed'
    finally:
        try:
            need(sorted(os.sched_getaffinity(0))==[a.cpu],'exact selected CPU affinity at offline audit closure')
            pin(__file__)
            for module in tuple(sys.modules.values()):
                q=getattr(module,'__file__',None)
                if q and Path(q).is_file():pin(q)
            need(all(whole(q)==v for q,v in r['inputs'].items()),'every full input unchanged')
            need(all(str(Path(q).resolve(strict=True))==v for q,v in r['aliases'].items()),'every literal alias unchanged')
            r['inputs_unchanged']=True
        except Exception as e:r['final_errors'].append(repr(e));r['status']='failed'
        r['source_unchanged']=source()==r['source'];r['cleanup_complete']=True
        if not r['source_unchanged']:r['status']='failed'
        save(out/'receipt.json',r)
    print(json.dumps({k:r[k]for k in ('status','error','inputs_unchanged','source_unchanged','cleanup_complete')}))
    return 0 if r['status']=='observed_unqualified'else 1

if __name__=='__main__':raise SystemExit(main())
