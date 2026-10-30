"""Strict extra report row; existing maps and application readers stay intact."""
import json
import maps_view as maps
need=maps.need
PREFIX=b'LI2_UNROLLED_HASH '
KEYS=('version status failure_code detail_abs detail_negative observe_only initialized first_error used candidates '
      'source_misses plan_misses capacity_misses publications hits entries completed head_exits stop_exits '
      'iterations unexpected events signals active busy first_detail_abs first_detail_negative current').split()
COUNTERS=('used candidates source_misses plan_misses capacity_misses publications hits entries completed '
          'head_exits stop_exits iterations unexpected').split()

def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual report stream')
    rows=stderr[:-1].split(b'\n')
    need(len(rows)>1 and rows[-1].startswith(PREFIX)and
         sum(row.startswith(PREFIX)for row in rows)==1 and len(rows[-1])<=4096 and b'\r'not in rows[-1],
         'one final bounded unrolled row in the exact report stream')
    r=maps.pair.pair_reports.rseq.decode(rows[-1][len(PREFIX):])
    need(type(r)is dict and list(r)==KEYS,'complete ordered unrolled schema without duplicate keys')
    need(all(type(r[k])is int and 0<=r[k]<1<<64 for k in KEYS if k not in('signals','current')),
         'exact unsigned unrolled scalars, no bool or float')
    for k,n in(('signals',5),('current',29)):
        need(type(r[k])is list and len(r[k])==n and all(type(x)is int and 0<=x<1<<64 for x in r[k]),
             'complete exact unsigned unrolled '+k)
    need(r['version']==1 and r['status']in(0,125)and r['observe_only']in(0,1)and
         all(r[k]in(0,1)for k in('detail_negative','initialized','active','busy','first_detail_negative')),
         'exact version, observed terminal status and boolean fields')
    return r,b'\n'.join(rows[:-1])+b'\n'

def completed(r,observe_only):
    need(type(observe_only)is bool and r['observe_only']==int(observe_only),'exact requested execution mode')
    need(r['status']==r['failure_code']==r['detail_abs']==r['detail_negative']==r['first_error']==
         r['active']==r['busy']==r['first_detail_abs']==r['first_detail_negative']==0 and r['initialized']==1,
         'complete successful initialized owner with no pending error')
    need(r['events']==sum(r['signals'])and r['events']>0 and all(r['signals'][i]>0 for i in(0,1,2))and
         r['signals'][3:]==[0,0],'actual whole successful handler entries by signal')
    if observe_only:
        need(all(r[k]==0 for k in COUNTERS)and r['current']==[0]*29,'observation-only never attempts generated ownership')
        return
    need(0<r['used']==r['publications']<=64 and r['candidates']==r['source_misses']+r['plan_misses']+
         r['capacity_misses']+r['publications']+r['hits'] and
         r['entries']==r['publications']+r['hits']==r['completed']==r['head_exits']+r['stop_exits']and
         r['unexpected']==0 and r['head_exits']*64+r['stop_exits']<=r['iterations']<=64*r['completed'],
         'actual bounded immutable slot entries and all completion/iteration counts close')
    c=r['current']
    need(c[0]==1 and c[1]<r['used']and c[2:5]==[1,1,1]and 1<=c[5]<=64 and
         c[6:14]==[1]*8 and c[14:20]==[0,0,1,1,0,0]and c[20:24]==[1,1,0,0]and
         c[24:]==[4096,4096,4096,0,1],
         'last actual owner completed, closed its full page and released source without cleanup/fault')

def check(stdout,stderr,args,kind,lane, *, chain_closure=None):
    need(lane in('observe','unrolled','differential'),'explicit unrolled comparison lane')
    r,suffix=split(stderr);completed(r,lane=='observe')
    parsed,summary,view,original=maps.check(stdout,suffix,args,kind,'differential'if lane=='differential'else'maintained',chain_closure=chain_closure)
    need(all(r[k]==parsed['loader'][k]for k in('status','failure_code','detail_abs','detail_negative')),
         'same actual original terminal outcome')
    return parsed,summary,view,r,suffix

def controls(stdout,stderr,args,kind,lane, *, chain_closure=None):
    _,_,_,r,suffix=check(stdout,stderr,args,kind,lane,chain_closure=chain_closure)
    old=maps.controls(stdout,suffix,args,kind,'differential'if lane=='differential'else'maintained',chain_closure=chain_closure)
    lines=stderr[:-1].split(b'\n');trials=[]
    def changed(name,record):
        trials.append((name,b'\n'.join(lines[:-1])+b'\n'+PREFIX+json.dumps(record,separators=(',',':')).encode()+b'\n'))
    for key in('version','status','failure_code','detail_abs','detail_negative','observe_only','initialized',
               'first_error','active','busy','first_detail_abs','first_detail_negative','events'):
        q=dict(r);q[key]+=1;changed(key,q)
    for key,value in(('candidates',True),('iterations',1.5),('hits',-1),('entries',1<<64)):
        q=dict(r);q[key]=value;changed('type_'+key,q)
    for key in('signals','current'):
        for change in('short','bool','different'):
            q=dict(r);q[key]=list(r[key])
            if change=='short':q[key].pop()
            elif change=='bool':q[key][0]=True
            else:q[key][0]+=1
            changed(key+'_'+change,q)
    q=dict(r);q.pop('busy');changed('missing_key',q)
    q=dict(r);q['extra']=0;changed('extra_key',q)
    changed('reordered',dict(reversed(list(r.items()))))
    trials.extend([('absent',suffix),('duplicate',stderr+lines[-1]+b'\n'),('early',lines[-1]+b'\n'+suffix),
                   ('truncated',stderr[:-1]),('duplicate_key',stderr[:-2]+b',"version":1}\n')])
    refused=[]
    for name,subject in trials:
        rejected=False
        try:check(stdout,subject,args,kind,lane,chain_closure=chain_closure)
        except ValueError:rejected=True
        need(rejected,'whole reader refuses supplied unrolled '+name);refused.append(name)
    need(len(refused)==len(set(refused))==31,'complete fixed unrolled reader refusal population')
    return dict(original=old,unrolled_refusals=refused,actual_subjects=0,native_qualification_credit=False,
                original_stderr_sha256=maps.H(stderr))
