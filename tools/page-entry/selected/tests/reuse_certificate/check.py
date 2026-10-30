"""Eight actual certificate transaction components; supplied owner boundaries."""
import copy
import json
import re

CONTROL_COUNT=32
KEYS=['version','component_only','supplied_boundary','supplied_completion','mode',
      'result','check_called','cleanup_result','refused','cleanup_maps','cleanup_fds',
      'r_mask','rw_mask','hole_mask','archive','policy','decoder','postseal_equal','checks','events']
FIELDS=['op','check_result','generation','live','ready','publications','retirements',
        'claims','permit_valid','pending','constructing','committed','old_verified',
        'authority_revoked','writable_complete','zeroed','copied','verified',
        'certificate_prot','certificate_pages','certificate_query_error','code_prot',
        'certificate_cleanup_complete','code_cleanup_complete']


def need(ok,message):
    if not ok:raise ValueError(message)


def expected(mode):
    # Independent finite transaction ledger. Values are concrete returned/query
    # observations, not elapsed-time tolerances or accepted alternative states.
    initial=[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,16,0,3,0,0]
    prepared=initial.copy();prepared[0]=2;prepared[9:11]=[1,1]
    rows=[initial,prepared]
    if mode==6:
        aborted=prepared.copy();aborted[0]=8
        aborted[18:24]=[0,8,305,1,0,1]
        return rows+[aborted]
    published=[3,0,1,1,1,1,0,1,0,1,1,1,0,0,0,65536,57568,65536,1,16,0,1,0,0]
    rows.append(published)
    current=published.copy()
    if mode==1:
        current[0]=4;current[7]=2;current[10]=0;rows.append(current.copy())
    elif mode==2:
        retired=published.copy();retired[0]=5;retired[3:5]=[0,0];retired[11]=0
        retired[12:15]=[1,1,1];retired[18]=3;rows.append(retired)
        current[0]=6;current[2:8]=[2,2,2,2,1,2];current[12:15]=[1,1,1]
        rows.append(current.copy())
    elif mode in(3,4,5,7):
        current[0]=7;current[1]={3:2600,4:2610,5:2600,7:2603}[mode]
        if mode==5:current[8]=1
        if mode==7:current[18]=3
        rows.append(current.copy())
    current[0]=8;current[4]=0;current[18]=1;current[22:24]=[1,1]
    return rows+[current]


def check(stdout,stderr,exit_status,mode,archive_sha256,policy_sha256):
    need(type(mode)is int and 0<=mode<8,'fixed eight modes')
    need(type(exit_status)is int and exit_status==(0 if mode<3 else 125)and
         type(stderr)is bytes and not stderr,'actual terminal result')
    need(type(stdout)is bytes and 0<len(stdout)<=32768,'bounded complete output')
    for sha in(archive_sha256,policy_sha256):
        need(type(sha)is str and re.fullmatch('[0-9a-f]{64}',sha)and sha!='0'*64,'actual external build binding')
    def unique(pairs):
        need(len(pairs)==len({k for k,_ in pairs}),'duplicate field');return dict(pairs)
    v=json.loads(stdout,object_pairs_hook=unique)
    need(type(v)is dict and list(v)==KEYS and
         json.dumps(v,separators=(',',':'),allow_nan=False).encode()+b'\n'==stdout,'whole canonical schema')
    for key in KEYS:
        if key not in('archive','policy','decoder','events'):
            need(type(v[key])is int and -(1<<63)<=v[key]<1<<64,'exact numeric type and range')
    need([v[k]for k in KEYS[:9]]==[1,1,1,int(mode in(1,2)),mode,
         {3:2600,4:2610,5:2600,7:2603}.get(mode,0),int(mode!=6),-12 if mode==6 else 0,int(mode>=3)],
         'exact component scope and actual failure source')
    need([v[k]for k in KEYS[9:14]]==[4,2,255 if mode==6 else 0,65024 if mode==6 else 0,256 if mode==6 else 0],
         'complete terminal resources and actual partial mprotect prefix')
    need(v['archive']==archive_sha256 and v['policy']==policy_sha256,'actual archive and full policy header identity')
    d=v['decoder'];need(type(d)is list and len(d)==2,'both actual allocator snapshots')
    for row in d:
        need(type(row)is list and len(row)==8 and all(type(x)is int and 0<=x<1<<64 for x in row),
             'complete actual allocator ABI')
    need(d[0]==d[1]and d[0][:5]==[1,2,0,0,2<<20]and 0<d[0][5]<=d[0][4]and d[0][6]>0 and
         v['postseal_equal']==1,'unchanged complete postseal allocator state')
    need(v['checks']==(2 if mode==0 else 1 if mode in(1,2)else 0),'actual successful certificate check count')
    events=v['events'];want=expected(mode)
    need(type(events)is list and len(events)==len(want)and all(type(row)is list and len(row)==24 and
         all(type(x)is int and 0<=x<1<<64 for x in row)for row in events),'complete typed transaction ledger')
    need(events==want,'every actual transaction field, permission and cleanup boundary')
    return v


def controls(stdout,stderr,exit_status,mode,archive_sha256,policy_sha256):
    value=check(stdout,stderr,exit_status,mode,archive_sha256,policy_sha256);trials=[]
    def encoded(v):return json.dumps(v,separators=(',',':')).encode()+b'\n'
    for index in range(24):
        v=copy.deepcopy(value);v['events'][-1][index]^=1;trials.append((encoded(v),stderr,exit_status))
    v=copy.deepcopy(value);v['version']=True;trials.append((encoded(v),stderr,exit_status))
    v=copy.deepcopy(value);del v['checks'];trials.append((encoded(v),stderr,exit_status))
    v=copy.deepcopy(value);v['extra']=0;trials.append((encoded(v),stderr,exit_status))
    trials.extend([(stdout[:-2]+b',"version":1}\n',stderr,exit_status),
        (stdout[:-1],stderr,exit_status),(stdout,b'x',exit_status),
        (stdout,stderr,exit_status^1),(b' '*32769,stderr,exit_status)])
    need(len(trials)==CONTROL_COUNT,'fixed supplied refusal population')
    for out,err,status in trials:
        refused=False
        try:check(out,err,status,mode,archive_sha256,policy_sha256)
        except ValueError:refused=True
        need(refused,'every supplied record mutation must be refused')
    return {'refusals':CONTROL_COUNT,'native_operations':0}
