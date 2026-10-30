"""Three additional real retired-cache component paths; no actual TF credit."""
import copy
import json

CONTROL_COUNT=32
KEYS=['version','component_only','supplied_boundary','values','cleanup','io']

def need(ok,message):
    if not ok:raise ValueError(message)

def check(stdout,stderr,exit_status,mode,differential):
    need(type(mode)is int and 0<=mode<3 and type(differential)is int and differential in(0,1),'fixed mode/profile')
    need(type(exit_status)is int and exit_status==(0 if mode==0 else 125)and type(stderr)is bytes and not stderr,'actual outcome')
    need(type(stdout)is bytes and 0<len(stdout)<=4096,'bounded actual stdout')
    def unique(pairs):
        need(len(pairs)==len({k for k,_ in pairs}),'duplicate key');return dict(pairs)
    v=json.loads(stdout,object_pairs_hook=unique)
    need(type(v)is dict and list(v)==KEYS and json.dumps(v,separators=(',',':')).encode()+b'\n'==stdout,'canonical complete schema')
    need(all(type(v[k])is int and v[k]==1 for k in KEYS[:3]),'component/supplied boundary scope')
    for name,n in (('values',24),('cleanup',3),('io',5)):
        need(type(v[name])is list and len(v[name])==n and all(type(x)is int and 0<=x<1<<64 for x in v[name]),'whole exact numeric extent')
    x=v['values'];good=mode==0;delta=int(good)
    need(x[:4]==[mode,differential,1,1]and x[4]>0 and x[5]==x[6]==x[7]>0 and x[11]>0,'real retirement/unavailable and physical stage')
    need(x[8]==x[9]+x[5]-x[10]and x[10]==differential*x[9],'actual complete maps partition before commit')
    need(x[12]==(0 if good else 302)and x[13]==x[4]+(0 if good else 2),'actual success or stale epoch refusal')
    need(x[14:20]==[x[5]+delta,x[6]+delta,x[7]+delta,x[8]+delta,x[9],x[10]],'exact full physical refresh at successful cold commit; no invented hit or comparison')
    need(x[20:24]==[x[11]+2*delta,int(good),1,0 if good else 302],'real retained continuation or unchanged failed borrow')
    need(v['cleanup']==[1,2,int(good)],'actual complete mapping/FD cleanup with truthful release')
    a,reads,eof,closed,size=v['io']
    need(a==eof==closed>=x[15]and reads>=2*a and size>0,'every actual physical read reaches EOF and closes')
    return v

def controls(stdout,stderr,exit_status,mode,differential):
    value=check(stdout,stderr,exit_status,mode,differential);trials=[]
    def encoded(x):return json.dumps(x,separators=(',',':')).encode()+b'\n'
    for i in range(24):
        x=copy.deepcopy(value);x['values'][i]^=1;trials.append((encoded(x),stderr,exit_status))
    x=copy.deepcopy(value);x['version']=True;trials.append((encoded(x),stderr,exit_status))
    x=copy.deepcopy(value);del x['cleanup'];trials.append((encoded(x),stderr,exit_status))
    x=copy.deepcopy(value);x['extra']=0;trials.append((encoded(x),stderr,exit_status))
    trials.extend([(stdout[:-2]+b',"version":1}\n',stderr,exit_status),
        (stdout[:-1],stderr,exit_status),(stdout,b'x',exit_status),
        (stdout,stderr,exit_status^1),(b' '*4097,stderr,exit_status)])
    need(len(trials)==CONTROL_COUNT,'all fixed supplied refusals')
    for out,err,status in trials:
        caught=False
        try:check(out,err,status,mode,differential)
        except ValueError:caught=True
        need(caught,'complete checker refuses actual supplied mutation')
    return {'refusals':CONTROL_COUNT,'native_operations':0}
