"""A separate gate row; every reached old completion predicate is unchanged."""
import importlib.util
from pathlib import Path
from page_selected import need
import page_selected_rseq_compare as decode
_SPEC=importlib.util.spec_from_file_location('rtc_boundary_reports',Path(__file__).resolve().parent.parent/'rseq_native_boundary/reports.py')
old=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(old)
native=old.old;nx=native.old
SCALARS=set('version status failure_code detail_abs detail_negative'.split())
ARRAYS=dict(prefix=15,launch=7,current=7,query=7,mount=12)


def reports(stderr,initial=False):
    need(type(initial)is bool and type(stderr)is bytes and stderr.endswith(b'\n'),'literal report route and complete actual stderr')
    lines=stderr[:-1].split(b'\n');at=[i for i,x in enumerate(lines)if x.startswith(b'LI2_RSEQ_TCGETS ')]
    need(len(at)==1 and at[0]>0 and lines[at[0]-1].startswith(b'LI2_RSEQ_BOUNDARY ')and len(lines[at[0]])+1<=4096,
         'one bounded TCGETS row after original boundary row')
    at=at[0];row=decode.decode(lines[at][len(b'LI2_RSEQ_TCGETS '):]);nx._unsigned(row,SCALARS,ARRAYS,'trusted_parent_capture_btrfs_tcgets_v1')
    rest=b'\n'.join(lines[:at]+lines[at+1:])+b'\n'
    parsed=initial_reports(rest)if initial else old.reports(rest)
    need(all(row[k]==parsed['loader'][k]for k in SCALARS-{'version'}),'same actual terminal outcome including failure')
    p=row['prefix'];q=row['query'];m=row['mount']
    need(p[0]in(0,1)and p[1]in(0,1)and p[2]<=8 and p[5]in(0,1)and
         p[11]<=p[10]<=p[9]<=p[8]<=p[7]and q[1]<=q[0]<=1 and all(q[k]in(0,1)for k in(4,6))and
         all(m[k]in(0,1)for k in(0,1,2,3,4,6,8))and m[9]<=256*1024 and m[10]<=2048 and m[11]<=1,
         'truthful typed gate/query/mount partial progression')
    parsed['tcgets']=row;return parsed


def initial_reports(stderr):
    """New pre-entry failure shape, never an old successful-parser exception."""
    lines=stderr[:-1].split(b'\n');parts=[x.partition(b' ')for x in lines]
    names=[b'LI2_LOADER',b'LI2_NATIVE',b'LI2_CPUID_NX',b'LI2_RSEQ',b'LI2_RSEQ_NATIVE',b'LI2_RSEQ_BOUNDARY',b'LI2_RUN']
    need([p[0]for p in parts]==names and all(p[1]==b' 'and 0<len(p[2])<4096 for p in parts),
         'complete exact pre-application report inventory without invented CHAIN/REP rows')
    d={name:decode.decode(body)for name,_,body in parts}
    l,n,c,r,rn,b,run=(d[k]for k in names)
    nx._unsigned(l,nx.generic.KEYS-{'scope'},scope='partial_selected_native_pages_cpuid_nx')
    nx._unsigned(n,nx.NATIVE_KEYS-{'revisit_ns'},{'revisit_ns':0})
    nx._unsigned(c,nx.NX_SCALARS,{'raw':4,'result':4})
    nx._unsigned(r,nx.RSEQ_SCHEMA['scalar_keys'],{k:len(v)for k,v in nx.RSEQ_SCHEMA['arrays'].items()},nx.RSEQ_SCHEMA['scope'])
    nx._unsigned(rn,native.SCALARS,{'before':28,'after':28},'registered_native_epochs')
    nx._unsigned(b,old.SCALARS,old.ARRAYS,'registered_current_pc_refault')
    arrays={k:v for k,v in nx.register.ARRAYS.items()if k not in('cache','initialization','attempt','publication')}
    nx._unsigned(run,nx.register.SCALARS,arrays)
    need(all(x['status']==125 and x['failure_code']==1207 for x in d.values()),'every real row retains initialization failure125/1207')
    need(all(l[k]==0 for k in('source_patches','selected_selftests','first_target_is_interpreter_entry','interpreter_entry_faults',
         'nx_faults','main_faults','interpreter_faults','dependency_faults','cpuid','rdtsc','rdtscp','rdrand','rdseed','rdpid',
         'generic_tf_attempts','generic_tf_steps','source_syscalls','vdso_close_attempted','vdso_close_observed','vdso_closed')),
         'initial gate failure precedes real first entry/selftest/source effects and vDSO closure')
    need(all(n[k]==0 for k in nx.NATIVE_KEYS-{'version','status','failure_code','revisit_ns','epoch_error','close_complete'})and n['revisit_ns']==[]and n['epoch_error']==1207 and n['close_complete']==1,
         'no native admission; terminal error and actual zero-page close remain distinct')
    need(c['hardware_entered']==c['hardware_returned']==1 and all(c[k]==0 for k in nx.NX_SCALARS-{'version','status','failure_code','hardware_entered','hardware_returned'})and
         c['raw']==c['result']==[0]*4,'pre-arm hardware occurred, no target CPUID dispatch')
    for x,scalars,arrays in((rn,native.SCALARS,{'before':28,'after':28}),(b,old.SCALARS,old.ARRAYS),
                             (run,nx.register.SCALARS,arrays)):
        need(all(x[k]==0 for k in scalars-{'version','status','failure_code','detail_abs','detail_negative'})and
             all(x[k]==[0]*size for k,size in arrays.items()),'no hidden owner/RUN progress on initial refusal')
    need(r['maps_profile']==1 and r['owner'][:7]==[1,0,0,0,1207,16,0]and
         r['owner'][7]>0 and r['owner'][7]==r['owner'][8]and r['owner'][9:]==[0]*5 and
         all(r[k]==[0]*len(v)for k,v in nx.RSEQ_SCHEMA['arrays'].items()if k!='owner'),
         'old rseq owner initialized but never registered, exact failure prefix')
    return dict(loader=l,native=n,cpuid_nx=c,rseq=r,rseq_native=rn,rseq_boundary=b,run=run,chain=None,repeat=None)


def completed(parsed,pid):
    old.completed(parsed,pid)
    s=parsed['tcgets'];p=s['prefix'];q=s['query'];m=s['mount']
    need(s['status']==s['failure_code']==0 and p[:7]==[1,0,7,0,0,0,0]and p[7:12]==[1]*5 and p[12]>0 and p[13]==1 and p[14]>0,
         'one actual gate permit/raw return/result validation with no invalidation')
    need(s['launch']==s['current']and q[:2]==[1,1]and q[5:]==[25,1]and m[:5]==[1]*5 and m[6:9]==[0,0,0]and m[9]>0 and m[10]>0 and m[11]==1,
         'complete actual inherited FD/current identity, -ENOTTY result and mount acquisition')


def join(parsed,r,data,pid):
    s=parsed['tcgets'];st='li2_tcgets_state';n=r.types[st]['bytes'];b=r.field(data,r.rt,'stages')[6*n:7*n];I=r.integer;F=r.field
    signed=lambda v:v-(1<<64)if v>>63 else v
    val=lambda k:I(b,st,k)
    absolute=lambda k:abs(signed(val(k)))
    negative=lambda k:int(signed(val(k))<0)
    expected=dict(prefix=[val(k)for k in('initialized','invalidated','phase','first_error')]+[absolute('first_detail'),negative('first_detail'),val('invalidated_number')]+
        [val(k)for k in('attempts','permitted','issued','returned','completed','queries','registration_epoch','syscall_check')],
        query=[val('query_attempted'),val('query_returned'),val('query_number'),absolute('query_result'),negative('query_result'),absolute('result'),negative('result')],
        mount=[val(k)for k in('mount_opened','mount_eof','mount_close_started','mount_closed','mount_complete')]+[absolute('mount_fd'),negative('mount_fd'),absolute('mount_close_result'),negative('mount_close_result')]+[val(k)for k in('mount_bytes','mount_rows','mount_matches')])
    for key in('launch','current'):expected[key]=[I(F(b,st,key),'li2_tcgets_identity',k)for k in('device','inode','mount_id','major','minor','mode','flags')]
    need(all(s[k]==v for k,v in expected.items()),'every new report scalar/array joins the actual terminal binary state')
    cl=r.field(data,r.rt,'terminal_close');h=__import__('struct').unpack('<64Q',r.field(data,r.rt,'h'))
    need(parsed['native']['epoch_error']==h[45]and parsed['native']['close_error']==I(cl,'li2_native_close','first_error')and
         parsed['native']['close_complete']==I(cl,'li2_native_close','complete')and parsed['native']['close_busy']==I(cl,'li2_native_close','busy'),
         'old native terminal report joins actual cleanup prefix without turning failure into success')
    owner=r.field(data,r.rt,'owners')[6*r.types['li2_rseq_state']['bytes']:]
    need(I(owner,'li2_rseq_state','pid')==I(owner,'li2_rseq_state','tid')==pid==parsed['rseq']['owner'][7]==parsed['rseq']['owner'][8],
         'actual binary/report rseq identity joins Popen PID')
