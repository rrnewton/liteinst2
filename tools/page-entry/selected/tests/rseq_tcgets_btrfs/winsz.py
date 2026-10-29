"""Fixed additive TIOCGWINSZ profile; original full gate/owner readers remain required."""
import importlib.util,struct
from pathlib import Path
from page_selected import need
_spec=importlib.util.spec_from_file_location('rtc_winsz_original_reports',Path(__file__).with_name('reports.py'))
base=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(base)
PAIRS=((0,False),)+tuple((i,True)for i in range(16))
LABEL=b'LI2_RSEQ_BTRFS_TTY_QUERY '
SCOPE='trusted_parent_capture_btrfs_tcgets_tiocgwinsz_v1'


def request(case,alternate):
    need(type(case)is int and 0<=case<20 and type(alternate)is bool,'fixed literal request case')
    return ({9:0x5412,10:0x5414,11:0x100005413,15:0x541b}.get(case,0x5413)if alternate else
            {9:0x5400,10:0x5402,11:0x100005401,15:0x541b}.get(case,0x5401))


def corpus(extra,original):
    expected=[]
    for ordinal,(case,alternate)in enumerate(PAIRS):
        row=dict(original['cases'][case]);row.update(ordinal=ordinal,request_profile=alternate,request=request(case,alternate))
        row['name']=('winsz-'if alternate else'combined-tcgets-')+row['name'];expected.append(row)
    need(extra==dict(version=1,pairs=expected,injected_refusals=[dict(index=15,case=0,request_profile=True,
        name='actual-winsz-enotty-supplied-zero',exit=125,actual_ioctl=1,frame_commits=0,command_completed=[0,0])],
        required_macro_off=dict(tcgets_pairs=20,tcgets_injected=16,oneshot_positive=6,oneshot_failures=49,
                               inactive_rseq=17,registered_native=16,registered_boundary=4),
        bounds=original['bounds'],planned_processes=35,planned_programs=18),
        'exact17 fixed same-ELF pairs plus one supplied result refusal; complete old cohort remains mandatory')


def reports(stderr,initial=False):
    need(type(initial)is bool and type(stderr)is bytes and stderr.endswith(b'\n'),'literal report route and complete actual stderr')
    lines=stderr[:-1].split(b'\n');at=[i for i,x in enumerate(lines)if x.startswith(LABEL)]
    need(len(at)==1 and at[0]>0 and lines[at[0]-1].startswith(b'LI2_RSEQ_BOUNDARY ')and len(lines[at[0]])+1<=4096,
         'one bounded explicit two-command row after original boundary row')
    at=at[0];row=base.decode.decode(lines[at][len(LABEL):])
    base.nx._unsigned(row,base.SCALARS,dict(base.ARRAYS,commands=3),SCOPE)
    rest=b'\n'.join(lines[:at]+lines[at+1:])+b'\n'
    parsed=base.initial_reports(rest)if initial else base.old.reports(rest)
    need(all(row[k]==parsed['loader'][k]for k in base.SCALARS-{'version'}),'same actual terminal outcome including failure')
    p=row['prefix'];q=row['query'];m=row['mount'];commands=row['commands']
    need(p[0]in(0,1)and p[1]in(0,1)and p[2]<=8 and p[5]in(0,1)and
         p[11]<=p[10]<=p[9]<=p[8]<=p[7]and q[1]<=q[0]<=1 and all(q[k]in(0,1)for k in(4,6))and
         all(m[k]in(0,1)for k in(0,1,2,3,4,6,8))and m[9]<=256*1024 and m[10]<=2048 and m[11]<=1,
         'truthful typed gate/query/mount partial progression')
    need(commands[0]+commands[1]==p[11]and commands[2]in(0,0x5401,0x5413),
         'complete exact per-command counts and retained checked request')
    parsed['tcgets']=row;return parsed


def completed(parsed,pid):
    base.completed(parsed,pid)
    c=parsed['tcgets']['commands']
    need(c==([1,0,0x5401]if c[2]==0x5401 else[0,1,0x5413]),
         'one finite validated actual command, not merely permission')


def counters(r,data,image,baseline):
    st='li2_tcgets_state';shape=r.types[st]
    need(type(baseline)is dict and baseline['bytes']==279832 and 'command_completed'not in baseline['fields']and
         shape==dict(bytes=baseline['bytes']+16,fields=dict(baseline['fields'],command_completed=dict(offset=baseline['bytes'],bytes=16))),
         'all original actual macro-off DWARF fields exact, only two appended64-bit command counters')
    states=r.field(data,r.rt,'stages');size=shape['bytes']
    need(len(states)==7*size,'complete actual seven gate states')
    case=image['case'];injected=image['injected'];alternate=image.get('request_profile',False)
    need(type(case)is int and (case,alternate)in PAIRS and type(alternate)is bool and
         type(injected)is int and injected in(0,15)and (not injected or case==0 and alternate),
         'only fixed new pair or result-injection identity')
    successful=case<7 and not injected
    expected=([0,1]if alternate else[1,0])if successful else[0,0]
    for i in range(7):
        state=states[i*size:(i+1)*size]
        actual=list(struct.unpack('<2Q',r.field(state,st,'command_completed')))
        need(actual==(expected if i in(5,6)and successful else[0,0]),
             'actual counters remain zero through returned raw result; increment only after validation')
        need(sum(actual)==r.integer(state,st,'completed'),'each actual stage command counts equal aggregate validation count')
    end=states[6*size:7*size];args=struct.unpack('<6Q',r.field(end,st,'args'))
    need(args[1]==(request(case,alternate)if successful or injected else 0),
         'retained accepted-check request, no stale-argument attribution for precondition refusal')
    return expected


def join(parsed,r,data,pid,image,baseline):
    base.join(parsed,r,data,pid)
    counts=counters(r,data,image,baseline)
    size=r.types['li2_tcgets_state']['bytes'];state=r.field(data,r.rt,'stages')[6*size:7*size]
    args=struct.unpack('<6Q',r.field(state,'li2_tcgets_state','args'))
    need(parsed['tcgets']['commands']==counts+[args[1]],'full additive report joins actual terminal counters/retained request')
    return counts
