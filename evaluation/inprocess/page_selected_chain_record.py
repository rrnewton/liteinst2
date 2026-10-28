"""Finite three-lane replay; actual retained executable DWARF supplies extents.

No native execution, synthetic frame or timing acceptance is implemented here.
The parent must authenticate the ELF/layout/source/capture before calling check.
"""
from page_selected import need
from page_selected_maps_record import unpack

REGS=[13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7]
TF=0x100
RF=0x10000
MASK=(1<<64)-1
COUNTS=[3,3,3,3,4,7,2,3,2,3,3,4]
OFFSETS=[4093,4094,4092,4094,4094,4092,4093,4091,4094,4092,4092,4092]
ENCODINGS=['4801d84883f001e900000000','4801d84883f001e900000000',
 '660fefc7660f74c7e900000000','660fefc7660f74c7e900000000',
 '488b064801d8488907e900000000','4883e90175fae900000000','4801d8ffe2',
 'e800000000','0fa24983c001e900000000','eb0248b80fa24983c001e900000000',
 '4883c0014889c14883c001e900000000','4983c0010f01d04983c001e900000000']
TAIL=[7,7,8,8,9,6,None,None,6,10,11,11]
ERRORS=[0,7,101,6,6,903,10,11,12,7,7,906]


def u(n):return n&MASK


def frame(f):
    need(len(f['greg'])==23 and f['initialized']==f['fp_bytes'] and
         512<=f['fp_bytes']<=65536 and f['fp_address'] and f['fp_address']%16==0,
         'actual complete kernel frame')


def equal_state(a,b):
    frame(a['frame']);frame(b['frame'])
    need([u(a['frame']['greg'][x]) for x in REGS]==[u(b['frame']['greg'][x]) for x in REGS],
         'all sixteen actual GPRs')
    need(a['stack']==b['stack'] and len(a['stack'])==8192 and
         a['data']==b['data'] and len(a['data'])==4096 and a['fs']==b['fs'] and a['gs']==b['gs'],
         'whole target stack/redzone/data and FS/GS')
    need(a['frame']['mask']==b['frame']['mask'] and
         a['frame']['greg'][18]==b['frame']['greg'][18] and
         a['frame']['fp_bytes']==b['frame']['fp_bytes'] and a['frame']['fp']==b['frame']['fp'],
         'whole initialized kernel FP and retained unused tail, mask and CSGSFS')


def live(lane,native,flags,xsave):
    for i,state in enumerate((lane['before'],lane['after'])):
        f=state['frame'];v=lane['live'][i]
        need(v['started']==v['complete']==1 and not v['reserved'] and
             v['gpr']==[u(f['greg'][x]) for x in REGS] and v['rflags']==flags[i],
             'independent actual user capture before/after sigreturn')
        need(len(v['selectors'])==6 and v['selectors']==native['live'][0]['selectors'] and
             v['selectors'][0]==(u(f['greg'][18])&0xffff) and v['selectors'][1]==(u(f['greg'][18])>>48),
             'all six live segment selectors')
        need(lane['fp'][i]==native['fp'][i] and len(lane['fp'][i])==65536 and
             not any(lane['fp'][i][xsave:]), 'complete actual standard XSAVE plus zero unused extent')


def query(q,pc):
    need(q['attempted']==q['page_observed']==q['complete']==1 and q['result']==0 and q['pc']==pc and
         q['page']['closed_prot']==1 and q['page']['logical']==5 and q['page']['allocation']>0 and
         q['page']['generation']>0, 'actual closed owned continuation query')


def startup(s):
    need(s['id']==0 and s['selftest']==s['checked']==s['native_complete']==s['step_endpoint_seen']==1 and
         not s['native_fault'] and s['owner']['step']['phase']==5 and not s['owner']['step']['first_error'],
         'unchanged genuine native/NOP startup selftest')
    equal_state(s['native_before'],s['step_before']);equal_state(s['native_after'],s['step_endpoint'])
    need(s['initial_flags']==s['post_flags'] and s['native_before']['stack']==s['native_after']['stack'] and
         s['native_before']['data']==s['native_after']['data'], 'startup no-op state')


def check(data,layout,case_id,mode):
    need(type(case_id)is int and 0<=case_id<12 and type(mode)is int and 0<=mode<=11 and
         set(layout)=={'li2_chain_record','samples','ctl'}, 'closed case/layout')
    need(layout['samples']['kind']=='array' and layout['samples']['count']==21, 'actual old sample array')
    sizes=[layout['li2_chain_record']['bytes'],layout['samples']['element']['bytes'],layout['ctl']['bytes']]
    need(sum(sizes)==len(data)<16<<20, 'exact entire record, startup and control trailer')
    r=unpack(data,layout['li2_chain_record'])
    s=unpack(data,layout['samples']['element'],sizes[0]);ctl=unpack(data,layout['ctl'],sizes[0]+sizes[1])
    need(r['magic']==0x314e48434649324c and r['version']==1 and r['record_bytes']==sizes[0] and
         r['header_bytes']==next(x['offset'] for x in layout['li2_chain_record']['fields'] if x['name']=='source') and
         r['case_id']==case_id and r['mode']==mode and ctl['bytes']==sizes[2] and ctl['mode']==mode and
         r['fixture_failure']==0 and r['refusals']==47 and r['route_controls']==15,
         'actual full record identity/outcome/refusal facts')
    need(r['initial_stats']==r['final_stats'] and r['initial_stats']['phase']==2 and
         576<=r['xsave_bytes']<=65536 and r['xcr0']&3==3, 'sealed decoder and actual qualified XSAVE envelope')
    startup(s)
    base=r['mapping'];pc=base+OFFSETS[case_id];stop=base+(4096 if case_id==7 else 8192)
    need(base>0 and base%4096==0 and r['pc']==pc and r['stop']==stop and r['callee']==base+8256 and
         len(r['source'])==12288 and r['source'][stop-base:stop-base+2]==b'\x0f\x0b', 'literal NX endpoint and source allocation')
    code=bytearray.fromhex(ENCODINGS[case_id]);tail=TAIL[case_id]
    if tail is not None:code[tail+1:tail+5]=(stop-(pc+tail+5)).to_bytes(4,'little',signed=True)
    if mode==1:code[:6]=bytes.fromhex('4801d8488b06')
    if case_id==7:code[1:5]=(r['callee']-(pc+5)).to_bytes(4,'little',signed=True)
    need(r['source'][pc-base:pc-base+len(code)]==code, 'literal original instruction stream and original branch addresses')
    if case_id==7:need(r['source'][8256:8260]==bytes.fromhex('4801d8c3'), 'literal actual callee and RET')
    if mode:return failure(r,ctl,case_id,mode)
    need(r['completed_lanes']==3 and not r['owner_failure'] and not r['verified_failure'] and
         not ctl['verified'] and r['chain']['first_error']==0 and r['chain']['pending']==0 and
         r['chain']['entry']['valid']==0 and r['final_fetch']['held']==r['final_fetch']['first_error']==0,
         'complete three lanes with no hidden failed or pending owner')
    n=r['lanes'][0];flags=[u(n['before']['frame']['greg'][17])&~RF,n['flags']]
    need(not flags[0]&(RF|TF) and not flags[1]&(RF|TF), 'known input and successful flags remain TF/RF clear')
    for i,l in enumerate(r['lanes']):
        need(l['started']==l['complete']==l['checked']==1 and not l['fault'] and
             2<=l['event_count']<=24 and l['returns']==l['event_count'], 'actual completed lane and returns')
        equal_state(l['before'],n['before']);equal_state(l['after'],n['after'])
        need(l['before']['frame']['greg'][16]==pc and l['after']['frame']['greg'][16]==stop and
             u(l['before']['frame']['greg'][17])==flags[0]|RF and
             u(l['after']['frame']['greg'][17])==flags[1]|RF and l['flags']==flags[1],
             'same original endpoint PC and whole flags, authentic NX RF only')
        live(l,n,flags,r['xsave_bytes'])
        selected=int(case_id in (8,9));old=int(i==2 and case_id==10)
        total=COUNTS[case_id]+int(case_id==10)
        need(l['selected']==(selected if i else 0) and l['old']==old and
             l['completed_instructions']==(total-old if i else 0) and l['traces']==(total if i else 0),
             'literal actual generic/selected/old instruction counts')
        nx=2 if not i else total+selected+1 if i==1 else (4 if case_id in (9,10) else 3 if case_id in (8,11) else 2)
        need(l['nx']==nx and l['event_count']==l['nx']+l['traces'], 'actual event counts, no fabricated NX')
        for j,e in enumerate(l['events'][:l['event_count']]):
            f=e['actual']['frame'];frame(f)
            need(e['ordinal']==j+1 and e['pc']==u(f['greg'][16]) and e['flags']==u(f['greg'][17]) and e['error']==0,
                 'retained actual event frame and siginfo')
            if e['signal']==11:
                need(e['code']==2 and f['greg'][19:21]==[21,14] and e['address']==e['pc'] and
                     e['flags']&RF and not e['flags']&TF, 'genuine NX event')
            else:
                need(e['signal']==5 and e['code']==2 and f['greg'][19:21]==[0,1] and
                     e['address']==e['pc'] and e['flags']&TF and not e['flags']&RF,
                     'genuine CPU TRACE, never relabelled NX')
                if e['origin']:
                    pages=2 if e['decoded']['pc']//4096!=(e['decoded']['next_pc']-1)//4096 else 1
                    mask=(1<<pages)-1
                    need(e['owner_phase']==5 and not e['owner_error'] and e['trace']==1 and
                         e['open']==e['opened']==e['revoke']==e['revoked']==mask and
                         e['release_started']==e['release_complete']==1 and not e['fetch']['held'] and
                         not e['fetch']['first_error'], 'retained actual completed owner cycle and source release')
                    query(e['query'],e['pc'])
        need(all(e['ordinal']==0 for e in l['events'][l['event_count']:]), 'no invented unused events')
    separate=int(case_id in (9,10,11));c=r['chain']
    need(c['nx_entries']==1+separate and c['trace_entries']==COUNTS[case_id]-1-separate and
         c['steps']==c['attempts']==COUNTS[case_id] and c['fallbacks']==1+separate,
         'exact source-NX versus genuine-TRACE entry totals')
    for slot in c['slots']:
        need(slot['release']['started']==slot['release']['complete']==1 and slot['release']['result']==0 and
             not slot['fetch']['progress']['held'] and not slot['fetch']['progress']['first_error'],
             'both retained slots released their own actual borrowed source')
        if slot['phase']==5:query(slot['query'],slot['owner']['actual_post_pc'])
        else:need(slot['phase']==6 and slot['fallback']!=0, 'distinct descriptive terminal fallback')
    literal(r,case_id)
    return dict(operation='completed',programs=1,lanes=3,old_startup_pairs=1,refusal_bytes=47,route_controls=15,
                nx=[l['nx'] for l in r['lanes']],trace=[l['traces'] for l in r['lanes']],
                genuine_trace_entries=c['trace_entries'],selected_callbacks=r['lanes'][2]['selected'])


def literal(r,case):
    n=r['lanes'][0];a=n['before']['frame']['greg'];b=n['after']['frame']['greg']
    if case in (0,1):need(u(b[13])==((u(a[13])+u(a[11]))&MASK)^1, 'literal ADD then XOR')
    if case in (2,3):
        x=n['fp'][0][160:176];y=n['fp'][0][272:288]
        need(n['fp'][1][160:176]==bytes(255 if (p^q)==q else 0 for p,q in zip(x,y)), 'literal PXOR/PCMPEQB lanes')
    if case==4:
        v=(int.from_bytes(n['before']['data'][:8],'little')+u(a[11]))&MASK
        need(u(b[13])==v and int.from_bytes(n['after']['data'][8:16],'little')==v, 'literal load/ADD/store')
    if case==5:need(b[14]==0 and n['flags']&0x40, 'three real SUB/JNZ iterations')
    if case==7:
        need(b[15]==a[15] and int.from_bytes(n['after']['stack'][4088:4096],'little')==r['pc']+5 and
             r['lanes'][1]['call_return_checked']==r['lanes'][2]['call_return_checked']==1,
             'actual original CALL return word and observed unexecuted NX return page')


def failure(r,ctl,case,mode):
    c=r['chain'];slot=c['slots'][c['active']];o=slot['owner']['step'];code=ERRORS[mode]
    need(r['verified_failure']==ctl['verified']==1 and r['owner_failure']==c['first_error']==code and
         not r['lanes'][2]['complete'] and r['completed_lanes']==0 and not c['entry']['valid'] and
         ctl['mode']==mode and slot['phase']==7, 'actual failed operation, no completion credit')
    if mode in (1,2):
        n=r['lanes'][0];f=slot['unexpected'] if mode==1 else o['after'];frame(f)
        need(n['started']==n['fault']==1 and not n['complete'] and n['event_count']==2 and n['returns']==2,
             'independent native failed-operation observation, not native successful continuation')
        need([u(f['greg'][x]) for x in REGS]==[u(n['after']['frame']['greg'][x]) for x in REGS] and
             u(f['greg'][17])&~TF==u(n['after']['frame']['greg'][17]) and
             f['mask']==n['after']['frame']['mask'] and f['greg'][18]==n['after']['frame']['greg'][18] and
             f['fp_bytes']==n['after']['frame']['fp_bytes'] and f['fp']==n['after']['frame']['fp'],
             'full actual failed-frame GPR/flags/kernel FP with owned TF distinction')
        actual=r['lanes'][2]['events'][r['lanes'][2]['event_count']-1]['actual']
        equal_state(actual,n['after'])
        need(actual['frame']['greg']==f['greg'] and actual['frame']['fp']==f['fp'],
             'independent whole handler capture equals retained failed owner frame')
        if mode==1:need(slot['unexpected_frame_observed']==1 and not o['trace_seen'] and
             f['greg'][16]==r['pc']+3 and f['greg'][19:21]==[4,14] and slot['origin']==2 and c['steps']==1, 'genuine operand #PF retained')
        else:need(o['trace_seen']==1 and slot['owner']['actual_post_pc']==ctl['unowned'] and
             slot['query']['attempted']==1 and not slot['query']['complete'] and slot['query']['result']!=0 and
             n['after']['frame']['greg'][16]==ctl['unowned']+1 and n['after']['frame']['greg'][19:21]==[0,3],
             'failed owned-continuation query versus explicit native INT3 diagnostic')
    if mode in (3,4,5):need(ctl['issued_effects']==1 and not ctl['injected_returns'], 'real mutation/alias/generation effect')
    if mode==3:
        original=r['source'][r['pc']-r['mapping']:r['pc']-r['mapping']+15]
        need(ctl['effects'][0:2]==[0,0] and slot['fetch']['progress']['first_error']!=0 and
             ctl['changed_source']==bytes([original[0]^1])+original[1:], 'actual COW bytes and source-integrity refusal')
    if mode==4:need(ctl['alias']>0 and ctl['effects'][0]==ctl['alias'] and ctl['alias_prot']==3 and slot['fetch']['progress']['first_error']!=0,
                      'real writable sealed-backing alias refused')
    if mode==5:need(ctl['effects'][0]==0 and ctl['effects'][1]==r['mapping'] and
        ctl['before_ref']['sequence']!=ctl['after_ref']['sequence'] and
        ctl['before_page']['generation']!=ctl['after_page']['generation'] and not any(o['open_started']),
        'genuine same-address lifecycle generation replacement, exact stale reference refused')
    if mode in (6,7,8):need(ctl['injected_returns']==1 and ctl['pending_raw']==ctl['raw_complete']==1 and
        not ctl['raw_issued'] and ctl['returned_result']==(-13 if mode==6 else -5) and
        c['first_detail']==ctl['returned_result'], 'explicit nonissued negative raw result, never hardware-labelled')
    if mode in (9,10):
        frame(ctl['delivered']['frame'])
        need(ctl['signal_count']==ctl['pending_raw']==slot['unexpected_frame_observed']==1 and
             not ctl['raw_issued'] and not ctl['raw_complete'] and ctl['signal']==5 and ctl['error']==0,
             'genuine pending nested event, original open not issued')
        if mode==9:need(ctl['code']==-6 and ctl['sender_pid']==ctl['expected_pid']>0 and
                           ctl['sender_uid']==ctl['expected_uid'] and 0<=ctl['sender_uid']<=0xffffffff,
                           'actual SI_TKILL bound to independently retained PID and raw UID')
        else:need(ctl['code']==128 and ctl['delivered']['frame']['greg'][19:21]==[0,3], 'actual INT3, not TRAP_TRACE')
    if mode==11:need(ctl['replay_attempts']==1 and not ctl['replayed']['valid'] and c['steps']==1 and
         not any(o['open_started']) and c['slots'][c['active']^1]['release']['complete']==1,
         'actual consumed proof replay fails before opening successor')
    for i,opened in enumerate(o['open_started']):
        if opened:
            need(o['revoke_started'][i]==o['revoke_sync_started']==1, 'actual cleanup attempt retained')
            if mode==8:need(o['revoke_result'][i]==-5 and not o['revoked'][i] and ctl['cleanup_prot'][i]==5, 'failed revoke remains failed')
            else:need(o['revoke_result'][i]==0 and o['revoked'][i]==1 and ctl['cleanup_prot'][i]==1, 'real successful cleanup')
    return dict(operation='failed',completed=0,expected_failure_verified=True,owner_error=code,
                native_failed_observations=int(mode in (1,2)),old_startup_pairs=1,refusal_bytes=47,route_controls=15,
                real_effects=ctl['issued_effects'],nonissued_negative_returns=ctl['injected_returns'],real_signals=ctl['signal_count'])
