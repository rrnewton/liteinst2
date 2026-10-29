"""Two genuine SLOW paths; exact closed TRACE and natural NX, no run credit."""
from page_selected import need
from page_selected_maps_record import unpack
from page_selected_chain_record import REGS,RF,TF,u,equal_state,live,startup
from page_selected_trace_run_record import snapshot,event,release,slot,zero,query,uc_edit


def closed(r,l,layout):
    pc,s=r['pc'],r['run_pc'];n=r['native'][0]
    event(l['before'],'nx',pc,0x247|RF,layout);equal_state(l['before']['state'],n['before']['state'])
    event(l['trace'],'trace',s,0xa96|TF,layout);equal_state(l['trace']['state'],n['after']['state'])
    event(l['closed'],'trace',s,0xa96,layout);event(l['input'],'trace',s,0xa96,layout)
    uc_edit(l['trace'],l['closed'],layout,17,0xa96)
    need(l['closed']==l['input'],'the SLOW decision preserves the whole actual post-predecessor snapshot')
    c=l['closed_chain'];o=l['offered']
    need(c['initialized']==1 and c['first_error']==c['first_detail']==c['pending']==c['in_handler']==0 and
         not c['entry']['valid'] and o['issued']==1 and o['previous'] in (0,1) and o['next']==c['active']==o['previous']^1 and
         o['event_id']==c['event_id']>0 and o['pc']==s and o['flags']==0xa96 and
         all(o[k]==0 for k in ('consume_attempted','consumed','preflight_skipped','miss_released','run_borrow','result')),
         'actual opaque offer only at closed predecessor/OLD_STEP fallback')
    p,q=c['slots'][o['previous']],c['slots'][o['next']]
    need(p['phase']==5 and q['phase']==6 and q['fallback']==4 and p['generation']==o['previous_generation']>0 and
         q['generation']==o['next_generation']>0 and q['event_id']==o['event_id'],
         'exact prior/successor slot generations and fallback identity')
    for slot,seq in ((p,o['previous_borrow']),(q,o['next_borrow'])):
        need(slot['release']==dict(started=1,complete=1,result=0) and slot['fetch']['ref']['sequence']==seq and
             slot['fetch']['ref']['owner']>0,'both actual source owners and complete release callbacks')
        release(slot['fetch']['progress'],seq)
        need(slot['fetch']['pid']==slot['fetch']['tid']==r['pid'] and slot['fetch']['identity_observed']==1,
             'actual source borrow belongs to recorded singleton')
        at=pc if slot is p else s
        need(slot['fetch']['pc']==at and slot['fetch']['length']==15 and slot['fetch']['page_count']==1 and
             slot['fetch']['bytes']==r['literal'][at-r['mapping']:at-r['mapping']+15] and
             slot['fetch']['pages'][0]['address']==r['mapping'] and
             slot['fetch']['pages'][0]['closed_prot']==1 and slot['fetch']['pages'][0]['logical']==5 and
             slot['fetch']['pages'][0]['allocation']>0 and slot['fetch']['pages'][0]['generation']>0 and
             zero(slot['fetch']['pages'][1]), 'actual whole original held-source copy and one closed page')
    step=p['owner']['step']
    need(step['phase']==5 and not step['first_error'] and step['trace_seen']==1 and
         step['after']==l['trace']['state']['frame'] and p['owner']['actual_post_pc']==s and
         p['owner']['actual_post_flags']==0xa96|TF,'complete original predecessor frame retained in its owner')
    query(p['query'],s)
    need(step['request']['page_count']==1 and step['open_started']==step['opened']==step['revoke_started']==step['revoked']==[1,0] and
         step['open_result']==step['revoke_result']==[0,0] and step['open_sync']==step['revoke_sync']==0 and
         step['revoke_sync_started']==1,'predecessor original source actually opened, synchronized and revoked once')
    need(q['owner']['step']['phase']==0 and q['decoded']['pc']==s and q['decoded']['kind']==0 and
         q['decoded']['step_disposition']==1 and q['prepare_attempted']==q['prepare_complete']==
         q['decode_attempted']==q['decode_complete']==1 and q['prepare_result']==q['decode_result']==0,
         'actual unentered old-step successor, no manufactured source description')

def native_prefix(r,layout):
    n=r['native'][0];before=n['before']['state'];after=n['after']['state']
    need((n['started'],n['complete'],n['fault'],n['events'],n['start'],n['stop'])==
         (1,1,0,2,r['pc'],r['run_pc']),'one actual independent predecessor interval')
    event(n['before'],'nx',r['pc'],0x247|RF,layout)
    event(n['after'],'int3',r['run_pc']+1,0xa96,layout);release(n['released'])
    values=[(0x123456789abcdef+0x101010101010101*i)&((1<<64)-1) for i in range(16)]
    values[0]=0x7fffffffffffffff;values[4]=r['subject_address']+4096
    values[6]=r['data_address'];values[7]=r['data_address']+8
    need([u(before['frame']['greg'][x]) for x in REGS]==values,'literal full native ADD inputs')
    values[0]=0x8000000000000000
    need([u(after['frame']['greg'][x]) for x in REGS]==values,'independent literal ADD overflow before any MOV')
    for s in (before,after):
        need(s['stack']==bytes((i*29+11)&255 for i in range(8192)) and
             s['data']==bytes((i*17+3)&255 for i in range(4096)), 'entire original private memory seed retained')
    need(before['frame']['fp']==after['frame']['fp'] and before['frame']['mask']==after['frame']['mask'] and
         before['frame']['greg'][18]==after['frame']['greg'][18] and before['fs']==after['fs'] and before['gs']==after['gs'],
         'native predecessor preserves complete FP, selectors, bases and signal mask')
    lane=dict(before=before,after=after,live=n['live'],fp=n['fp']);live(lane,lane,[0x247,0xa96],r['xsave_bytes'])
    need(all(zero(x) for x in r['native'][1:]),'no invented additional native references')


def plan(p,pc,source,immediate,positive):
    count=2 if positive else 1;length=7 if positive else 5
    need(p['policy']==1 and p['decoder_result']==0 and p['pc']==pc and p['source_length']==15 and
         p['source']==source and p['instruction_count']==count and p['run_length']==length,
         'unchanged planner actual full source and exact eligible population')
    first=p['instructions'][0]
    need((first['code'],first['offset'],first['length'],first['effect'],first['destination'],first['source'],first['width'],first['immediate'])==
         (357,0,5,1,0,16,32,immediate),'literal MOV EAX immediate descriptor')
    if positive:
        second=p['instructions'][1]
        need((second['code'],second['offset'],second['length'],second['effect'],second['destination'],second['source'],second['width'],second['immediate'])==
             (281,5,2,2,1,0,32,0),'literal dependent MOV ECX,EAX descriptor')
        code=source[:7]+bytes.fromhex('ff2500000000')+(pc+7).to_bytes(8,'little')+bytes(8)
        need(p['stop']==pc+7 and p['generated_length']==21 and p['generated']==code,
             'unchanged positive two-MOV plan and original guard address')
    else:
        need(p['stop']==p['generated_length']==0 and zero(p['generated']),
             'one eligible instruction is descriptive SLOW before generated-code construction')
    need(all(zero(x) for x in p['instructions'][count:]) and p['guard']==dict(pc=pc+length,
         next_pc=pc+length+2,abi_version=1,decode_status=0,code=7,kind=0,destination=16,width_bits=0,
         step_disposition=1,available=15-length,length=2,reserved=0,bytes=source[length:]+bytes(1+length)),
         'exact unexecuted guard/full tail and no extra planned instruction')


def maps_io(p):
    need(set(p)==set('fd last_read close_result bytes rows opened close_started closed'.split()) and
         p['opened']==p['close_started']==p['closed']==1 and p['fd']>=0 and
         p['last_read']==p['close_result']==0 and 0<p['bytes']<256<<10 and 0<p['rows']<=2048,
         'complete original direct maps I/O, including EOF and successful close')


def private_query(q,first,length,prot):
    need(q['attempted']==q['complete']==1 and q['first']==first and q['end']==first+length and
         q['expected_prot']==q['actual_prot']==prot and q['pages_checked']==length//4096 and
         q['result']==q['detail']==0 and q['first_vma']<=first<first+length<=q['last_vma_end'],
         'actual complete private mapping query covers the full requested interval')
    maps_io(q['maps'])


def prepared(p,sequence):
    need(p['held']==p['complete']==p['identity_observed']==1 and p['first_error']==p['first_detail']==0 and
         p['sequence']==sequence and p['pages_copied']==1 and p['bytes_copied']==15 and
         p['validation_calls']==p['last_backing_page']==p['last_backing_observed']==0 and zero(p['validation']),
         'complete real initial source borrow before validation/release')
    maps_io(p['preparation'])


def publish_attempt(a,initial,sequence):
    need(a['pages_validated']==1 and a['view_result']==a['validation_result']==a['plan_result']==0,
         'actual publish view, page validation and independent replan all succeeded')
    held=a['fetch'];need(held==dict(initial,validation_calls=1,last_backing_observed=1,
         validation=held['validation']) and held['sequence']==sequence,
         'publication retains the exact fresh borrow plus its one actual validation')
    maps_io(held['validation'])


def released_after(p,held):
    release(p,held['sequence'])
    need(p==dict(held,held=0,validation_calls=held['validation_calls']+1,
         last_backing_observed=1,validation=p['validation']),
         'actual release changes only held state and the final complete validation')
    maps_io(p['validation'])


def publication(p,sequence,index):
    need(p['phase']==2 and p['first_error']==p['first_detail']==0 and p['allocation']==1 and
         p['generation']==index+1 and p['borrow_sequence']==sequence and p['entry']>0 and p['entry']%4096==0 and
         p['fill_bytes']==p['verified_bytes']==4096 and p['code_bytes']==21 and
         all(p[k]==1 for k in ('rw_checked','rx_started','rx_complete','sync_started','sync_complete')) and
         all(p[k]==0 for k in ('rx_result','sync_result','cleanup_started','cleanup_complete','cleanup_sync_started','cleanup_result','cleanup_sync_result')),
         'each real retained cache slot completed W^X, full verification and sync')
    for key,prot in (('before',3),('after',5)):
        private_query(p[key],p['entry'],4096,prot)
    need(zero(p['cleanup']),'no invented cleanup on a successful publication')


def cache(c,slots,attempts,misses):
    need(c['phase']==2 and c['slots_used']==c['complete_slots']==slots and c['attempts']==attempts and
         c['full_misses']==misses and c['hits']==0 and
         all(c[k]==0 for k in ('first_error','first_detail','interrupted','interrupted_again','interrupted_code','interrupted_detail')),
         'actual fixed cache population and complete no-error attempt totals')
    init=c['initialization'];need(all(init[k]==1 for k in ('metadata_started','metadata_complete',
         'allocation_started','allocated','arena_protection_started','arena_protection_complete','complete')) and
         init['arena']>0 and init['arena']%4096==0 and init['arena_bytes']==64*4096 and
         init['allocation_result']==init['arena'] and init['metadata_bytes']>0 and
         init['metadata_result']==init['arena_protection_result']==0 and zero(c['last_brk']),
         'same actual immutable original64-slot arena and complete protection registration')
    private_query(init['mapping'],init['arena'],64*4096,3)


def fills(r,s):
    old=r['native'][0]['released']['sequence'];first_entry=None;pages=None
    for i,f in enumerate(s['fills']):
        pc=r['mapping']+512+16*i;seq=f['ref']['sequence']
        need((f['started'],f['complete'],f['ordinal'])==(1,1,i) and f['ref']['owner']>0 and seq>old,
             'all64 actual publication attempts and strictly fresh source refs')
        p=f['prepared'];prepared(p,seq)
        page=f['pages'][0]
        need(page['address']==r['mapping'] and page['allocation']>0 and page['generation']>0 and
             page['closed_prot']==1 and page['logical']==5 and page['backing']==2 and
             page['vma_first']<=r['mapping']<r['mapping']+4096<=page['vma_end'] and
             all(page[k]==0 for k in ('vma_major','vma_minor','vma_inode','vma_offset')) and
             zero(f['pages'][1]) and f['backing'][0]['retained_fd']==-1 and
             zero(dict(f['backing'][0],retained_fd=0)) and zero(f['backing'][1]),
             'fixed original closed source page, never a synthetic source map')
        if pages is None:pages=f['pages']
        else:need(f['pages']==pages,'all fill sites retain the same actual unmodified source generation')
        source=r['literal'][pc-r['mapping']:pc-r['mapping']+15]
        plan(f['plan'],pc,source,i+1,True);publication(f['publication'],seq,i)
        slot(f['inspected'],f['plan'],f['publication'])
        if first_entry is None:first_entry=f['publication']['entry']
        need(f['publication']['entry']==first_entry+4096*i,'64 distinct consecutive actual immutable RX slots')
        cache(f['cache'],i+1,i+1,0);a=f['cache']['last_attempt']
        need(a['ordinal']==i+1 and a['borrow_sequence']==seq and a['slot']==i and
             a['installed']==a['source_complete']==a['plan_complete']==a['complete']==1 and
             a['hit']==a['miss_before_publication']==a['first_error']==a['first_detail']==0,
             'actual successful publish prefix, not execution or completion of a run')
        publish_attempt(a,p,seq);released_after(f['released'],a['fetch'])
        need(f['publication']['entry']==f['cache']['initialization']['arena']+4096*i,
             'actual slot belongs to the independently retained allocated arena')
        old=seq
    need(s['before_cache']==s['fills'][-1]['cache'] and s['fill_started']==s['fill_completed']==64 and
         r['lanes'][0]['offered']['previous_borrow']>old,
         'real full cache exists before genuine predecessor begins')
    return pages


def check(data,layout,mode,pid):
    need(type(mode)is int and mode in (0,1) and set(layout)=={'tr','samples','slow','frame'} and
         layout['samples']['kind']=='array' and layout['samples']['count']==21,'fixed additive two-mode layout')
    a=layout['tr']['bytes'];b=layout['samples']['element']['bytes']
    need(len(data)==a+b+layout['slow']['bytes']<16<<20,'whole actual base/startup/SLOW record extent')
    r=unpack(data,layout['tr']);startup(unpack(data,layout['samples']['element'],a));s=unpack(data,layout['slow'],a+b)
    need((r['magic'],r['version'],r['bytes'],r['mode'])==(0x3152554e5446324c,1,a,7+mode) and
         (s['magic'],s['version'],s['bytes'],s['mode'])==(0x31574f4c5352324c,1,layout['slow']['bytes'],mode) and
         r['complete']==s['complete']==1 and r['pid']==r['tid']==pid>0 and r['old_refusals']==47 and r['startup_pairs']==1 and
         r['native_completed']==1 and r['native_faults']==0 and r['consume_calls']==1 and
         all(r[k]==0 for k in ('fixture_failure','error','detail_abs','detail_negative','verified_failure',
                               'completed_runs','supplied_mutations','real_signals','guard_executed')),
         'completed observation envelope only; no generated run, failed operation or supplied signal credit')
    need(r['initial_stats']==r['final_stats'] and r['initial_stats']['phase']==2 and r['xcr0']&3==3 and
         576<=r['xsave_bytes']<=65536,'sealed decoder and actual full XSAVE extent')
    base=r['mapping'];pc=base+128;run=pc+4;guard=run+(7 if mode else 5)
    need(base>0 and base%4096==0 and (r['pc'],r['run_pc'],r['guard'])==(pc,run,guard) and
         all(r[k]>0 and r[k]%4096==0 for k in ('subject_address','data_address','fault_address')),
         'fixed original source and private-memory geometry')
    source=bytearray(b'\xcc'*12288);source[128:132]=bytes.fromhex('4883c001')
    body=bytes.fromhex('b87856341289c101c0' if mode else 'b87856341201c0');source[132:132+len(body)]=body
    if mode:
        for i in range(64):source[512+16*i:521+16*i]=b'\xb8'+(i+1).to_bytes(4,'little')+bytes.fromhex('89c101c0')
    need(r['literal']==source,'entire exact original literal image including all capacity source sites')
    reference=bytearray(source);reference[132]=0xcc
    need(r['reference_source'][0]==reference and all(zero(x) for x in r['reference_source'][1:]),
         'single independent native predecessor source with exact temporary end byte')
    native_prefix(r,layout['frame']);l=r['lanes'][0];closed(r,l,layout['frame'])
    need((l['started'],l['complete'],l['nx'],l['trace_events'],l['events'],l['returns'],l['reset'])==(1,0,2,1,3,3,0) and
         all(zero(l[k]) for k in ('redirected','complete_owner','publication','history_before','history_after')) and
         zero(r['lanes'][1]) and zero(r['final_owner']) and zero(r['history']) and zero(r['delivered']),
         'one real TRACE, natural NX and empty run owner/history with no redirect')
    c=l['closed_chain'];need(c['nx_entries']==c['steps']==c['attempts']==c['fallbacks']==1 and
         c['trace_entries']==0 and c['event_id']==4,'actual independent native then closed predecessor chronology')
    need(l['closed']==l['input'],'entire actual UC/SI/FP/stack/data unchanged through the SLOW decision')
    event(l['after'],'nx',run,0xa96|RF,layout['frame'])
    equal_state(l['after']['state'],r['native'][0]['after']['state'])
    need(u(l['after']['state']['frame']['greg'][13])==0x8000000000000000,'first MOV and its guard genuinely unexecuted')
    live(dict(before=l['before']['state'],after=l['after']['state'],live=l['live'],fp=l['fp']),
         dict(live=r['native'][0]['live'],fp=r['native'][0]['fp']),[0x247,0xa96],r['xsave_bytes'])
    need(s['preflight_started']==s['decision_complete']==s['natural_nx']==s['source_closed_checked']==1 and
         s['publication_pointer']==0 and all(s[k]==0 for k in ('consume_result','skip_result','release_result','verify_result')),
         'truthful completed decline with no installed publication or hidden error')
    q=c['slots'][l['offered']['next']]
    need(s['before_fetch']==q['fetch']['progress'],'preflight starts at actual released successor prefix')
    plan(s['descriptive'],run,r['literal'][132:147],0x12345678,bool(mode))
    need(q['decoded']==dict(pc=run,next_pc=run+5,abi_version=1,decode_status=0,code=357,kind=0,
         destination=16,width_bits=0,step_disposition=1,available=15,length=5,reserved=0,
         bytes=r['literal'][132:147]+b'\0'),
         'actual OLD_STEP successor decoder is the complete literal MOV descriptor')
    expected=dict(l['offered'],consume_attempted=1,consumed=1)
    if mode==0:
        need(s['preflight_result']==1 and s['skip_started']==1 and s['before_fetch']==s['after_fetch'] and
             s['before_cache']==s['after_cache'] and zero(s['fills']) and
             all(s[k]==0 for k in ('fill_started','fill_completed','fresh_started','publish_started','publish_result',
                                  'consume_started','release_started','release_complete','release_verified')) and
             zero(s['consumed_frame']) and zero(l['fresh']) and zero(l['plan']) and zero(l['published']),
             'actual preflight SLOW skips once without fresh borrow, publication or release')
        cache(s['after_cache'],0,0,0);need(zero(s['after_cache']['last_attempt']),
             'no publication attempt on descriptive preflight SLOW');expected['preflight_skipped']=1
    else:
        pages=fills(r,s)
        need(q['fetch']['pages']==pages and s['preflight_result']==s['skip_started']==0 and
             s['fresh_started']==s['publish_started']==s['consume_started']==s['release_started']==s['release_complete']==s['release_verified']==1 and
             s['publish_result']==1 and l['plan']==s['descriptive'],
             'actual full-cache SLOW after fresh positive replan, before any run owner')
        fresh=l['fresh'];prepared(fresh,fresh['sequence']);need(fresh['sequence']>l['offered']['next_borrow'],
             'new real held source for consumed capacity miss')
        snapshot(s['consumed_frame'],layout['frame']);need(s['consumed_frame']==l['closed'],
             'entire genuine TRACE remains unchanged immediately after proof consume')
        cache(s['after_cache'],64,65,1);attempt=s['after_cache']['last_attempt']
        need(attempt['ordinal']==65 and attempt['slot']==64 and attempt['borrow_sequence']==fresh['sequence'] and
             attempt['installed']==attempt['source_complete']==attempt['plan_complete']==attempt['miss_before_publication']==attempt['complete']==1 and
             attempt['hit']==attempt['first_error']==attempt['first_detail']==0 and l['published']==s['after_cache'],
             'actual65th attempt declines before any65th slot, preserving exact capacity64')
        expected.update(run_borrow=fresh['sequence'],miss_released=1)
        publish_attempt(attempt,fresh,fresh['sequence']);released_after(s['after_fetch'],attempt['fetch'])
        need(s['before_cache']['initialization']==s['after_cache']['initialization'],
             'capacity miss never replaces the original64-slot arena')
    need(l['consumed']==r['final_origin']==expected and r['final_chain']==dict(c,event_id=5) and
         r['cache']==l['finished']==s['after_cache'] and r['final_fetch']==l['final_fetch']==s['after_fetch'],
         'exact consume/skip/release observation survives handler return and natural NX')
    release(r['final_fetch'])
    return dict(operation='declined',preflight_slow=int(not mode),capacity_slow=mode,native_predecessors=1,
        completed_runs=0,copied_instructions=0,publications=64*mode,executed_publications=0,
        fresh_attempts=mode,skip_calls=int(not mode),consumed_fresh_releases=mode,
        genuine_traces=1,natural_nx=1,old_startup_pairs=1,old_refusal_checks=47,
        supplied_signals=0,generated_traces=0)


def controls(data,layout,mode,pid):
    """Eight violating supplied captures per actual case; no signal/native credit."""
    check(data,layout,mode,pid)
    roots={'tr':0,'slow':layout['tr']['bytes']+layout['samples']['element']['bytes']}
    def position(path):
        root,*parts=path;node=layout[root];at=roots[root]
        for part in parts:
            if isinstance(part,str):
                fields=[x for x in node['fields'] if x['name']==part]
                need(len(fields)==1,'unique actual supplied-mutation field')
                at+=fields[0]['offset'];node=fields[0]['type']
            else:
                need(node['kind']=='array' and 0<=part<node['count'],'actual supplied-mutation element')
                at+=part*node['element']['bytes'];node=node['element']
        return at
    paths=[None,('tr','literal',132),('tr','lanes',0,'after','state','frame','fp',160),
        ('tr','lanes',0,'after','state','stack',8191),('tr','native',0,'live',1,'gpr',0)]
    paths += [('tr','final_origin','preflight_skipped'),('slow','fresh_started'),
              ('slow','after_cache','last_attempt','installed')] if mode==0 else [
              ('slow','fills',63,'inspected','bytes',0),('slow','release_verified'),
              ('slow','after_fetch','held')]
    need(len(paths)==8,'fixed eight supplied violations per actual SLOW case')
    for index,path in enumerate(paths):
        altered=bytearray(data)
        if path is None:altered.pop()
        else:altered[position(path)]^=1
        try:check(bytes(altered),layout,mode,pid)
        except ValueError:pass
        else:raise ValueError('supplied violating SLOW record accepted: '+str(index))
    return len(paths)
