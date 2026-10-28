"""Strict saved-data protocol; full architecture remains enforced by the C oracle."""
import hashlib
import struct
from page_selected import need
from page_selected_chain_record import REGS,RF,TF,u,frame,equal_state,live,query,startup
from page_selected_maps_record import unpack

MASK=(1<<64)-1
ENCODINGS=('62b1754074c8','c4e1fb93c1','c4e2c8f3d6')
PROGRAM=bytes.fromhex('62b1754074c8c4e1fb93c1c4e2c8f3d64821f07407480fbdc04801f8c3')
NAMES=('magic','version','header_bytes','sample_bytes','pairs','completed','control','xcr0','xsave_bytes',
       'refusals','failed_refusal','decoder_result','expected_failure_verified','fixture_failure',
       'owner_failure','owner_detail_abs','owner_detail_negative')


def observations(data,group,checked,xcr0,size):
    need(len(data)==5176,'complete actual CPUID/XSAVE observations')
    h=struct.unpack_from('<8Q',data)
    need(h[:4]==(0x315452485356324c,1,5176,group) and h[5:]==(checked,xcr0,size),
         'actual observer header identity')
    rows=[struct.unpack_from('<6Q',data,64+48*i)for i in range(68)];basic,components=rows[:4],rows[4:]
    need([x[:2]for x in basic]==[(0,0),(1,0),(7,0),(13,0)] and
         all(all(v<1<<32 for v in row)for row in rows),'actual CPUID queries and32-bit outputs')
    need(basic[0][2]>=13 and basic[1][4]&0x1c000000==0x1c000000 and
         basic[2][3]&0x40010008==0x40010008,'actual XSAVE/OSXSAVE/AVX/AVX512F/BW/BMI1 prerequisites')
    supported=basic[3][2]|basic[3][5]<<32
    need(xcr0&0xe7==0xe7 and not xcr0&~supported and not xcr0>>63 and
         576<=size<=65536 and basic[3][3]==size<=basic[3][4],'actual enabled standard XSAVE extent')
    active=[i for i in range(2,63)if xcr0>>i&1];regions=[]
    need(h[4]==4+len(active),'each enabled extended component queried exactly once')
    for i,q in enumerate(components):
        if i not in active:need(not any(q),'unqueried components absent');continue
        leaf,index,n,at,flags,reserved=q
        need((leaf,index)==(13,i) and n>0 and 576<=at<=size and n<=size-at and not flags&1,
             'bounded user standard XSAVE component')
        need(all(at>=end or start>=at+n for start,end in regions),'disjoint actual XSAVE components')
        regions.append((at,at+n))
    need([components[i][2]for i in (2,5,6,7)]==[256,64,512,1024],'architectural AVX512 component extents')
    ids=struct.unpack_from('<21Q',data,3328);bvs=[struct.unpack_from('<10Q',data,3496+80*i)for i in range(21)]
    expected=([0]+list(range(8000+20*group,8000+20*group+checked-1)))if group<3 else [((group+9)<<32)|i for i in range(3)]
    need(list(ids[:checked])==expected and not any(ids[checked:]),'actual case identities and zero unused slots')
    for r in bvs[:checked]:
        actual=r if group<3 else r[:4]
        need(all(v&0xe7==0xe7 and not v&~xcr0 for v in actual),'all seeded kernel/live state represented')
        need((len(set(r[:6]))==len(set(r[6:]))==1)if group<3 else
             (r[0]==r[1] and r[2]==r[3] and not any(r[4:])),
             'exact respective kernel/live XSTATE_BV and zero unused fields')
    need(not any(v for row in bvs[checked:]for v in row),'unused observer rows zero')
    return dict(checked=checked,xcr0=xcr0,xsave_bytes=size,cpuid_basic=[list(q)for q in basic],
        components=[dict(index=i,raw=list(components[i]))for i in active],
        kernel_xstate_bv=sorted({r[0]for r in bvs[:checked]}),
        live_xstate_bv=sorted({r[6 if group<3 else 2]for r in bvs[:checked]}),
        sha256=hashlib.sha256(data).hexdigest()),components


def leaf(data,expected,sample_bytes):
    need(len(data)>=136,'complete header')
    h=dict(zip(NAMES,struct.unpack_from('<17Q',data)))
    need(all(h[k]==v for k,v in expected['header_equals'].items()),'exact leaf outcome, no alternate success')
    need(h['sample_bytes']==sample_bytes>0 and len(data)==136+22*sample_bytes+40+5176<16<<20,
         'actual ELF-bound sample size and complete unchanged record extent')
    need(not any(data[136+h['pairs']*sample_bytes:136+22*sample_bytes]),'all unused/negative full samples zero')
    obs,_=observations(data[-5176:],expected['group'],h['pairs'],h['xcr0'],h['xsave_bytes'])
    return dict(operation='completed',pairs=h['pairs'],new_pairs=h['pairs']-1,refusals=h['refusals'],
                header=h,observations=obs,architecture='Exact reviewed emitted C full-state/native comparator; this reader validates protocol/CPUID/extent, not a second full-state replay.')


def connected(data,layout,expected):
    case=expected['case'];steps=expected['steps'];need(case in (12,13) and steps==(8 if case==12 else 6),'two closed programs')
    need(set(layout)=={'li2_chain_record','samples','ctl'} and layout['samples']['kind']=='array' and
         layout['samples']['count']==21,'actual existing record roots and sample array')
    sizes=[layout['li2_chain_record']['bytes'],layout['samples']['element']['bytes'],layout['ctl']['bytes']]
    need(sum(sizes)+5176==len(data)<16<<20,'complete chain/startup/control/CPUID extent')
    r=unpack(data,layout['li2_chain_record']);s=unpack(data,layout['samples']['element'],sizes[0])
    ctl=unpack(data,layout['ctl'],sum(sizes[:2]));startup(s)
    need(ctl['bytes']==sizes[2] and not any(data[sum(sizes[:2])+8:sum(sizes)]),'no failure-control activity')
    need(r['magic']==0x314e48434649324c and r['version']==1 and r['record_bytes']==sizes[0] and
         r['header_bytes']==next(x['offset']for x in layout['li2_chain_record']['fields']if x['name']=='source') and
         r['case_id']==case and r['mode']==0 and r['refusals']==47 and r['route_controls']==15 and
         r['completed_lanes']==3 and not r['fixture_failure'] and not r['owner_failure'] and
         not r['verified_failure'] and not r['detail_abs'] and not r['detail_negative'],'exact actual completed identity')
    need(r['initial_stats']==r['final_stats'] and r['initial_stats']['phase']==2,'sealed decoder stable')
    obs,components=observations(data[-5176:],case-9,3,r['xcr0'],r['xsave_bytes'])
    base=r['mapping'];pc=base+(4090 if case==12 else 4093);stop=base+8192
    need(base>0 and base%4096==0 and r['pc']==pc and r['stop']==stop and r['callee']==base+8256,'actual source/endpoint geometry')
    original=bytearray(b'\xcc'*12288);original[pc-base:pc-base+29]=PROGRAM;original[8192:8194]=b'\x0f\x0b'
    need(r['source']==original,'complete exact original byte image and never-executed endpoint')
    n=r['lanes'][0];flags=[u(n['before']['frame']['greg'][17])&~RF,n['flags']]
    need(not(flags[0]|flags[1])&(RF|TF),'logical application flags never carry owned TF/RF')
    for i,l in enumerate(r['lanes']):
        need(l['started']==l['complete']==l['checked']==1 and not l['fault'] and
             l['nx']==expected['nx'][i] and l['traces']==expected['trace'][i] and
             l['event_count']==l['returns']==l['nx']+l['traces']<=24 and
             l['completed_instructions']==(steps if i else 0) and not l['selected'] and not l['old'],
             'exact native/all-NX/chained events and counts')
        equal_state(l['before'],n['before']);equal_state(l['after'],n['after'])
        need(l['before']['frame']['greg'][16]==pc and l['after']['frame']['greg'][16]==stop and
             u(l['before']['frame']['greg'][17])==flags[0]|RF and
             u(l['after']['frame']['greg'][17])==flags[1]|RF and l['flags']==flags[1],'whole exact logical flags and genuine NX RF')
        live(l,n,flags,r['xsave_bytes']);seen=[]
        for j,e in enumerate(l['events'][:l['event_count']]):
            f=e['actual']['frame'];frame(f)
            need(e['ordinal']==j+1 and e['pc']==u(f['greg'][16]) and e['flags']==u(f['greg'][17]) and not e['error'],'actual event binding')
            if e['signal']==11:
                need(e['code']==2 and f['greg'][19:21]==[21,14] and e['address']==e['pc'] and
                     e['flags']&RF and not e['flags']&TF,'genuine NX')
            else:
                need(e['signal']==5 and e['code']==2 and f['greg'][19:21]==[0,1] and
                     e['address']==e['pc'] and e['flags']&TF and not e['flags']&RF,'genuine TRACE')
                mask=(1<<(2 if e['decoded']['pc']//4096!=(e['decoded']['next_pc']-1)//4096 else 1))-1
                need(e['owner_phase']==5 and not e['owner_error'] and e['trace']==1 and
                     e['open']==e['opened']==e['revoke']==e['revoked']==mask and
                     e['release_started']==e['release_complete']==1 and not e['fetch']['held'] and
                     not e['fetch']['first_error'],'actual completed owner cycle/release')
                query(e['query'],e['pc']);seen.append(e)
        need(all(e['ordinal']==0 for e in l['events'][l['event_count']:]),'unused events absent')
        if i:
            offsets=[0,6,11,16,19]+([21,25]if case==12 else [])+[28]
            targets=[6,11,16,19]+([21,25,28]if case==12 else [28])+[stop-pc]
            need([e['decoded']['pc']-pc for e in seen]==offsets and [e['pc']-pc for e in seen]==targets,'literal actual branch/RET flow')
            need([e['decoded']['code']for e in seen[:3]]==[1720,1933,3676],'three exact new instruction identities')
            need(int.from_bytes(seen[0]['actual']['frame']['fp'][components[5][3]+8:components[5][3]+16],'little')==0x100080 and
                 u(seen[1]['actual']['frame']['greg'][13])==0x100080 and
                 u(seen[2]['actual']['frame']['greg'][9])==(0x1fff if case==12 else 0xf) and
                 not seen[2]['flags']&0x8c1,'actual new mask/GPR/defined BLSMSK flags after genuine TRACE')
        a=l['before']['frame']['greg'];b=l['after']['frame']['greg'];expected_gpr=[u(a[x])for x in REGS]
        expected_gpr[0]=u(a[8])+7 if case==12 else 0;expected_gpr[4]+=8;expected_gpr[6]=0x1fff if case==12 else 0xf
        need([u(b[x])for x in REGS]==expected_gpr and int.from_bytes(l['before']['stack'][4096:4104],'little')==stop and
             l['before']['stack']==l['after']['stack'] and l['before']['data']==l['after']['data'],'literal return RAX/RSP/mask and unchanged full memory')
        at=components[5][3]+8
        for before,after,size in ((l['before']['frame']['fp'],l['after']['frame']['fp'],l['before']['frame']['fp_bytes']),
                                  (l['fp'][0],l['fp'][1],r['xsave_bytes'])):
            copy=bytearray(before[:size]);copy[at:at+8]=(0x100080).to_bytes(8,'little')
            need(after[:size]==copy,'only exact K1 field changes in complete saved FP/XSAVE')
    c=r['chain'];need(not c['pending'] and not c['first_error'] and not c['entry']['valid'] and
        c['nx_entries']==c['fallbacks']==1 and c['steps']==c['attempts']==steps and c['trace_entries']==steps-1 and
        not r['final_fetch']['held'] and not r['final_fetch']['first_error'],'complete closed chain and exact handoffs')
    for slot in c['slots']:
        need(slot['release']['started']==slot['release']['complete']==1 and not slot['release']['result'] and
             not slot['fetch']['progress']['held'] and not slot['fetch']['progress']['first_error'],'each slot owns/releases actual borrow')
        if slot['phase']==5:query(slot['query'],slot['owner']['actual_post_pc'])
        else:need(slot['phase']==6 and slot['fallback']!=0,'actual terminal unsupported guard fallback')
    return dict(operation='completed',programs=1,lanes=3,old_startup_pairs=1,refusals=47,route_checks=15,
        nx=expected['nx'],trace=expected['trace'],genuine_trace_handoffs=steps-1,observations=obs)
