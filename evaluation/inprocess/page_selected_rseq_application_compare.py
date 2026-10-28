"""Strict finite rseq protocol. No native refusal or active-CS success inferred."""
import json
import struct
from pathlib import Path
from page_selected import need
import page_selected_chain_compare as chain
from page_selected_rseq_application_images import AREA,AREA_PAGE,WORD,NAMES,DATA
from page_selected_rseq_compare import reports

def unique(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,'duplicate key');out[k]=v
    return out
def decode(b):
    return json.loads(b,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))

def output(spec,data):
    need(len(data)==512,'complete exact application stdout')
    q=struct.unpack('<64Q',data)
    expected=[r['expected']&((1<<64)-1) for r in spec['results']]
    need(list(q[:len(expected)])==expected and q[len(expected):]==(0,)*(64-len(expected)),
         'genuine literal syscall results and complete unused output zeros')
    return expected


def check(spec,row,stdout,stderr,record,native_stdout,schema):
    loader,repeat,run,c,r=reports(stderr,schema)
    need(loader['selected_selftests']==1 and loader['first_target_is_interpreter_entry']==1 and
         loader['source_patches']==0 and loader['admissions']==0 and not loader['partial_errors'],
         'actual source-entry/selftest/all-NX profile')
    need(len(record)==13312,'full fixed actual observation record')
    h=struct.unpack_from('<128Q',record);pages=[record[1024+i*4096:1024+(i+1)*4096]for i in range(3)]
    need(h[:4]==(0x3153424f51455352,1,13312,spec['index']) and
         h[4:7]==(r['status'],r['failure_code'],(-r['detail_abs'] if r['detail_negative'] else r['detail_abs'])&((1<<64)-1)),
         'record source case and original failure association')
    need(r['owner'][0]==1 and r['owner'][7]==r['owner'][8]==row['pid']>0,'actual owned singleton identity')
    need(h[105:108]==tuple(r['owner'][1:4]) and h[108:110]==(r['owner'][4],(-r['owner'][5] if r['owner'][6] else r['owner'][5])&((1<<64)-1)),
         'terminal actual state joins')
    need(h[114:118]==tuple(r['counts'][:4]),'actual registration counts')
    if spec['index']<2:
        need(row['exit']==0 and stdout==native_stdout,'matching real completed native/gated application')
        output(spec,stdout);chain.completed(loader,repeat,run,c)
        need(r['counts'][7]>0,'actual registered run guard executed before generated cache execution')
        expected=(13,2,2,9) if spec['index']==0 else (3,1,1,1)
        need(tuple(r['counts'][:4])==expected and r['owner'][1:7]==[0]*6 and
             r['identity'][0]==1 and r['identity'][1]>0 and r['identity'][2]>0 and
             r['tls'][:6]==[1,1,0,0,0,0], 'genuine lifecycle success, actual mapping identity and TLS observations')
        need(h[8]==0 and h[30:32]==(0,0) and pages[:2]==[bytes(4096)]*2 and h[32]==1 and h[16]==0,
             'positive terminal word observed; no invented guard failure')
        # Anonymous mmap starts zero. Successful unregister resets exactly the
        # ABI CPU-ID pair; no rseq kernel writer remains at this endpoint.
        expected_page=bytearray(4096)
        struct.pack_into('<Q',expected_page,64,0xffffffff00000000)
        if spec['index']==1:
            struct.pack_into('<Q',expected_page,128,0x1122334455667788)
            struct.pack_into('<QQ',expected_page,160,0x1122334455667788,DATA+1024)
            struct.pack_into('<QQ',expected_page,256,0x1122334455667788,0x1122334455667788)
            struct.pack_into('<Q',expected_page,512,0x00010102464c457f)
            # Only the eight explicitly successful getrandom output bytes are
            # nondeterministic. Retain all eight actual bytes in the raw page.
            need(next(x['expected']for x in spec['results']if x['name']=='random_disjoint')==8,
                 'declared exact eight-byte successful random output')
            expected_page[520:528]=pages[2][520:528]
        need(pages[2]==bytes(expected_page),'complete literal terminal data page')
    else:
        need(row['exit']==125 and stdout==b'' and r['status']==125 and
             r['failure_code']==spec['error'] and r['detail_abs']==spec['detail'] and not r['detail_negative'],
             'exact required failed operation, never completion')
        need(h[8]==1 and h[10]==spec['target_pc'] and h[30:33]==(1,1,1),'real target guard plus full three page observations')
        need(h[40:63]==h[63:86] and h[86]==h[87],'all actual saved GPR/flags/RSP and mask unchanged by guard')
        need(h[20]==h[21]==h[22] and h[23]==h[24]==h[25]==0,'no new RX opening and no matching raw target call')
        need(h[11]==spec['trap'] and h[12]==(0 if spec['trap']==1 else 21),'genuine NX or TRACE source frame')
        if spec['operation_syscall']<0:
            target=next(x for x in spec['rows']if x['name']=='forbidden_operation')
            b=bytes.fromhex(target['bytes']);need(h[7]==1 and h[9]==spec['error'] and h[90]==len(b) and
                struct.pack('<QQ',h[88],h[89])[:len(b)]==b,'actual authenticated source instruction and returned guard error')
        else:
            need(h[7]==2 and h[26]==spec['operation_syscall'],'actual syscall source operation')
            need(h[9]==(0 if spec['index'] in (2,12,13) else spec['error']),
                 'before-syscall vs subsequent real registration/mapping rejection')
            need(loader['source_syscalls']==loader['syscalls']==loader['forwarded']+1,
                 'real source syscall retained as unforwarded operation')
            if spec['name'] in ('read_overlap','readv_unsupported'):
                need(h[45]==h[48] and 0<h[48]<1<<31,'actual successfully opened source FD, not EBADF stand-in')
        word=1 if spec['index']==2 else 0
        need(h[14:17]==(word,word,word),'actual publication word never changed')
        # Retain all bytes; compare everything except the separately specified
        # kernel-owned CPU-ID/node/mm-CID fields of the registered32-byte ABI.
        # These fields are not application effects and the raw copies remain.
        mutable=set(range(64,72))|set(range(84,92))
        need(all(pages[0][i]==pages[1][i]==pages[2][i]for i in range(4096)if i not in mutable),
             'complete non-kernel-owned data page unchanged')
        if spec['index']==2:
            expected_page=bytearray(4096);struct.pack_into('<Q',expected_page,72,1)
            need(pages==[bytes(expected_page)]*3,
                 'complete preissue page; no registered kernel writer or byte exemption')
            need(r['owner'][1:4]==[0,1,1] and r['transaction']==[1,0,0,0,0,0,1,1] and
                 r['counts'][:4]==[2,0,0,1] and r['before'][7:10]==[1,1,0],
                 'actual preissue failure, no fabricated registration result')
        else:
            need(r['owner'][1:4]==[1,1,3] and r['counts'][:4]==[2,1,0,1] and r['identity'][0]==1 and
                 r['identity'][1]>0 and r['identity'][2]>0 and r['transaction'][1:3]==[1,1],
                 'real successful registration remains held through terminal refusal')
        if spec['trap']==1:
            s=chain.slot(c,c['active'])
            need(s['origin']==2 and s['pc']==spec['target_pc'] and s['open']==s['opened']==s['trace']==0 and
                 s['owner_error']==spec['error'],'authentic successor refusal before OPENING after real predecessor TRACE')
    need(h[118:]==(0,)*10,'complete reserved record tail zero')
    return dict(name=spec['name'],accepted=True,operation_exit=row['exit'],outcome='completed' if spec['index']<2 else 'required_refusal',
                status=r['status'],error=r['failure_code'],counts=r['counts'],guard_kind=h[7],actual_trap=h[11],
                word_before=h[14],word_terminal=h[16],new_rx_calls=h[22]-h[20],target_raw_calls=h[25],
                source_pc=spec['target_pc'])
