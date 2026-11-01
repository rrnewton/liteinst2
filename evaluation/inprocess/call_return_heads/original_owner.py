"""Compose the whole installed nine-case gate with literal version7/raw PID joins."""
import struct
from call_owner import custody
from cached_ret_prerequisite import check as installed_check, CASES
from ret_owner.prerequisites import need, row, captured


def check(args,current,pin,archive,build):
    # pin preserves whole bytes AND modes through the caller's final closure.
    # Its produced-only binary callback cannot accept these historical artifacts.
    checked=installed_check(args.ret_owner_receipt,args.ret_owner_receipt_sha256,
                            current,pin,pin,archive,build)
    path=pin(args.ret_owner_receipt);p=custody.load(path)
    need(p['archive_reuse']['build']==build and
         p['archive_reuse']['receipt']==current['archive_reuse']['receipt'] and
         p['finite_prerequisites']==current['finite_prerequisites'],
         'identical already-authenticated archive, CALL, RET, ordering and compile prerequisite chains')
    for lane in ('maintained','differential'):
        layout=custody.load(pin(path.parent/lane/'layout.json'))
        need(layout['types']['prto_wire']['bytes']==1261760 and
             layout['types']['li2_pg_compact']['fields']['version']['bytes']==4,
             'original complete owner layout and literal version field')
    for case,(label,mode,lane) in zip(p['cases'],CASES,strict=True):
        if lane=='native':continue
        c=row(p,label)
        raw=captured(path,p,label,'record');h=struct.unpack_from('<96Q',raw)
        footer=struct.unpack_from('<8Q',raw,len(raw)-64)
        need(h[:9]==(0x314f54525049324c,1,1261760,3998208,362688,364544,69632,968,128) and h[19]==mode and
             footer[:4]==(0x314654525049324c,1,1261760,1261760) and
             1<=footer[4]<=64 and 0<footer[5]<=1261760 and footer[6:]==(0,0),
             'literal original complete record and successful bounded footer')
        layout=custody.load(pin(path.parent/lane/'layout.json'))
        types=layout['types']
        def field(kind,key):return types[kind]['fields'][key]['offset']
        at=field('prto_wire','payload')+field('pe_payload','plan')
        need(struct.unpack_from('<I',raw,at+field('li2_pg_compact','version'))[0]==7 and
             struct.unpack_from('<I',raw,at+field('li2_pg_compact','heads'))[0]==7,
             'literal original version7 seven-head graph, no inferred new-flag credit')
        at=field('prto_wire','session')
        need(struct.unpack_from('<Q',raw,at+field('li2_step_session','pid'))[0]==c['pid'] and
             struct.unpack_from('<Q',raw,at+field('li2_step_session','tid'))[0]==c['pid'],
             'actual original owner raw session joins the reaped process')
    return dict(receipt=custody.fact(path),revision=p['revision'],status=p['status'],result=p['result'],
        installed_gate=checked,plan_version=7,subjects=9,executions_here=0,controls_replayed=0,
        new_flag_credit=False,qualification_credit=False,performance_credit=False)
