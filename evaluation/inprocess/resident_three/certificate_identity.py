"""Independent compiled-address and retained-record joins for SBC observations.

The complete original D3 audit is a required caller precondition. Historical
FD/device/inode values remain runtime-observed; no extra live fstat or captured
historical query is inferred from this join.
"""
import copy
import hashlib
import struct
from page_selected import need
from resident_three import certificate_reports as reports

PAGE=4096

def storage_layout(extra,layout):
    need(set(extra)=={'schema','objects','types','storage'} and extra['schema']==1 and
         set(extra['objects'])=={'sbc_observed','sbco'}, 'whole exact additional storage layout')
    expected={
      'sbc_certificate':(200,[('valid',4),('slot',4),('bank',4),('reserved',4),('serial',8),
          ('mirror_epoch',8),('generation',8),('build_serial',8),('owner',8),('mirror',8),
          ('mirror_bytes',8),('session',48),('backing',80)]),
      'sbc_owner':(448,[('next_serial',8),('mirror_epoch',16),('writer',16),('poisoned',4),
          ('reserved',4),('certificate',400)]),
      'sbc_counts':(120,[(k,8)for k in reports.COUNT_WORDS]+[('initialized',4),
          ('last_failure',4),('last_full_result',4),('reserved',4)]),
      'sbco_observation':(1216,[(k,8)for k in reports.EVENT]+[('old',200),('current',200),
          ('before',120),('after',120),('failed_query',296)]),
      'sg_owner_state':(776,[('initialized',4),('reserved',4),('bank',320),('bytes',448)])}
    need(set(extra['types'])==set(expected),'complete exact five extra DWARF types')
    for name,(size,fields) in expected.items():
        actual=extra['types'][name];offset=0;want={}
        for key,n in fields:want[key]=dict(offset=offset,bytes=n);offset+=n
        need(offset==size and actual==dict(bytes=size,alignment=8,fields=want),
             'every actual certificate field and extent: '+name)
    need(extra['storage']==dict(sg_bytes=328),
         'actual whole protected owner-state embedding')
    need(layout['registrations']['sg_owner']['bytes']==PAGE and
         extra['storage']['sg_bytes']+448<=PAGE and
         layout['types']['li2_ptr_slot']['fields']['publication']==dict(offset=42096,bytes=362656,alignment=8,type='struct pe_payload') and
         layout['types']['li2_ptr_slot']['bytes']==406832,
         'unchanged SG page and actual full two-slot mirror geometry')
    for name,tag,n,source in (('sbc_observed','sbc_counts',120,'sealed_byte_certificate.inc'),
                             ('sbco','sbco_observation',1216,'sealed_byte_certificate_observe.h')):
        d=extra['objects'][name]
        need(set(d)=={'address','bytes','alignment','tag','source'} and d['bytes']==n and d['tag']==tag and
             d['alignment']==8 and type(d['address'])is int and d['address']>0 and d['address']%8==0 and
             d['source'].endswith('/tools/page-entry/selected/'+source),
             'actual complete source-bound protected observation object '+name)
    return extra


def extra_symbols(data):
    need(len(data)>=64,'whole bridge ELF for extra symbols')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(3,62,1) and h[11]==64 and
         h[12]>0 and h[6]+64*h[12]<=len(data),'complete actual bridge symbol sections')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])];found={}
    for s in sections:
        if s[1]!=2:continue
        need(s[9]==24 and s[5]%24==0 and s[6]<len(sections) and s[4]+s[5]<=len(data),'whole symbol table')
        tab=sections[s[6]];need(tab[1]==3 and tab[4]+tab[5]<=len(data),'whole symbol-name table')
        names=data[tab[4]:tab[4]+tab[5]]
        for i in range(s[4],s[4]+s[5],24):
            n,info,other,sec,at,size=struct.unpack_from('<IBBHQQ',data,i)
            if not sec or not n:continue
            end=names.find(b'\0',n);need(0<=n<end<len(names),'bounded actual ELF symbol name')
            name=names[n:end].decode('ascii')
            if name in ('sbc_observed','sbco'):
                need(name not in found and info==1 and other==0 and 0<sec<len(sections),
                     'unique local actual storage object')
                row=sections[sec]
                need(row[1]==8 and row[2]&7==3 and row[3]<=at<at+size<=row[3]+row[5],
                     'complete actual initialized-zero writable/nonexecuting object')
                found[name]=(at,size)
    need(set(found)=={'sbc_observed','sbco'},'both complete new compiled observation objects')
    return found


def registered_objects(layout,extra,image,bias,registry,elf_symbols):
    """Authenticate two actual additions before the inherited whole registry rule."""
    storage_layout(extra,layout)
    need(image['persistent_binding']['sealed_byte_certificate'] is True and
         image['persistent_binding']['certificate_observer'] is True,
         'extra objects belong only to the explicit actual certificate build')
    syms=extra_symbols(image['bridge']);_,ph,_=elf_symbols(image['bridge']);objects=[]
    for name,d in extra['objects'].items():
        need(syms[name]==(d['address'],d['bytes']) and d['source'] in image['headers'],
             'actual ELF/DWARF/compiler-M whole extra object identity')
        a=bias+d['address'];z=a+d['bytes']
        need(registry.count((a,z))==1 and
             any(p[0]==1 and p[1]==6 and bias+p[3]<=a<z<=bias+p[3]+p[6] for p in ph),
             'new protected storage registered before full D3 guard construction')
        objects.append((a,z))
    need(len(objects)==len(set(objects))==2,'both exact distinct additional registrations')
    return objects


def join(stderr,record,layout,extra,image,owner,pid,reader):
    storage_layout(extra,layout)
    need(owner['status']==owner['code']==owner['detail']==0 and owner['interior_signals']==0 and
         len(record)==2063104,'full original owner success is a mandatory independent precondition')
    r=reader.wire.Reader(memoryview(record)[:-64],layout);t='r3o_wire'
    field=lambda b,name,key:r.field(b,name,key)
    # Reader.field has the same complete typed extent contract as its old donor.
    h=struct.unpack('<48Q',bytes(field(r.data,t,'h')))
    bias=h[9]-layout['symbols']['r3_owner'];pe=bias+layout['symbols']['pe']
    session=list(struct.unpack('<6Q',bytes(field(r.data,t,'session'))))
    entered=field(r.data,t,'entered');count=r.integer(entered,'r3o_state','registry_count')
    registry=[struct.unpack('<QQ',bytes(row))for row in r.items(r.data,t,'registry','li2_fork_range')[:count]]
    need(0<count<=128 and session[0]==session[1]==pid and session[4]==reports.MASK,
         'actual retained selected session and complete protected registry')
    registered_objects(layout,extra,image,bias,registry,reader.elf_symbols)
    _,c,tst=reports.strip(stderr);e=dict(zip(reports.EVENT,tst['event']))
    need(e['stage']==4,'mandatory actual complete replacement for full identity audit')
    certs=[reports.certificate(tst[k],pid)for k in ('old','current')]
    mirrors=[pe+layout['retained_storage']['retained']['offset']+
             i*layout['types']['li2_ptr_slot']['bytes']+42096 for i in range(2)]
    for value in certs:
        need(value['owner']==pe and value['mirror']==mirrors[value['slot']] and value['session']==session,
             'whole certificate owner/mirror/session independently joined to actual compiled and retained identities')
        backing=value['backing'];code,proof=backing[5:7]
        need(registry.count((code,code+19*PAGE))==1 and registry.count((proof,proof+89*PAGE))==1 and
             (value['bank']!=0 or code<(1<<31)-19*PAGE),
             'each actual historical backing extent is an exact independently retained protected allocation')
    need(certs[0]['backing'][6]==certs[1]['backing'][6] and
         ((certs[0]['bank']==certs[1]['bank'])==(certs[0]['backing'][5]==certs[1]['backing'][5])),
         'same retained-slot proof and exact actual bank address relation across replacement')
    return dict(owner=pe,mirrors=mirrors,session=session,extra_objects=extra['objects'],
        old_certificate=certs[0],new_certificate=certs[1],replacement_observed=True,
        independent_elf_dwarf_registry_session_join=True,historical_fd_identity_scope='runtime_observed',
        independently_retained_historical_query=False,qualification_credit=False,performance_credit=False)


def controls(stderr,record,layout,extra,image,owner,pid,reader):
    original=join(stderr,record,layout,extra,image,owner,pid,reader);refused=[]
    lines=stderr[:-1].split(b'\n');at=next(i for i,x in enumerate(lines)if x.startswith(reports.TEST_PREFIX))
    import json
    _,_,t=reports.strip(stderr)
    # These coordinated changes keep the report-internal equality but must not
    # pass the independent compiled-address/session/registry join.
    for name,index,delta in (('both_owner',6,8),('both_mirror',7,8),('both_sync_query',12,128),
                             ('both_code_extent',20,PAGE),('both_proof_extent',21,PAGE)):
        changed=copy.deepcopy(t)
        for key in ('old','current'):changed[key][index]^=delta
        data=lines[:];data[at]=reports.TEST_PREFIX+json.dumps(changed,separators=(',',':')).encode()
        try:join(b'\n'.join(data)+b'\n',record,layout,extra,image,owner,pid,reader)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted independent certificate identity corruption '+name)
    need(len(refused)==len(set(refused))==5 and join(stderr,record,layout,extra,image,owner,pid,reader)==original,
         'all five independent identity controls and unchanged original')
    return dict(count=5,refusals=refused,native_operations=0,stderr_sha256=hashlib.sha256(stderr).hexdigest())


def failed_record(record,layout,pid,control,st,reader):
    """Transport and explicit absent-focal prefix only; never full-owner credit."""
    need(control in (1,2,3) and len(record)==2063104,'whole fixed refusal record')
    footer=struct.unpack('<8Q',record[-64:])
    need(footer[:4]==(0x3152334f4632494c,2,2063040,2063040) and
         1<=footer[4]<=64 and 0<footer[5]<=2063040 and footer[6:]==(125,3303),
         'complete actual failed record transport, no successful footer promotion')
    r=reader.wire.Reader(memoryview(record)[:-64],layout);data=r.data;t='r3o_wire'
    h=struct.unpack('<48Q',bytes(r.field(data,t,'h')))
    need(h[:9]==(0x3152334f5732494c,2,2063040,1246656,362544,364544,69632,968,128) and
         h[14:16]==(1,0) and h[16]&(3|0x400|0x800)==1 and h[17:19]==(0,1) and
         h[22]==0 and h[24:33]==(0,)*9 and h[33:38]==(1,125,3303,192+control,1) and
         h[38:41]==(h[16],0,1) and h[41:]==(0,)*7,
         'exact failed startup prefix and no invented D3 entry/terminal/prebind witness')
    session=struct.unpack('<6Q',bytes(r.field(data,t,'session')))
    need(session[:3]==(pid,pid,0) and session[3]&96==96 and session[4:]==(reports.MASK,0x100000001) and
         struct.unpack('<9Q',bytes(r.field(data,t,'bootstrap')))==(pid,)*5+(0,0,24,1),
         'actual full selected session and trusted bootstrap retained in failed prefix')
    for key in ('transfer','held','entered','terminal','closed','before','after','next','memory','registry',
                'source','certificate','directory','directory_query','directory_scan','unexpected_scan','next_closed'):
        need(not any(r.field(data,t,key)),'every absent focal byte is zero: '+key)
    final=r.field(data,t,'final')
    for key in ('busy','active','consumed','released','exit_seen','first_error','registry_bound','first_detail',
                'serial','publications','entries','completed','cancelled','unexpected','ingresses','count','planned'):
        need(r.integer(final,'r3o_state',key)==0,'no actual resident activity at this first-eligible refusal: '+key)
    for name in ('sink_initial','sink_terminal'):
        sink=r.field(data,t,name)
        for key,want in (('st_dev',st.st_dev),('st_ino',st.st_ino),('st_mode',0x8180),
                         ('st_nlink',1),('st_size',0),('st_uid',st.st_uid),('st_gid',st.st_gid)):
            need(r.integer(sink,'stat',key)==want,'actual retained exclusive record sink: '+name+'/'+key)
    return dict(status='failed_prefix',exit_status=125,code=3303,detail=192+control,
        owner_bytes=len(record),record_sha256=hashlib.sha256(record).hexdigest(),
        focal_entries=0,application_completed=False,owner_full_state_credit=False,
        qualification_credit=False,performance_credit=False)


def failed_controls(record,layout,pid,control,st,reader):
    original=failed_record(record,layout,pid,control,st,reader);refused=[]
    fields=layout['types']['r3o_wire']['fields']
    offsets=[('header_version',8),('entry',24*8),('status',34*8),('code',35*8),('detail',36*8),
             ('finished',37*8),('sink_complete',40*8),('whole_focal_frame',fields['before']['offset']),
             ('session_mask',fields['session']['offset']+32),('footer_status',len(record)-16),
             ('footer_code',len(record)-8)]
    for name,offset in offsets:
        changed=bytearray(record);changed[offset]^=1
        try:failed_record(bytes(changed),layout,pid,control,st,reader)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted failed-prefix supplied mutation '+name)
    need(len(refused)==len(set(refused))==11 and failed_record(record,layout,pid,control,st,reader)==original,
         'all exact failed-prefix data controls and unchanged actual input')
    return dict(count=11,refusals=refused,native_operations=0,record_sha256=hashlib.sha256(record).hexdigest())
