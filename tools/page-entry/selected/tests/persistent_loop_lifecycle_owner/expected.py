"""Pure shared lifecycle expectations from already reconstructed source graphs.

The caller first authenticates each complete graph, directory and native trace.
No captured write mask or reset-cell value participates in this reconstruction.
Only an external DIRECT arm that actually hits this directory writes its cell;
internal arms and the final directory miss leave the previous value intact.
"""
import hashlib
import struct

CONTROL_COUNT=10

def need(ok,why):
    if not ok:raise ValueError(why)

def epoch(page,graphs,directory,native_pcs,lo,hi):
    need(type(page)is int and page>=4096 and page%4096==0 and page+8192<1<<47 and
         type(graphs)is tuple and len(graphs)in(1,2)and
         type(directory)is bytes and len(directory)==8224 and
         type(native_pcs)is tuple and all(type(pc)is int and 4096<=pc<1<<47 for pc in native_pcs)and
         type(lo)is int and type(hi)is int and 0<=lo<=hi<len(native_pcs)-1,
         'whole active graphs, directory and actual native lifecycle interval')
    version,count,serial,reserved=struct.unpack_from('<4Q',directory)
    need(version==1 and serial>0 and reserved==0 and count==sum(g['heads']for g in graphs),
         'exact active-member directory population')
    gpr=flags=0;rows={};external={};owners={};cursor=0;identities=[]
    for member,graph in enumerate(graphs):
        n=graph['heads'];offsets=graph['offsets'];heads=graph['head_rows']
        need(type(n)is int and 0<n<=128 and len(offsets)==len(heads)==n and
             len(set(offsets))==n and all(type(off)is int and 0<=off<8192 for off in offsets),
             'complete independently reconstructed member heads')
        for name,limit in(('gpr_written',0xffef),('flags_written',0x8d5)):
            need(type(graph[name])is int and graph[name]>=0 and not graph[name]&~limit,
                 'independent bounded member write mask')
        gpr|=graph['gpr_written'];flags|=graph['flags_written']
        first=None
        for head,off in enumerate(offsets):
            pc,generated,generation,slot,index=struct.unpack_from('<3Q2I',directory,32+32*cursor)
            need(pc==page+off and pc not in rows and 4096<=generated<1<<47 and
                 generation>0 and slot in(0,1)and index==head,
                 'whole ordered source-to-generated directory head')
            if first is None:first=(generated,generation,slot)
            need((generated,generation,slot)==(first[0]+512*head,first[1],first[2]),
                 'one exact immutable generation and bank per active member')
            rows[pc]=generated;owners[pc]=member;cursor+=1
        identities.append(first)
        for index,boundary in enumerate(graph['boundary_rows']):
            head,arm=boundary['head'],boundary['arm']
            need(boundary['index']==index and boundary['kind']=='direct'and
                 boundary['token']==128+index and type(head)is int and 0<=head<n and
                 type(arm)is int and 0<=arm<heads[head][4]and heads[head][0]==5 and
                 heads[head][5+arm]==boundary['token'],
                 'only exact source-derived external DIRECT arms write directory cells')
            key=(page+offsets[head],boundary['target'])
            need(key not in external,'one independent external arm per source/target')
            external[key]=member
    need(len({x[1]for x in identities})==len(graphs)and
         len({x[2]for x in identities})==len(graphs)and
         directory[32+32*count:]==bytes((256-count)*32),
         'distinct whole member identities and exact unused directory tail')
    last=[0]*len(graphs)
    for j in range(lo,hi+1):
        pc,target=native_pcs[j:j+2]
        need(pc in owners,'every generated instruction belongs to an active source graph')
        member=external.get((pc,target))
        if j==hi:
            need(member is not None and target not in rows,
                 'the actual final original branch is the directory miss before replay')
        elif member is not None:
            need(target in rows,'every earlier actual external branch commits an exact directory hit')
            last[member]=rows[target]
    return dict(gpr_written=gpr,flags_written=flags,cell_before=tuple(last))


def controls(reader,codec,raw_bytes,schema_version,data,layout,image,app,native,pid,cpu,exit_status):
    """Ten additional actual-capture full-reader refusals; old rosters are separate.

    Cell changes update both stored copies of the same completed generation,
    preserving the whole claim join so the exact native-derived value check is
    reached. No historical receipt or source/native input is rewritten.
    """
    reader(data,layout,image,app,native,pid,cpu,exit_status)
    raw,_=codec.decode(data,raw_bytes=raw_bytes,schema_version=schema_version)
    types=layout['types']
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+index*(types[child]['bytes']if child else 1)
    def u(t,k,base=0):return struct.unpack_from('<I',raw,at(t,k,base))[0]
    def q(t,k,base=0):return struct.unpack_from('<Q',raw,at(t,k,base))[0]
    def cells(index):
        e=at('pdo_wire','epochs',index=index,child='pdo_epoch')
        d=at('pdo_epoch','terminal_domain',e);work=at('pda_state','work',d)
        receipt=u('pda_work','receipt',work)
        need(receipt<3,'actual completed receipt for causal lifecycle mutations')
        c=at('pda_state','completion',d,receipt,'pda_completion')
        slots=at('pdo_stage','slots',at('pdo_epoch','terminal',e));out={}
        for i in range(u('pda_completion','count',c)):
            m=at('pda_completion','member',c,i,'pda_member_completion')
            identity=at('pda_member_completion','identity',m);slot=u('li2_pgd_ref','slot',identity)
            root=q('li2_pgd_ref','root',identity)
            need(slot in(0,1)and root not in out,'distinct actual causal member identities')
            a=at('pdo_slot','generation',at('pdo_slots','slots',slots,slot,'pdo_slot'))
            b=at('pda_member_completion','generation',m)
            size=types['li2_pg_generation']['bytes']
            need(raw[a:a+size]==raw[b:b+size],'whole actual claimed generation before mutation')
            offsets=tuple(at('pg_dispatch_cell_transition','before',at('li2_pg_generation','cell',g,2,'pg_dispatch_cell_transition'))for g in(a,b))
            out[root]=(q('li2_pg_generation','generated',a),offsets)
        return e,out
    page=app['page'];a_root=page+512;b_root=page+256;c_root=page+535
    e,warm=cells(2)
    need(set(warm)=={a_root,b_root},'actual warm union of both independently validated members')
    info=at('pdo_epoch','info',e);mask=at('pdo_epoch_info','gpr_written',info)
    flags=at('pdo_epoch_info','flags_written',info)
    need(struct.unpack_from('<Q',raw,mask)[0]==514 and
         struct.unpack_from('<Q',raw,flags)[0]==0x8d5,
         'actual complete A/B union before causal mask mutations')
    a_gen,a_cell=warm[a_root];b_gen,b_cell=warm[b_root]
    need(all(struct.unpack_from('<Q',raw,o)[0]==b_gen for o in a_cell)and
         all(struct.unpack_from('<Q',raw,o)[0]==a_gen for o in b_cell),
         'actual last external hits before separate reset mutations')
    _,cold=cells(app['mode']);_,replacement=cells(4)
    need(set(cold)=={a_root}and set(replacement)=={c_root},'actual cold A and replacement C contexts')
    cold_gen,cold_cell=cold[a_root];c_gen,c_cell=replacement[c_root]
    need(all(struct.unpack_from('<Q',raw,o)[0]==0 for o in cold_cell+c_cell),
         'cold lifetimes have no committed directory hit')
    tests=[('omitted_R9_member_mask',(mask,),2,'exact pdo_epoch_info.gpr_written'),
           ('summed_not_unioned_masks',(mask,),516,'exact pdo_epoch_info.gpr_written'),
           ('omitted_flag_effect',(flags,),0x8d4,'exact pdo_epoch_info.flags_written'),
           ('internal_A_arm_mistaken_hit',a_cell,a_gen,'actual final reset binds completed directory dispatch'),
           ('final_A_miss_clears_prior_hit',a_cell,0,'actual final reset binds completed directory dispatch'),
           ('wrong_A_external_head',a_cell,b_gen+512,'actual final reset binds completed directory dispatch'),
           ('zero_B_reset_target',b_cell,0,'actual final reset binds completed directory dispatch'),
           ('wrong_B_external_head',b_cell,a_gen+512,'actual final reset binds completed directory dispatch'),
           ('cold_A_invented_hit',cold_cell,cold_gen,'actual final reset binds completed directory dispatch'),
           ('replacement_C_invented_hit',c_cell,c_gen,'actual final reset binds completed directory dispatch')]
    names=[]
    for name,offsets,value,message in tests:
        changed=bytearray(raw)
        for offset in offsets:
            need(struct.unpack_from('<Q',raw,offset)[0]!=value,'nonidentity actual lifecycle expectation mutation')
            struct.pack_into('<Q',changed,offset,value)
        try:reader(codec.encode_for_control(bytes(changed),schema_version=schema_version),
                   layout,image,app,native,pid,cpu,exit_status)
        except ValueError as error:
            need(str(error)==message,'exact intended lifecycle expectation refusal '+name)
            names.append(name)
        else:raise ValueError('accepted actual lifecycle expectation mutation '+name)
    need(len(names)==len(set(names))==CONTROL_COUNT,'all ten separate actual lifecycle expectation refusals')
    return dict(count=CONTROL_COUNT,refusals=names,original_sha256=hashlib.sha256(data).hexdigest(),
                native_operations=0,qualification_credit=False)
