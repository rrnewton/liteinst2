"""Actual unrolled owner observations; no application or supplied-control credit.

The caller separately authenticates all process/source/binary closure, the
application stdout/native frames and exact old terminal report controls. This
leaf never executes a decoder, reevaluates a candidate, or reads an address.
"""
import hashlib
import struct

U64=(1<<64)-1
PAGE, FP, TF, RF = 4096, 65536, 0x100, 0x10000
MASK=0xffffffffbffbfae7
P,L,R='li2_native_pair_progress','li2_native_pair_lifecycle','li2_rseq_pair_progress'
BODY=bytes.fromhex('4889d84883c10148c1e0054801c34801d30fb61184d275e8')
DATA,STACK=0x500000000000,0x500000100000
RSP=STACK+4096+131072-504
OFFSETS=(0,3,7,11,14,17,20,22)
LENGTHS=(3,4,4,3,3,3,2,2)
CODES=(282,249,381,8,8,2090,271,176)


def need(ok, why):
    if not ok: raise ValueError(why)


def q(b):
    need(len(b)%8==0,'whole qwords')
    return struct.unpack('<'+'Q'*(len(b)//8),b)


def zero(b, why): need(not any(b),why)


def canonical(a,n=1):
    return type(a)is int and type(n)is int and n>0 and 4096<=a<(1<<47) and n<=(1<<47)-a


def old_shapes(r):
    """Exact C field inventories and compiler-required minimum alignment."""
    def form(name,groups,align=8):
        fields={}
        for names,size,alignment in groups:
            for name0 in names.split():fields[name0]=(size,alignment)
        r.shape(name,fields,align)
    s=lambda name:r.types[name]['bytes']
    form('timespec',[('tv_sec tv_nsec',8,8)])
    form('stat',[('st_dev st_ino st_nlink',8,8),('st_mode st_uid st_gid __pad0',4,4),
        ('st_rdev st_size st_blksize st_blocks',8,8),('st_atim st_mtim st_ctim',16,8),('__glibc_reserved',24,8)])
    form('li2_maps_observation',[('acquisition_id handler_id mutation_epoch',8,8),('kind io_performed',4,4)])
    form('li2_fetch_map_progress',[('fd last_read close_result bytes rows',8,8),
        ('opened close_started closed',4,4),('observation',s('li2_maps_observation'),8)])
    form('li2_fetch_page',[('address allocation generation offset initial_extent',8,8),
        ('backing object logical closed_prot',4,4),('vma_first vma_end vma_major vma_minor vma_inode vma_offset',8,8)])
    form('li2_fetch_backing',[('retained_fd',4,4),('seals stat_result',8,8),('stat',s('stat'),8),
        ('seals_observed stat_observed',4,4)])
    form('li2_native_close',[('sequence allocation_epoch generation_epoch transactions_epoch records_epoch pages attempted returned closed verified last_address first_error_address pid tid last_result sync_result first_detail',8,8),
        ('busy complete first_error sync_started sync_returned cleanup_started cleanup_complete',4,4),
        ('cleanup_attempted cleanup_returned cleanup_first_result cleanup_sync_result',8,8),
        ('before after',s('li2_fetch_map_progress'),8)])
    form('li2_native_pair_slot',[('prepared published slot window_before window_after policy',4,4),('pc',8,8),
        ('page',s('li2_fetch_page'),8),('backing',s('li2_fetch_backing'),8),
        ('window_bytes window_initialized',8,8),('window',4124,1)])
    form(L,[('owner',8,8),('initialized busy live first_error opening post_verified',4,4),
        ('first_detail pid tid sequence allocation_epoch generation_epoch transactions_epoch records_epoch attempts published closed_pages close_calls candidate',8,8),
        ('candidate_policy candidate_eligible',4,4),('before after',s('li2_fetch_map_progress'),8),
        ('slots',2*s('li2_native_pair_slot'),8),('close',s('li2_native_close'),8)])
    form('li2_rseq_data',[('address page allocation generation offset pid tid',8,8),
        ('attempted complete error',4,4),('detail',8,8),('maps',s('li2_fetch_map_progress'),8)])
    form('li2_rseq_transaction',[('args',48,8),('result',8,8),
        ('attempted issued returned prior_registered input_word_observed',4,4),('input_word',8,8),
        ('before after',s('li2_rseq_data'),8)])
    form('li2_write_footprint',[('pc next_pc first end',8,8),('abi_version policy code length',4,4)])
    form('li2_rseq_state',[('initialized registered held first_error phase',4,4),
        ('first_detail pid tid address page',8,8),('length signature',4,4),
        ('epoch fs_base gs_base fs_result gs_result',8,8),('tls_attempted tls_complete',4,4),
        ('calls registrations unregistrations kernel_errors instruction_checks range_checks repeat_checks run_checks syscall_checks last_first last_end last_pc last_code last_policy',8,8),
        ('last_footprint',s('li2_write_footprint'),8),('data',s('li2_rseq_data'),8),
        ('transaction',s('li2_rseq_transaction'),8)])
    form(R,[('owner',8,8),('initialized registered active checking entry_checked first_error unsafe_terminal',4,4),
        ('first_detail pid tid attempts published preentries entries refreshes closed registration_epoch address page',8,8),
        ('length signature',4,4),('word_before word_entry word_after fs_before gs_before fs_after gs_after',8,8),
        ('fs_selector_entry gs_selector_entry fs_selector_after gs_selector_after',2,2),('before after',s('li2_rseq_data'),8)])
    form(P,[('session',8,8),('initialized phase in_handler first_error live entry_pending first_observed second_observed close_reason',4,4),
        ('first_detail pid tid events seeds extensions epochs_closed one_page_closes two_page_closes policy_closes capacity_closes refaults refault_completed logical_flags',8,8),
        ('signal_number signal_code signal_errno',4,4),('pc signal_address',8,8),
        ('first second',s('li2_step_frame'),64),('first_close',s('li2_native_close'),8)],64)


def shapes(r):
    def form(name, groups, align=8):
        fields={}
        for keys,size,a in groups:
            for key in keys.split():fields[key]=(size,a)
        r.shape(name,fields,align)
    s=lambda t:r.types[t]['bytes']
    form('li2_step_frame',[('greg',184,8),('mask fp_address fp_bytes initialized',8,8),('fp',65536,64)],64)
    old_shapes(r)
    form('li2_maps_stats',[('fresh_calls acquisitions reuses invalidations handler_id mutation_epoch',8,8),('active valid poisoned reserved',4,4)])
    form('li2_fetch_ref',[('owner sequence',8,8)])
    form('li2_fetch_progress',[('held complete first_error identity_observed',4,4),
        ('first_detail pages_copied bytes_copied sequence validation_calls last_backing_page',8,8),
        ('last_backing_observed',4,4),('preparation validation',s('li2_fetch_map_progress'),8)])
    form('li2_unrolled_source',[('ready',4,4),('borrow',s('li2_fetch_ref'),8),('pc',8,8),
        ('page',s('li2_fetch_page'),8),('backing',s('li2_fetch_backing'),8),('bytes',39,1)])
    form('li2_decoded',[('pc next_pc',8,8),('abi_version decode_status code kind destination width_bits step_disposition available length reserved',4,4),('bytes',16,1)])
    form('li2_unrolled_hash_plan',[('version ready decoder_calls decoder_result',4,4),('pc stop entry',8,8),
        ('source',39,1),('generated',1797,1),('instructions',8*s('li2_decoded'),8),('guard',s('li2_decoded'),8)])
    form('li2_unrolled_hash_pc',[('version ready copy_index source_offset kind source_length generated_length reserved',4,4),('original_pc generated_pc',8,8)])
    form('li2_private_code_query',[('first end first_vma last_vma_end pages_checked',8,8),
        ('attempted complete expected_prot actual_prot result',4,4),('detail',8,8),('maps',s('li2_fetch_map_progress'),8)])
    form('li2_step_session',[('pid tid sync_register sync_query application_mask',8,8),('initialized self_test_complete',4,4)])
    form('li2_selected_hardware',[('abi_version reserved',4,4),('leaf0 leaf1 leaf7',16,4)],4)
    form('li2_native_counts',[('attempts admissions closed blocked low_address_refusals',8,8),('last_block',4,4),
        ('first_admission_ns first_source_offset revisit_count',8,8),('revisit_ns',128,8)])
    form('image',[('bias entry ph n source source_size',8,8),('backing_fd kind',4,4),('source_hash',32,1)])
    form('li2_rseq_native_state',[('phase checking first_error unsafe_terminal entry_checked',4,4),
        ('first_detail pid tid attempts admissions preentries entries closed tls_refreshes pc address page registration_epoch native_admissions_before native_closed_before',8,8),
        ('length signature',4,4),('word_before word_entry word_after fs_before gs_before fs_after gs_after',8,8),
        ('fs_selector_entry gs_selector_entry fs_selector_after gs_selector_after',2,2),('before after',s('li2_rseq_data'),8)])
    form('uh_frame',[('started si_saved uc_saved complete sig',4,4),('si',r.layout['si']['bytes'],8),
        ('uc',r.layout['uc_bytes'],8),('frame',s('li2_step_frame'),64),('fs gs fs_result gs_result',8,8),('tls_complete',4,4)],64)
    form('uh_permission',[('started returned sync_started sync_returned complete prot',4,4),('result sync_result',8,8),('query',s('li2_private_code_query'),8)])
    form('uh_slot',[('installed complete',4,4),('identity filled verified',8,8),('source',s('li2_unrolled_source'),8),
        ('plan',s('li2_unrolled_hash_plan'),8),('writable',s('li2_private_code_query'),8),('publication',s('uh_permission'),8)])
    form('uh_record',[('slot_present slot redirected exit_seen completed release_started release_complete cleanup_started cleanup_complete unexpected_seen release_result map_result',4,4),
        ('flags iterations',8,8),('source',s('li2_unrolled_source'),8),('before after unexpected',s('uh_frame'),64),
        ('original',s('li2_unrolled_hash_pc'),8),('idle live',s('li2_private_code_query'),8),('idle_bytes live_bytes closed_bytes',8,8),
        ('open close cleanup',s('uh_permission'),8),('final_fetch',s('li2_fetch_progress'),8)],64)
    form('unrolled_owner',[('initialized first_error metadata_registered arena_registered allocated low_arena_registered low_allocated',4,4),
        ('first_detail allocation_result low_allocation_result arena low_arena used candidates source_misses plan_misses capacity_misses publications hits entries completed head_exits stop_exits iterations unexpected events',8,8),
        ('signals',40,8),('session',s('li2_step_session'),8),('initial low_initial',s('li2_private_code_query'),8),
        ('slots',64*s('uh_slot'),8),('current last',s('uh_record'),64)],64)
    form('li2_uho_map_row',[('first end offset major minor inode',8,8),('prot private',4,4)])
    form('li2_uho_memory',[('attempted complete after_abort rows_checked data_copied stack_copied result',4,4),
        ('detail rsp data_first stack_first',8,8),('maps',s('li2_fetch_map_progress'),8),('before after',s('li2_maps_stats'),8),
        ('rows',6*s('li2_uho_map_row'),8),('data',8192,1),('stack',160,1)])
    form('uho_owners',[('captured word_observed',4,4),('word',8,8),('rseq',s('li2_rseq_state'),8),
        ('rseq_native',s('li2_rseq_native_state'),8),('pair',s(P),64),('lifecycle',s(L),8),('rseq_pair',s(R),8)],64)
    form('uho_entry',[('present ordinal committed terminal source_bytes generated_bytes',8,8),('owner',s('uh_record'),64),
        ('redirected',s('uh_frame'),64),('before_memory after_memory',s('li2_uho_memory'),8),
        ('redirected_owners completed_owners',s('uho_owners'),64),('source_page generated_page terminal_source_page',4096,1),('terminal_source_bytes',8,8)],64)
    form('uho_wire',[('h',512,8),('control',192,8),('sink_initial sink_terminal main_backing',s('stat'),8),
        ('main interpreter',s('image'),8),('hardware',s('li2_selected_hardware'),4),('owner',s('unrolled_owner'),64),
        ('terminal_owners',s('uho_owners'),64),('terminal_fetch',s('li2_fetch_progress'),8),
        ('terminal_global_close',s('li2_native_close'),8),('terminal_native_counts',s('li2_native_counts'),8),
        ('entries',2*s('uho_entry'),64),('supplied_before',s('uh_frame'),64),
        ('control_before',s('uh_record'),64),('original_source',39,1),('generated',64*4096,1)],64)


class Reader:
    def __init__(self, data, layout):
        self.data,self.layout,self.types=data,layout,layout['types']
        self.padding={}
        need(layout['record']=='uho_wire' and layout['member_witnesses']=={
            'li2_step_frame.fp':dict(symbol='uho_step_frame_fp_alignment',bytes=8,alignment=64)},'actual symbol/member witness')
        need(layout['uc_bytes']==968 and layout['uc']==dict(
            offsets=dict(flags=0,link=8,greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),
            widths=dict(flags=8,link=8,greg=184,fp_pointer=8,mask=128,stack_sp=8,stack_flags=4,stack_size=8)),
            'complete actual x86-64 ucontext ABI')
        need(layout['si']==dict(bytes=128,offsets=dict(signo=0,errno=4,code=8,addr=16,pid=16,uid=20),
            widths=dict(signo=4,errno=4,code=4,addr=8,pid=4,uid=4)),'actual signal-info fields')
        shapes(self)
        need(set(self.types)==set(self.padding)==set(layout['edges']),'complete transitive private type inventory')
        expected={t:{} for t in self.types}
        # Source-declared embedded objects, independently of DWARF's strings.
        # Primitive arrays and the deliberately opaque SI/UC are not edges.
        for parent,child,keys in (
            ('stat','timespec','st_atim st_mtim st_ctim'),
            ('li2_fetch_map_progress','li2_maps_observation','observation'),
            ('li2_fetch_backing','stat','stat'),
            ('li2_native_close','li2_fetch_map_progress','before after'),
            ('li2_native_pair_slot','li2_fetch_page','page'),('li2_native_pair_slot','li2_fetch_backing','backing'),
            (L,'li2_fetch_map_progress','before after'),(L,'li2_native_pair_slot','slots'),(L,'li2_native_close','close'),
            ('li2_rseq_data','li2_fetch_map_progress','maps'),('li2_rseq_transaction','li2_rseq_data','before after'),
            ('li2_rseq_state','li2_write_footprint','last_footprint'),('li2_rseq_state','li2_rseq_data','data'),
            ('li2_rseq_state','li2_rseq_transaction','transaction'),(R,'li2_rseq_data','before after'),
            (P,'li2_step_frame','first second'),(P,'li2_native_close','first_close'),
            ('li2_fetch_progress','li2_fetch_map_progress','preparation validation'),
            ('li2_unrolled_source','li2_fetch_ref','borrow'),('li2_unrolled_source','li2_fetch_page','page'),
            ('li2_unrolled_source','li2_fetch_backing','backing'),('li2_unrolled_hash_plan','li2_decoded','instructions guard'),
            ('li2_private_code_query','li2_fetch_map_progress','maps'),('li2_rseq_native_state','li2_rseq_data','before after'),
            ('uh_frame','li2_step_frame','frame'),('uh_permission','li2_private_code_query','query'),
            ('uh_slot','li2_unrolled_source','source'),('uh_slot','li2_unrolled_hash_plan','plan'),
            ('uh_slot','li2_private_code_query','writable'),('uh_slot','uh_permission','publication'),
            ('uh_record','li2_unrolled_source','source'),('uh_record','uh_frame','before after unexpected'),
            ('uh_record','li2_unrolled_hash_pc','original'),('uh_record','li2_private_code_query','idle live'),
            ('uh_record','uh_permission','open close cleanup'),('uh_record','li2_fetch_progress','final_fetch'),
            ('unrolled_owner','li2_step_session','session'),('unrolled_owner','li2_private_code_query','initial low_initial'),
            ('unrolled_owner','uh_slot','slots'),('unrolled_owner','uh_record','current last'),
            ('li2_uho_memory','li2_fetch_map_progress','maps'),('li2_uho_memory','li2_maps_stats','before after'),
            ('li2_uho_memory','li2_uho_map_row','rows'),('uho_owners','li2_rseq_state','rseq'),
            ('uho_owners','li2_rseq_native_state','rseq_native'),('uho_owners',P,'pair'),('uho_owners',L,'lifecycle'),('uho_owners',R,'rseq_pair'),
            ('uho_entry','uh_record','owner'),('uho_entry','uh_frame','redirected'),
            ('uho_entry','li2_uho_memory','before_memory after_memory'),('uho_entry','uho_owners','redirected_owners completed_owners'),
            ('uho_wire','stat','sink_initial sink_terminal main_backing'),('uho_wire','image','main interpreter'),
            ('uho_wire','li2_selected_hardware','hardware'),('uho_wire','unrolled_owner','owner'),
            ('uho_wire','uho_owners','terminal_owners'),('uho_wire','li2_fetch_progress','terminal_fetch'),
            ('uho_wire','li2_native_close','terminal_global_close'),('uho_wire','li2_native_counts','terminal_native_counts'),
            ('uho_wire','uho_entry','entries'),('uho_wire','uh_frame','supplied_before'),('uho_wire','uh_record','control_before')):
            for key in keys.split():expected[parent][key]=child
        need(layout['edges']==expected,'every source-declared embedded object and array is traversed')
        need(type(data)is bytes and len(data)==self.types['uho_wire']['bytes']+64<4<<20,'complete wire plus footer')
        self.walk(data[:-64],'uho_wire')

    def shape(self,t,fields,align=8):
        d=self.types[t];need(set(d)=={'bytes','alignment','fields'} and set(d['fields'])==set(fields) and d['alignment']==align,'exact source field inventory '+t)
        at=0;gaps=[]
        for k,(size,a) in fields.items():
            start=(at+a-1)&-a;f=d['fields'][k]
            need(set(f)=={'offset','bytes','alignment','type'} and (f['offset'],f['bytes'],f['alignment'])==(start,size,a) and type(f['type'])is str and f['type'],'actual minimal field layout '+t+'.'+k)
            if start>at:gaps.append((at,start))
            at=start+size
        end=(at+align-1)&-align
        if end>at:gaps.append((at,end))
        need(d['bytes']==end,'complete source object extent '+t);self.padding[t]=gaps

    def field(self,b,t,k):
        need(len(b)==self.types[t]['bytes'],'whole typed object '+t)
        f=self.types[t]['fields'][k];return b[f['offset']:f['offset']+f['bytes']]
    def integer(self,b,t,k):return int.from_bytes(self.field(b,t,k),'little')
    def values(self,b,t,keys):return tuple(self.integer(b,t,k) for k in keys.split())
    def equal(self,b,t,**values):
        for k,v in values.items():
            x=self.field(b,t,k);need(int.from_bytes(x,'little')==v% (1<<(8*len(x))),'exact '+t+'.'+k)
    def walk(self,b,t):
        need(len(b)==self.types[t]['bytes'],'full captured '+t)
        for a,z in self.padding[t]:zero(b[a:z],'all alignment padding '+t)
        for k,child in self.layout['edges'][t].items():
            need(k in self.types[t]['fields'] and child in self.types,'actual embedded type edge')
            f=self.field(b,t,k);n=self.types[child]['bytes'];need(len(f)%n==0,'whole embedded array')
            for a in range(0,len(f),n):self.walk(f[a:a+n],child)
    def items(self,b,t,k,child):
        f=self.field(b,t,k);n=self.types[child]['bytes'];need(len(f)%n==0,'full child array')
        return [f[a:a+n] for a in range(0,len(f),n)]
    def change(self,a,b,t,values=None,observed=()):
        want=bytearray(a)
        for k in observed:
            f=self.types[t]['fields'][k];want[f['offset']:f['offset']+f['bytes']]=self.field(b,t,k)
        for k,v in (values or {}).items():
            f=self.types[t]['fields'][k];n=f['bytes'];v=v if type(v)is bytes else (v%(1<<(8*n))).to_bytes(n,'little')
            need(len(v)==n,'whole transition field');want[f['offset']:f['offset']+n]=v
        need(bytes(want)==b,'complete exact transition '+t)


def elf(data):
    need(type(data)is bytes and 64<=len(data)<=64<<20,'bounded retained original ELF')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1] in (2,3) and h[2:4]==(62,1) and h[8:10]==(64,56) and 0<h[10]<=32,'original ELF shape')
    need(h[5]<=len(data) and h[10]*56<=len(data)-h[5],'whole original program headers')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i) for i in range(h[10])]
    loads=[p for p in ph if p[0]==1]
    for p in loads:
        need(p[5]<=p[6] and p[2]<=len(data) and p[5]<=len(data)-p[2] and p[3]<=U64-p[6] and p[1]&3!=3,'complete original non-WX load')
    return h,loads


class Check:
    def __init__(self,reader,image,app,pid,cpu,control):
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'uho_wire','h'))
        self.control_words=q(self.f(self.b,'uho_wire','control'))
        self.owner=self.f(self.b,'uho_wire','owner');self.bias=self.h[9]-reader.layout['symbols']['li2_raw6']
        self.objects={};self.bases={};self.source_ids={};self.backings={};self.maps_seen={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'explicit lifecycle object inventory')
            h,loads=elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object'] in self.objects and image['interpreter_object'] in self.objects,'actual main/interpreter object assignment')
    def f(self,b,t,k):return self.r.field(b,t,k)
    def i(self,b,t,k):return self.r.integer(b,t,k)
    def v(self,b,t,k):return self.r.values(b,t,k)
    def eq(self,b,t,**v):self.r.equal(b,t,**v)
    def z(self,b,label):zero(b,label)
    def symbol(self,n):return self.bias+self.r.layout['symbols'][n]

    def stat(self,b):
        t='stat';self.eq(b,t,__pad0=0);zero(self.f(b,t,'__glibc_reserved'),'kernel stat reserved words')
        for k in ('st_atim','st_mtim','st_ctim'):
            need(self.i(self.f(b,t,k),'timespec','tv_nsec')<1000000000,'actual stat nanoseconds')
        return dict(zip(('dev','ino','mode','size'),self.v(b,t,'st_dev st_ino st_mode st_size')))

    def maps(self,b,kind=None):
        t='li2_fetch_map_progress';self.eq(b,t,last_read=0,close_result=0,opened=1,close_started=1,closed=1)
        fd,n,rows=self.v(b,t,'fd bytes rows');need(fd<1<<31 and 0<n<=256<<10 and 0<rows<=2048,'complete real maps read bounds')
        o=self.f(b,t,'observation');a,h,e,k,io=self.v(o,'li2_maps_observation','acquisition_id handler_id mutation_epoch kind io_performed')
        need(a>0 and e>0 and k in (0,1,4) and io==int(k!=4) and (h==0 if k==0 else h>0),'exact maintained acquisition class and physical I/O')
        if kind is not None:need(k==kind,'exact maps call-site kind')
        identity=self.v(b,t,'fd last_read close_result bytes opened close_started closed')
        if a in self.maps_seen:need(self.maps_seen[a]==identity,'same retained physical acquisition bytes/descriptor')
        else:self.maps_seen[a]=identity
        # The maintained updater changes canonical row_count after mprotect,
        # while retaining the physical read's fd/byte receipt. Its mutation
        # epoch, not acquisition_id alone, identifies this exact row view.
        if (a,e) in self.maps_seen:need(self.maps_seen[a,e]==rows,'same exact canonical view within its mutation epoch')
        else:self.maps_seen[a,e]=rows
        return a,h,e,k

    def query(self,b,entry,prot,pages=1,failed=False):
        t='li2_private_code_query';self.eq(b,t,first=entry,end=entry+pages*PAGE,attempted=1,expected_prot=prot)
        self.maps(self.f(b,t,'maps'))
        if failed:
            self.eq(b,t,complete=0,pages_checked=0,first_vma=0,last_vma_end=0,actual_prot=0,result=305,detail=0)
        else:
            self.eq(b,t,complete=1,pages_checked=pages,actual_prot=prot,result=0,detail=0)
            a,z=self.v(b,t,'first_vma last_vma_end')
            need(a%PAGE==z%PAGE==0 and 0<a<=entry and entry+pages*PAGE<=z<(1<<47),'complete actual private VMA envelope')

    def permission(self,b,entry,prot,error=0,sync_error=0):
        t='uh_permission';ok=not(error or sync_error)
        self.eq(b,t,started=1,returned=1,sync_started=1,sync_returned=1,complete=int(ok),prot=prot,result=error,sync_result=sync_error)
        self.query(self.f(b,t,'query'),entry,prot,failed=bool(error))

    def image_header(self,b,objid):
        t='image';obj,h,loads=self.objects[objid];bias,source=self.v(b,t,'bias source')
        need(canonical(source,len(obj['data'])) and bias%PAGE==0,'real protected original snapshot and image bias')
        need(self.i(b,t,'backing_fd')<1<<31,'actual original sealed descriptor')
        self.eq(b,t,entry=bias+h[4],ph=source+h[5],n=h[10],source_size=len(obj['data']),kind=obj['kind'])
        need(self.f(b,t,'source_hash')==hashlib.sha256(obj['data']).digest(),'whole original image digest')
        self.bases[objid]=bias

    def source(self,b,loop=True):
        t='li2_unrolled_source';self.eq(b,t,ready=1);pc=self.i(b,t,'pc')
        need(canonical(pc,39) and pc%PAGE<=PAGE-39,'bounded same-page source39')
        ref=self.f(b,t,'borrow');need(canonical(self.i(ref,'li2_fetch_ref','owner')) and self.i(ref,'li2_fetch_ref','sequence')>0,'actual occupied source borrow')
        p=self.f(b,t,'page');pt='li2_fetch_page';page=pc&-PAGE
        self.eq(p,pt,address=page,backing=1,logical=5,closed_prot=1)
        allocation,generation,offset,objid=self.v(p,pt,'allocation generation offset object')
        need(allocation>0 and generation>0 and offset%PAGE==0 and objid in self.objects,'known exact source allocation/generation/object')
        obj,h,loads=self.objects[objid]
        extent=max((p[3]+p[6]+PAGE-1)&-PAGE for p in loads)
        need(self.i(p,pt,'initial_extent') in ((0,extent) if offset==0 and objid not in (self.image['main_object'],self.image['interpreter_object']) else (0,)),'source-exact initial loader extent annotation')
        owners=[p for p in loads if p[1]==5 and (p[2]&-PAGE)<=offset and offset+pc%PAGE+39<=p[2]+p[5]]
        need(len(owners)==1,'one retained file-backed executable source range')
        seg=owners[0];bias=page-((seg[3]&-PAGE)+offset-(seg[2]&-PAGE))
        need(bias>=0 and bias%PAGE==0,'actual source bias from authenticated file offset')
        if objid in self.bases:need(self.bases[objid]==bias,'same actual object bias across all observations')
        else:self.bases[objid]=bias
        start=offset+pc%PAGE;want=obj['data'][start:start+39]
        need(len(want)==39 and self.f(b,t,'bytes')==want and (not loop or (want[:24]==BODY and want[24:26]==b'\x89\xdb')),'entire captured source window and real guard from retained ELF')
        backing=self.f(b,t,'backing');bt='li2_fetch_backing';self.eq(backing,bt,seals_observed=1,stat_observed=1,stat_result=0)
        st=self.stat(self.f(backing,bt,'stat'));fd,seals=self.v(backing,bt,'retained_fd seals')
        need(200<=fd<1<<31 and seals==15 and st['size']==obj['carrier_bytes'] and st['mode']&0xf000==0x8000,'actual retained duplicate, four seals and full carrier extent')
        if objid not in (self.image['main_object'],self.image['interpreter_object']):
            expected=obj['backing'];need(all(st[k]==expected[k] for k in ('dev','ino','size')) and seals==expected['seals'],'dependency backing equals actual launch inventory')
        elif objid==self.image['main_object']:
            need(st==self.stat(self.f(self.b,'uho_wire','main_backing')),'main retained duplicate equals actual original carrier stat')
        stable=(fd,seals,st['dev'],st['ino'],st['mode'],st['size'])
        if objid in self.backings:need(stable==self.backings[objid],'same complete retained backing per object')
        else:self.backings[objid]=stable
        first,end,major,minor,inode,vmaoff=self.v(p,pt,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        dev=st['dev'];maj=((dev>>8)&0xfff)|((dev>>32)&0xfffff000);minr=(dev&255)|((dev>>12)&0xffffff00)
        need(first%PAGE==end%PAGE==vmaoff%PAGE==0 and first<=page and page+PAGE<=end and vmaoff+page-first==offset and (major,minor,inode)==(maj,minr,st['ino']),'exact source VMA offset/device/inode')
        identity=(allocation,generation,offset,objid,fd,st['dev'],st['ino'],st['size'],seals)
        # Repeated snapshots of this fixed immutable source must not invent a
        # new allocation. Generations can change only across real app effects;
        # exact focal recurrence is additionally joined as whole page bytes.
        key=(page,allocation,generation)
        if key in self.source_ids:need(self.source_ids[key]==identity,'stable same-generation source identity')
        else:self.source_ids[key]=identity
        return dict(pc=pc,page=page,object=objid,bytes=want,raw=b,borrow=self.i(ref,'li2_fetch_ref','sequence'),identity=identity)

    def plan(self,b,source,entry):
        t='li2_unrolled_hash_plan';pc=source['pc'];self.eq(b,t,version=1,ready=1,decoder_calls=9,decoder_result=0,pc=pc,stop=pc+24,entry=entry)
        need(self.f(b,t,'source')==source['bytes'],'whole source in plan')
        generated=bytearray()
        for i in range(64):
            d=pc+24-(entry+(i+1)*28);need(-(1<<31)<=d<1<<31,'actual JZ rel32 reach')
            generated+=BODY[:22]+b'\x0f\x84'+struct.pack('<i',d)
        d=pc-entry-1797;need(-(1<<31)<=d<1<<31,'actual final rel32 reach')
        generated+=b'\xe9'+struct.pack('<i',d)
        need(self.f(b,t,'generated')==generated,'every generated byte and all65 branches')
        rows=self.r.items(b,t,'instructions','li2_decoded')+[self.f(b,t,'guard')]
        for i,row in enumerate(rows):
            o,n,code=(OFFSETS[i],LENGTHS[i],CODES[i]) if i<8 else (24,2,281)
            self.eq(row,'li2_decoded',pc=pc+o,next_pc=pc+o+n,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=int(i in (0,8)),available=15,length=n,reserved=0)
            need(self.f(row,'li2_decoded','bytes')==source['bytes'][o:o+15]+b'\0','all actual decoder input bytes')
        return bytes(generated)+b'\xcc'*(PAGE-1797)

    def frame(self,b,tls=True):
        t='uh_frame';self.eq(b,t,started=1,si_saved=1,uc_saved=1,complete=1)
        si,uc,s=(self.f(b,t,k) for k in ('si','uc','frame'))
        greg=q(self.f(s,'li2_step_frame','greg'));mask,fpaddr,n,initialized=self.v(s,'li2_step_frame','mask fp_address fp_bytes initialized')
        fp=self.f(s,'li2_step_frame','fp');lo,cap=self.h[12:14]
        need(cap==524288 and lo%PAGE==0 and fpaddr%16==0 and lo<=fpaddr and 580<=n<=FP and fpaddr+n<=lo+cap and initialized==n,'actual signal FP extent on configured altstack')
        need(q(uc[40:224])==greg and int.from_bytes(uc[224:232],'little')==fpaddr and int.from_bytes(uc[296:304],'little')==mask,'all copied signal GREG/mask/FP pointers')
        need(struct.unpack_from('<II',fp,464)==(0x46505853,n) and struct.unpack_from('<I',fp,480)[0]==n-4 and struct.unpack_from('<I',fp,n-4)[0]==0x46505845 and q(fp[520:528])==(0,),'full standard kernel FP metadata')
        zero(fp[n:],'every unused FP byte')
        need(int.from_bytes(uc[16:24],'little')==lo and int.from_bytes(uc[24:28],'little')==0 and int.from_bytes(uc[32:40],'little')==cap,'actual installed altstack, no invented SS_ONSTACK')
        fs,gs=self.v(b,t,'fs gs')
        if tls:self.eq(b,t,tls_complete=1,fs_result=0,gs_result=0)
        else:self.eq(b,t,tls_complete=0,fs_result=0,gs_result=0,fs=0,gs=0)
        sig=self.i(b,t,'sig');need(struct.unpack_from('<i',si)[0]==sig,'actual signal number in complete SI')
        return dict(greg=greg,fp=fp,fp_bytes=n,mask=mask,fs=fs,gs=gs,si=si,uc=uc,raw=b,sig=sig)

    def nx(self,f,pc,mutated=False):
        g=f['greg'];si=f['si'];need(f['sig']==11 and struct.unpack_from('<iii',si)==(11,0,2) and g[16]==pc and g[19:21]==(21,14) and g[22]==pc and int.from_bytes(si[16:24],'little')==pc+int(mutated),'exact first-byte genuine NX or explicit supplied SI+1')
        need(g[17]&(TF|RF)==RF and g[18]==0x2b000000000033 and g[21]==MASK and f['mask']==MASK and g[15]<(1<<47),'actual saved NX execution envelope')

    def memory(self,b,after_abort=False):
        t='li2_uho_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(after_abort),rows_checked=6,data_copied=8192,stack_copied=160,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0 if after_abort else 1)
        before,after=(self.f(b,t,k) for k in ('before','after'));st='li2_maps_stats'
        for v in (before,after):self.eq(v,st,active=int(not after_abort),poisoned=0,reserved=0)
        self.eq(after,st,valid=1,fresh_calls=self.i(before,st,'fresh_calls')+1,acquisitions=self.i(before,st,'acquisitions')+1,handler_id=self.i(before,st,'handler_id'))
        need(m[0]==self.i(after,st,'acquisitions') and m[1]==(0 if after_abort else self.i(before,st,'handler_id')) and m[2]==self.i(after,st,'mutation_epoch'),'memory acquisition actual stats join')
        # Fresh parser RAW advances mutation/invalidation counters according to
        # the fixed gateway; they are retained, never called extra acquisitions.
        need(self.i(after,st,'mutation_epoch')>=self.i(before,st,'mutation_epoch') and self.i(after,st,'invalidations')>=self.i(before,st,'invalidations') and self.i(after,st,'reuses')==self.i(before,st,'reuses'),'source-bound fresh parser counters')
        points=(DATA,DATA+8191,DATA+8192,STACK,RSP-128,STACK+4096+131072)
        for i,row in enumerate(self.r.items(b,t,'rows','li2_uho_map_row')):
            self.eq(row,'li2_uho_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_uho_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<=points[i]<z,'actual private fixed-memory VMA')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'whole data VMA')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'whole alternate application stack VMA')
            else:need(prot==0 and z-points[i]>=PAGE,'actual unreadable guard VMA')
        result={k:self.f(b,t,k) for k in ('data','stack')}
        need(result['data']==self.app['data'] and result['stack']==self.app['stack'],'every immutable application data/stack byte')
        return result

    def fetch(self,b,source,held):
        t='li2_fetch_progress';self.eq(b,t,held=int(held),complete=1,first_error=0,identity_observed=1,
            first_detail=0,pages_copied=1,bytes_copied=15,sequence=source['borrow'],last_backing_page=0,last_backing_observed=1)
        need(self.i(b,t,'validation_calls')>=(1 if held else 5),'actual source validation calls retained')
        self.maps(self.f(b,t,'preparation'));self.maps(self.f(b,t,'validation'))

    def pin(self,b,pid):
        t='li2_rseq_data';self.eq(b,t,pid=pid,tid=pid,attempted=1,complete=1,error=0,detail=0)
        a,p,alloc,gen,offset=self.v(b,t,'address page allocation generation offset')
        need(canonical(a,32) and a%32==0 and p==a&-PAGE and alloc>0 and gen>0 and offset%PAGE==0,'actual registered page geometry/identity')
        self.maps(self.f(b,t,'maps'));return a,p,alloc,gen,offset

    def owners(self,b,redirected=False,pc=None):
        t='uho_owners';self.eq(b,t,captured=1,word=0)
        state=self.f(b,t,'rseq');st='li2_rseq_state'
        self.eq(state,st,initialized=1,first_error=0,first_detail=0,pid=self.pid,tid=self.pid)
        reg=self.i(state,st,'registered');need(reg in (0,1),'actual optional registration')
        self.eq(b,t,word_observed=int(redirected and reg))
        need(self.i(state,st,'calls')==sum(self.i(state,st,k) for k in ('registrations','unregistrations','kernel_errors')),'all actual registration calls accounted')
        need(self.i(state,st,'registrations')-self.i(state,st,'unregistrations')==reg,'actual current registration lifetime')
        self.eq(state,st,epoch=self.i(state,st,'registrations'))
        if reg:
            self.eq(state,st,held=1,phase=3,length=32,tls_attempted=1,tls_complete=1,fs_result=0,gs_result=0)
            need(self.i(state,st,'epoch')>0,'actual registered epoch')
            data=self.f(state,st,'data');identity=self.pin(data,self.pid)
            need(self.v(state,st,'address page')==identity[:2],'current exact retained pin')
        else:self.eq(state,st,held=0,phase=0)
        if pc is not None:
            self.eq(state,st,last_pc=pc+22,last_code=176,last_policy=1,last_first=0,last_end=0)
            self.eq(self.f(state,st,'last_footprint'),'li2_write_footprint',pc=pc+22,next_pc=pc+24,first=0,end=0,abi_version=1,policy=1,code=176,length=2)
        # This build routes all physical native epochs through native_pair;
        # the old registered one-page owner is never initialized or entered.
        zero(self.f(b,t,'rseq_native'),'complete unused old one-page rseq owner')
        p,l,r=(self.f(b,t,k) for k in ('pair','lifecycle','rseq_pair'))
        self.eq(p,P,initialized=1,phase=2,in_handler=0,first_error=0,first_detail=0,live=0,entry_pending=0,pid=self.pid,tid=self.pid,session=self.symbol('selected_session'))
        self.eq(l,L,initialized=1,busy=0,live=0,first_error=0,first_detail=0,opening=0,pid=self.pid,tid=self.pid)
        self.eq(r,R,initialized=1,active=0,checking=0,entry_checked=0,first_error=0,first_detail=0,unsafe_terminal=0)
        need(self.i(l,L,'owner')==self.i(r,R,'owner') and canonical(self.i(l,L,'owner')),'same private pair owner')
        need(self.i(l,L,'published')==self.i(l,L,'closed_pages')==self.i(r,R,'published'),'all actual pair pages closed')
        need(self.i(p,P,'seeds')==self.i(p,P,'epochs_closed')==self.i(r,R,'attempts')==self.i(r,R,'closed'),'all actual pair epochs closed')
        need(self.i(r,R,'preentries')==self.i(r,R,'entries') and self.i(p,P,'refaults')==self.i(p,P,'refault_completed'),'every prior native boundary/refault completed')
        need(self.i(p,P,'epochs_closed')==self.i(p,P,'one_page_closes')+self.i(p,P,'two_page_closes') and self.i(l,L,'published')==self.i(p,P,'seeds')+self.i(p,P,'extensions'),'pair page/epoch conservation')
        if self.i(r,R,'attempts'):
            self.eq(r,R,pid=self.pid,tid=self.pid,word_before=0,word_entry=0,word_after=0)
            if self.i(r,R,'registered'):
                x=self.pin(self.f(r,R,'before'),self.pid);y=self.pin(self.f(r,R,'after'),self.pid)
                need(x==y and self.v(r,R,'address page')==x[:2],'closed pair pin retains full allocation/generation')
            else:
                for k in ('before','after'):zero(self.f(r,R,k),'unregistered pair has no invented pin')
        return b

    def mapped(self,b,source,entry,copy=0,offset=0,kind=1):
        t='li2_unrolled_hash_pc';length=LENGTHS[OFFSETS.index(offset)]
        generated=entry+copy*28+offset
        if kind==3:generated=entry+1792
        out=dict(version=1,ready=1,copy_index=copy,source_offset=offset,kind=kind,source_length=length,
                 generated_length=5 if kind==3 else 6 if kind==2 else length,reserved=0,original_pc=source['pc']+offset,generated_pc=generated)
        self.eq(b,t,**out);return out

    def slot(self,b,index):
        t='uh_slot';self.eq(b,t,installed=1,complete=1,filled=PAGE,verified=PAGE)
        source=self.source(self.f(b,t,'source'));entry=self.i(self.owner,'unrolled_owner','low_arena' if source['pc']<1<<31 else 'arena')+index*PAGE
        identity=index+1
        if self.control==5 and source['pc']==self.h[20]:identity^=1<<63
        self.eq(b,t,identity=identity)
        page=self.plan(self.f(b,t,'plan'),source,entry)
        self.query(self.f(b,t,'writable'),entry,3);self.permission(self.f(b,t,'publication'),entry,1)
        need(entry+PAGE<=source['page'] or entry>=source['page']+PAGE,'generated/source page disjoint')
        return dict(source=source,entry=entry,page=page,raw=b)

    def record(self,b,slots,kind='complete',focal=False):
        t='uh_record';slot=self.i(b,t,'slot');need(self.i(b,t,'slot_present')==1 and slot<len(slots),'real retained slot selected')
        s=slots[slot];source=self.source(self.f(b,t,'source'));entry=s['entry']
        # Borrow sequence changes per real entry; source/page/backing identity
        # does not change inside this borrow or on a same-generation hit.
        a,bsource=s['source']['raw'],source['raw'];self.r.change(a,bsource,'li2_unrolled_source',observed=('borrow','backing'))
        need(source['identity']==s['source']['identity'],'slot current exact source identity')
        before=self.frame(self.f(b,t,'before'));self.nx(before,source['pc'])
        flags=self.i(b,t,'flags');need(flags&(TF|RF)==0 and before['greg'][17]==flags|RF,'actual logical/physical entry flags')
        result=dict(before=before,after=None,unexpected=None,source=source,entry=entry,mapped=None)
        if kind=='slot_identity':
            self.eq(b,t,redirected=0,exit_seen=0,completed=0,release_started=0,release_complete=0,unexpected_seen=0,release_result=0,map_result=0,iterations=0,idle_bytes=0,live_bytes=0,closed_bytes=0)
            for k in ('original','idle','live','open','close','after','unexpected'):zero(self.f(b,t,k),'unexecuted slot-identity prefix '+k)
        else:
            if kind not in ('nested','exit_interior'):
                self.mapped(self.f(b,t,'original'),source,entry,copy=63 if kind=='fault_late' else 0,offset=17 if kind.startswith('fault') else 0)
            self.query(self.f(b,t,'idle'),entry,1);self.eq(b,t,idle_bytes=PAGE)
            self.permission(self.f(b,t,'open'),entry,5,error=-13 if kind=='open_error' else 0,sync_error=-13 if kind=='sync_error' else 0)
            entered=kind not in ('open_error','sync_error')
            self.eq(b,t,redirected=int(entered),live_bytes=PAGE if entered else 0)
            if entered:self.query(self.f(b,t,'live'),entry,5)
            else:zero(self.f(b,t,'live'),'failed open has no invented live query')
            if kind in ('complete','close_error'):
                after=self.frame(self.f(b,t,'after'));self.nx(after,after['greg'][16]);g=after['greg'];a=before['greg'];count=(g[14]-a[14])&U64
                need(1<=count<=64 and g[16] in (source['pc'],source['pc']+24) and
                    (g[12]==0 if g[16]==source['pc']+24 else count==64 and 1<=g[12]<=255),'actual bounded original head/stop NX')
                parity=(g[12]&255).bit_count()%2;defined=(0 if parity else 4)|(0 if g[12] else 64)|(g[12]&128)
                need(g[17]&0x8c5==defined and g[17]&~(0x8d5|RF)==flags&~0x8d5,'all defined final TEST flags; AF remains actual')
                need(all(a[i]==g[i] for i in range(23) if i not in (13,14,12,11,16,17,22)),'all unchanged actual GREGs')
                need(before['fp']==after['fp'] and before['fp_bytes']==after['fp_bytes'] and before['mask']==after['mask'] and (before['fs'],before['gs'])==(after['fs'],after['gs']),'complete FP/mask/TLS preservation')
                need(before['uc'][:40]==after['uc'][:40] and before['uc'][296:424]==after['uc'][296:424],'whole unchanged UC stack/flags/link/mask')
                result['after']=after
                self.eq(b,t,exit_seen=1,completed=int(kind=='complete'),iterations=count if kind=='complete' else 0,release_started=int(kind=='complete'),release_complete=int(kind=='complete'),release_result=0,unexpected_seen=0,map_result=0,closed_bytes=PAGE if kind=='complete' else 0)
                self.permission(self.f(b,t,'close'),entry,1,error=-13 if kind=='close_error' else 0)
                zero(self.f(b,t,'unexpected'),'completed/close-error event has no unexpected frame')
            else:
                self.eq(b,t,exit_seen=0,completed=0,iterations=0,release_started=0,release_complete=0,release_result=0,closed_bytes=0)
                for k in ('after','close'):zero(self.f(b,t,k),'no fabricated endpoint '+k)
                unexpected=kind in ('nested','exit_interior','fault_first','fault_late')
                self.eq(b,t,unexpected_seen=int(unexpected),map_result=0 if kind.startswith('fault') else int(unexpected))
                if unexpected:
                    f=self.frame(self.f(b,t,'unexpected'));result['unexpected']=f
                    if kind.startswith('fault'):
                        g=f['greg'];copy=63 if kind=='fault_late' else 0
                        result['mapped']=self.mapped(self.f(b,t,'original'),source,entry,copy,17)
                        need(f['sig']==11 and struct.unpack_from('<iii',f['si'])==(11,0,2) and g[16]==entry+copy*28+17 and g[19:21]==(4,14) and g[22]==DATA+8192 and int.from_bytes(f['si'][16:24],'little')==DATA+8192 and g[17]&(TF|RF)==RF,'genuine generated data-read fault and exact original association')
                    elif kind=='exit_interior':
                        self.nx(f,source['pc']+24,True);zero(self.f(b,t,'original'),'outside generated image map MISS has zero association')
                    else:
                        need(f['sig']==5 and struct.unpack_from('<iii',f['si'])==(5,0,-6) and struct.unpack_from('<II',f['si'],16)==(self.pid,self.image['uid']),'real nested SI_TKILL sender and explicit launch UID, never NUMA node')
                        need(f['greg'][16]==f['greg'][14]==self.h[9]+25 and f['greg'][13]==0 and (f['greg'][8],f['greg'][9],f['greg'][12],f['greg'][2],f['greg'][0],f['greg'][1])==(self.pid,self.pid,5,0,0,0) and self.h[12]<=f['greg'][15]<self.h[12]+self.h[13] and f['greg'][17]&0x10500==0,'actual nested tgkill return PC/arguments/runtime stack and control flags')
                        need(f['mask']==MASK and f['greg'][21]==MASK and
                            (f['fs'],f['gs'])==(before['fs'],before['gs']),
                            'nested SA_NODEFER mask/OLD_MASK and actual unchanged handler TLS')
                        zero(self.f(b,t,'original'),'runtime gateway map MISS has zero association')
                else:zero(self.f(b,t,'unexpected'),'unentered failure has no unexpected event')
        if kind=='complete':
            self.eq(b,t,cleanup_started=0,cleanup_complete=0);zero(self.f(b,t,'cleanup'),'no fabricated successful cleanup')
            self.fetch(self.f(b,t,'final_fetch'),source,False)
        else:
            good=kind not in ('close_error','sync_error');self.eq(b,t,cleanup_started=1,cleanup_complete=int(good))
            self.permission(self.f(b,t,'cleanup'),entry,1,error=-13 if kind=='close_error' else 0,sync_error=-13 if kind=='sync_error' else 0)
            self.fetch(self.f(b,t,'final_fetch'),source,True)
        return result

    def nested_fp(self,outer,inner):
        saved=outer['fp'];n=outer['fp_bytes'];c=self.control_words;hw=self.app['hardware']
        need(c[22]==1 and c[21]==self.app['header'][14] and c[23]==0,'actual guarded handler XGETBV equals same-process initial XCR0')
        features=0xe7|(0x200 if c[21]&0x200 else 0)
        need(struct.unpack_from('<IIQI',saved,464)==(0x46505853,n,features,n-4) and q(saved[512:520])==(features,),'closed supported signal user-feature set')
        ends=[576]
        for feature in (2,5,6,7,9):
            if features>>feature&1:
                row=hw[3+feature];need(row[:2]==(13,feature) or row[:2]==[13,feature],'actual CPUID subleaf identity')
                size,offset=row[2:4];need(size>0 and offset>=576 and offset+size<=65532,'bounded standard component')
                ends.append(offset+size)
        need(n==max(ends)+4 and inner['fp_bytes']==n,'exact initialized-handler FP extent')
        zero(saved[484:512],'full kernel FP software reserved bytes');zero(saved[520:576],'full standard header reserved bytes')
        expected=bytearray(FP);struct.pack_into('<H',expected,0,0x37f)
        mask=struct.unpack_from('<I',saved,28)[0];need(mask&0x1f80==0x1f80,'same-CPU actual MXCSR capability')
        struct.pack_into('<II',expected,24,0x1f80,mask)
        struct.pack_into('<IIQI',expected,464,0x46505853,n,features,n-4)
        struct.pack_into('<Q',expected,512,3|(features&0x200))
        if features&0x200:
            need(c[18]<(1<<32) and c[19:21]==(0,1) and hw[2][4]&24==24 and hw[12][2]==8,'actual permitted RDPKRU/CPUID D9 geometry')
            struct.pack_into('<I',expected,hw[12][3],c[18])
        else:need(c[18:21]==(0,0,0),'no unsupported PKRU instruction or invented result')
        struct.pack_into('<I',expected,n-4,0x46505845)
        need(inner['fp']==expected,'entire initialized live-handler FP buffer including actual independently observed PKRU')

    def header(self,exit_status):
        h=self.h;r=self.r;c=self.control_words;mode=self.app['header'][4]
        code,detail=(0,0) if exit_status==0 else ((2404,11) if not self.control else
            ((2404,5),(2403,7),(2403,9),(2403,7),(2403,5),(2404,11),(2404,11))[self.control-1])
        need(h[:9]==(0x314f48554c49324c,1,r.types['uho_wire']['bytes'],r.types['unrolled_owner']['bytes'],r.types['uho_entry']['bytes'],r.types['uh_record']['bytes'],r.types['uh_frame']['bytes'],968,128),'whole actual capture version/type extents')
        need(canonical(self.bias) and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k) for k in ('li2_raw6','li2_gateway_start','li2_gateway_end')) and h[10]<=h[9]<h[11],'actual retained bridge/gateway address relation')
        need(canonical(h[12],h[13]) and h[12]%PAGE==0 and h[13]==524288,'actual full altstack')
        need(h[14:16]==(1,0) and h[16]& (3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual private regular-file sink and main stat observations')
        need(h[20]==self.app['header'][10] and h[22]==self.image['main_object'] and h[23]==1 and h[26:30]==(1,exit_status,code,detail&U64),'actual focal image and terminal outcome')
        need(h[39]==0 and h[41:43]==(h[16],0) and h[45]<=h[44]<=h[43] and h[46]<=h[43] and h[47:50]==(0,0,0) and h[50:53]==(1,1,1) and not any(h[53:]),'complete diagnostics/FD guards/terminal copies without violation')
        need(c[0]==self.control and not any(c[4:6]),'actual requested control and reserved words')
        if self.control!=1:need(not any(c[18:]),'no unexecuted handler PKRU observations')
        a,b=(self.f(self.b,'uho_wire',k) for k in ('sink_initial','sink_terminal'))
        for value in (a,b):
            st=self.stat(value);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual0600 regular-file empty pre-write sink')
            self.eq(value,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(a,b,'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x31464f48554c4932,1,len(self.b),len(self.b)) and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b) and footer[6:]==(exit_status,code),'exact complete record/footer and actual write prefix')
        if footer[4]==1:need(footer[5]==len(self.b),'actual single full write')
        self.image_header(self.f(self.b,'uho_wire','main'),self.image['main_object'])
        self.image_header(self.f(self.b,'uho_wire','interpreter'),self.image['interpreter_object'])
        obj,_,loads=self.objects[self.image['main_object']]
        matches=[p for p in loads if p[1]==5 and p[3]<=h[20] and h[20]+39<=p[3]+p[5]]
        need(len(matches)==1 and h[21]==matches[0][2]+h[20]-matches[0][3],'actual main head file offset')
        need(self.f(self.b,'uho_wire','original_source')==self.app['source'][:39],'all actual focal original bytes')
        hardware=self.f(self.b,'uho_wire','hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):
            need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app hardware equality')
        return dict(status=exit_status,failure_code=code,detail_abs=abs(detail),detail_negative=int(detail<0))

    def redirected(self,raw,before,entry):
        frame=self.frame(raw,False);want=bytearray(before['raw']);t='uh_frame'
        f=self.r.types[t]['fields'];st=self.r.types['li2_step_frame']['fields']
        struct.pack_into('<Q',want,f['uc']['offset']+40+16*8,entry)
        struct.pack_into('<Q',want,f['frame']['offset']+st['greg']['offset']+16*8,entry)
        for key in ('fs','gs','fs_result','gs_result','tls_complete'):
            x=f[key];want[x['offset']:x['offset']+x['bytes']]=bytes(x['bytes'])
        need(raw==bytes(want),'entire saved SI/UC/GREG/FP frame changes only RIP at actual redirect')
        return frame

    def controls(self,current,result):
        c=self.control_words;kind=self.control;t='uh_record'
        before=self.f(self.b,'uho_wire','control_before');supplied=self.f(self.b,'uho_wire','supplied_before')
        want=[0]*24;want[0]=kind
        if not kind:
            need(c==tuple(want),'no fabricated control progress');zero(before,'unused control owner');zero(supplied,'unused supplied signal');return
        want[1:4]=[1 if kind==1 else 2 if kind in (2,3,4) else kind,1,0 if kind==1 else 1]
        slot=self.i(current,t,'slot');entry=result['entry'] if result else 0
        if kind==1:
            want[6:9]=[self.pid,self.pid,5];want[12]=1;want[18:23]=c[18:23]
            self.nested_fp(result['before'],result['unexpected'])
        elif kind in (2,3,4):
            want[8:14]=[entry,PAGE,5 if kind==2 else 1,324 if kind==4 else 10,1,1];want[15:17]=[1,1]
        elif kind==5:want[6:8]=[slot+1,(slot+1)^(1<<63)]
        else:want[6:8]=[self.h[20]+(24 if kind==7 else 0),self.h[20]+(24 if kind==7 else 0)+1]
        need(c==tuple(want),'exact actual/supplied control protocol, no invented return marker')
        if kind==6:
            zero(before,'entry mutation captures genuinely zero owner before first capture')
            actual=self.frame(supplied,False);self.nx(actual,self.h[20])
            changed=self.f(current,t,'before');desired=bytearray(supplied)
            at=self.r.types['uh_frame']['fields']['si']['offset']+16
            struct.pack_into('<Q',desired,at,self.h[20]+1)
            need(changed==desired,'entire actual entry frame retained separately from supplied SI mutation')
        else:
            if kind==7:
                actual=self.frame(supplied,False);self.nx(actual,self.h[20]+24)
                desired=bytearray(supplied);f=self.r.types['uh_frame']['fields'];struct.pack_into('<Q',desired,f['si']['offset']+16,self.h[20]+25)
                for k in ('fs','gs','fs_result','gs_result','tls_complete'):
                    x=f[k];desired[x['offset']:x['offset']+x['bytes']]=self.f(result['unexpected']['raw'],'uh_frame',k)
                need(result['unexpected']['raw']==desired,'whole actual exit retained; only supplied SI+1 and actual later TLS observations differ')
            else:zero(supplied,'no unused supplied event')
            later=('cleanup_started','cleanup_complete','cleanup','final_fetch')
            if kind in (1,7):later+=('unexpected_seen','unexpected','map_result','original')
            elif kind in (2,4):later+=('open',)
            elif kind==3:later+=('open','live','live_bytes','redirected','exit_seen','after','close')
            self.r.change(before,current,t,observed=later)

    def clean_miss(self,b,slots):
        """Only the actual unentered before/source prefix may remain at exit."""
        t='uh_record';source=self.f(b,t,'source');ready=self.i(source,'li2_unrolled_source','ready')
        need(ready in (0,1),'actual source-ready bit on clean miss')
        before=self.frame(self.f(b,t,'before'),bool(ready));pc=before['greg'][16]
        self.nx(before,pc);flags=self.i(b,t,'flags')
        need(flags&(TF|RF)==0 and before['greg'][17]==flags|RF,'clean miss preserves actual entry flags')
        expected=bytearray(len(b))
        for key in ('before','flags','source'):
            f=self.r.types[t]['fields'][key];expected[f['offset']:f['offset']+f['bytes']]=self.f(b,t,key)
        need(b==expected,'no publication/redirect/exit/release fabricated on a clean miss')
        if not ready:
            zero(source,'unsupported source leaves complete output zero')
            need(self.i(self.owner,'unrolled_owner','source_misses')>0,'real source-miss count')
            found=[]
            for objid,bias in self.bases.items():
                obj,_,loads=self.objects[objid]
                for p in loads:
                    if p[1]==5 and bias+p[3]<=pc and pc+15<=bias+p[3]+p[5]:
                        at=p[2]+pc-bias-p[3];found.append(obj['data'][at:at+15])
            need(found==[BODY[:15]],'actual source-miss PC still has one retained prefix origin')
        else:
            s=self.source(source,False);need(s['pc']==pc,'whole clean-miss source belongs to its actual frame')
            need(all(x['source']['identity']!=s['identity'] or x['source']['pc']!=pc for x in slots),'existing exact slot cannot become a miss')
            if len(slots)==64:
                need(self.i(self.owner,'unrolled_owner','capacity_misses')>0,'actual unchanged full-capacity miss')
            else:
                entry=self.i(self.owner,'unrolled_owner','low_arena' if pc<1<<31 else 'arena')+len(slots)*PAGE
                reachable=all(-(1<<31)<=pc+24-(entry+(i+1)*28)<1<<31 for i in range(64)) and -(1<<31)<=pc-entry-1797<1<<31
                need(self.i(self.owner,'unrolled_owner','plan_misses')>0 and
                    (s['bytes'][:24]!=BODY or s['bytes'][24:26]!=b'\x89\xdb' or not reachable),'source-derived exact planner MISS, never a skipped accepted body')

    def report_rows(self,outcome):
        """Exact raw snapshots projected in the unchanged report field order."""
        wire=Fields(self.r,self.b,'uho_wire');bundle=wire.child('terminal_owners','uho_owners')
        pair=bundle.child('pair',P);life=bundle.child('lifecycle',L);rp=bundle.child('rseq_pair',R)
        state=bundle.child('rseq','li2_rseq_state');close=wire.child('terminal_global_close','li2_native_close')
        native=wire.child('terminal_native_counts','li2_native_counts')
        cb=close.data;ct=close.name;pages=close.integer('pages')
        self.eq(cb,ct,busy=0,complete=1,first_error=0,first_detail=0,first_error_address=0,
            pid=self.pid,tid=self.pid,last_result=0,sync_result=0,
            attempted=pages,returned=pages,closed=pages,verified=pages,
            sync_started=int(pages>0),sync_returned=int(pages>0),cleanup_started=0,cleanup_complete=0,
            cleanup_attempted=0,cleanup_returned=0,cleanup_first_result=0,cleanup_sync_result=0)
        need(close.integer('sequence')>0 and pages<=2 and
            close.integer('sequence')>=life.integer('close_calls'),'distinct global successful native-close sequence')
        if pages:need(canonical(close.integer('last_address')) and close.integer('last_address')%PAGE==0,'actual last closed native page')
        else:self.eq(cb,ct,last_address=0)
        for key in ('before','after'):self.maps(close.field(key))
        need(native.integer('admissions')==native.integer('closed')==life.integer('published') and
            native.integer('attempts')==life.integer('attempts') and
            native.integer('attempts')>=sum(native.integer(k) for k in ('admissions','blocked','low_address_refusals')),
            'physical pair admissions and closed pages, independent of generated entries')
        revisit=native.integer('revisit_count');need(0<=revisit<=16 and revisit<=max(native.integer('admissions')-1,0),'actual bounded native revisit population')
        values=list(q(native.field('revisit_ns')));need(all(v>0 for v in values[:revisit]) and not any(values[revisit:]),'actual positive revisit prefix and entire zero tail')
        need(native.integer('first_source_offset')%PAGE==0 and (native.integer('first_admission_ns')>0 if native.integer('admissions') else native.integer('first_admission_ns')==0),'actual first native timing/offset observation')
        physical={k:native.integer(k) for k in ('attempts','admissions','closed','blocked','low_address_refusals','first_admission_ns','first_source_offset','revisit_count')}
        physical.update(status=outcome['status'],failure_code=outcome['failure_code'],revisit_ns=values[:revisit],
            close_error=close.integer('first_error'),close_complete=close.integer('complete'),close_busy=close.integer('busy'),
            epoch_exits=0,refaults=0,epoch_error=0)
        own=Fields(self.r,self.owner,'unrolled_owner');current=own.child('current','uh_record')
        names=('initialized first_error used candidates source_misses plan_misses capacity_misses publications hits '
               'entries completed head_exits stop_exits iterations unexpected events').split()
        unrolled=dict(version=1,**outcome,observe_only=0,**{k:own.integer(k) for k in names},
            signals=list(q(own.field('signals'))),active=self.h[31],busy=self.h[32],
            first_detail_abs=abs(own.signed('first_detail')),first_detail_negative=int(own.signed('first_detail')<0))
        unrolled['current']=(current.values('slot_present slot redirected exit_seen completed iterations')+
            current.child('open','uh_permission').values('started returned complete')+
            current.child('close','uh_permission').values('started returned complete')+
            current.values('release_started release_complete cleanup_started cleanup_complete')+
            [current.child('before','uh_frame').integer('complete'),current.child('after','uh_frame').integer('complete'),
             current.integer('unexpected_seen'),current.child('unexpected','uh_frame').integer('complete')]+
            current.child('original','li2_unrolled_hash_pc').values('ready kind copy_index source_offset')+
            current.values('idle_bytes live_bytes closed_bytes')+current.child('final_fetch','li2_fetch_progress').values('held complete'))
        return dict(outcome=outcome,native_pair=pair_row(pair,life,rp,close,outcome),rseq=rseq_row(state,outcome),
            native=physical,unrolled=unrolled,route=self.h[36],pending=self.h[35],dependencies=self.h[22])

    def finish(self,exit_status):
        outcome=self.header(exit_status);h=self.h;r=self.r;ot='unrolled_owner';o=self.owner
        mode=self.app['header'][4];control=self.control;failed=exit_status==125
        self.eq(o,ot,initialized=1,metadata_registered=1,arena_registered=1,allocated=1,low_arena_registered=1,low_allocated=1,
            first_error=outcome['failure_code'],first_detail=outcome['detail_abs'])
        arena,low,used=self.v(o,ot,'arena low_arena used')
        need(canonical(arena,64*PAGE) and arena%PAGE==0 and 0<low<=2**31-64*PAGE and low%PAGE==0 and
            (low+64*PAGE<=arena or arena+64*PAGE<=low) and 0<=used<=64 and (used>0 or control==6),'both actual disjoint arenas and unchanged total capacity')
        self.eq(o,ot,allocation_result=arena,low_allocation_result=low,publications=used)
        self.query(self.f(o,ot,'initial'),arena,3,64);self.query(self.f(o,ot,'low_initial'),low,3,64)
        session=self.f(o,ot,'session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')<1<<63 and self.i(session,'li2_step_session','sync_query')&96==96,'actual sync-core session')
        generated=self.f(self.b,'uho_wire','generated');slots=[]
        for i,b in enumerate(r.items(o,ot,'slots','uh_slot')):
            if i>=used:zero(b,'entire unused slot');zero(generated[i*PAGE:(i+1)*PAGE],'entire unused page capture');continue
            s=self.slot(b,i);need(generated[i*PAGE:(i+1)*PAGE]==s['page'],'entire actual terminal published page including fill');slots.append(s)
        need(h[40]==used,'every actual used page captured')
        entries_count=self.i(o,ot,'entries');completed=self.i(o,ot,'completed')
        self.eq(o,ot,candidates=sum(self.i(o,ot,k) for k in ('source_misses','plan_misses','capacity_misses','publications','hits'))+int(control==6),
            entries=used+self.i(o,ot,'hits')-int(control in (2,4,5)),completed=entries_count-int(failed and control not in (2,4,5,6)),
            unexpected=int((failed and not control) or control in (1,7)))
        need(completed==self.i(o,ot,'head_exits')+self.i(o,ot,'stop_exits') and completed<=self.i(o,ot,'iterations')<=64*completed,'all genuine bounded exit iterations accounted')
        need(self.i(o,ot,'events')==sum(q(self.f(o,ot,'signals'))),'complete event/signal partition')
        current=self.f(o,ot,'current');last=self.f(o,ot,'last');rows=r.items(self.b,'uho_wire','entries','uho_entry')
        count=0 if control==6 else 2 if mode==4 and not control else 1
        need(h[24]==count and h[25]==(count if not failed else 0),'exact focal attempt/completion population')
        kind=(('complete' if not failed else 'fault_late' if mode==8 else 'fault_first') if not control else
            ('nested','open_error','close_error','sync_error','slot_identity','entry_interior','exit_interior')[control-1])
        outputs=[];bundles=[]
        for i,e in enumerate(rows):
            if i>=count:zero(e,'complete unused focal entry capacity');continue
            et='uho_entry';self.eq(e,et,present=1,ordinal=i,committed=int(not failed),source_bytes=PAGE,terminal_source_bytes=PAGE)
            raw=self.f(e,et,'owner');result=self.record(raw,slots,kind,focal=True)
            need(result['source']['pc']==h[20],'focal source is actual application head')
            result['source_page']=self.f(e,et,'source_page');result['terminal_source_page']=self.f(e,et,'terminal_source_page')
            need(result['source_page']==result['terminal_source_page']==self.app['source'],'whole actual initial/final source page')
            result['before_memory']=self.memory(self.f(e,et,'before_memory'))
            result['after_memory']=self.memory(self.f(e,et,'after_memory'),failed)
            entered=self.i(raw,'uh_record','redirected')==1
            self.eq(e,et,generated_bytes=PAGE if entered else 0)
            if entered:
                need(self.f(e,et,'generated_page')==slots[self.i(raw,'uh_record','slot')]['page'],'entire actual RX page at redirect')
                self.redirected(self.f(e,et,'redirected'),result['before'],result['entry'])
                b=self.owners(self.f(e,et,'redirected_owners'),True,h[20]);bundles.append(b)
            else:
                for k in ('generated_page','redirected','redirected_owners'):zero(self.f(e,et,k),'no fabricated redirect '+k)
            if not failed:
                b=self.owners(self.f(e,et,'completed_owners'),False,h[20]);r.change(bundles[-1],b,'uho_owners',dict(word_observed=0))
            else:zero(self.f(e,et,'completed_owners'),'failure has no completed owner snapshot')
            need((result['before']['fs'],result['before']['gs'])==tuple(self.app['machine'][1:3]),'actual app TLS at focal entry')
            if control:
                greg=tuple(result['before']['greg'][k] for k in (13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7))
                need(greg==self.app['seed'][0] and result['before']['greg'][17]==self.app['seed'][1]|RF,'complete actual fixed control entry state')
            need(self.i(e,et,'terminal') in (0,1),'actual terminal row marker')
            if self.i(e,et,'terminal'):
                need(h[30]==i and raw==current,'whole final focal record equals actual current owner')
            outputs.append(result)
        if control==6:
            before=self.frame(self.f(current,'uh_record','before'),False);self.nx(before,h[20],True)
            expected=bytearray(len(current));f=r.types['uh_record']['fields']
            for k in ('before','flags','final_fetch'):
                d=f[k];expected[d['offset']:d['offset']+d['bytes']]=self.f(current,'uh_record',k)
            need(bytes(expected)==current and self.i(current,'uh_record','flags')==self.app['seed'][1],'exact pre-source required refusal prefix')
            need(h[30]==2,'no focal row for rejected supplied entry')
            f=self.f(current,'uh_record','final_fetch');ft='li2_fetch_progress'
            self.eq(f,ft,held=1,complete=1,first_error=0,first_detail=0,identity_observed=1,pages_copied=1,bytes_copied=15,last_backing_page=0)
            calls=self.i(f,ft,'validation_calls');self.eq(f,ft,last_backing_observed=int(calls>0))
            need(self.i(f,ft,'sequence')>0,'actual pre-source occupied borrow sequence')
            self.maps(self.f(f,ft,'preparation'))
            if calls:self.maps(self.f(f,ft,'validation'))
            else:zero(self.f(f,ft,'validation'),'no fabricated validation before supplied entry refusal')
        elif failed:
            need(h[30]==0 and rows[0] and self.i(rows[0],'uho_entry','terminal')==1,'actual failed focal terminal prefix')
        else:
            if self.i(current,'uh_record','completed'):
                self.record(current,slots);need(current==last,'whole current successful record equals last completed record')
            else:
                # A later real prefix may cleanly miss. Its only initialized
                # members are before/source/flags; no publication or completion.
                self.clean_miss(current,slots)
            focal=self.i(self.f(current,'uh_record','source'),'li2_unrolled_source','pc')==h[20]
            need(h[30]==(count-1 if focal else 2),'exact source-derived current focal index')
        if completed:self.record(last,slots)
        else:zero(last,'no fabricated previous completion')
        if failed:
            entered=control not in (2,4,5,6)
            need(h[31:34]==(int(entered),1,1) and h[34]==(0 if control==7 or not control else 1) and h[35:38]==(0 if control==6 else 1,0 if control==6 else 7,1) and h[38]==self.i(current,'uh_record','flags'),'actual failed active/busy/route/flags prefix')
            need(self.f(self.b,'uho_wire','terminal_fetch')==self.f(current,'uh_record','final_fetch'),'whole failed retained fetch prefix, no invented release')
        else:
            need(h[31:38]==(0,0,0,1,0,0,1),'real successful idle new owner at report')
            self.eq(self.f(self.b,'uho_wire','terminal_fetch'),'li2_fetch_progress',held=0,first_error=0)
        terminal=self.owners(self.f(self.b,'uho_wire','terminal_owners'))
        if failed and bundles:r.change(bundles[-1],terminal,'uho_owners',dict(word_observed=0))
        self.controls(current,outputs[0] if outputs else None)
        need(sum(self.i(self.f(e,'uho_entry','owner'),'uh_record','iterations') for e in rows[:count])<=self.i(o,ot,'iterations'),'focal subset never counted as global execution')
        expected=self.report_rows(outcome)
        return dict(control=control,entries=outputs,terminal_expected=expected,
            supplied_before=self.frame(self.f(self.b,'uho_wire','supplied_before'),False) if control in (6,7) else None,
            summary=dict(focal_entries=count,focal_completed=h[25],global_entries=entries_count,global_completed=completed,
                publications=used,required_failed_operation=int(failed),supplied_control=int(bool(control)),
                held_fetch=self.i(self.f(self.b,'uho_wire','terminal_fetch'),'li2_fetch_progress','held'),
                cleanup_complete=self.i(current,'uh_record','cleanup_complete')))



class Fields:
    def __init__(self, reader, data, name):
        self.reader, self.data, self.name = reader, data, name
        need(type(data) is bytes and len(data) == reader.types[name]['bytes'] and
             name in reader.padding,
             'whole owner with source-authenticated layout/padding '+name)

    def field(self, key):return self.reader.field(self.data, self.name, key)
    def integer(self, key):return self.reader.integer(self.data, self.name, key)
    def values(self, keys):return [self.integer(k) for k in keys.split()]
    def child(self, key, name):return Fields(self.reader, self.field(key), name)
    def signed(self, key):
        b = self.field(key)
        need(len(b) in (2,4,8), 'actual signed scalar extent '+self.name+'.'+key)
        return int.from_bytes(b, 'little', signed=True)
    def cast(self, key):return self.signed(key)&U64
    def magnitude(self, key):
        value = self.signed(key)
        return [abs(value), int(value < 0)]


def pair_row(p, l, r, close, outcome):
    """Literal native_pair_report.inc order, including signed C casts."""
    slots = l.field('slots')
    size = l.reader.types['li2_native_pair_slot']['bytes']
    need(len(slots) == 2*size, 'exact two captured lifecycle slots')
    rows = []
    for index in range(2):
        s = Fields(l.reader, slots[index*size:(index+1)*size], 'li2_native_pair_slot')
        page = s.child('page', 'li2_fetch_page')
        backing = s.child('backing', 'li2_fetch_backing')
        stat = backing.child('stat', 'stat')
        rows.append(s.values('prepared published slot pc')+
            page.values('address allocation generation offset object backing logical closed_prot')+
            s.values('window_before window_after window_bytes window_initialized policy')+
            [backing.cast('retained_fd'), backing.cast('seals')]+
            backing.values('seals_observed stat_observed')+[backing.cast('stat_result')]+
            stat.values('st_dev st_ino st_size st_mode'))
    first = p.magnitude('first_detail')
    life_first = l.magnitude('first_detail')
    rseq_first = r.magnitude('first_detail')
    return dict(version=1, **outcome,
        control=p.values('initialized phase in_handler first_error')+first[::-1]+
                p.values('live entry_pending first_observed second_observed close_reason pid tid'),
        counts=p.values('events seeds extensions epochs_closed one_page_closes two_page_closes '
                        'policy_closes capacity_closes refaults refault_completed'),
        last_nx=[p.cast(k) for k in ('signal_number','signal_code','signal_errno')]+
                p.values('pc signal_address logical_flags'),
        lifecycle=l.values('initialized busy live first_error')+life_first[::-1]+
                  l.values('sequence allocation_epoch generation_epoch transactions_epoch records_epoch '
                           'attempts published closed_pages close_calls candidate candidate_policy '
                           'candidate_eligible opening post_verified'),
        slots=rows,
        rseq=r.values('initialized registered active checking entry_checked first_error')+
             rseq_first[::-1]+r.values('unsafe_terminal pid tid attempts published preentries entries '
                'refreshes closed registration_epoch address page length signature word_before word_entry '
                'word_after fs_before gs_before fs_after gs_after fs_selector_entry gs_selector_entry '
                'fs_selector_after gs_selector_after'),
        pin_before=r.child('before','li2_rseq_data').values('allocation generation offset attempted complete error'),
        pin_after=r.child('after','li2_rseq_data').values('allocation generation offset attempted complete error'),
        close=close.values('sequence pages attempted returned closed verified busy complete first_error '
                           'cleanup_started cleanup_complete'))


def data_row(data):
    """All 28 existing rseq_data_report fields; no synthetic maps receipt."""
    maps = data.child('maps','li2_fetch_map_progress')
    observation = maps.child('observation','li2_maps_observation')
    return (data.values('address page allocation generation offset pid tid attempted complete error')+
            data.magnitude('detail')+maps.magnitude('fd')+maps.magnitude('last_read')+
            maps.magnitude('close_result')+maps.values('bytes rows opened close_started closed')+
            observation.values('acquisition_id handler_id mutation_epoch kind io_performed'))


def rseq_row(state, outcome):
    """Complete unchanged LI2_RSEQ row from the actual terminal snapshot."""
    transaction = state.child('transaction','li2_rseq_transaction')
    footprint = state.child('last_footprint','li2_write_footprint')
    data = state.child('data','li2_rseq_data')
    args = transaction.field('args')
    need(len(args) == 48, 'six complete actual rseq syscall arguments')
    return dict(version=1, scope='registered_inactive_prototype', **outcome, maps_profile=1,
        owner=state.values('initialized registered held phase first_error')+
              state.magnitude('first_detail')+state.values('pid tid address page length signature epoch'),
        tls=state.values('tls_attempted tls_complete')+state.magnitude('fs_result')+
            state.magnitude('gs_result')+state.values('fs_base gs_base'),
        counts=state.values('calls registrations unregistrations kernel_errors instruction_checks '
                            'range_checks repeat_checks run_checks syscall_checks'),
        last=state.values('last_pc last_code last_policy last_first last_end'),
        footprint=footprint.values('abi_version pc next_pc code length policy first end'),
        transaction=transaction.values('attempted issued returned prior_registered')+
                    transaction.magnitude('result')+transaction.values('input_word_observed input_word'),
        args=list(struct.unpack('<6Q',args)),
        identity=data.values('complete allocation generation offset'),
        before=data_row(transaction.child('before','li2_rseq_data')),
        after=data_row(transaction.child('after','li2_rseq_data')))


def read(data,layout,image,app,pid,cpu,exit_status,control=0):
    """Validate one whole actual FD3 record, returning observations, not credit.

    `image` is the qualifier's byte-pinned retained ELF/carrier inventory, and
    uid is its actual launch UID. Mapped biases are derived from observations.
    `app` has already passed the independent full stdout/native-prefix reader.
    The caller must also run terminal(), the unchanged old report gates, and
    B1's native/frame pair or supplied-control reference comparison.
    """
    need(type(pid)is int and pid>0 and type(cpu)is int and cpu>=0 and
        type(control)is int and 0<=control<=7 and type(exit_status)is int,'actual subject identity/control')
    need(type(image)is dict and type(image.get('uid'))is int and 0<=image['uid']<1<<32,'explicit actual launch UID')
    mode=app['header'][4]
    need(type(mode)is int and 0<=mode<=8 and (not control or mode==0),'fixed9 application modes and7 separate mode0 controls')
    need(exit_status==(125 if control or mode>=7 else 0),'exact required process result, no unexpected failure accepted')
    return Check(Reader(data,layout),image,app,pid,cpu,control).finish(exit_status)


def terminal(parsed,unrolled,owner):
    """Join actual report values; the caller retains every original gate."""
    expected=owner['terminal_expected'];outcome=expected['outcome']
    need(type(parsed)is dict and unrolled==expected['unrolled'],'every unrolled terminal field equals actual owner bytes')
    for key in ('native_pair','rseq'):
        need(parsed[key]==expected[key],'entire actual '+key+' report equals captured terminal state')
    for key,value in expected['native'].items():
        need(parsed['native'][key]==value,'physical native report/capture '+key)
    for name in ('loader','native_pair','rseq','run','chain','trace_run','reuse','repeat_lease'):
        need(all(parsed[name][key]==value for key,value in outcome.items()),'unchanged shared terminal outcome '+name)
    if parsed['repeat'] is not None:
        need(all(parsed['repeat'][key]==value for key,value in outcome.items()),'unchanged optional REP outcome')
    need(parsed['loader']['admissions']==expected['native']['admissions'] and
        parsed['loader']['dependency_objects']==expected['dependencies'] and
        parsed['loader']['step_route']==parsed['run']['route']==expected['route'] and
        parsed['run']['pending']==expected['pending'],'actual loader route/dependency/physical count joins')
    # These two old owners are never entered in this explicit pair profile.
    # Their schemas are checked by the original caller before this projection.
    for key,scope in (('rseq_native','registered_native_epochs'),('rseq_boundary','registered_current_pc_refault')):
        row=parsed[key]
        for name,value in row.items():
            if name=='version':want=1
            elif name=='scope':want=scope
            elif name in outcome:want=outcome[name]
            elif type(value)is list:want=[0]*len(value)
            else:want=0
            need(value==want,'whole untouched old idle owner '+key+'.'+name)
    return dict(reports_present=1,status=outcome['status'],failure_code=outcome['failure_code'],
        captured_global_native_closed=expected['native']['closed'],captured_fetch_held=owner['summary']['held_fetch'],
        captured_cleanup_complete=owner['summary']['cleanup_complete'])


def controls(data,layout,image,app,pid,cpu,exit_status,control=0):
    """Finite supplied-copy refusals. No native operation or acceptance credit."""
    original=hashlib.sha256(data).hexdigest();read(data,layout,image,app,pid,cpu,exit_status,control)
    types=layout['types']
    def where(path):
        at=0;t='uho_wire'
        for key,index,child in path:
            field=types[t]['fields'][key];at+=field['offset']
            if index is not None:
                at+=index*(types[child]['bytes'] if child else 8)
            if child:t=child
        return at
    tests=[]
    def add(name,path,byte=0):tests.append((name,where(path)+byte))
    for index in (0,2,27,28,39,40,48,50,51,52):add('header_'+str(index),[('h',index,None)])
    add('nested_uid_authority',[('sink_initial',None,'stat'),('st_uid',None,None)])
    add('owner_publications',[('owner',None,'unrolled_owner'),('publications',None,None)])
    add('owner_first_error',[('owner',None,'unrolled_owner'),('first_error',None,None)])
    add('actual_native_closed',[('terminal_native_counts',None,'li2_native_counts'),('closed',None,None)])
    add('actual_global_close',[('terminal_global_close',None,'li2_native_close'),('complete',None,None)])
    add('terminal_rseq_epoch',[('terminal_owners',None,'uho_owners'),('rseq',None,'li2_rseq_state'),('epoch',None,None)])
    add('terminal_pair_live',[('terminal_owners',None,'uho_owners'),('pair',None,P),('live',None,None)])
    count=0 if control==6 else 2 if app['header'][4]==4 and not control else 1
    if count:
        base=[('entries',0,'uho_entry')]
        for name,tail in (
            ('source_page',[('source_page',None,None)]),('terminal_source',[('terminal_source_page',None,None)]),
            ('data_memory',[('before_memory',None,'li2_uho_memory'),('data',None,None)]),
            ('after_stack',[('after_memory',None,'li2_uho_memory'),('stack',None,None)]),
            ('source_generation',[('owner',None,'uh_record'),('source',None,'li2_unrolled_source'),('page',None,'li2_fetch_page'),('generation',None,None)]),
            ('cleanup_prefix',[('owner',None,'uh_record'),('cleanup_complete',None,None)]),
            ('maps_io',[('after_memory',None,'li2_uho_memory'),('maps',None,'li2_fetch_map_progress'),('observation',None,'li2_maps_observation'),('io_performed',None,None)])):
            add(name,base+tail)
        add('before_fp_metadata',base+[('owner',None,'uh_record'),('before',None,'uh_frame'),('frame',None,'li2_step_frame'),('fp',None,None)],464)
        if control not in (2,4,5):add('whole_actual_generated_page',base+[('generated_page',None,None)],1796)
    else:add('actual_unmutated_entry',[('supplied_before',None,'uh_frame'),('si',None,None)],16)
    tests.extend([('footer_status',len(data)-16),('footer_extent',len(data)-48)])
    tests=[(name,[offset]) for name,offset in tests]
    if control==1:
        inners=[
            [('entries',0,'uho_entry'),('owner',None,'uh_record'),('unexpected',None,'uh_frame')],
            [('owner',None,'unrolled_owner'),('current',None,'uh_record'),('unexpected',None,'uh_frame')]]
        masks=[];oldmasks=[]
        for inner in inners:
            copied=inner+[('frame',None,'li2_step_frame')]
            masks.extend([where(inner+[('uc',None,None)])+296,where(copied+[('mask',None,None)])])
            oldmasks.extend([where(inner+[('uc',None,None)])+40+21*8,where(copied+[('greg',None,None)])+21*8])
        tests.extend([
            ('nested_coherent_mask',masks),('nested_coherent_oldmask',oldmasks),
            ('nested_actual_fs',[where(inner+[('fs',None,None)]) for inner in inners]),
            ('nested_actual_gs',[where(inner+[('gs',None,None)]) for inner in inners])])
    need(len({name for name,_ in tests})==len(tests),'unique fixed supplied record controls')
    names=[]
    for name,offsets in tests:
        changed=bytearray(data);rejected=False
        for offset in offsets:changed[offset]^=1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control)
        except ValueError as error:
            if name in ('nested_coherent_mask','nested_coherent_oldmask','nested_actual_fs','nested_actual_gs'):
                need(str(error)=='nested SA_NODEFER mask/OLD_MASK and actual unchanged handler TLS',
                    'coherent nested control reaches its exact semantic refusal')
            rejected=True
        need(rejected,'whole owner reader refuses supplied '+name);names.append(name)
    need(hashlib.sha256(data).hexdigest()==original,'original actual record unchanged')
    return dict(refusals=names,native_operations=0,original_sha256=original)
