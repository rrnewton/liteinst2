"""Exact D3 reader with two independently authenticated SBC registrations.

All old whole-state predicates and all 231/24/44 supplied controls remain.
No registry row is removed, resized, or hidden from plan reconstruction.
"""
import hashlib,struct,importlib.util,copy
from pathlib import Path
from resident_three import certificate_identity
ROOT=Path(__file__).resolve().parents[3]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
base=load('certificate_original_owner',ROOT/'tools/page-entry/selected/tests/resident_three_owner/read.py')
wire,plan,old=base.wire,base.plan,base.old
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,FP,TF,RF,MASK=base.PAGE,base.FP,base.TF,base.RF,base.MASK
T,STATE,CERT,STEP,GREG=base.T,base.STATE,base.CERT,base.STEP,base.GREG
elf_symbols,pair,pair_controls=base.elf_symbols,base.pair,base.pair_controls

class Check(base.Check):
    def registry(self):
        count=self.i(self.entered,STATE,'registry_count');need(0<count<=128,'whole bounded actual protected registry')
        rows=self.r.items(self.b,T,'registry','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:count]]
        for row in rows[count:]:zero(row,'whole unused protected registry range')
        need(all(canonical(a,z-a)for a,z in ranges),'all actual protected intervals')
        declarations=self.r.layout['registrations'];need(set(declarations)==set(wire.REGISTERED),'whole exact compiled registration roster');objects=certificate_identity.registered_objects(self.r.layout,self.image['certificate_layout'],self.image,self.bias,ranges,base.elf_symbols)
        headers=self.image['headers'];need(type(headers)is dict and headers,'actual complete compiler-M header closure')
        for name,(source,tag)in wire.REGISTERED.items():
            d=declarations[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual complete symbol/DWARF/source identity '+name)
            need(d['source']in headers and set(headers[d['source']])=={'bytes','sha256'},'registered DWARF origin belongs to actual compiler-M closure')
            objects.append((a,z))
            if name not in wire.LIFETIME:need(ranges.count((a,z))==1,'whole strict protected object '+name)
            loads=[p for p in self.ph if p[0]==1 and p[6]and self.bias+p[3]<z and a<self.bias+p[3]+p[6]]
            need(len(loads)==1 and loads[0][1]==6 and self.bias+loads[0][3]<=a<z<=self.bias+loads[0][3]+loads[0][6],'whole object in actual RW/NX bridge LOAD')
            p=loads[0];rounded=((self.bias+p[3])&-PAGE,(self.bias+p[3]+p[6]+PAGE-1)&-PAGE)
            need(ranges.count(rounded)==1,'whole containing bridge LOAD remains protected')
        need(all(a%PAGE==z%PAGE==0 or(a,z)in objects for a,z in ranges),'every non-page interval is an exact source registration')
        arena=self.i(self.entered,STATE,'arena');need(canonical(arena,327*PAGE)and arena%PAGE==0 and ranges.count((arena,arena+327*PAGE))==1,'whole independent three-certificate arena protection')
        need(self.symbol('r3_memory')==self.h[9]and self.symbols['r3_memory'][1]==1249280 and self.h[3]==1246656 and self.symbols['r3_work'][1]==2329264 and self.symbols['rsl'][1]==70*PAGE and self.symbols['rsl_initialization'][1]==72,'actual complete separate owner/source/bootstrap storage')
        self.ranges=ranges


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(data)is bytes and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'whole record and actual process/CPU identity')
    need(len(data)==2063040+64 and len(data)<4<<20,'complete distinct D3 raw record and footer')
    footer=q(data[-64:]);need(footer[:4]==(0x3152334f4632494c,2,2063040,2063040)and 1<=footer[4]<=64 and 0<footer[5]<=2063040 and footer[6:]==(0,0),'whole successful bounded record transport')
    r=wire.Reader(memoryview(data)[:-64],layout);out=Check(r,image,app,pid,cpu).finish(exit_status)
    out['transport']=dict(raw_bytes=2063040,body_bytes=footer[3],body_calls=footer[4],last_body_result=footer[5],status=footer[6],code=footer[7]);return out


def controls(data,layout,image,app,pid,cpu,exit_status):
    """Causal supplied corruptions of this new finite observation only."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types'];tests=[]
    def at(path):
        t=T;offset=0
        for key,index in path:
            field=types[t]['fields'][key];offset+=field['offset'];child=layout['edges'][t].get(key)
            if child:offset+=index*types[child]['bytes'];t=child
            else:
                need(index<field['bytes'],'bounded supplied scalar-byte stimulus');offset+=index
        return offset
    def add(name,path):tests.append((name,at(path)))
    def scalar(name,*path):add(name,[(x,0)if type(x)is str else x for x in path])
    for name,index in(('magic',0),('version',8),('whole_extent',16),('owner_extent',24),('raw_owner',72),('wire_address',80),('altstack',96),('sink_registered',112),('root',152),('terminal_pc',160),('actual_stack',176),('entered_complete',192),('terminal_complete',200),('next_complete',208),('ordinary_close',216),('terminal_ordinal',232),('incomplete',264),('status',272),('footer_sink',320),('prebind_epoch',328)):
        add(name,[('h',index)])
    for name,offset in(('bindings',336),('invalidations',344),('initialized',352),('valid',356),('pages',360),('reserved',364),('old_owner',368)):
        add('prebind_'+name,[('h',offset)])
    for i in range(9):add('bootstrap_'+str(i),[('bootstrap',i*8)])
    scalar('sink_inode','sink_terminal','st_ino');scalar('hardware','hardware','leaf1');scalar('session_mask','session','application_mask')
    for state in('entered','terminal','closed','final'):
        for key in('phase','publications','entries','completed','references','closed','generation','source_pages','registry_count','first_error'):
            scalar(state+'_'+key,state,key)
        scalar(state+'_rseq',state,'rseq','active');scalar(state+'_source_epoch',state,'source_progress','epoch')
        scalar(state+'_source_cost',state,'resident_progress','source_bytes')
    scalar('token_owner','entered','token','owner');scalar('actual_source_owner','entered','source','owner')
    scalar('held_borrow','held','ref','sequence');scalar('held_source','held','bytes');scalar('consumed_ticket','transfer','consumed')
    scalar('old_released_borrow','transfer','released','progress','held');scalar('source_union_page',('source',0),'identity','address')
    scalar('source_union_byte',('source',0),'bytes');scalar('protected_range',('registry',0),'end')
    for index in range(3):
        c=('certificate',index)
        for name,path in(
            ('sealed_fd',('identity','fd')),('sealed_inode',('identity','inode')),('sealed_extent',('identity','bytes')),
            ('source_generation',('payload','header','source_epoch')),('publication',('payload','header','publication_serial')),
            ('archive',('payload','header','archive')),('policy',('payload','header','policy')),
            ('source_bytes',('payload','source',('page',0),'bytes')),('table',('payload','plan','table','node')),
            ('head',('payload','plan','head')),('original',('payload','plan','original')),('frontier',('payload','plan','frontier')),
            ('instruction',('payload','plan','instruction')),('recovery',('payload','plan','guard')),
            ('generated',('code',)),('code_tail',(('code',69631),)),('proof_tail',('proof_tail',)),
            ('slots',('slots',)),('initial_spill',('spill_entered',)),('final_spill',('spill_closed',)),
            ('published_NX',(('published',0),'expected_prot')),('opened_RX',(('opened',0),'actual_prot')),
            ('drained_NX',(('drained',0),'complete')),('seals',(('opened',0),'sealed','seals_result')),
            ('query_backing',(('opened',0),'sealed','identity','inode')),('alias_census',(('proof',0),'sealed','alias_pages')),
            ('proof_offset',(('proof',1),'sealed','offset')),('anonymous_sidecar',(('slot_query',0),'sealed','kind')),
            ('whole_byte_scan',('proof_scan','compared'))):
            scalar('certificate'+str(index)+'_'+name,c,*path)
    scalar('directory_row','directory');add('directory_tail',[('directory',12287)])
    scalar('directory_query',('directory_query',1),'actual_prot');scalar('directory_scan','directory_scan','compared')
    for key in('before','after','next'):
        scalar(key+'_GREG',key,'frame','greg');scalar(key+'_FP',key,'frame','fp')
        scalar(key+'_mask',key,'frame','mask');scalar(key+'_TLS',key,'fs')
        add(key+'_whole_FP_tail',[(key,0),('frame',0),('fp',65535)])
        add(key+'_UC_alias',[(key,0),('uc',304)])
    for i in range(3):
        m=('memory',i)
        scalar('memory'+str(i)+'_origin',m,'origin','anchor');scalar('memory'+str(i)+'_fresh',m,'after','acquisitions')
        scalar('memory'+str(i)+'_stack',m,'stack');add('memory'+str(i)+'_lastbyte',[m,('stack',519)])
    scalar('next_chain_phase','next_closed','phase');scalar('next_chain_release','next_closed','release','complete')
    scalar('next_chain_after','next_closed','owner','step','after','fp');scalar('next_chain_unexpected','next_closed','unexpected')
    scalar('next_target_identity','next_closed','query','page','object');scalar('next_close_scan','unexpected_scan','compared')
    refused=[]
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied finite D3 corruption '+name)
    changed=bytearray(data);valid=struct.unpack_from('<I',data,356)[0]
    struct.pack_into('<Q',changed,376,0 if valid else 1)
    try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
    except ValueError:refused.append('prebind_old_serial')
    else:raise ValueError('accepted actual prebind old-owner serial corruption')
    for name,changed in(('truncated',data[:-1]),('extra',data+b'\0'),('failed_footer',data[:-16]+struct.pack('<QQ',125,4900))):
        try:read(changed,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted complete-record/failed-outcome corruption '+name)
    need(len(refused)==231,'all231 finite D3 owner supplied controls refused')
    return dict(refusals=refused,count=len(refused),source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)


def prepared_fetch_controls(data,layout,image,app,pid,cpu,exit_status):
    """Separate exact prepared/released chronology mutations; original231 stay whole."""
    read(data,layout,image,app,pid,cpu,exit_status);types=layout['types'];refused=[]
    def at(path):
        t=T;offset=0;size=types[t]['bytes']
        for item in path:
            key,index=(item,0)if type(item)is str else item
            field=types[t]['fields'][key];offset+=field['offset'];child=layout['edges'][t].get(key)
            if child:
                size=types[child]['bytes'];need((index+1)*size<=field['bytes'],'bounded prepared-fetch aggregate stimulus')
                offset+=index*size;t=child
            else:
                need(index<field['bytes'],'bounded prepared-fetch scalar stimulus');offset+=index;size=field['bytes']-index
        return offset,size
    def reject(name,changed):
        need(bytes(changed)!=data,'changed prepared-fetch stimulus '+name)
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied prepared/released fetch corruption '+name)
    def flip(name,path,tail=False):
        offset,size=at(path);changed=bytearray(data);changed[offset+(size-1 if tail else 0)]^=1;reject(name,changed)
    prepared=(('entered',('entered','fetch')),('fresh',('transfer','fresh','progress')),('held',('held','progress')))
    for name,path in prepared:
        for key in('validation_calls','last_backing_observed','validation'):
            flip(name+'_'+key,path+(key,))
    for name,path in(('fresh',('transfer','fresh')),('held',('held',))):
        flip(name+'_last_backing',path+('last_backing',))
        flip(name+'_last_backing_tail',path+('last_backing',),True)
        flip(name+'_initial_backing',path+(('backing',0),'seals'))
        flip(name+'_initial_page',path+(('pages',0),'address'))
        flip(name+'_source_bytes',path+('bytes',))
    offset,size=at(('terminal','fetch','validation_calls'));need(size==8,'actual validation-call counter width')
    for count in(0,2):
        changed=bytearray(data);struct.pack_into('<Q',changed,offset,count);reject('terminal_validation_calls_'+str(count),changed)
    flip('terminal_validation_closed',('terminal','fetch','validation','closed'))
    # Copy genuine later validation evidence into every prepared observation:
    # a coherent fabricated early validation must still refuse exact zero.
    changed=bytearray(data);source,size=at(('terminal','fetch','validation'))
    for name,path in prepared:
        target,n=at(path+('validation',));need(n==size,'same actual validation-map extent')
        changed[target:target+n]=data[source:source+n]
        target,n=at(path+('validation_calls',));need(n==8,'prepared validation-call width');struct.pack_into('<Q',changed,target,1)
        target,n=at(path+('last_backing_observed',));need(n==4,'prepared last-backing flag width');struct.pack_into('<I',changed,target,1)
    for name,path in(('fresh',('transfer','fresh')),('held',('held',))):
        source,n=at(path+(('backing',0),));target,m=at(path+('last_backing',));need(n==m,'whole backing extent')
        changed[target:target+m]=data[source:source+n]
    reject('coordinated_invented_preentry_validation',changed)
    changed=bytearray(data)
    for key in('validation_calls','last_backing_observed','validation'):
        offset,size=at(('terminal','fetch',key));changed[offset:offset+size]=bytes(size)
    reject('coordinated_missing_release_validation',changed)
    need(len(refused)==len(set(refused))==24,'all24 additional prepared/released fetch controls')
    return dict(count=24,refusals=refused,source_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)



def storage_controls(data,layout,image,app,pid,cpu,exit_status):
    original=read(data,layout,image,app,pid,cpu,exit_status);refused=[]
    for name in ('sbc_observed','sbco'):
        for key in ('address','bytes','tag','source'):
            changed=copy.deepcopy(image);row=changed['certificate_layout']['objects'][name]
            row[key]=row[key]+8 if key in ('address','bytes') else row[key]+'-invalid'
            try:read(data,layout,changed,app,pid,cpu,exit_status)
            except ValueError:refused.append(name+'/'+key)
            else:raise ValueError('accepted extra protected storage corruption '+name+'/'+key)
    need(len(refused)==len(set(refused))==8 and read(data,layout,image,app,pid,cpu,exit_status)==original,
         'all eight new registration controls and unchanged whole original observation')
    return dict(count=8,refusals=refused,native_operations=0,source_sha256=hashlib.sha256(data).hexdigest())
