"""Finite two-page owner/custody observations; no case acceptance authority.

The caller independently authenticates ELF geometry, real events, full frames,
application effects, process outcomes and cross-lane state. This leaf checks the
complete captured production owners and the exact operations between them.
"""
import struct
from page_selected import need

U64 = (1 << 64)-1
MAIN, BODY, TAIL, GUARD, DATA = (0x200401000,0x200403000,0x200404000,0x200405000,0x200408000)
PAGE, AREA = 0x300001000,0x300001040
P, L, R = 'li2_native_pair_progress','li2_native_pair_lifecycle','li2_rseq_pair_progress'
PC = ('events','seeds','extensions','epochs_closed','one_page_closes','two_page_closes',
      'policy_closes','capacity_closes','refaults','refault_completed')
RC = ('attempts','published','preentries','entries','refreshes','closed')
LC = ('sequence','attempts','published','closed_pages','close_calls')


def q(data):
    need(len(data)%8 == 0, 'whole owner qwords')
    return struct.unpack('<'+'Q'*(len(data)//8),data)


def shapes(r):
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


class Owners:
    def __init__(self,r,image,pid):
        self.r,self.image,self.pid=r,image,pid
        self.case,self.control=image['case'],image['control']
        self.registered=self.case>=2
        self.source=bytes.fromhex(image['source_hex'])
        self.pin_identity=None;self.backing_identity=None;self.owner=None;self.session=None
        self.pages={};self.map_observations={}
        shapes(r)

    def f(self,b,t,k):return self.r.field(b,t,k)
    def i(self,b,t,k):return self.r.integer(b,t,k)
    def v(self,b,t,keys):return tuple(self.i(b,t,k) for k in keys.split())
    def zero(self,b,label):need(not any(b),label)
    def equal(self,b,t,values,label):
        need(all(self.i(b,t,k)==(v&((1 << (8*len(self.f(b,t,k))))-1)) for k,v in values.items()),label)
    def change(self,a,b,t,values=(),observed=()):
        """Exact entire-object transition; every variable observation is checked elsewhere."""
        wanted=bytearray(a)
        for k in observed:
            z=self.r.types[t]['fields'][k];wanted[z['offset']:z['offset']+z['bytes']]=self.f(b,t,k)
        for k,v in dict(values).items():
            z=self.r.types[t]['fields'][k]
            value=v if type(v) is bytes else (v&((1 << (z['bytes']*8))-1)).to_bytes(z['bytes'],'little')
            need(len(value)==z['bytes'],'whole typed transition '+t+'.'+k)
            wanted[z['offset']:z['offset']+z['bytes']]=value
        need(bytes(wanted)==b,'complete exact owner transition '+t)

    def maps(self,b,direct=True):
        t='li2_fetch_map_progress';o=self.f(b,t,'observation');ot='li2_maps_observation'
        self.equal(b,t,dict(last_read=0,close_result=0,opened=1,close_started=1,closed=1),'complete actual maps I/O')
        need(self.i(b,t,'fd')<1<<31 and self.i(b,t,'bytes')>0 and self.i(b,t,'rows')>0,'actual maps descriptor/extent')
        acq,handler,epoch,kind,io=self.v(o,ot,'acquisition_id handler_id mutation_epoch kind io_performed')
        need(acq>0 and epoch>0 and ((kind==0 and handler==0 and io==1) if direct else
             ((kind==0 and handler==0 and io==1) or (kind in (1,2) and handler>0 and io==(kind==1)))),
             'actual maps acquisition kind and I/O provenance')
        # The same acquisition may be labeled reused, but its actual rows and
        # descriptor receipt cannot change. No reused row is accepted as new I/O.
        identity=(self.v(b,t,'fd last_read close_result bytes rows opened close_started closed'),handler,epoch)
        if acq in self.map_observations:need(identity==self.map_observations[acq],'stable whole maps acquisition identity')
        else:self.map_observations[acq]=identity
        return acq

    def pin(self,b,direct=True):
        t='li2_rseq_data';identity=self.v(b,t,'address page allocation generation offset pid tid')
        need(identity[:2]==(AREA,PAGE) and identity[2]>0 and identity[3]>0 and identity[4]%4096==0 and
             identity[5:]==(self.pid,self.pid),'actual registered allocation/pin identity')
        self.equal(b,t,dict(attempted=1,complete=1,error=0,detail=0),'complete real registered page observation')
        if self.pin_identity is None:self.pin_identity=identity
        need(identity==self.pin_identity,'same actual registration allocation/generation')
        return self.maps(self.f(b,t,'maps'),direct)

    def slot(self,b,index):
        if not any(b):return None
        t='li2_native_pair_slot';pc=self.i(b,t,'pc');page=pc&~4095
        need(MAIN<=page<MAIN+len(self.source),'retained source belongs to exact fixture RX image')
        before=14 if page>MAIN else 0;after=14 if page+4096<MAIN+len(self.source) else 0
        policy=self.image['page_policy'][page]
        self.equal(b,t,dict(slot=index,window_before=before,window_after=after,policy=policy,
            window_bytes=4096+before+after,window_initialized=4096+before+after,prepared=int(policy==0)),
            'exact full source page, halos and immutable policy result')
        need(self.i(b,t,'published') in (0,1) and (not self.i(b,t,'published') or policy==0),'no publication from a blocked source')
        window=self.f(b,t,'window');start=page-MAIN-before;n=4096+before+after
        need(window[:n]==self.source[start:start+n] and not any(window[n:]),'every retained source/halo byte and zero unused window')
        p=self.f(b,t,'page');pt='li2_fetch_page';offset=4096+page-MAIN
        self.equal(p,pt,dict(address=page,offset=offset,backing=1,logical=5,closed_prot=1),'exact source-page identity/closed permission')
        allocation,generation,initial=self.v(p,pt,'allocation generation initial_extent')
        need(allocation>0 and generation>0 and initial==0,'actual initial-image allocation/generation, no invented mmap extent')
        # Only MAIN's actual syscalls and case5/6 TAIL's selected operation
        # can renew source generations after the focal baseline. Case16.0
        # separately records its one supplied private GUARD-generation edit.
        stable=page!=MAIN and not (page==TAIL and self.case in (5,6)) and not (
            page==GUARD and (self.case,self.control)==(16,0))
        if stable:
            identity=self.v(p,pt,'allocation generation offset backing object')
            if page in self.pages:need(identity==self.pages[page],
                'same complete identity/generation for every source-stable page recurrence')
            else:self.pages[page]=identity
        first,end,major,minor,inode,vmaoffset=self.v(p,pt,'vma_first vma_end vma_major vma_minor vma_inode vma_offset')
        need(first%4096==end%4096==vmaoffset%4096==0 and first<=page and page+4096<=end and
             vmaoffset+page-first==offset and inode>0,'actual unique VMA file offset and complete page extent')
        backing=self.f(b,t,'backing');bt='li2_fetch_backing'
        self.equal(backing,bt,dict(stat_result=0,seals_observed=1,stat_observed=1),'actual backing queries completed')
        fd,seals=self.v(backing,bt,'retained_fd seals');need(fd<1<<31 and seals&15==15,'retained real descriptor and immutable seals')
        st=self.f(backing,bt,'stat');dev,ino,size,mode=self.v(st,'stat','st_dev st_ino st_size st_mode')
        need(ino==inode and size==self.image['sealed_carrier_bytes'] and mode&0xf000==0x8000 and
             (((dev>>8)&0xfff)|((dev>>32)&0xfffff000))==major and
             ((dev&0xff)|((dev>>12)&0xffffff00))==minor,'actual sealed backing inode/device/full carrier extent')
        self.equal(st,'stat',dict(__pad0=0),'actual stat reserved padding');self.zero(self.f(st,'stat','__glibc_reserved'),'stat reserved words')
        for key in ('st_atim','st_mtim','st_ctim'):
            ts=self.f(st,'stat',key);need(self.i(ts,'timespec','tv_nsec')<1000000000,'actual timestamp nanosecond extent')
        identity=(fd,seals,dev,ino,size,mode,self.i(p,pt,'object'),allocation)
        if self.backing_identity is None:self.backing_identity=identity
        need(identity==self.backing_identity,'same actual main source object/backing across snapshots')
        return dict(pc=pc,page=page,generation=generation,published=self.i(b,t,'published'),policy=policy)

    def close(self,b,pages=None,addresses=None,failure=0,cleanup=False):
        t='li2_native_close'
        if not any(b):need(pages is None,'required actual close is present');return None
        n=self.i(b,t,'pages') if pages is None else pages
        need(n in (0,1,2) and self.i(b,t,'sequence')>0 and
             all(self.i(b,t,k)>0 for k in ('allocation_epoch','generation_epoch','records_epoch')),'bounded actual close owner')
        self.equal(b,t,dict(pid=self.pid,tid=self.pid),'actual close singleton identity')
        keys=('pages','attempted','returned','closed','verified')
        if not failure:
            self.equal(b,t,{**{k:n for k in keys},'complete':1,'busy':0,'first_error':0,'first_detail':0,
                'first_error_address':0,'last_result':0,'sync_result':0,'sync_started':int(n>0),'sync_returned':int(n>0),
                'cleanup_started':0,'cleanup_complete':0,'cleanup_attempted':0,'cleanup_returned':0,
                'cleanup_first_result':0,'cleanup_sync_result':0},'complete exact verified native closure')
            need(self.maps(self.f(b,t,'after'))>self.maps(self.f(b,t,'before')),'distinct fresh actual pre/post close maps')
            if addresses is not None:self.equal(b,t,dict(last_address=max(addresses) if addresses else 0),'actual last revoked retained page')
            elif not n:self.equal(b,t,dict(last_address=0),'zero-page close has no permission operation')
        elif failure in (12,13,20):
            err,result=(1455,-1) if failure==12 else (1456,-5 if failure==13 else -1)
            self.equal(b,t,dict(pages=2,attempted=2,returned=2,closed=1 if failure==12 else 2,verified=0,
                complete=0,busy=1,first_error=err,first_detail=result,first_error_address=BODY if failure==12 else 0,
                last_address=GUARD,last_result=0,sync_started=1,sync_returned=1,sync_result=0 if failure==12 else result,
                cleanup_started=int(cleanup),cleanup_complete=int(cleanup),cleanup_attempted=2 if cleanup else 0,
                cleanup_returned=2 if cleanup else 0,cleanup_first_result=-1 if cleanup and failure==12 else 0,
                cleanup_sync_result=-1 if cleanup and failure==20 else 0),'actual failed close prefix stays incomplete')
            need(self.maps(self.f(b,t,'after'))>self.maps(self.f(b,t,'before')),'failed revoke retains real fresh post-query')
        elif failure==15:
            self.equal(b,t,dict(pages=1,attempted=0,returned=0,closed=0,verified=0,complete=0,busy=1,
                first_error=119,first_detail=0,first_error_address=GUARD,last_address=0,last_result=0,
                sync_started=0,sync_returned=0,sync_result=0,cleanup_started=1,cleanup_complete=1,
                cleanup_attempted=1,cleanup_returned=1,cleanup_first_result=0,cleanup_sync_result=0),
                'actual alias denial precedes revoke; separate best-effort cleanup')
            self.maps(self.f(b,t,'before'));self.zero(self.f(b,t,'after'),'no invented failed-alias after query')
        else:need(False,'fixed finite close failure')
        return self.i(b,t,'sequence')

    def empty_close(self,previous,current,count,renewals):
        """Exact global-only close sequence at fixed source effect boundaries.

        A reusable publication may be refused before mutation; when it does
        execute, both generation passes cover this one-page source. These
        receipts never count as native publication or pair completion.
        """
        t='li2_native_close';self.close(current,0,[])
        self.equal(current,t,dict(sequence=self.i(previous,t,'sequence')+count,
            **{key:self.i(previous,t,key) for key in
               ('allocation_epoch','transactions_epoch','records_epoch')}),
            'exact source-defined global empty closes, without a new pair epoch')
        delta=self.i(current,t,'generation_epoch')-self.i(previous,t,'generation_epoch')
        need(delta in range(0,2*renewals+1,2),
             'only complete single-page publication/restoration generation pairs before this close')
        need(self.maps(self.f(current,t,'before'))>self.maps(self.f(previous,t,'after')),
             'later empty close performs its own fresh before/after queries')

    def life(self,b):
        self.equal(b,L,dict(initialized=1,pid=self.pid,tid=self.pid),'initialized lifecycle singleton owner')
        owner=self.i(b,L,'owner');need(owner>0,'real private owner address')
        if self.owner is None:self.owner=owner
        need(owner==self.owner and self.i(b,L,'live')<=2,'same fixed owner and bounded retained slots')
        slots=self.f(b,L,'slots');size=self.r.types['li2_native_pair_slot']['bytes']
        result=[self.slot(slots[i*size:(i+1)*size],i) for i in range(2)]
        for key in ('before','after'):
            value=self.f(b,L,key)
            if any(value):self.maps(value)
        cl=self.f(b,L,'close')
        if any(cl):
            error=self.i(cl,'li2_native_close','first_error')
            self.close(cl,failure=self.case if error else 0)
        need(self.i(b,L,'published')>=self.i(b,L,'closed_pages') and
             self.i(b,L,'sequence')==self.i(b,L,'attempts') and self.i(b,L,'attempts')>=self.i(b,L,'published'),
             'honest lifecycle attempt/publication/closure denominators')
        return result

    def rseq(self,b):
        self.equal(b,R,dict(owner=self.owner,initialized=1,registered=int(self.registered),checking=0,
            unsafe_terminal=0,pid=self.pid,tid=self.pid,word_before=0,word_entry=0,word_after=0,
            fs_selector_entry=0,gs_selector_entry=0,fs_selector_after=0,gs_selector_after=0),
            'actual initialized pair registration/zero-word/selector observations')
        need(self.i(b,R,'active') in (0,1) and self.i(b,R,'entry_checked') in (0,1) and
             self.i(b,R,'attempts')-self.i(b,R,'closed')==self.i(b,R,'active') and
             self.i(b,R,'preentries')-self.i(b,R,'entries') in (0,1) and
             (self.i(b,R,'entry_checked') or self.i(b,R,'preentries')==self.i(b,R,'entries')),
             'exact outstanding pair epoch and ingress counts')
        if self.registered:
            self.equal(b,R,dict(registration_epoch=1,address=AREA,page=PAGE,length=32,signature=0x53053053),
                'exact real registered pair pin')
            self.pin(self.f(b,R,'before'))
        else:
            self.equal(b,R,dict(registration_epoch=0,address=0,page=0,length=0,signature=0),'exact unregistered pair domain')
            self.zero(self.f(b,R,'before')+self.f(b,R,'after'),'unregistered owner fabricates no pin')
        self.equal(b,R,dict(fs_before=DATA+2048,gs_before=DATA+2304),'actual pre-entry TLS bases')
        if any(self.f(b,R,'after')):
            self.pin(self.f(b,R,'after'));self.equal(b,R,dict(fs_after=DATA+2048,gs_after=DATA+2304),'actual refreshed TLS bases')
        else:need(self.v(b,R,'fs_after gs_after') in ((0,0),(DATA+2048,DATA+2304)),
                  'source-defined reset or real unregistered TLS refresh')

    def pair(self,b):
        self.equal(b,P,dict(initialized=1,pid=self.pid,tid=self.pid),'initialized actual pair session')
        session=self.i(b,P,'session');need(session>0,'actual real session pointer')
        if self.session is None:self.session=session
        need(session==self.session and self.i(b,P,'phase')<=11 and self.i(b,P,'live')<=2 and
             all(self.i(b,P,k) in (0,1) for k in ('in_handler','entry_pending','first_observed','second_observed')),
             'fixed actual pair owner/phase and completion markers')
        need(self.i(b,P,'one_page_closes')+self.i(b,P,'two_page_closes')==self.i(b,P,'epochs_closed') and
             self.i(b,P,'epochs_closed')<=self.i(b,P,'seeds') and self.i(b,P,'refault_completed')<=self.i(b,P,'refaults'),
             'honest pair epoch/refault counters')
        self.close(self.f(b,P,'first_close'))

    def frame(self,b,frame):
        """Join a production snapshot to the caller-authenticated raw capture."""
        ft='rn_frame';h=q(self.f(frame,ft,'h'));uc=self.f(frame,ft,'uc');fp=self.f(frame,ft,'fp')
        need(h[0]==1,'real source frame for owner snapshot')
        wanted=bytearray(len(b));t='li2_step_frame'
        pieces=dict(greg=uc[self.r.go:self.r.go+23*8],mask=uc[self.r.layout['offsets']['mask']:self.r.layout['offsets']['mask']+8],
            fp_address=uc[self.r.fo:self.r.fo+8],fp_bytes=h[2].to_bytes(8,'little'),initialized=h[2].to_bytes(8,'little'),fp=fp)
        for key,value in pieces.items():
            f=self.r.types[t]['fields'][key];need(len(value)==f['bytes'],'whole production frame field')
            wanted[f['offset']:f['offset']+f['bytes']]=value
        need(bytes(wanted)==b,'complete production frame equals genuine source frame, including padding and FP tail')

    def state(self,b):
        t='li2_rseq_state';reg=int(self.registered)
        self.equal(b,t,dict(initialized=1,registered=reg,held=reg,phase=3*reg,first_error=0,first_detail=0,
            pid=self.pid,tid=self.pid,address=AREA if reg else 0,page=PAGE if reg else 0,
            length=32*reg,signature=0x53053053 if reg else 0,epoch=reg,calls=reg,registrations=reg,
            unregistrations=0,kernel_errors=0,fs_base=DATA+2048,gs_base=DATA+2304,
            fs_result=0,gs_result=0,tls_attempted=1,tls_complete=1),'actual original rseq registration/TLS owner')
        transaction=self.f(b,t,'transaction');tt='li2_rseq_transaction'
        if reg:
            self.pin(self.f(b,t,'data'),False)
            args=q(self.f(transaction,tt,'args'))
            # R8/R9 retain actual setup operands and are ignored by SYS_rseq;
            # the exact instruction fixture leaves -1 and0 from mmap.
            need(args==(AREA,32,0,0x53053053,U64,0),'literal actual six registration syscall arguments')
            self.equal(transaction,tt,dict(result=0,attempted=1,issued=1,returned=1,
                prior_registered=0,input_word_observed=1,input_word=0),'actual kernel registration completed')
            before=self.pin(self.f(transaction,tt,'before'),False);after=self.pin(self.f(transaction,tt,'after'),False)
            need(after>before,'separate real registration before/after pin observations')
        else:self.zero(transaction+self.f(b,t,'data'),'unregistered state fabricates no kernel registration')

    def refresh(self,changes,observed,base):
        changes['refreshes']=changes.get('refreshes',self.i(base,R,'refreshes'))+1
        changes.update(fs_after=DATA+2048,gs_after=DATA+2304)
        if self.registered:observed.add('after')

    def rchange(self,a,b,changes,observed):
        self.rseq(b)
        for name in observed:
            need(name in ('before','after'),'only an actual fresh pin is variable in the pair rseq owner')
            current=self.pin(self.f(b,R,name))
            for previous in ('before','after'):
                old=self.f(a,R,previous)
                if any(old):need(current>self.pin(old),'fresh pin query follows every retained prior pin observation')
        self.change(a,b,R,changes,observed)

    def frames(self,row,pair,retry):
        name='second' if retry else 'first'
        self.frame(self.f(pair,P,name),self.f(row,'npf_row','before'))

    def pair_change(self,a,b,row,result,closed,partial=False):
        """Actual entered event, with fixed operation counters and exact failure prefixes."""
        h=q(self.f(row,'npf_row','h'));phase,live=self.v(a,P,'phase live')
        retry=phase==9;foreign=self.case==10 and result==1905
        values=dict(events=self.i(a,P,'events')+1,phase=11,in_handler=1,
                    signal_number=11,signal_code=2,signal_errno=0,pc=h[2],signal_address=h[3])
        observed=[]
        if not foreign:
            values.update(second_observed=1 if retry else 0)
            if not retry:values['first_observed']=1
            observed.append('second' if retry else 'first');self.frames(row,b,retry)
        def increment(key):values[key]=self.i(a,P,key)+1
        if closed:
            reason=3 if result==2 else 2 if live==2 else 1
            values['close_reason']=reason
            if result in (0,1,2):
                values.update(live=0,first_close=closed)
                for key in ('epochs_closed','one_page_closes' if live==1 else 'two_page_closes'):increment(key)
                if reason!=3:increment('policy_closes' if reason==1 else 'capacity_closes')
        if result in (0,1,2):
            values.update(in_handler=0,entry_pending=0)
            if result==1:
                if phase==2 or live==2:increment('seeds');values.update(live=1,phase=4)
                else:increment('extensions');values.update(live=2,phase=7)
            elif result==2:increment('refaults');values.update(live=0,phase=9)
            else:
                values.update(live=0,phase=2)
                if retry:increment('refault_completed')
                if phase!=2:
                    uc=self.f(self.f(row,'npf_row','before'),'rn_frame','uc')
                    values['logical_flags']=q(uc[self.r.go:self.r.go+184])[17]&~0x10000
        elif result is not None:
            detail={1905:11,1901:3,1910:5,1911:4,1455:-1,1456:-5 if self.case==13 else -1}[result]
            values.update(first_error=result,first_detail=detail)
            if result==1911:values['extensions']=U64
        else:
            need(partial and self.case in (11,15),'only the two genuine nonreturning inside-operation events')
            values.update(first_error=1477 if self.case==11 else 119,first_detail=41 if self.case==11 else 0)
        self.change(a,b,P,values,observed);self.pair(b)

    def markers(self,row,result,bphase):
        h=q(self.f(row,'npf_row','h'));returned=result is not None
        normal=returned and result in (0,1,2)
        guard=self.case in (7,8,9) and bphase==9
        before=self.f(row,'npf_row','before');uc=self.f(before,'rn_frame','uc')
        flags=q(uc[self.r.go:self.r.go+184])[17]
        known=int(bphase==2)
        need(h[11]==known and (not known or h[12]==flags&~0x10000),
             'exact source known-flags domain; cold logical flags equal the real frame without RF')
        logical=(flags&~0x10000) if result==0 and bphase!=2 else h[12]
        need(h[4:15]==(int(returned),result if returned else 0,int(normal),int(normal and result!=0),
             int(guard),int(guard),0,known,h[12],known if returned else 0,logical if returned else 0),
             'exact pair/controller/guard attempts, returns, results and logical-flag observations')
        return guard

    def permits(self,row,returned,guard,life0,life1):
        values=q(self.f(row,'npf_row','permits'));p=[values[i*12:(i+1)*12] for i in range(4)]
        need(p[0][:3]==(0,0,0) and p[0][3]>=p[0][4] and p[0][5:10]==(0,)*5,
             'actual old owners are closed and no held fetch grants pair entry')
        need(p[0][10]-p[0][11]==self.i(life0,L,'live'),'all actual occupied permissions equal the retained live set')
        if returned:
            need(p[1][:10]==p[0][:10] and
                 p[1][10]-p[0][10]==self.i(life1,L,'published')-self.i(life0,L,'published') and
                 p[1][11]-p[0][11]==self.i(life1,L,'closed_pages')-self.i(life0,L,'closed_pages'),
                 'actual publication/verified-revoke counters; every other original permit unchanged')
        else:need(p[1]==(0,)*12,'nonreturning pair has no after permits')
        if guard:
            need(p[2][:3]==(0,0,301) and p[2][3:]==p[1][3:] and p[3]==p[2],
                 'genuine fresh fetch guards retain exactly their actual held borrow and closed owner counters')
            state=self.f(row,'npf_row','guard_state');self.state(state)
            code,length,policy=(696,5,1) if self.case==7 else (282,3,1) if self.case==8 else (693,5,2)
            pc=q(self.f(row,'npf_row','h'))[2]
            first,end=(DATA+16312,DATA+16320) if self.case==9 else (0,0)
            self.equal(state,'li2_rseq_state',dict(last_pc=pc,last_code=code,last_policy=policy,
                last_first=first,last_end=end),'exact actual post-refault instruction guard result')
            footprint=self.f(state,'li2_rseq_state','last_footprint')
            self.equal(footprint,'li2_write_footprint',dict(pc=pc,next_pc=pc+length,first=first,end=end,
                abi_version=1,policy=policy,code=code,length=length),'complete true instruction write footprint')
            need(self.i(state,'li2_rseq_state','instruction_checks')>0 and
                 self.i(state,'li2_rseq_state','range_checks')>=(self.case==9),'real instruction and range checks occurred')
        else:
            need(p[2]==p[3]==(0,)*12,'no unexecuted guard permit observations')
            self.zero(self.f(row,'npf_row','guard_state'),'no invented unexecuted instruction state')
        return p

    def life_step(self,a,b,kind,pc,phase,result):
        """One real operation; exact whole-object inverse outside fresh observations."""
        slotsize=self.r.types['li2_native_pair_slot']['bytes'];live=self.i(a,L,'live')
        if kind==1 and result:
            need(self.case==17 and result==1901,'only explicit copied-owner preparation refusal')
            self.change(a,b,L,dict(first_error=1901,first_detail=3));return
        if kind==1:
            cold=phase==3;need(phase in (3,6) and live==(0 if cold else 1),'real seed/extend preparation phase')
            expected_policy=self.image['page_policy'][pc&~4095];eligible=int(expected_policy==0)
            changed=dict(sequence=self.i(a,L,'sequence')+1,attempts=self.i(a,L,'attempts')+1,
                candidate=pc,candidate_policy=expected_policy,candidate_eligible=eligible,
                busy=eligible,opening=0,post_verified=0,pid=self.pid,tid=self.pid)
            observations=['before','slots']
            if cold:
                observations+=['allocation_epoch','generation_epoch','transactions_epoch','records_epoch']
                need(all(self.i(b,L,k)>0 for k in ('allocation_epoch','generation_epoch','records_epoch')) and
                     all(self.i(b,L,k)>=self.i(a,L,k) for k in ('allocation_epoch','generation_epoch','transactions_epoch','records_epoch')),
                     'fresh current lifecycle epochs at a new seed')
                self.zero(self.f(b,L,'slots')[slotsize:],'cold prepare resets the unused second slot completely')
            else:need(self.f(a,L,'slots')[:slotsize]==self.f(b,L,'slots')[:slotsize],'retained live first slot is byte-exact during extension')
            self.change(a,b,L,changed,observations)
            slot=self.f(b,L,'slots')[live*slotsize:(live+1)*slotsize]
            self.equal(slot,'li2_native_pair_slot',dict(pc=pc,published=0),'actual new candidate never preclaims publication')
            need(self.maps(self.f(b,L,'before'))>self.maps(self.f(a,L,'before')),'new prepare performs actual fresh maps query')
        elif kind==2 and result:
            need(self.case==16 and self.control==0 and result==1910,'only explicit stale-generation publication refusal')
            self.change(a,b,L,dict(first_error=1910,first_detail=5))
        elif kind==2:
            need(live in (0,1) and phase==(3 if live==0 else 6),'real publication uses the prepared slot')
            slots=bytearray(self.f(a,L,'slots'));t='li2_native_pair_slot';f=self.r.types[t]['fields']['published']
            at=live*slotsize+f['offset'];slots[at:at+f['bytes']]=(1).to_bytes(f['bytes'],'little')
            self.change(a,b,L,dict(live=live+1,published=self.i(a,L,'published')+1,
                transactions_epoch=self.i(a,L,'transactions_epoch')+1,busy=0,opening=0,post_verified=1,slots=bytes(slots)),['after'])
            need(self.maps(self.f(b,L,'after'))>self.maps(self.f(b,L,'before')),'publication has real fresh post-permission validation')
        elif kind==3:
            need(a==b and phase in (8,10) and result==0,'actual close-before has no completed close')
        elif kind==4:
            failure=self.case if result else 0
            addresses=[self.slot(self.f(a,L,'slots')[i*slotsize:(i+1)*slotsize],i)['page'] for i in range(live)]
            cl=self.f(b,L,'close');self.close(cl,live,addresses,failure)
            prior=self.f(a,L,'close');need(self.i(cl,'li2_native_close','sequence')>self.i(prior,'li2_native_close','sequence'),'new actual close sequence')
            if phase==10:need(self.i(cl,'li2_native_close','sequence')==self.i(prior,'li2_native_close','sequence')+1,'exact genuine zero-page refault successor')
            change=dict(close_calls=self.i(a,L,'close_calls')+1)
            if result:change.update(busy=1,first_error=result,first_detail=-5 if self.case==13 else -1)
            else:change.update(busy=0,live=0,closed_pages=self.i(a,L,'closed_pages')+live,candidate_eligible=0)
            self.change(a,b,L,change,['close'])
        else:need(kind in (5,6) and a==b and phase==6 and result==0,'exact supplied/control observation changes no lifecycle authority')

    def controls(self,record,rows,stages):
        c,sub=self.case,self.control;v=q(self.f(record,'npf_record','control'))
        expected=[0]*64
        if c not in (11,12,13,15,16,17,18,20) or (c==16 and sub==1):
            need(v==tuple(expected),'no control receipts invented for this finite profile');return
        expected[0]=c;expected[1]=sub;expected[3]=1
        if c in (16,17,18):
            expected[2]=5 if c==17 else 1;expected[4]=1
            old,new=v[12:14]
            if c==16:
                size=self.r.types['li2_native_pair_slot']['bytes']
                prepared=next(x for x in stages if q(self.f(x,'npf_stage','h'))[1:3]==(1,1))
                slot=self.f(self.f(prepared,'npf_stage','life'),L,'slots')[size:]
                page=self.f(slot,'li2_native_pair_slot','page')
                need(old==self.i(page,'li2_fetch_page','generation')>0 and new==(old^1) and
                     v[14]>0 and v[14]%8==0 and v[15]==0,'supplied actual retained generation mutation')
            if c==17:need((old,new)==(1,0) and v[14]==self.owner and v[15]>0 and v[15]!=v[14],'copied owner fails exact address binding')
            if c==18:need(old==self.i(self.f(rows[1],'npf_row','pair_before'),P,'extensions')<U64 and
                         new==U64 and v[14]==self.owner and v[15]==0,'supplied actual private overflow field')
            expected[12:16]=v[12:16]
        elif c==13:
            expected[2]=3;expected[4]=1;expected[5]=(-5)&U64;expected[6:8]=[324,32]
        elif c==11:
            expected[2]=1;expected[6:9]=[self.pid,self.pid,5];expected[16:18]=[1,1]
            need(v[18]<1<<32,'actual returned uid joins caller signal validation');expected[18]=v[18]
        elif c==15:
            expected[2]=1;expected[4]=1;need(v[5]>0 and v[5]<(1<<63) and v[5]%4096==0,'actual successful private writable alias mapping')
            expected[5]=v[5];expected[6:11]=[4096,3,2,self.backing_identity[0],4096+GUARD-MAIN]
        else:
            expected[2]=2;expected[4]=1;expected[16:22]=[1,1,0,1,1,0]
        need(v==tuple(expected),'entire explicit control receipt including unused words and issue/return distinction')
        kinds=[q(self.f(x,'npf_stage','h'))[1] for x in stages]
        need(kinds.count(5)==(0 if c==13 else 1) and kinds.count(6)==(0 if c in (11,13) else 1),
             'actual control before/after markers, never fabricated return')


def _operations(case,control,index,bphase,live,result):
    """Fixed actual call order, not a tolerance over possible owner routes."""
    if index==1 and case==11:return [(1,6,0),(5,6,0)]
    if index==1 and case==15:return [(1,6,0),(5,6,0),(6,6,0)]
    if index==1 and case==16 and control==0:return [(1,6,0),(5,6,0),(6,6,0),(2,6,1910)]
    if index==1 and case==17:return [(5,6,0),(6,6,0),(1,6,1901)]
    if index==1 and case==18:return [(1,6,0),(5,6,0),(6,6,0)]
    if case==10 and index==2:return []
    if case==11 and index==2:return []
    if result in (1455,1456):return [(3,8,0),(4,8,result)]
    if bphase==9:return [(3,10,0),(4,10,0)]
    if result==2:return [(3,8,0),(4,8,0)]
    if bphase==2:ops=[(1,3,0)]+([(2,3,0)] if result==1 else [])
    elif live==1:ops=[(1,6,0)]+([(2,6,0)] if result==1 else [(3,8,0),(4,8,0)])
    else:ops=[(3,8,0),(4,8,0),(1,3,0)]+([(2,3,0)] if result==1 else [])
    if index==1 and case in (12,20):ops += [(5,6,0),(6,6,0)]
    return ops


def validate(reader,record,image,pid):
    """Check captured production owners; caller retains all case acceptance gates."""
    o=Owners(reader,image,pid);f,i=o.f,o.i
    need(type(image.get('sealed_carrier_bytes')) is int and image['sealed_carrier_bytes']>0,
         'caller independently authenticates complete sealed carrier extent')
    h=q(f(record,'npf_record','h'));spec=image['spec'];flow=spec['gated_flow']
    need((spec['case']['case'],spec['case']['control'])==(o.case,o.control) and
         len(flow)==h[13] and spec['case']['stages']==h[20], 'fixed exact finite owner population')
    def array(field,typ,n):
        data=f(record,'npf_record',field);size=reader.types[typ]['bytes']
        need(n*size<=len(data),'complete observed owner array')
        return [data[j*size:(j+1)*size] for j in range(n)]
    rows=array('rows','npf_row',h[13]);stages=array('stages','npf_stage',h[20])
    need(rows and stages,'actual focal entry and lifecycle stages exist')
    basep=f(rows[0],'npf_row','pair_before');basel=f(rows[0],'npf_row','life_before')
    baser=f(rows[0],'npf_row','rseq_before')
    o.life(basel);o.rseq(baser);o.pair(basep)
    o.equal(basep,P,dict(phase=2,in_handler=0,entry_pending=0,live=0,first_error=0,first_detail=0),
            'actual closed post-setup pair baseline, never a fixture reset')
    o.equal(basel,L,dict(busy=0,opening=0,live=0,first_error=0,first_detail=0), 'actual closed lifecycle baseline')
    o.equal(baser,R,dict(active=0,entry_checked=0,first_error=0,first_detail=0), 'actual closed rseq baseline')
    need(i(basep,P,'seeds')==i(basep,P,'epochs_closed')==i(baser,R,'attempts')==i(baser,R,'closed') and
         i(basep,P,'seeds')+i(basep,P,'extensions')==i(basel,L,'published')==i(basel,L,'closed_pages')==i(baser,R,'published') and
         i(baser,R,'preentries')==i(baser,R,'entries'), 'whole baseline contains only genuinely completed old epochs')
    permit0=q(f(rows[0],'npf_row','permits'))[:12]
    offset=permit0[10]-i(basel,L,'published')
    need(offset>=0 and permit0[11]-i(basel,L,'closed_pages')==offset,
         'actual pre-pair bootstrap physical publication/closure offset')
    stage_at=0;previous=None;global_close=f(basel,L,'close');o.close(global_close)
    lastp,lastl,lastr=basep,basel,baser
    focal_seeds=focal_extensions=focal_closes=focal_refaults=0
    for number,(row,expected) in enumerate(zip(rows,flow)):
        v=q(f(row,'npf_row','h'));result=expected['pair_result']
        p,l,r=(f(row,'npf_row',name+'_before') for name in ('pair','life','rseq'))
        o.life(l);o.rseq(r);o.pair(p)
        phase,live=o.v(p,P,'phase live')
        nested=o.case==11 and number==2
        if previous is not None:
            if nested:
                # Genuine inner delivery interrupts the outer prepare. It
                # sets the first reentry error before any pair call occurs.
                need(l==lastl,'nested ingress retains the interrupted actual lifecycle prefix')
                o.change(lastr,r,R,dict(first_error=1477,first_detail=41))
                o.pair_change(previous[0],p,previous[1],None,b'',True)
            else:
                need(l==lastl,'ordinary application execution changes no private lifecycle owner')
                active=i(lastp,P,'phase') in (4,7,9)
                o.change(lastp,p,P,dict(entry_pending=1) if active else {})
                o.rchange(lastr,r,dict(preentries=i(lastr,R,'preentries')+1,entry_checked=1) if active else {},set())
                if active:need(v[12]==previous[2],'active epoch retains the actual previous logical-flags scalar')
        guard=o.markers(row,result,phase)
        ops=_operations(o.case,o.control,number,phase,live,result)
        need(stage_at+len(ops)<=len(stages),'all real operation stages retained')
        rb,lb=r,l;pending={};fresh=set();closed=b''
        if o.case in (5,6) and number==3:
            # The preceding literal CPUID/SYSCALL is in a complete sealed
            # source page. selected_oneshot_try closes before its publication;
            # only SYSCALL then closes again in dispatch_operation.
            previous_pc=q(f(rows[number-1],'npf_row','h'))[2]
            need(previous_pc==TAIL+32 and v[2]==previous_pc+2 and
                 o.source[previous_pc-MAIN:previous_pc-MAIN+2]==
                    (bytes.fromhex('0fa2') if o.case==5 else bytes.fromhex('0f05')) and
                 (phase,live,result)==(2,0,0) and ops==[(1,3,0)],
                 'fixed real selected-effect continuation, no arbitrary close gap')
            actual=f(stages[stage_at],'npf_stage','close')
            o.empty_close(global_close,actual,1 if o.case==5 else 2,0 if o.case==5 else 1)
            next_life=f(stages[stage_at],'npf_stage','life')
            after_generation=i(next_life,L,'generation_epoch')-i(actual,'li2_native_close','generation_epoch')
            need(after_generation in ((0,2) if o.case==5 else (0,)),
                 'close snapshot precedes CPUID publication but follows syscall restoration')
            global_close=actual
        if phase in (4,7) and not (o.case==10 and number==2):
            pending['entries']=i(r,R,'entries')+1
            if v[2]==v[3]:o.refresh(pending,fresh,r)
        if nested:
            need(result is None and not ops and p==f(record,'npf_record','terminal_pair'),
                 'inner nonreturning event cannot fabricate a new pair attempt')
        for kind,op_phase,op_result in ops:
            stage=stages[stage_at];stage_at+=1
            sh=q(f(stage,'npf_stage','h'))
            need(sh==(1,kind,number,v[2],op_result&U64,op_phase)+(0,)*10,
                 'exact actual lifecycle/control operation, phase, current event and result')
            ls,rs,cs=(f(stage,'npf_stage',name) for name in ('life','rseq','close'))
            o.life(ls)
            if kind==2 and op_phase==3:
                pending.update(attempts=pending.get('attempts',i(rb,R,'attempts'))+1,active=1,entry_checked=0,
                    after=bytes(reader.types['li2_rseq_data']['bytes']),word_before=0,word_entry=0,word_after=0,
                    fs_before=DATA+2048,gs_before=DATA+2304)
                fresh.discard('after')
                if o.registered:fresh.add('before')
            o.rchange(rb,rs,pending,fresh);rb=rs;pending={};fresh=set()
            o.life_step(lb,ls,kind,v[2],op_phase,op_result);lb=ls
            if kind==4:
                need(i(cs,'li2_native_close','sequence')==i(global_close,'li2_native_close','sequence')+1,
                     'each actual pair close advances the current global close exactly once')
                need(cs==f(ls,L,'close'),'actual close-after copies the same completed/failed kernel owner')
                if op_phase==10:
                    prior=f(p,P,'first_close')
                    need(i(cs,'li2_native_close','sequence')==i(prior,'li2_native_close','sequence')+1 and
                         all(i(cs,'li2_native_close',key)==i(prior,'li2_native_close',key) for key in
                         ('allocation_epoch','generation_epoch','transactions_epoch','records_epoch')),
                         'genuine empty refault has exact successor sequence and unchanged lifecycle epochs')
                else:closed=cs
                global_close=cs
                if not op_result:
                    o.refresh(pending,fresh,rb);pending['entry_checked']=0
                    if result!=2:
                        pending.update(closed=i(rb,R,'closed')+1,active=0)
                        if op_phase==10:pending['entries']=i(rb,R,'entries')+1
            else:need(cs==global_close,'no unrelated operation fabricates a new close observation')
            # PUBLISHED instrumentation (and a real filter control inside
            # that wrapper) precedes the rseq published call in production.
            if (kind==2 and not op_result and not (number==1 and o.case in (12,20))) or (
                    kind==6 and number==1 and o.case in (12,20)):
                pending.update(published=i(rb,R,'published')+1,entry_checked=0)
        returned=result is not None
        if returned:
            pa,la,ra=(f(row,'npf_row',name+'_after') for name in ('pair','life','rseq'))
            need(la==lb,'whole returned lifecycle equals its final actual operation stage')
            o.rchange(rb,ra,pending,fresh)
            o.pair_change(p,pa,row,result,closed)
            need(f(row,'npf_row','close')==global_close,'returned current close snapshot has exact operation provenance')
            lastp,lastl,lastr=pa,la,ra
            focal_seeds+=i(pa,P,'seeds')-i(p,P,'seeds')
            if result in (0,1,2):focal_extensions+=i(pa,P,'extensions')-i(p,P,'extensions')
            focal_closes+=i(pa,P,'epochs_closed')-i(p,P,'epochs_closed')
            focal_refaults+=i(pa,P,'refault_completed')-i(p,P,'refault_completed')
        else:
            for name in ('pair_after','life_after','rseq_after','close'):
                o.zero(f(row,'npf_row',name),'nonreturning call has no invented '+name)
            need(not pending and not fresh,'nonreturning prefix does not hide an unobserved completed rseq operation')
            lastp,lastl,lastr=p,lb,rb
        permits=o.permits(row,returned,guard,l,lastl)
        need(permits[0][10]==offset+i(l,L,'published') and permits[0][11]==offset+i(l,L,'closed_pages'),
             'every focal permission count joins the actual lifecycle lifetime totals')
        previous=(p,row,v[14])
    need(stage_at==len(stages),'no omitted or invented lifecycle/control stages')
    o.controls(record,rows,stages)
    summary=_terminal(o,record,rows,lastp,lastl,lastr,global_close,offset)
    return dict(rows=len(rows),stages=len(stages),focal_seeds=focal_seeds,focal_extensions=focal_extensions,
                focal_closes=focal_closes,focal_refaults=focal_refaults,**summary)


def _terminal(o,record,rows,lastp,lastl,lastr,global_close,offset):
    """Exact unsafe/failure prefixes; successful totals retain post-focal scope."""
    f,i=o.f,o.i;h=q(f(record,'npf_record','h'));case=o.case
    p,l,r=(f(record,'npf_record','terminal_'+name) for name in ('pair','life','rseq_pair'))
    cl=f(record,'npf_record','terminal_close');state=f(record,'npf_record','terminal_rseq')
    o.life(l);o.rseq(r);o.pair(p);o.state(state)
    safe=case==14 or (case==16 and o.control==1)
    need((h[9],h[19])==(0,1) if safe else (h[9],h[19])==(1,0),
         'safe pre-mutation evidence stays distinct from terminal closure')
    if safe:
        need((p,l,r,cl)==(lastp,lastl,lastr,global_close) and
             h[17]==offset+i(l,L,'published') and h[18]==offset+i(l,L,'closed_pages'),
             'unsafe prefix ends at the actual still-live publication, before supplied mutation')
        o.equal(p,P,dict(phase=4,live=1,in_handler=0,entry_pending=0,first_error=0,first_detail=0),
                'safe prefix has one genuine unclosed pair epoch and no fabricated error')
        o.equal(l,L,dict(live=1,busy=0,opening=0,post_verified=1,first_error=0,first_detail=0),
                'actual pre-mutation retained publication')
        o.equal(r,R,dict(active=1,entry_checked=0,first_error=0,first_detail=0),
                'actual valid zero-word pin before supplied unsafe control')
        need(h[17]-h[18]==1,'unsafe exit does not earn verified final closure credit')
    elif case in (10,11,12,13,15,16,17,18,20):
        if case==15:
            outer=rows[-1];o.pair_change(f(outer,'npf_row','pair_before'),p,outer,None,b'',True)
            o.change(lastl,l,L,dict(opening=1));need(r==lastr,'alias publication failure does not complete rseq publication')
        else:need((p,l,r)==(lastp,lastl,lastr),'terminal failure preserves the actual captured owner prefix')
        error,detail={10:(1905,11),11:(1477,41),12:(1455,-1),13:(1456,-5),15:(119,0),
                      16:(1910,5),17:(1901,3),18:(1911,4),20:(1456,-1)}[case]
        o.equal(p,P,dict(phase=11,in_handler=1,entry_pending=1,first_error=error,first_detail=detail),
                'first actual pair error and incomplete in-handler prefix remain failed')
        if case==11:o.equal(r,R,dict(first_error=1477,first_detail=41),'genuine nested preentry first error')
        else:o.equal(r,R,dict(first_error=0,first_detail=0),'unfailed rseq owner is not relabeled with unrelated error')
        if case in (12,13,20):
            o.close(cl,2,[BODY,GUARD],case,True)
            changes={k:i(cl,'li2_native_close',k) for k in ('cleanup_started','cleanup_complete',
                'cleanup_attempted','cleanup_returned','cleanup_first_result','cleanup_sync_result')}
            o.change(global_close,cl,'li2_native_close',changes)
            need(h[17]==offset+i(l,L,'published') and h[18]==offset+i(l,L,'closed_pages') and h[17]-h[18]==2,
                 'attempted failed cleanup never becomes two verified physical closes')
        elif case==15:
            o.close(cl,failure=15)
            need(i(cl,'li2_native_close','sequence')==i(global_close,'li2_native_close','sequence')+1 and
                 h[17]==offset+i(l,L,'published') and h[18]==offset+i(l,L,'closed_pages') and h[17]-h[18]==1,
                 'actual alias-denied abort retains one descriptive outstanding admission')
        else:
            live=i(l,L,'live');size=o.r.types['li2_native_pair_slot']['bytes']
            slots=f(l,L,'slots');addresses=[o.slot(slots[j*size:(j+1)*size],j)['page'] for j in range(live)]
            o.close(cl,live,addresses)
            need(i(cl,'li2_native_close','sequence')==i(global_close,'li2_native_close','sequence')+1 and
                 h[17]==offset+i(l,L,'published') and h[18]==offset+i(l,L,'closed_pages')+live and h[17]==h[18],
                 'actual fatal abort verifies held permissions but does not complete the failed pair/rseq owner')
        need(i(r,R,'active')==1 and i(r,R,'attempts')==i(r,R,'closed')+1,
             'failed source/control epoch is explicitly not a completed pair epoch')
    else:
        need(case in tuple(range(10))+(19,),'fixed successful terminal domain')
        o.equal(p,P,dict(phase=2,in_handler=0,entry_pending=0,live=0,first_error=0,first_detail=0),
                'successful final pair owner is genuinely quiet')
        o.equal(l,L,dict(busy=0,opening=0,live=0,first_error=0,first_detail=0,candidate_eligible=0),
                'successful lifecycle has no live permission or pending source proof')
        o.equal(r,R,dict(active=0,entry_checked=0,first_error=0,first_detail=0),
                'successful terminal private pin has no outstanding pair obligation')
        need(i(p,P,'seeds')==i(p,P,'epochs_closed')==i(r,R,'attempts')==i(r,R,'closed') and
             i(p,P,'seeds')+i(p,P,'extensions')==i(l,L,'published')==i(l,L,'closed_pages')==i(r,R,'published') and
             i(r,R,'preentries')==i(r,R,'entries') and
             i(p,P,'refaults')==i(p,P,'refault_completed') and
             h[17]==h[18]==offset+i(l,L,'published'), 'exact lifetime physical, logical, pin and refault closure equations')
        # The only remaining application path is one forward HELPER capture,
        # then blocked MAIN syscalls/exit. These totals describe that tail;
        # they never add focal native-pair completion credit. Old TF fallback
        # may expose HELPER to a genuine seed before its remaining stores.
        extra=i(p,P,'seeds')-i(lastp,P,'seeds')
        need(extra in (0,1) and o.image['page_policy'][MAIN+4096]==0 and o.image['page_policy'][MAIN]!=0,
             'at most the single remaining authenticated helper epoch; no new application loop')
        for key in ('extensions','two_page_closes','capacity_closes','refaults','refault_completed'):
            need(i(p,P,key)==i(lastp,P,key),'no unobserved extra '+key)
        for key in ('epochs_closed','one_page_closes','policy_closes'):
            need(i(p,P,key)-i(lastp,P,key)==extra,'remaining helper epoch closes exactly once: '+key)
        for key in ('published','closed_pages','close_calls'):
            need(i(l,L,key)-i(lastl,L,key)==extra,'remaining helper lifecycle count: '+key)
        attempts=i(l,L,'attempts')-i(lastl,L,'attempts')
        # Successful gated rn_finish skips the native observer call. Its
        # conditional error branches are excluded by the independently
        # checked success/output; its remaining path has no backward edge.
        # Every MAIN prepare therefore consumes a distinct forward source
        # byte position. This is a finite upper bound, not a guessed count.
        sy=o.image['symbols'];finish=sy['rn_finish'];end=sy['rn_fail']-4
        need(MAIN<=finish<end<MAIN+3072 and o.source[finish-MAIN]==0xfc and
             o.source[end-MAIN-7:end-MAIN+4]==bytes.fromhex('31ffb8e70000000f050f0b'),
             'actual source-bound successful finish through exit_group, excluding failure/startup code')
        need(extra<=attempts<=extra+end-finish+1 and i(p,P,'events')-i(lastp,P,'events')==attempts,
             'bounded distinct forward source entries, each with one actual preparation')
        o.rchange(lastr,r,{key:i(lastr,R,key)+(2*extra if key=='refreshes' else extra) for key in RC},
                  {'before','after'} if extra and o.registered else set())
        size=o.r.types['li2_native_pair_slot']['bytes'];slots=f(l,L,'slots')
        if attempts:
            candidate=i(l,L,'candidate')
            need(finish<=candidate<=end and i(l,L,'candidate_policy')==o.image['page_policy'][MAIN],
                 'the final blocked MAIN candidate belongs to the actual successful forward finish path')
            o.zero(slots[size:],'fresh final blocked MAIN prepare leaves no stale second slot')
            slot=o.slot(slots[:size],0);need(slot['pc']==candidate and slot['published']==0,'actual final blocked source is never publication')
            need(MAIN<=i(p,P,'pc')<MAIN+4096 and i(p,P,'signal_address')==i(p,P,'pc') and
                 o.v(p,P,'signal_number signal_code signal_errno')==(11,2,0) and
                 o.v(p,P,'first_observed second_observed')==(1,0),'last descriptive pair event is genuine first-byte MAIN NX')
            need(candidate==i(p,P,'pc') and o.maps(f(l,L,'before'))>o.maps(f(lastl,L,'before')),
                 'final event and actual fresh candidate query refer to the same blocked MAIN PC')
            observations=['before','slots','close','allocation_epoch','generation_epoch','transactions_epoch','records_epoch']
            for key in observations[3:]:
                need(i(l,L,key)>=i(lastl,L,key),'tail cannot reduce actual lifecycle epoch '+key)
            if extra:
                observations.append('after')
                need(o.maps(f(l,L,'after'))>o.maps(f(lastl,L,'after')) and
                     o.maps(f(l,L,'before'))>o.maps(f(l,L,'after')),
                     'helper post-publication query precedes the final blocked MAIN query')
            o.change(lastl,l,L,dict(sequence=i(lastl,L,'sequence')+attempts,attempts=i(lastl,L,'attempts')+attempts,
                published=i(lastl,L,'published')+extra,closed_pages=i(lastl,L,'closed_pages')+extra,
                close_calls=i(lastl,L,'close_calls')+extra,candidate=candidate,candidate_policy=o.image['page_policy'][MAIN],
                candidate_eligible=0,busy=0,opening=0,post_verified=0),observations)
            # This is the last descriptive owner history, not a second focal
            # application endpoint. Its full FP payload remains the original
            # already-checked architecture: this tail only stores that state.
            first=f(p,P,'first');lastframe=f(rows[-1],'npf_row','before')
            previous_fp=f(lastframe,'rn_frame','fp');previous_uc=f(lastframe,'rn_frame','uc')
            fh=q(f(lastframe,'rn_frame','h'));g=q(f(first,'li2_step_frame','greg'))
            need(f(first,'li2_step_frame','fp')==previous_fp and
                 o.v(first,'li2_step_frame','fp_bytes initialized')==(fh[2],fh[2]) and
                 f(first,'li2_step_frame','mask')==previous_uc[o.r.layout['offsets']['mask']:o.r.layout['offsets']['mask']+8] and
                 h[15]<=i(first,'li2_step_frame','fp_address')<=h[15]+h[16]-fh[2] and
                 i(first,'li2_step_frame','fp_address')%16==0 and
                 (g[16],g[19],g[20],g[22])==(candidate,21,14,candidate) and
                 g[18]==0x002b000000000033 and g[17]&0x10000 and not g[17]&0x100,
                 'complete unchanged FP and genuine saved MAIN fault shape in descriptive final history')
            logical=(q(previous_uc[o.r.go:o.r.go+184])[17]&~0x10000) if extra else i(lastp,P,'logical_flags')
            updates={key:i(lastp,P,key)+(attempts if key=='events' else extra if key in
                ('seeds','epochs_closed','one_page_closes','policy_closes') else 0) for key in PC}
            updates.update(first_observed=1,second_observed=0,signal_number=11,signal_code=2,signal_errno=0,
                pc=candidate,signal_address=candidate,logical_flags=logical,close_reason=1 if extra else i(lastp,P,'close_reason'))
            o.change(lastp,p,P,updates,['first','first_close'])
        else:need(l==lastl and p==lastp,'no observed tail attempts means whole private histories unchanged')
        expected_close=f(l,L,'close')
        if extra:
            o.close(expected_close,1,[MAIN+4096])
            need(i(expected_close,'li2_native_close','sequence')==i(global_close,'li2_native_close','sequence')+1 and
                 f(p,P,'first_close')==expected_close,'remaining HELPER permission has its own exact real one-page close')
        else:
            need(expected_close==f(lastl,L,'close') and f(p,P,'first_close')==f(lastp,P,'first_close'),
                 'no helper epoch means no new close history')
        # rn_finish performs exactly ARCH_GET_FS, ARCH_GET_GS, two writes,
        # and exit_group. Each selected publication attempts one empty close;
        # each dispatch performs one more. MAIN's complete sealed source and
        # five-byte borrow are authenticated by the enclosing ELF reader.
        # The final dispatch receipt replaces only the global close history.
        o.empty_close(expected_close,cl,10,5)
        need(i(cl,'li2_native_close','generation_epoch')-i(l,L,'generation_epoch') in (0,2),
             'final global close follows only the last source publication after the final MAIN prepare')
    return dict(safe_prefix=int(safe),terminal_seeds=i(p,P,'seeds'),terminal_extensions=i(p,P,'extensions'),
                terminal_epochs_closed=i(p,P,'epochs_closed'),terminal_published=i(l,L,'published'),
                terminal_closed_pages=i(l,L,'closed_pages'),
                focal_empty_closes=1 if case==5 else 2 if case==6 else 0,
                terminal_empty_closes=10 if case in tuple(range(10))+(19,) else 0)
