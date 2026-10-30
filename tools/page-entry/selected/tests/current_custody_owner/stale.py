"""Separate actual pre-hash chain failure; never rewrites an old failed wire."""
import importlib.util
from pathlib import Path
import struct
_spec=importlib.util.spec_from_file_location('current_custody_stale_wire',Path(__file__).with_name('wire.py'))
wire=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(wire)
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
PAGE,FP,MASK,TF,RF,U64=old.PAGE,old.FP,old.MASK,old.TF,old.RF,old.U64

class Check(old.Check):
    def header(self,exit_status):
        h=self.h;r=self.r;c=self.control_words;mode=self.app['header'][4]
        need(exit_status==125 and self.control==0,'separate actual stale-chain failure')
        code,detail=903,302
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

    def finish(self):
        outcome=self.header(125);o=self.owner;t='unrolled_owner';h=self.h;r=self.r
        self.eq(o,t,initialized=1,metadata_registered=1,arena_registered=1,allocated=1,low_arena_registered=1,low_allocated=1,first_error=0,first_detail=0,unexpected=0)
        arena,low,used=self.v(o,t,'arena low_arena used')
        need(canonical(arena,64*PAGE) and arena%PAGE==0 and 0<low<=2**31-64*PAGE and low%PAGE==0 and (low+64*PAGE<=arena or arena+64*PAGE<=low) and 0<=used<=64,'both actual original arenas, unchanged total64 capacity')
        self.eq(o,t,allocation_result=arena,low_allocation_result=low,publications=used)
        self.query(self.f(o,t,'initial'),arena,3,64);self.query(self.f(o,t,'low_initial'),low,3,64)
        session=self.f(o,t,'session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        n=self.i(session,'li2_step_session','sync_query');need(n<1<<63 and n&96==96,'actual original sync-core session')
        generated=self.f(self.b,'uho_wire','generated');slots=[]
        for i,b in enumerate(r.items(o,t,'slots','uh_slot')):
            if i>=used:zero(b,'whole unused old slot');zero(generated[i*PAGE:(i+1)*PAGE],'whole unused image capture');continue
            s=self.slot(b,i);need(generated[i*PAGE:(i+1)*PAGE]==s['page'],'whole actual old image remains unchanged');slots.append(s)
        need(h[40]==used and h[24:26]==(0,0) and h[30]==2 and h[31:38]==(0,0,0,1,1,2,1),'actual quiet old owner and pending failed original TF route; no hash entry')
        need(h[38]==self.app['seed'][1],'actual failed prefix keeps original selected logical flags')
        for k in ('entries','supplied_before','control_before','nested_fp'):zero(self.f(self.b,'uho_wire',k),'no fabricated old owner operation '+k)
        zero(self.f(self.b,'uho_wire','control'),'no old supplied-control execution')
        self.eq(o,t,candidates=sum(self.i(o,t,k)for k in('source_misses','plan_misses','capacity_misses','publications','hits')),entries=used+self.i(o,t,'hits'),completed=self.i(o,t,'entries'))
        completed=self.i(o,t,'completed');need(completed==self.i(o,t,'head_exits')+self.i(o,t,'stop_exits') and completed<=self.i(o,t,'iterations')<=64*completed and self.i(o,t,'events')==sum(q(self.f(o,t,'signals'))),'all prior genuine old generated work closed')
        # The NOP prefix fails the literal fifteen-byte hash comparison before
        # current is cleared. Its actual previous loader record remains intact.
        current=self.f(o,t,'current');last=self.f(o,t,'last')
        if self.i(current,'uh_record','completed'):
            self.record(current,slots);need(current==last,'entire retained successful loader current equals actual last')
        elif self.i(o,t,'candidates'):self.clean_miss(current,slots)
        else:zero(current,'no initialized old candidate exists before this prefix')
        need(self.i(self.f(current,'uh_record','source'),'li2_unrolled_source','pc')!=self.image['current_elf']['head'],'no invented hash-source admission of NOP prefix')
        if completed:self.record(last,slots)
        else:zero(last,'no invented prior completion')
        fetch=self.f(self.b,'uho_wire','terminal_fetch');self.eq(fetch,'li2_fetch_progress',held=1,complete=1,first_error=302,first_detail=0,identity_observed=1,pages_copied=1,bytes_copied=15,last_backing_page=0,last_backing_observed=1)
        need(self.i(fetch,'li2_fetch_progress','sequence')>0 and self.i(fetch,'li2_fetch_progress','validation_calls')>0,'actual occupied validated source retained on chain failure')
        self.maps(self.f(fetch,'li2_fetch_progress','preparation'));self.maps(self.f(fetch,'li2_fetch_progress','validation'))
        self.owners(self.f(self.b,'uho_wire','terminal_owners'))
        return dict(control=0,entries=[],supplied_before=None,terminal_expected=self.report_rows(outcome),summary=dict(focal_entries=0,focal_completed=0,global_entries=self.i(o,t,'entries'),global_completed=completed,publications=used,required_failed_operation=1,supplied_control=0,held_fetch=1,cleanup_complete=0))
