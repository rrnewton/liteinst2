/* Included after the unchanged interval storage and capture primitives. */
static unsigned tci_pending;
static void tci_snapshot(struct li2_page_custody_stats *c,struct li2_maps_stats *m) {
 tfi_copy(c,li2_page_custody_snapshot(),sizeof *c);li2_maps_stats_read(m);
}
static void tci_entry(unsigned index) {
 checked(index<TFI_MAX_EVENTS && !tci_pending,1762,1);
 tci_snapshot(&tfi_record.custody.rows[index].entry,
              &tfi_record.custody.rows[index].entry_maps);
}
static void tci_returned(unsigned index) {
 checked(index<TFI_MAX_EVENTS && !tci_pending,1762,2);
 tci_snapshot(&tfi_record.custody.rows[index].returned,
              &tfi_record.custody.rows[index].returned_maps);
 tci_pending=index+1;
}
void tci_fetch_returned(unsigned point,int result,const struct li2_fetch_ref *argument,
 const struct li2_custody_owner *key,const struct li2_fetch_rx_view *view,
 const struct li2_fetch_ref *published) {
 if(!tfi_trace_active)return;
 checked(tfi_count<TFI_MAX_EVENTS && (point==1 || point==2) && argument && key &&
         key->owner && key->owner->session && view,1762,3);
 struct tci_meta *m=point==1?&tfi_record.custody.rows[tfi_count].stage:
                              &tfi_record.custody.rows[tfi_count].commit;
 checked(!m->h[0],1762,4);
 m->h[0]=1;m->h[1]=point;m->h[2]=tfi_count;m->h[3]=(uint64_t)(long)result;
 m->h[4]=(uintptr_t)key->chain;m->h[5]=(uintptr_t)key->owner;
 m->h[6]=key->slot;m->h[7]=key->generation;m->h[8]=key->event;
 m->h[9]=(uintptr_t)key->owner->session;
 tfi_copy(&m->argument,argument,sizeof m->argument);
 if(published)tfi_copy(&m->published,published,sizeof m->published);
 tfi_copy(&m->session,key->owner->session,sizeof m->session);
 tci_snapshot(&m->custody,&m->maps);
 tfi_copy(&m->view,view,sizeof m->view);
}
static void tci_handler_end(struct li2_tf_chain *c,int sig,const siginfo_t *si,const ucontext_t *u) {
 li2_tf_chain_handler_end(c);
 if(!tci_pending)return;
 unsigned index=tci_pending-1;
 checked(index<TFI_MAX_EVENTS && tfi_count==index+1 && !tfi_trace_active,1762,5);
 struct tci_row *r=&tfi_record.custody.rows[index];
 tci_snapshot(&r->ready,&r->ready_maps);tfi_compact(&r->ready_frame,sig,si,u);
 ++tfi_record.custody.h[4];tci_pending=0;
}
static void tci_terminal(void) {
 tfi_record.custody.h[0]=UINT64_C(0x3159545344434954);
 tfi_record.custody.h[1]=1;tfi_record.custody.h[2]=sizeof tfi_record.custody;
 tfi_record.custody.h[3]=tfi_count;tfi_record.custody.h[5]=tci_pending;
 tfi_record.custody.h[6]=selected_chain.event_id;
 tfi_record.custody.h[7]=(uintptr_t)&selected_chain;
 tfi_record.custody.h[8]=(uintptr_t)selected_chain.session;
 tfi_copy(&tfi_record.custody.terminal,li2_page_custody_snapshot(),
          sizeof tfi_record.custody.terminal);
}
