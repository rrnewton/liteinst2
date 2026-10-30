/* Distinct pure observation of this actual lifecycle translation unit. */
#include "span_fetch.h"
#if !defined(LI2_SCALAR_SPAN_TRACE) || LI2_SCALAR_SPAN_TRACE != 1
#error "literal scalar-span TRACE transfer profile required"
#endif
int li2_lifecycle_span_fetch_snapshot(struct li2_span_fetch_observation *out) {
    if(!out || out->complete)return LI2_FETCH_ARGUMENT;
    if(!active || tx.guard || !fetch.progress.complete || fetch.progress.first_error ||
       fetch.progress.first_detail || fetch.progress.held>1 || !fetch.progress.sequence ||
       !fetch.progress.identity_observed || fetch.pid<=0 || fetch.pid!=fetch.tid ||
       !fetch.requested || fetch.requested>15 || !fetch.page_count || fetch.page_count>2 ||
       fetch.progress.pages_copied!=fetch.page_count ||
       fetch.progress.bytes_copied!=fetch.requested ||
       allocation_id!=fetch.allocation_epoch || generation!=fetch.generation_epoch ||
       used!=fetch.records_epoch || counts.transactions!=fetch.transactions_epoch ||
       tx.phase!=fetch.phase_epoch)return LI2_FETCH_STALE;
    out->ref=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};
    copy(&out->progress,&fetch.progress,sizeof out->progress);
    out->pc=fetch.pc;out->length=fetch.requested;out->page_count=fetch.page_count;
    out->pid=fetch.pid;out->tid=fetch.tid;
    for(size_t i=0;i<15;i++)out->bytes[i]=i<fetch.requested?fetch.bytes[i]:0;
    for(size_t i=0;i<fetch.page_count;i++) {
        copy(&out->pages[i],&fetch.pages[i],sizeof out->pages[i]);
        copy(&out->backing[i],&fetch.backing[i],sizeof out->backing[i]);
    }
    if(fetch.progress.last_backing_observed)
        copy(&out->last_backing,&fetch.last_backing,sizeof out->last_backing);
    __asm__ volatile("":::"memory");out->complete=1;return 0;
}
