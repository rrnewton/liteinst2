/* Measurement only. No result from this module participates in admission. */
_Static_assert(LI2_PTR_SLOTS==2 && LI2_PG_HEADS==128 && RANGES==128,"observed original policy dimensions");
static uint64_t rcc_slot[2],rcc_slot_generation[2];
static struct li2_rcc_attempt *rcc_attempt;
static uint64_t rcc_select_seen,rcc_select_pass;
static void rcc_bad(uint64_t code) {
    if(rcc_wire && !rcc_wire->header[16])__atomic_store_n(&rcc_wire->header[16],code,__ATOMIC_RELEASE);
}
static int rcc_lock(void) {
    if(!rcc_wire || !rcc_wire->header[15] || rcc_wire->header[16])return 0;
    if(rcc_wire->header[22]){rcc_bad(1);return 0;}
    __atomic_store_n(&rcc_wire->header[22],1,__ATOMIC_RELEASE);return 1;
}
static void rcc_unlock(void) {__atomic_store_n(&rcc_wire->header[22],0,__ATOMIC_RELEASE);}
static void rcc_scan(unsigned phase,unsigned result) {
    if(!rcc_lock())return;
    if(phase>=LI2_RCC_PHASES || result>2)rcc_bad(23);
    else {
        uint64_t *cell=&rcc_wire->header[LI2_RCC_SCAN_HEADER+phase*3+result];
        if(*cell==UINT64_MAX)rcc_bad(24);
        else __atomic_store_n(cell,*cell+1,__ATOMIC_RELEASE);
    }
    rcc_unlock();
}
static void rcc_select_reset(void) {
    rcc_select_seen=0;rcc_select_pass=0;
}
static int rcc_select_test(unsigned bit,int value) {
    if(rcc_lock()) {
        if(bit>=6)rcc_bad(22);
        else {rcc_select_seen|=UINT64_C(1)<<bit;if(value>0)rcc_select_pass|=UINT64_C(1)<<bit;}
        rcc_unlock();
    }
    return value;
}
static void rcc_commit(uint64_t bit) {
    uint64_t old=__atomic_load_n(&rcc_attempt->words[31],__ATOMIC_RELAXED);
    __atomic_store_n(&rcc_attempt->words[31],old|bit,__ATOMIC_RELEASE);
}
static uint64_t rcc_page(const struct li2_pg_source_page *s) {
    const struct li2_fetch_page *p=&s->identity;const struct li2_fetch_backing *b=&s->backing;
    uint64_t m[32]={p->address,p->allocation,p->generation,p->offset,p->initial_extent,
        p->backing,p->object,p->logical,p->closed_prot,p->vma_first,p->vma_end,
        p->vma_major,p->vma_minor,p->vma_inode,p->vma_offset,
        (uint64_t)(int64_t)b->retained_fd,(uint64_t)b->seals,(uint64_t)b->stat_result,
        (uint64_t)b->stat.st_dev,(uint64_t)b->stat.st_ino,(uint64_t)b->stat.st_size,
        (uint64_t)b->stat.st_mode,b->seals_observed,b->stat_observed};
    uint64_t n=rcc_wire->header[17];
    if(n>LI2_RCC_PAGES || b->retained_fd<0 || b->seals<0 || b->stat_result || b->seals_observed!=1 || b->stat_observed!=1){rcc_bad(2);return 0;}
    for(uint64_t i=0;i<n;i++)if(equal(m,rcc_wire->pages[i].meta,sizeof m)) {
        if(!equal(s->bytes,rcc_wire->pages[i].bytes,4096)){rcc_bad(3);return 0;}
        return i+1;
    }
    if(n==LI2_RCC_PAGES){rcc_bad(4);return 0;}
    copy(rcc_wire->pages[n].meta,m,sizeof m);copy(rcc_wire->pages[n].bytes,s->bytes,4096);
    __atomic_store_n(&rcc_wire->header[17],n+1,__ATOMIC_RELEASE);return n+1;
}
static uint64_t rcc_registry(void) {
    uint64_t n=rcc_wire->header[20];
    if(n>LI2_RCC_REGISTRIES || protected_count>128){rcc_bad(5);return 0;}
    for(uint64_t i=0;i<n;i++) {
        const uint64_t *v=rcc_wire->registries[i].words;
        if(v[0]!=protected_count)continue;
        size_t j=0;for(;j<protected_count;j++)if(v[1+2*j]!=protected[j].first || v[2+2*j]!=protected[j].end)break;
        if(j==protected_count)return i+1;
    }
    if(n==LI2_RCC_REGISTRIES){rcc_bad(6);return 0;}
    uint64_t *v=rcc_wire->registries[n].words;v[0]=protected_count;
    for(size_t j=0;j<protected_count;j++){v[1+2*j]=protected[j].first;v[2+2*j]=protected[j].end;}
    __atomic_store_n(&rcc_wire->header[20],n+1,__ATOMIC_RELEASE);return n+1;
}
static void rcc_begin(uintptr_t pc) {
    if(!rcc_lock())return;
    if(rcc_attempt || pe.selected_slot>=2){rcc_bad(7);rcc_unlock();return;}
    uint64_t n=rcc_wire->header[21];
    if(n>=LI2_RCC_ATTEMPTS){rcc_bad(8);rcc_unlock();return;}
    /* Reservation precedes all writes: a kill may leave one explicit partial row. */
    __atomic_store_n(&rcc_wire->header[21],n+1,__ATOMIC_RELEASE);
    rcc_attempt=&rcc_wire->attempts[n];uint64_t *v=rcc_attempt->words;
    const struct li2_ptr_slot *s=&pe.retained[pe.selected_slot];
    if((s->generation.installed && (rcc_slot_generation[pe.selected_slot]!=s->generation.generation || !rcc_slot[pe.selected_slot])) ||
       (!s->generation.installed && (rcc_slot_generation[pe.selected_slot] || rcc_slot[pe.selected_slot])))rcc_bad(9);
    v[0]=n+1;v[1]=pc;v[2]=pe.selected_slot;v[3]=pe.selected_bank;
    /* Actual root priority is PC-only, before source/lifetime comparison. */
    v[4]=pe.subentry_selected?2U:(s->generation.installed && s->publication.source.entry==pc)?1U:0U;
    v[4]|=rcc_select_seen<<8|rcc_select_pass<<16;
    v[5]=rcc_slot[pe.selected_slot];v[6]=s->generation.generation;v[7]=s->last_completed;
    v[8]=PGC_VALUE(offers);rcc_commit(1);rcc_unlock();
}
static void rcc_source(const struct li2_pg_sources *s,const struct li2_pg_rseq_progress *r) {
    if(!rcc_lock())return;
    if(!rcc_attempt || rcc_attempt->words[31]!=1 || !s || !s->complete || !r){rcc_bad(10);rcc_unlock();return;}
    uint64_t a=rcc_page(&s->key.page[0]),b=rcc_page(&s->key.page[1]),registry=rcc_registry();
    if(!a || !b || !registry){rcc_unlock();return;}
    const uint64_t key[8]={s->key.entry,a,b,r->lifetime_mode,r->registration_epoch,r->address,r->length,r->signature};
    uint64_t n=rcc_wire->header[18],id=0;
    if(n>LI2_RCC_KEYS){rcc_bad(11);rcc_unlock();return;}
    for(uint64_t i=0;i<n;i++)if(equal(key,rcc_wire->keys[i].words,sizeof key)){id=i+1;break;}
    if(!id) {
        if(n==LI2_RCC_KEYS){rcc_bad(12);rcc_unlock();return;}
        copy(rcc_wire->keys[n].words,key,sizeof key);id=n+1;
        __atomic_store_n(&rcc_wire->header[18],id,__ATOMIC_RELEASE);
    }
    uint64_t *v=rcc_attempt->words;v[9]=id;v[10]=registry;v[11]=pe.p.serial;
    v[12]=s->allocation_epoch;v[13]=s->generation_epoch;v[14]=s->transactions_epoch;v[15]=s->records_epoch;
    v[16]=r->registration_calls;rcc_commit(2);rcc_unlock();
}
static int rcc_test(unsigned bit,int value) {
    /* Called only where the original short-circuit expression evaluates. */
    if(rcc_lock()) {
        if(!rcc_attempt || rcc_attempt->words[31]!=3 || bit>=10)rcc_bad(13);
        else {rcc_attempt->words[21]|=UINT64_C(1)<<bit;if(value)rcc_attempt->words[22]|=UINT64_C(1)<<bit;}
        rcc_unlock();
    }
    return value;
}
static void rcc_plan(unsigned kind) {
    if(!rcc_lock())return;
    if(!rcc_attempt || rcc_attempt->words[31]!=3 || kind<1 || kind>4){rcc_bad(14);rcc_unlock();return;}
    uint64_t *v=rcc_attempt->words;v[17]=kind;
    if(kind==3){v[18]=(uint64_t)pe.miss.reason|((uint64_t)pe.miss.site<<32);v[19]=pe.miss.pc;v[20]=pe.miss.detail;}
    rcc_commit(4);rcc_unlock();
}
static void rcc_bound(void) {
    if(!rcc_lock())return;
    if(!rcc_attempt || rcc_attempt->words[31]!=7 || pe.selected_slot>=2){rcc_bad(15);rcc_unlock();return;}
    uint64_t *v=rcc_attempt->words;const struct li2_ptr_slot *s=&pe.retained[pe.selected_slot];
    if(v[17]==4) {
        uint64_t n=rcc_wire->header[19];const struct li2_pg_compact *p=&s->publication.plan;
        if(n==LI2_RCC_GRAPHS || !p->heads || p->heads>128){rcc_bad(16);rcc_unlock();return;}
        struct li2_rcc_graph *g=&rcc_wire->graphs[n];
        g->words[0]=v[9];g->words[1]=v[10];g->words[2]=pe.selected_bank;g->words[3]=p->heads;
        g->words[4]=s->generation.build_serial;g->words[5]=s->generation.generation;
        g->words[6]=s->generation.layout.generated[0];g->words[7]=s->generation.layout.generated[1];
        for(unsigned i=0;i<p->heads;i++) {
            if(p->head[i].source_page>=2 || p->head[i].source_offset>=4096){rcc_bad(17);rcc_unlock();return;}
            g->heads[i]=(uint16_t)(4096*p->head[i].source_page+p->head[i].source_offset);
        }
        __atomic_store_n(&rcc_wire->header[19],n+1,__ATOMIC_RELEASE);
        v[24]=v[5];v[25]=v[6];rcc_slot[pe.selected_slot]=n+1;rcc_slot_generation[pe.selected_slot]=s->generation.generation;
    } else if(v[17]!=1 && v[17]!=2)rcc_bad(18);
    v[23]=rcc_slot[pe.selected_slot];v[26]=s->generation.generation;rcc_commit(8);rcc_unlock();
}
static int rcc_frontier(const struct pda_work *w) {
    if(w->receipt>=3 || w->exit_member>=w->view.count || !rcc_attempt->words[0] ||
       rcc_attempt->words[0]>LI2_RCC_ATTEMPTS){rcc_bad(25);return 0;}
    const struct pda_completion *c=&pe.domain.completion[w->receipt];
    unsigned member=w->exit_member,slot=w->view.member[member].identity.slot;
    unsigned bank=w->view.member[member].identity.bank;
    if(!c->complete || c->serial!=pe.p.serial || c->count!=w->view.count ||
       slot>=2 || bank>=2 || !rcc_slot[slot]){rcc_bad(25);return 0;}
    uint64_t *v=rcc_wire->frontiers[rcc_attempt->words[0]-1].words;
    const struct pda_direct_exit *e=&c->direct_exit;
    if(e->complete) {
        if(e->complete!=1 || e->member!=member || e->head>=128 || e->index>=8 ||
           e->arm>=2 || e->head>=e->heads || e->index>=e->exits){rcc_bad(26);return 0;}
        v[0]=UINT64_C(1)|((uint64_t)member<<8)|((uint64_t)slot<<16)|((uint64_t)bank<<24)|
            ((uint64_t)e->head<<32)|((uint64_t)e->index<<48)|((uint64_t)e->arm<<56);
        v[1]=rcc_slot[slot];v[2]=e->flags;v[3]=e->original.decoded.pc;v[4]=e->direct.target[e->arm];
    } else {
        v[0]=UINT64_C(2)|((uint64_t)member<<8)|((uint64_t)slot<<16)|((uint64_t)bank<<24)|
            (UINT64_C(65535)<<32)|((uint64_t)pe.exit_index<<48);
        v[1]=rcc_slot[slot];v[2]=pe.after.frame.greg[REG_EFL];v[3]=pe.after.frame.greg[REG_RIP];
    }
    return 1;
}
static void rcc_finish(unsigned outcome) {
    if(!rcc_lock())return;
    if(!rcc_attempt || (outcome==1?rcc_attempt->words[31]!=7:rcc_attempt->words[31]!=15)){rcc_bad(19);rcc_unlock();return;}
    uint64_t *v=rcc_attempt->words;v[27]=outcome;v[28]=pe.p.serial;
    if(outcome==2) {
        const struct pda_work *w=&pe.domain.work;
        if(!w->completion || !w->view.count || w->view.count>2){rcc_bad(20);rcc_unlock();return;}
        unsigned peer=2;
        for(unsigned i=0;i<w->view.count;i++) {
            unsigned slot=w->view.member[i].identity.slot;
            if(slot>=2 || rcc_slot_generation[slot]!=w->view.member[i].identity.generation || !rcc_slot[slot]){rcc_bad(21);rcc_unlock();return;}
            if(slot!=pe.selected_slot)peer=slot;
        }
        if(peer<2)v[29]=rcc_slot[peer];
        v[30]=w->view.count|((uint64_t)peer<<8);
        if(!rcc_frontier(w)){rcc_unlock();return;}
    }
    rcc_commit(16);rcc_attempt=0;
    __atomic_store_n(&rcc_wire->header[23],rcc_wire->header[23]+1,__ATOMIC_RELEASE);rcc_unlock();
}
