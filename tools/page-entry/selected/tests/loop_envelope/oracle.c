/* Supplied instruction bytes are decoded, never executed. Expected graph
   below is a literal source model, independent of candidate discovery/ranking. */
#include "loop_envelope.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[2*1024*1024];
static struct li2_decoder_stats initial;
static unsigned char source[2][LI2_LE_PAGE];
static uintptr_t pages[2];
static struct li2_le_witness actual,scratch,bad;
static unsigned positives,refusals,corruptions;
static const unsigned char tunables[]={
    0x49,0x83,0xc1,0x01,0x49,0x83,0xe8,0x80,0x49,0x83,0xf9,0x25,
    0x0f,0x84,0x72,0xff,0xff,0xff,0x41,0x80,0x78,0xf8,0x00,0x4d,0x63,0xd1,
    0x75,0xe4,0x41,0x0f,0xb6,0x38,0x40,0x84,0xff,0x74,0xdb,
    0x4c,0x89,0xcd,0x4c,0x89,0xc6,0x48,0x89,0xd8,0x89,0xf9,0x48,0xc1,0xe5,0x07,
    0x0f,0x1f,0x40,0x00,0x0f,0xb6,0x10,0x84,0xd2,0x74,0xc1,0x38,0xca,0x75,0xbd,
    0x0f,0xb6,0x4e,0x01,0x48,0x83,0xc6,0x01,0x48,0x83,0xc0,0x01,0x84,0xc9,
    0x75,0xe5,0x80,0x38,0x3d,0x75,0xa8,0x45,0x85,0xdb,0x74,0x11,0x41,0x8b,0x40,0xfc,
    0x85,0xc0,0x0f,0x84,0x13,0x03,0x00,0x00,0x83,0xf8,0x02,0x75,0x92,
    0x49,0xc1,0xe2,0x07,0x48,0x8d,0x05,0x47,0x0f,0x02,0x00,0x42,0x83,0x7c,0x10,0x30,0x03,
    0x0f,0x84,0xe9,0x02,0x00,0x00,0x48,0x8b,0x3c,0x24,0x31,0xf6,0xe8,0xb0,0x5f,0xff,0xff
};
static const unsigned off[28]={0,4,8,12,18,23,26,28,32,35,37,40,43,46,48,52,
    56,59,61,63,65,67,71,75,79,81,83,86};
/* -1 is the source's outside escape; -2 is the true last fallthrough.
   Other values are literal linear-head ordinals, never decoder output. */
static const int first[28]={1,2,3,-1,5,6,0,8,9,0,11,12,13,14,15,16,
    17,18,0,20,0,22,23,24,25,16,27,0};
static const int second[28]={-3,-3,-3,4,-3,-3,7,-3,-3,10,-3,-3,-3,-3,-3,-3,
    -3,-3,19,-3,21,-3,-3,-3,-3,26,-3,-2};
static void stable(void) {
    struct li2_decoder_stats s;
    assert(!li2_decoder_stats(&s) && !memcmp(&s,&initial,sizeof s));
}
static void init(uintptr_t page,unsigned adjacent) {
    pages[0]=page;pages[1]=page+(adjacent?4096:16384);
    memset(source,0xcc,sizeof source);
}
static void put(unsigned offset,const unsigned char *bytes,size_t n) {
    assert(offset+n<=sizeof source);memcpy((unsigned char *)source+offset,bytes,n);
}
static void check(uintptr_t entry,int expected) {
    memset(&actual,0xa5,sizeof actual);
    assert(li2_le_choose(pages,source,entry,&actual)==expected);
    assert(actual.version==12 && actual.bytes==sizeof actual && actual.result==(unsigned)expected);
    assert(actual.ready==(expected==0));
    assert(!li2_le_validate(pages,source,entry,&actual,&scratch));
    if(expected) {
        struct li2_le_shape z={0};assert(!memcmp(&z,&actual.selected,sizeof z));refusals++;
    } else positives++;
    stable();
}
static void literal_graph(uintptr_t base,unsigned entry) {
    const struct li2_le_shape *s=&actual.selected;
    assert(s->choice.first==base && s->choice.end==base+88 && s->choice.latch==base+86);
    assert(s->choice.result==0 && s->choice.heads==28 && s->choice.exits==2 && !s->choice.links);
    assert(s->choice.backwards==6 && !s->choice.stores && s->choice.source_bytes==88);
    unsigned queue[28]={entry},rank[28],count=1;
    for(unsigned i=0;i<28;i++)rank[i]=28;
    rank[entry]=0;
    for(unsigned at=0;at<count;at++) {
        const int edge[2]={first[queue[at]],second[queue[at]]};
        for(unsigned arm=0;arm<2;arm++)if(edge[arm]>=0 && rank[edge[arm]]==28) {
            rank[edge[arm]]=count;queue[count++]=(unsigned)edge[arm];
        }
    }
    assert(count==28);unsigned exit=0;
    for(unsigned at=0;at<28;at++) {
        unsigned i=queue[at];const struct li2_le_head *h=&s->head[at];
        const int edge[2]={first[i],second[i]};unsigned arms=second[i]==-3?1:2;
        assert(h->pc==base+off[i] && h->kind==LI2_LE_NONE && h->successors==arms);
        assert(h->flow==(arms==2?LI2_REGION_JCC:LI2_REGION_NEXT));
        assert(h->decoded<actual.decoded && actual.node[h->decoded].scalar.decoded.pc==h->pc);
        unsigned mask=0;
        for(unsigned arm=0;arm<arms;arm++) {
            if(edge[arm]>=0)assert(h->token[arm]==rank[edge[arm]]);
            else {
                assert(h->token[arm]==128+exit);mask|=1U<<arm;
                assert(s->exit[exit].head==at && s->exit[exit].arm==arm);
                assert(s->exit[exit].target==base+(edge[arm]==-1?(uintptr_t)-124:88));exit++;
            }
        }
        assert(h->external_mask==mask && !h->reserved);
    }
    assert(exit==2 && s->head[0].pc==base+off[entry]);
}
static void ranking(void) {
    init(0x400000,0);put(0x200,tunables,sizeof tunables);uintptr_t h=pages[0]+0x200;
    check(h+23,0);literal_graph(h,5);
    static const unsigned ends[6]={28,37,63,67,88,110};
    static const unsigned heads[6]={7,10,19,21,28,35};
    static const unsigned backs[6]={1,2,3,4,6,7};
    assert(actual.candidates==6 && actual.eligible==6);
    for(unsigned i=0;i<6;i++) {
        const struct li2_le_candidate *c=&actual.candidate[i];
        assert(c->result==0 && c->first==h && c->end==h+ends[i]);
        assert(c->heads==heads[i] && c->backwards==backs[i]);
        assert(c->exits==(i==5?4:2) && !c->links);
    }
    /* Selection validation uses the separate unchanged supplied pages. Even a
       changed otherwise-unused source byte in the witness is rejected. */
    static const size_t positions[]={
        offsetof(struct li2_le_witness,version),offsetof(struct li2_le_witness,ready),
        offsetof(struct li2_le_witness,result),offsetof(struct li2_le_witness,page),
        offsetof(struct li2_le_witness,entry),offsetof(struct li2_le_witness,stop_pc),
        offsetof(struct li2_le_witness,source)+4000,
        offsetof(struct li2_le_witness,node)+offsetof(struct li2_le_decoded,scalar)+offsetof(struct li2_span_decoded,flags_written),
        offsetof(struct li2_le_witness,candidate)+7*sizeof(struct li2_le_candidate),
        offsetof(struct li2_le_witness,selected)+offsetof(struct li2_le_shape,choice)+offsetof(struct li2_le_candidate,end),
        offsetof(struct li2_le_witness,selected)+offsetof(struct li2_le_shape,head)+offsetof(struct li2_le_head,pc),
        offsetof(struct li2_le_witness,selected)+offsetof(struct li2_le_shape,head)+offsetof(struct li2_le_head,external_mask),
        offsetof(struct li2_le_witness,selected)+offsetof(struct li2_le_shape,head)+offsetof(struct li2_le_head,token),
        offsetof(struct li2_le_witness,selected)+offsetof(struct li2_le_shape,exit),
        offsetof(struct li2_le_witness,selected)+offsetof(struct li2_le_shape,exit)+offsetof(struct li2_le_arm,arm),
        sizeof(struct li2_le_witness)-1
    };
    for(unsigned i=0;i<sizeof positions/sizeof positions[0];i++) {
        bad=actual;((unsigned char *)&bad)[positions[i]]^=1;
        assert(li2_le_validate(pages,source,h+23,&bad,&scratch)==LI2_LE_CORRUPT);corruptions++;
    }
    assert(li2_le_validate(pages,source,h+23,&actual,&actual)==LI2_LE_ARGUMENT);
    assert(li2_le_choose(pages,source,h+23,(struct li2_le_witness *)source)==LI2_LE_ARGUMENT);
    stable();
}
static void entries(void) {
    const uintptr_t placement[2]={UINT64_C(0x400000),UINT64_C(0x700000000000)};
    for(unsigned place=0;place<2;place++)for(unsigned straddle=0;straddle<2;straddle++) {
        unsigned offset=straddle?4096-64:512;init(placement[place],1);put(offset,tunables,sizeof tunables);
        uintptr_t h=pages[0]+offset;
        for(unsigned entry=0;entry<28;entry++) { check(h+off[entry],0);literal_graph(h,entry); }
        /* The outside successor is a fresh entry. The later real latch can
           select a different35-head envelope; it is not membership in28. */
        check(h+88,0);
        assert(actual.selected.choice.heads==35 && actual.selected.choice.first==h);
        assert(actual.selected.choice.end==h+110 && actual.selected.choice.exits==4);
        assert(actual.selected.head[0].pc==h+88);
    }
}
static void put32(unsigned char *p,uint32_t n) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i)); }
/* Exact three-byte Nop_rm32 form from the separate scalar-read domain.
   Nopd (0x90) remains refused by that domain and is not a synthetic head. */
static void nops(unsigned offset,unsigned count) {
    static const unsigned char nop[]={0x0f,0x1f,0x00};
    for(unsigned i=0;i<count;i++)put(offset+3*i,nop,sizeof nop);
}
static void puzzles(void) {
    uintptr_t h;
    static const unsigned char forward[]={0x74,0x06,0x0f,0x1f,0x00,0x0f,0x1f,0x00,0x75,0xf6};
    init(0x400000,0);put(512,forward,sizeof forward);h=pages[0]+512;check(h,0);
    assert(actual.selected.choice.heads==4 && actual.selected.choice.exits==1);
    assert(!actual.selected.head[0].external_mask && actual.selected.head[0].token[0]==1 && actual.selected.head[0].token[1]==2);
    static const unsigned char interior[]={0x0f,0x1f,0x40,0,0x75,0xfb,0x75,0xf8};
    init(0x400000,0);put(512,interior,sizeof interior);check(pages[0]+512,LI2_LE_NO_ENVELOPE);
    assert(actual.candidates==1 && actual.candidate[0].result==LI2_LE_INTERIOR);
    static const unsigned char no_exit[]={0x0f,0x1f,0x00,0x0f,0x1f,0x00,0xeb,0xf8};
    init(0x400000,0);put(512,no_exit,sizeof no_exit);check(pages[0]+512,LI2_LE_NO_ENVELOPE);
    assert(actual.stop==LI2_LE_JUMP && actual.candidate[0].result==LI2_LE_NO_EXIT);
    static const unsigned char unsupported_prefix[]={0xcc,0x0f,0x1f,0x00,0x75,0xfa};
    init(0x400000,0);put(512,unsupported_prefix,sizeof unsupported_prefix);check(pages[0]+516,LI2_LE_NO_ENVELOPE);
    assert(actual.candidate[0].result==LI2_LE_PREFIX);
    static const unsigned char mov[]={0x48,0x89,0x07,0x75,0xfb};
    init(0x400000,0);put(512,mov,sizeof mov);check(pages[0]+512,0);
    assert(actual.selected.choice.heads==2 && actual.selected.choice.stores==1);
    assert(actual.selected.head[0].kind==LI2_LE_MOV && actual.selected.head[0].flow==LI2_REGION_NEXT);
    init(0x400000,0);put(4096-4,tunables,sizeof tunables);check(pages[0]+4096-4,LI2_LE_NO_ENVELOPE);
    assert(actual.stop==LI2_LE_FETCH_END && actual.decoded==1);
    /* An unsearched spine cannot escape with a previously seen latch. */
    init(0x400000,0);nops(512,32);source[0][608]=0x75;source[0][609]=0x9e;nops(610,96);
    check(pages[0]+512,LI2_LE_DISCOVERY_LIMIT);assert(actual.decoded==128);
    init(0x400000,0);nops(512,127);check(pages[0]+512,LI2_LE_NO_ENVELOPE);
    assert(actual.decoded==128 && actual.stop==LI2_LE_UNSUPPORTED);
    /* Exactly128 heads end at a real conditional latch, not a head-limit cut.
       Missing adjacent page is the descriptive spine stop, not a target read. */
    init(0x400000,0);unsigned start=4096-387;nops(start,127);
    source[0][start+381]=0x0f;source[0][start+382]=0x85;
    put32(source[0]+start+383,0U-387U);check(pages[0]+start,0);
    assert(actual.decoded==128 && actual.selected.choice.heads==128 && actual.selected.choice.links==2 && actual.selected.choice.exits==1);
    /* Same capacity, eight late backedges make actual BFS member links exceed
       the eight combined boundaries. Their candidate is refused, not clipped. */
    init(0x400000,0);start=4096-408;nops(start,120);
    for(unsigned i=0;i<8;i++) {
        unsigned o=start+360+6*i;source[0][o]=0x0f;source[0][o+1]=0x85;put32(source[0]+o+2,0U-(366U+6*i));
    }
    check(pages[0]+start,0);
    assert(actual.candidates==8 && actual.candidate[7].result==LI2_LE_LINK_LIMIT);
    assert(actual.selected.choice.heads==121 && actual.selected.choice.exits==1 && actual.selected.choice.links==2);
    for(unsigned external=7;external<=8;external++) {
        init(0x400000,0);start=512;
        for(unsigned i=0;i<external;i++) { source[0][start+2*i]=0x74;source[0][start+2*i+1]=0x40; }
        unsigned o=start+2*external;source[0][o]=0x75;source[0][o+1]=(unsigned char)(0U-(2*external+2));
        check(pages[0]+start,external==7?0:LI2_LE_NO_ENVELOPE);
        assert(actual.candidate[0].exits==external+1);
        assert(actual.candidate[0].result==(external==7?LI2_LE_ELIGIBLE:LI2_LE_EXIT_LIMIT));
    }
    /* A root beyond the held pair, duplicate pages and NULL output cannot
       create a description or silently choose a different entry. */
    check(pages[1]+4096,LI2_LE_ARGUMENT);
    pages[1]=pages[0];check(pages[0]+512,LI2_LE_ARGUMENT);
    assert(li2_le_choose(pages,source,pages[0],0)==LI2_LE_ARGUMENT);
}
int main(void) {
    struct li2_decoder_stats s;
    assert(!li2_decoder_initialize(arena,sizeof arena,&s));
    assert(!li2_decoder_stats(&initial));
    ranking();entries();puzzles();stable();
    assert(positives==122 && refusals==9 && corruptions==16);
    printf("{\"profile\":\"loop-envelope-component-v1\",\"version\":12,\"positive\":%u,\"refused\":%u,\"corruptions\":%u,\"heads_max\":128,\"boundaries_max\":8,\"members\":2,\"emitted\":0,\"owner_entries\":0}\n",positives,refusals,corruptions);
    return 0;
}
