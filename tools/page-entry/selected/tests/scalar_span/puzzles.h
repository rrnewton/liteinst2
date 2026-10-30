#ifndef LI2_SPAN_PUZZLES_H
#define LI2_SPAN_PUZZLES_H
/* Fixed hardware puzzles; no expected arithmetic/undefined-flag model. */
enum { SPAN_NATIVE_MODES=58, SPAN_ENTRY=0x100 };
static unsigned offsets[64],lengths[64],generated_offsets[64];
static unsigned heads,body_bytes,expected_steps,fault_head,faulted;
static unsigned char source_page[PAGE];
static void instruction(const unsigned char *p,unsigned n){
    need(heads<64&&body_bytes+n<=256,180);
    offsets[heads]=body_bytes;lengths[heads++]=n;
    bytes(source_page+SPAN_ENTRY+body_bytes,p,n);body_bytes+=n;
}
#define INS(...) do { const unsigned char ins[]={__VA_ARGS__};instruction(ins,sizeof(ins)); } while(0)
static void rip_instruction(unsigned op,unsigned reg,uintptr_t target){
    unsigned char b[7]={0x48,(unsigned char)op,(unsigned char)(5+8*reg),0,0,0,0};
    uintptr_t next=source_address+SPAN_ENTRY+body_bytes+7;
    int64_t delta;
    if(target>=next){need(target-next<=INT32_MAX,181);delta=(int64_t)(target-next);}
    else{need(next-target<=UINT64_C(0x80000000),182);delta=-(int64_t)(next-target);}
    uint32_t d=(uint32_t)delta;bytes(b+3,&d,4);instruction(b,7);
}
static void puzzle(void){
    for(unsigned i=0;i<PAGE;i++)source_page[i]=0xcc;
    heads=body_bytes=0;faulted=mode==8||mode==9;fault_head=mode==9;
    if(mode==0){
        INS(0x48,0x83,0xc0,0x7f);INS(0x48,0x83,0xe8,0xff);
        INS(0x48,0x0d,0x00,0x00,0x00,0x80);INS(0x48,0x25,0xff,0xff,0xff,0x7f);
        INS(0x48,0x31,0xd8);INS(0x48,0x39,0xd8);INS(0x48,0xf7,0xc0,0x01,0x00,0x00,0x80);
    }else if(mode==1){
        INS(0xb8,0x01,0x00,0x00,0x80);INS(0x48,0xc7,0xc3,0x00,0x00,0x00,0x80);
        INS(0x49,0xb8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef);
        INS(0x48,0x29,0xc0);INS(0x45,0x31,0xc0);
    }else if(mode==2){
        INS(0x48,0x8d,0x44,0xca,0xf9);INS(0x8d,0x4c,0x8a,0x11);
    }else if(mode==3){
        INS(0x03,0x44,0x8a,0xf0);INS(0x48,0x2b,0x42,0x08);
        INS(0x48,0x3b,0x02);INS(0xf7,0x42,0x0c,0xff,0xff,0xff,0x7f);
    }else if(mode==4||mode==5){
        unsigned at=mode==4?0xf00:0x20;uint64_t value=UINT64_C(0x8877665544332211);
        bytes(source_page+at,&value,8);rip_instruction(0x8b,0,source_address+at);
        /* LEA's target is an actual PROT_NONE page; no CPU read is allowed. */
        rip_instruction(0x8d,3,data_address+DATA);
    }else if(mode==6||mode==7){
        INS(0x48,0x85,0xc0);INS(0x74,0x04);INS(0x48,0x83,0xc3,0x01);INS(0x48,0x83,0xcb,0x80);
    }else if(mode==8||mode==9){
        if(mode==9)INS(0x48,0x83,0xc0,0x01);
        rip_instruction(0x8b,0,data_address+DATA);
    }else{
        unsigned group=(mode-10)/8,variant=(mode-10)%8,width=group%2?64:32;
        unsigned field=group/2==0?4:group/2==1?5:7;
        unsigned char b[4];unsigned n=0;if(width==64)b[n++]=0x48;
        b[n++]=variant==0?0xd1:variant<6?0xc1:0xd3;
        b[n++]=(unsigned char)(0xc0+field*8+(variant==7?1:0));
        if(variant>0&&variant<6){unsigned count[]={0,0,1,width-1,width,255};b[n++]=(unsigned char)count[variant];}
        instruction(b,n);
    }
    source_page[SPAN_ENTRY+body_bytes]=0x90; /* real unsupported boundary */
    expected_steps=faulted?fault_head:mode==6?3:heads;
    unsigned at=0;for(unsigned i=0;i<heads;i++){generated_offsets[i]=at;at+=mode>=6&&mode<=7&&i==1?6:lengths[i];}
}
#undef INS
#endif
