/* Production source proof/parser/public callers. ELF buffers, environment and
   common-initializer outcome below are supplied observations, not native or
   sealed-source qualification. The real FD/membarrier body stays production. */
#include "bridge.h"
#include "lifecycle_loader.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static jmp_buf escape;
static unsigned error_code,active,common_calls;
static long error_detail;
static size_t common_count;
static const int *common_fds;
static struct li2_lifecycle_hooks hooks;
static const char *environment[3];
static unsigned image_checks,pair_checks,parser_checks,caller_checks;
static void require_case(int yes,const char *name) {
    if(!yes){fprintf(stderr,"empty-namespace: %s\n",name);exit(1);}
}
static void supplied_failure(unsigned code,long detail) __attribute__((noreturn));
static void supplied_failure(unsigned code,long detail) {
    error_code=code;error_detail=detail;longjmp(escape,1);
}
static void checked(int yes,unsigned code,long detail) {if(!yes)supplied_failure(code,detail);}
const char *const *bridge_environment(void) {return environment;}
#define DIE(code,detail) hooks.fail((code),(detail))
static void lifecycle_initialize_objects(const int *fds,size_t n) {
    ++common_calls;common_fds=fds;common_count=n;
}
/* ACTUAL_SOURCE */

struct fixture { _Alignas(8) unsigned char source[4096]; struct image image; };
static struct fixture main_image,interp_image;
static Elf64_Ehdr *eh(struct fixture *f){return (void *)f->source;}
static Elf64_Phdr *ph(struct fixture *f){return (void *)(f->source+sizeof(Elf64_Ehdr));}
static Elf64_Dyn *dyn(struct fixture *f){return (void *)(f->source+512);}
static void seed(struct fixture *f,unsigned kind) {
    memset(f,0,sizeof *f);Elf64_Ehdr *h=eh(f);
    memcpy(h->e_ident,"\177ELF\2\1\1",7);h->e_type=kind==IMAGE_MAIN?ET_EXEC:ET_DYN;
    h->e_machine=EM_X86_64;h->e_version=EV_CURRENT;h->e_ehsize=sizeof *h;
    h->e_phoff=sizeof *h;h->e_phentsize=sizeof(Elf64_Phdr);h->e_phnum=4;
    uintptr_t base=kind==IMAGE_MAIN?0x400000:0x1000;h->e_entry=base+256;
    ph(f)[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_vaddr=base,
        .p_filesz=sizeof f->source,.p_memsz=sizeof f->source,.p_align=4096};
    ph(f)[1]=(Elf64_Phdr){.p_type=PT_DYNAMIC,.p_flags=PF_R,.p_offset=512,.p_vaddr=base+512,
        .p_filesz=8*sizeof(Elf64_Dyn),.p_memsz=8*sizeof(Elf64_Dyn),.p_align=8};
    if(kind==IMAGE_MAIN){
        memcpy(f->source+2048,"/fixture-interpreter.so",24);
        ph(f)[2]=(Elf64_Phdr){.p_type=PT_INTERP,.p_offset=2048,.p_vaddr=base+2048,.p_filesz=24,.p_memsz=24};
    }
    dyn(f)[0]=(Elf64_Dyn){.d_tag=DT_STRTAB,.d_un.d_ptr=base+1024};
    dyn(f)[1]=(Elf64_Dyn){.d_tag=DT_STRSZ,.d_un.d_val=512};
    memcpy(f->source+1024,"\0libfixture.so\0",15);
    uintptr_t bias=kind==IMAGE_MAIN?0:0x70000000;
    f->image=(struct image){.bias=bias,.entry=bias+h->e_entry,.ph=ph(f),.n=4,
        .source=f->source,.source_size=sizeof f->source,.backing_fd=7,.kind=kind};
}
static void image_case(struct fixture *f,unsigned kind,int yes,const char *name) {
    ++image_checks;require_case(empty_namespace_image(&f->image,kind)==yes,name);
}
#define BAD(name,...) do{seed(&main_image,IMAGE_MAIN);__VA_ARGS__;image_case(&main_image,IMAGE_MAIN,0,name);}while(0)
static void source_cases(void) {
    seed(&main_image,IMAGE_MAIN);seed(&interp_image,IMAGE_INTERPRETER);
    image_case(&main_image,IMAGE_MAIN,1,"empty main");image_case(&interp_image,IMAGE_INTERPRETER,1,"empty interpreter");
    dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};
    image_case(&main_image,IMAGE_MAIN,1,"valid SONAME");
    dyn(&interp_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};
    image_case(&interp_image,IMAGE_INTERPRETER,1,"valid interpreter SONAME");
    BAD("source absent",main_image.image.source=0);
    BAD("source short",main_image.image.source_size=63);
    BAD("source bound",main_image.image.source_size=16U*1024U*1024U+1);
    BAD("source wrap",main_image.image.source=(const void *)(UINTPTR_MAX-32));
    BAD("backing absent",main_image.image.backing_fd=-1);
    BAD("kind",main_image.image.kind=IMAGE_BRIDGE);
    BAD("magic",eh(&main_image)->e_ident[0]=0);
    BAD("class",eh(&main_image)->e_ident[EI_CLASS]=ELFCLASS32);
    BAD("type",eh(&main_image)->e_type=ET_REL);
    BAD("machine",eh(&main_image)->e_machine=EM_386);
    BAD("version",eh(&main_image)->e_version=0);
    BAD("ehsize",eh(&main_image)->e_ehsize=0);
    BAD("phsize",eh(&main_image)->e_phentsize=0);
    BAD("phzero",eh(&main_image)->e_phnum=0);
    BAD("phbound",eh(&main_image)->e_phnum=33);
    BAD("phtable extent",eh(&main_image)->e_phoff=4090);
    BAD("actual ph pointer",main_image.image.ph=ph(&main_image)+1);
    BAD("actual ph population",main_image.image.n=3);
    BAD("actual entry",main_image.image.entry++);
    BAD("bias overflow",main_image.image.bias=UINTPTR_MAX);
    BAD("segment file offset",ph(&main_image)[3].p_offset=4097);
    BAD("segment file extent",ph(&main_image)[3].p_filesz=4097);
    BAD("segment mem extent",ph(&main_image)[0].p_memsz--);
    BAD("segment virtual wrap",ph(&main_image)[0].p_vaddr=UINT64_MAX);
    BAD("no dynamic",ph(&main_image)[1].p_type=PT_NULL);
    BAD("two dynamic",ph(&main_image)[3]=ph(&main_image)[1]);
    BAD("empty dynamic",ph(&main_image)[1].p_filesz=0);
    BAD("fractional dynamic",ph(&main_image)[1].p_filesz--);
    BAD("dynamic unowned",ph(&main_image)[1].p_vaddr+=8192);
    BAD("dynamic offset alias",ph(&main_image)[1].p_offset++);
    BAD("dynamic ambiguous owner",ph(&main_image)[3]=ph(&main_image)[0]);
    BAD("dynamic unterminated",for(unsigned i=2;i<8;i++)dyn(&main_image)[i].d_tag=DT_DEBUG);
    BAD("missing strtab",dyn(&main_image)[0].d_tag=DT_DEBUG);
    BAD("missing strsz",dyn(&main_image)[1].d_tag=DT_DEBUG);
    BAD("duplicate strtab",dyn(&main_image)[2]=dyn(&main_image)[0]);
    BAD("duplicate strsz",dyn(&main_image)[2]=dyn(&main_image)[1]);
    BAD("empty strsz",dyn(&main_image)[1].d_un.d_val=0);
    BAD("strsz limit",dyn(&main_image)[1].d_un.d_val=16U*1024U*1024U+1);
    BAD("strtab unowned",dyn(&main_image)[0].d_un.d_ptr=0x800000);
    BAD("strtab crosses load",dyn(&main_image)[0].d_un.d_ptr=0x400fff);
    BAD("strtab ambiguous owner",ph(&main_image)[3]=(Elf64_Phdr){.p_type=PT_LOAD,.p_offset=1024,.p_vaddr=0x400400,.p_filesz=512,.p_memsz=512});
    BAD("SONAME bound",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=512});
    BAD("SONAME empty",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=0});
    BAD("SONAME duplicate",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};dyn(&main_image)[3]=dyn(&main_image)[2]);
    BAD("SONAME slash",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};main_image.source[1025]='/');
    BAD("SONAME dot",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};memcpy(main_image.source+1025,".\0",2));
    BAD("SONAME dotdot",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};memcpy(main_image.source+1025,"..\0",3));
    BAD("SONAME high byte",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};main_image.source[1025]=128);
    BAD("SONAME unterminated",dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=DT_SONAME,.d_un.d_val=1};memset(main_image.source+1025,'a',511));
    BAD("no interpreter",ph(&main_image)[2].p_type=PT_NULL);
    BAD("two interpreters",ph(&main_image)[3]=ph(&main_image)[2]);
    BAD("relative interpreter",main_image.source[2048]='a');
    BAD("interpreter missing nul",main_image.source[2048+23]='x');
    BAD("interpreter embedded nul",main_image.source[2049]=0);
    static const long forbidden[]={DT_NEEDED,DT_RPATH,DT_RUNPATH,DT_AUDIT,DT_DEPAUDIT,DT_FILTER,DT_AUXILIARY};
    for(unsigned k=IMAGE_MAIN;k<=IMAGE_INTERPRETER;k++)for(size_t i=0;i<sizeof forbidden/sizeof forbidden[0];i++){
        seed(&main_image,k);dyn(&main_image)[2]=(Elf64_Dyn){.d_tag=forbidden[i],.d_un.d_val=1};
        image_case(&main_image,k,0,"actual dependency/search/filter/audit tag");
    }
    seed(&interp_image,IMAGE_INTERPRETER);eh(&interp_image)->e_type=ET_EXEC;
    image_case(&interp_image,IMAGE_INTERPRETER,0,"interpreter must be DYN");
    seed(&interp_image,IMAGE_INTERPRETER);ph(&interp_image)[2]=(Elf64_Phdr){.p_type=PT_INTERP,.p_filesz=2,.p_memsz=2};
    image_case(&interp_image,IMAGE_INTERPRETER,0,"interpreter cannot name another interpreter");
    seed(&main_image,IMAGE_MAIN);seed(&interp_image,IMAGE_INTERPRETER);
    ++pair_checks;require_case(empty_namespace_pair(&main_image.image,&interp_image.image),"both source proofs");
    dyn(&interp_image)[2].d_tag=DT_NEEDED;
    ++pair_checks;require_case(!empty_namespace_pair(&main_image.image,&interp_image.image),"interpreter dependency refuses pair");
    seed(&interp_image,IMAGE_INTERPRETER);dyn(&main_image)[2].d_tag=DT_NEEDED;
    ++pair_checks;require_case(!empty_namespace_pair(&main_image.image,&interp_image.image),"main dependency refuses pair");
    ++pair_checks;require_case(!empty_namespace_pair(&interp_image.image,&main_image.image),"swapped typed source identities");
}
static void parser_case(const char *a,const char *b,unsigned error,size_t count,int first,int last,const char *name) {
    environment[0]=a;environment[1]=b;environment[2]=0;
    static int fds[34];for(unsigned i=0;i<34;i++)fds[i]=-12345;
    error_code=0;error_detail=0;++parser_checks;
    if(!setjmp(escape)){
        size_t n=parse_fds(fds+1);require_case(!error && n==count,name);
        if(n)require_case(fds[1]==first && fds[n]==last,name);
        for(size_t i=n+1;i<34;i++)require_case(fds[i]==-12345,"unused FD output unchanged");
    }else require_case(error_code==error && error_detail==0,name);
    require_case(fds[0]==-12345 && fds[33]==-12345,"parser output guarded endpoints");
}
static void parser_cases(void) {
    parser_case(0,0,221,0,0,0,"missing key");
    parser_case("OTHER=1",0,221,0,0,0,"unrelated env");
    parser_case("LI2_DEPENDENCY_FDS=",0,0,0,0,0,"explicit empty");
    parser_case("LI2_DEPENDENCY_FDS=","LI2_DEPENDENCY_FDS=",220,0,0,0,"duplicate empty");
    parser_case("LI2_DEPENDENCY_FDS=7","LI2_DEPENDENCY_FDS=8",220,0,0,0,"duplicate nonempty");
    parser_case("LI2_DEPENDENCY_FDS=7",0,0,1,7,7,"one FD");
    parser_case("LI2_DEPENDENCY_FDS=0,17,29",0,0,3,0,29,"normal ordered FDs");
    parser_case("LI2_DEPENDENCY_FDS=-1",0,223,0,0,0,"negative FD");
    parser_case("LI2_DEPENDENCY_FDS=+1",0,223,0,0,0,"plus FD");
    parser_case("LI2_DEPENDENCY_FDS=a",0,223,0,0,0,"nondigit FD");
    parser_case("LI2_DEPENDENCY_FDS=1 2",0,223,0,0,0,"space FD");
    parser_case("LI2_DEPENDENCY_FDS=1000009",0,0,1,1000009,1000009,"exact old numeric upper accepted");
    parser_case("LI2_DEPENDENCY_FDS=1000010",0,223,0,0,0,"exact old next-digit overflow");
    parser_case("LI2_DEPENDENCY_FDS=,1",0,224,0,0,0,"empty first FD");
    parser_case("LI2_DEPENDENCY_FDS=1,,2",0,224,0,0,0,"empty middle FD");
    parser_case("LI2_DEPENDENCY_FDS=1,",0,225,0,0,0,"empty final FD");
    char text[128]="LI2_DEPENDENCY_FDS=";size_t at=strlen(text);
    for(unsigned i=0;i<32;i++){text[at++]='7';if(i!=31)text[at++]=',';}text[at]=0;
    parser_case(text,0,0,32,7,7,"exact32 FD bound");
    text[at++]=',';text[at++]='7';text[at]=0;parser_case(text,0,222,0,0,0,"33rd FD refuses before write");
}
static int protected_stub(uintptr_t a,size_t n,unsigned p){(void)a;(void)n;(void)p;return 1;}
static void caller_case(int empty,size_t n,int occupied,int valid,int protected,unsigned error,long detail,const char *name) {
    struct li2_lifecycle_hooks h={.fail=supplied_failure,.protected_mprotect=protected?protected_stub:0};
    int fds[32]={7};seed(&main_image,IMAGE_MAIN);seed(&interp_image,IMAGE_INTERPRETER);
    if(!valid)dyn(&interp_image)[2].d_tag=DT_NEEDED;
    active=(unsigned)occupied;common_calls=0;common_count=999;common_fds=fds;error_code=0;error_detail=0;++caller_checks;
    if(!setjmp(escape)){
        if(empty)li2_lifecycle_initialize_empty(&main_image.image,&interp_image.image,&h);
        else li2_lifecycle_initialize(fds,n,&h);
        require_case(!error && common_calls==1 && common_count==(empty?0:n) && common_fds==(empty?0:fds),name);
    }else require_case(error_code==error && error_detail==detail && !common_calls,name);
}
static void caller_cases(void) {
    caller_case(0,0,0,1,1,183,0,"old initializer still refuses zero");
    caller_case(0,1,0,1,1,0,0,"old nonempty initializer unchanged");
    caller_case(0,32,0,1,1,0,0,"old32 initializer unchanged");
    caller_case(0,33,0,1,1,183,33,"old33 initializer refusal");
    caller_case(0,1,1,1,1,183,1,"old active initializer refusal");
    caller_case(0,1,0,1,0,183,-1,"old protected hook refusal");
    caller_case(1,0,0,1,1,0,0,"new proof-bound zero initialization");
    caller_case(1,0,0,0,1,183,-2,"new nonempty proof refuses");
    caller_case(1,0,1,1,1,183,-2,"new active initializer refuses");
    caller_case(1,0,0,1,0,183,-1,"new protected hook refusal");
}
int main(void) {
    source_cases();parser_cases();caller_cases();
    require_case(image_checks==74 && pair_checks==4 && parser_checks==18 && caller_checks==10,"all exact source case populations");
    printf("empty-namespace images=%u pairs=%u parser=%u callers=%u synthetic_initialization=1 native_credit=0\n",image_checks,pair_checks,parser_checks,caller_checks);
    return 0;
}
