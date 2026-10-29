/* Fixture-only trusted bootstrap. Included after protect/checked are defined.
   No application address, environment policy, or observed load bias grants
   policy authority. The main's reconstructed header view is already trusted
   by bridge; its complete nonzero-offset site page is joined to the carrier. */
#include "app.h"
#include "policy.h"
#include "../../selected_source_identity.h"
#ifndef PA_POLICY_SCRIPTED
#error "explicit fixture policy required"
#endif
#ifndef PA_WORKLOAD_ROUNDS
#error "explicit fixture workload required"
#endif
#if (PA_POLICY_SCRIPTED != 0 && PA_POLICY_SCRIPTED != 1) || (PA_WORKLOAD_ROUNDS != 3 && PA_WORKLOAD_ROUNDS != 1536)
#error "fixed fixture modes only"
#endif
#define PAB_FILE (1U<<20)
struct pab_module {
    struct li2_effect_object_binding binding;
    uint64_t original_bytes,page_vaddr,page_offset,helper_vaddr,stack_vaddr;
    uint64_t capture_before,capture_after,seed_x87,sites[3],next[3];
    unsigned char original_page[PA_PAGE];
};
struct pab_state {
    uint64_t started,complete,main_original_bytes,main_carrier_bytes;
    unsigned char main_source_hash[32];
    struct pab_module modules[2];
};
static struct pab_state pab_state;
static struct pa_policy_context pa_policy_context;
const struct li2_effect_binding li2_effect_runtime_binding={
    LI2_EFFECT_ABI,0,pa_policy_callback,0,&pa_policy_context};
static unsigned char pab_file[PAB_FILE] __attribute__((aligned(64)));
static unsigned char pab_page[PA_PAGE] __attribute__((aligned(64)));
static struct li2_effect_object_binding pab_candidate;
static void pab_need(int ok,unsigned detail) { checked(ok,1780,(long)detail); }
static int pab_range(size_t total,uint64_t first,uint64_t count) {
    return first<=total && count<=total-first;
}
static void pab_pread(int fd,void *out,size_t n,uint64_t offset) {
    pab_need(offset<=INT64_MAX && n<=INT64_MAX-offset,1);
    size_t used=0;
    while(used<n) {
        long got=raw(SYS_pread64,fd,(long)((unsigned char *)out+used),n-used,offset+used,0,0);
        pab_need(got>0 && (uint64_t)got<=n-used,2);used+=(size_t)got;
    }
}
static int pab_string(const unsigned char *p,size_t n,uint64_t at,const char *want) {
    if(at>=n)return 0;
    size_t i=0;
    while(want[i]) {if(i>=n-at || p[at+i]!=(unsigned char)want[i])return 0;i++;}
    return i<n-at && !p[at+i];
}
static void pab_header(const unsigned char *p,size_t n,Elf64_Ehdr *e) {
    pab_need(n>=sizeof(*e),3);copy(e,p,sizeof(*e));
    const unsigned char ident[7]={127,'E','L','F',ELFCLASS64,ELFDATA2LSB,EV_CURRENT};
    pab_need(equal(e->e_ident,ident,sizeof ident) && e->e_type==ET_DYN &&
        e->e_machine==EM_X86_64 && e->e_version==EV_CURRENT && e->e_ehsize==sizeof(*e) &&
        e->e_phentsize==sizeof(Elf64_Phdr) && e->e_phnum && e->e_phnum<=32 &&
        pab_range(n,e->e_phoff,(uint64_t)e->e_phnum*sizeof(Elf64_Phdr)),4);
}
static void pab_ph(const unsigned char *p,const Elf64_Ehdr *e,unsigned i,Elf64_Phdr *h) {
    copy(h,p+e->e_phoff+(size_t)i*sizeof(*h),sizeof(*h));
}
static uint64_t pab_file_offset(const unsigned char *p,size_t n,const Elf64_Ehdr *e,
                              uint64_t va,size_t bytes,unsigned flags,int file) {
    unsigned found=0;uint64_t result=0;
    for(unsigned i=0;i<e->e_phnum;i++) {
        Elf64_Phdr h;pab_ph(p,e,i,&h);if(h.p_type!=PT_LOAD)continue;
        pab_need(h.p_filesz<=h.p_memsz && h.p_vaddr<=UINT64_MAX-h.p_memsz && pab_range(n,h.p_offset,h.p_filesz),5);
        if(va<h.p_vaddr || va-h.p_vaddr>h.p_memsz || bytes>h.p_memsz-(va-h.p_vaddr))continue;
        pab_need(h.p_flags==flags && ++found==1,6);
        uint64_t delta=va-h.p_vaddr;
        if(file)pab_need(delta<=h.p_filesz && bytes<=h.p_filesz-delta,7);
        pab_need(h.p_offset<=UINT64_MAX-delta,8);result=h.p_offset+delta;
    }
    pab_need(found==1,9);return result;
}
static int pab_soname(const unsigned char *p,size_t n) {
    Elf64_Ehdr e;pab_header(p,n,&e);Elf64_Phdr dynamic={0};unsigned count=0;
    for(unsigned i=0;i<e.e_phnum;i++) {Elf64_Phdr h;pab_ph(p,&e,i,&h);
        if(h.p_type==PT_DYNAMIC) {dynamic=h;count++;}}
    pab_need(count==1 && dynamic.p_filesz && dynamic.p_filesz%sizeof(Elf64_Dyn)==0 &&
        dynamic.p_filesz/sizeof(Elf64_Dyn)<=256 && pab_range(n,dynamic.p_offset,dynamic.p_filesz),10);
    uint64_t strings=0,size=0,name=0;unsigned ns=0,nz=0,nn=0,ended=0;
    for(uint64_t at=0;at<dynamic.p_filesz;at+=sizeof(Elf64_Dyn)) {
        Elf64_Dyn d;copy(&d,p+dynamic.p_offset+at,sizeof d);
        if(d.d_tag==DT_NULL) {ended=1;break;}
        if(d.d_tag==DT_STRTAB) {strings=d.d_un.d_ptr;ns++;}
        if(d.d_tag==DT_STRSZ) {size=d.d_un.d_val;nz++;}
        if(d.d_tag==DT_SONAME) {name=d.d_un.d_val;nn++;}
    }
    pab_need(ended && ns==1 && nz==1 && size && size<=PAB_FILE && nn<=1,11);
    if(!nn)return 0;
    /* Dynamic strings may be in R or RX PT_LOAD. They confer only a unique
       fixture selection; actual source authority is the sealed binding. */
    unsigned found=0;uint64_t offset=0;
    for(unsigned i=0;i<e.e_phnum;i++) {Elf64_Phdr h;pab_ph(p,&e,i,&h);
        if(h.p_type!=PT_LOAD || strings<h.p_vaddr || strings-h.p_vaddr>h.p_filesz)continue;
        uint64_t delta=strings-h.p_vaddr;if(size>h.p_filesz-delta)continue;
        pab_need((h.p_flags&PF_R) && !(h.p_flags&PF_W) && ++found==1 &&
            h.p_offset<=UINT64_MAX-delta && pab_range(n,h.p_offset+delta,size),12);
        offset=h.p_offset+delta;
    }
    pab_need(found==1,13);return pab_string(p+offset,(size_t)size,name,"libli2-provider-app.so");
}
static uint64_t pab_symbol(const unsigned char *p,size_t n,const Elf64_Ehdr *e,const char *name) {
    pab_need(e->e_shentsize==sizeof(Elf64_Shdr) && e->e_shnum && e->e_shnum<=256 &&
        pab_range(n,e->e_shoff,(uint64_t)e->e_shnum*sizeof(Elf64_Shdr)),14);
    unsigned tables=0,found=0;uint64_t value=0;
    for(unsigned i=0;i<e->e_shnum;i++) {
        Elf64_Shdr s;copy(&s,p+e->e_shoff+(size_t)i*sizeof s,sizeof s);if(s.sh_type!=SHT_SYMTAB)continue;
        pab_need(++tables==1 && s.sh_link<e->e_shnum && s.sh_entsize==sizeof(Elf64_Sym) &&
            s.sh_size%sizeof(Elf64_Sym)==0 && s.sh_size/sizeof(Elf64_Sym)<=8192 &&
            pab_range(n,s.sh_offset,s.sh_size),15);
        Elf64_Shdr names;copy(&names,p+e->e_shoff+(size_t)s.sh_link*sizeof names,sizeof names);
        pab_need(names.sh_type==SHT_STRTAB && pab_range(n,names.sh_offset,names.sh_size),16);
        for(uint64_t at=0;at<s.sh_size;at+=sizeof(Elf64_Sym)) {
            Elf64_Sym sym;copy(&sym,p+s.sh_offset+at,sizeof sym);
            if(!pab_string(p+names.sh_offset,(size_t)names.sh_size,sym.st_name,name))continue;
            pab_need(++found==1 && sym.st_shndx!=SHN_UNDEF && sym.st_shndx<e->e_shnum,17);value=sym.st_value;
        }
    }
    pab_need(tables==1 && found==1,18);return value;
}
static void pab_image(unsigned module,const unsigned char *p,size_t n,struct pab_module *out) {
    static const char *const names[2][13]={
        {"pa_main_page","pa_main_page_end","pa_main_helper_page","pa_main_helper_end",
         "stack","pa_main_capture_before","pa_main_capture_after","pa_main_seed_x87",
         "pa_main_cpuid","pa_main_getpid","pa_main_rdtsc","pa_main_cpuid_next","pa_main_getpid_next"},
        {"pa_dso_page","pa_dso_page_end","pa_dso_helper_page","pa_dso_helper_end",
         "stack","pa_dso_capture_before","pa_dso_capture_after","pa_dso_seed_x87",
         "pa_dso_cpuid","pa_dso_getpid","pa_dso_rdtsc","pa_dso_cpuid_next","pa_dso_getpid_next"}};
    Elf64_Ehdr e;pab_header(p,n,&e);uint64_t v[14];
    for(unsigned i=0;i<13;i++)v[i]=pab_symbol(p,n,&e,names[module][i]);
    v[13]=pab_symbol(p,n,&e,module?"pa_dso_rdtsc_next":"pa_main_rdtsc_next");
    pab_need(!(v[0]&4095) && v[0]<=UINT64_MAX-4096 && v[1]==v[0]+4096 &&
        !(v[2]&4095) && v[2]<=UINT64_MAX-4096 && v[3]==v[2]+4096 && v[0]!=v[2] &&
        v[5]>=v[2] && v[5]<v[3] && v[6]>v[5] && v[6]<v[3] && v[7]>=v[2] && v[7]<v[5],19);
    out->original_bytes=n;out->page_vaddr=v[0];out->helper_vaddr=v[2];out->stack_vaddr=v[4];
    out->capture_before=v[5];out->capture_after=v[6];out->seed_x87=v[7];
    pab_need(v[4]<=UINT64_MAX-PA_STACK,19);
    out->page_offset=pab_file_offset(p,n,&e,v[0],4096,PF_R|PF_X,1);
    pab_need(out->page_offset && !(out->page_offset&4095),20);
    (void)pab_file_offset(p,n,&e,v[2],4096,PF_R|PF_X,1);
    (void)pab_file_offset(p,n,&e,v[4],PA_STACK,PF_R|PF_W,0);
    copy(out->original_page,p+out->page_offset,4096);
    const unsigned char suffix[3]={0xa2,0x05,0x31};
    for(unsigned i=0;i<3;i++) {
        uint64_t delta=128+32*i;out->sites[i]=v[8+i];out->next[i]=v[11+i];
        pab_need(v[8+i]==v[0]+delta && v[11+i]==v[8+i]+2 &&
            out->original_page[delta]==15 && out->original_page[delta+1]==suffix[i] &&
            out->original_page[delta+2]==144 && out->original_page[delta+3]==144 &&
            out->original_page[delta+4]==144 && out->original_page[delta+5]==0xe9,21);
        int32_t displacement;copy(&displacement,out->original_page+delta+6,4);
        pab_need(v[8+i]<=INT64_MAX-INT32_MAX-10,22);
        int64_t target=(int64_t)(v[8+i]+10)+(int64_t)displacement;
        pab_need(target>=0 && (uint64_t)target==v[6],22);
    }
}
static void pab_initialize(const struct image *main,const int *fds,size_t count) {
    pab_need(!pab_state.started && count<=32 && main && main->source &&
        main->source_size<=PAB_FILE && main->kind==IMAGE_MAIN,23);pab_state.started=1;
    int e=li2_lifecycle_bind_sealed_object(main->backing_fd,&pab_state.modules[0].binding);pab_need(!e,24);
    pab_state.main_original_bytes=main->source_size;
    pab_state.main_carrier_bytes=(uint64_t)pab_state.modules[0].binding.actual.stat.st_size;
    copy(pab_state.main_source_hash,main->source_hash,32);
    pab_image(0,main->source,main->source_size,&pab_state.modules[0]);
    pab_pread(main->backing_fd,pab_page,4096,pab_state.modules[0].page_offset);
    pab_need(equal(pab_page,pab_state.modules[0].original_page,4096),25);
    unsigned found=0;
    for(size_t i=0;i<count;i++) {
        e=li2_lifecycle_bind_sealed_object(fds[i],&pab_candidate);pab_need(!e,26);
        int64_t bytes=pab_candidate.actual.stat.st_size;
        if(bytes<(int64_t)sizeof(Elf64_Ehdr) || bytes>PAB_FILE)continue;
        pab_pread(fds[i],pab_file,(size_t)bytes,0);
        if(!pab_soname(pab_file,(size_t)bytes))continue;
        pab_need(++found==1 && pab_candidate.object_id!=pab_state.modules[0].binding.object_id,27);
        copy(&pab_state.modules[1].binding,&pab_candidate,sizeof pab_candidate);
        pab_image(1,pab_file,(size_t)bytes,&pab_state.modules[1]);
    }
    pab_need(found==1,28);
    struct pa_policy_site *rows=memory(PAGE,PROT_READ|PROT_WRITE);protect((uintptr_t)rows,PAGE);
    const unsigned kinds[3]={LI2_CPUID,LI2_SYSCALL,LI2_RDTSC};
    for(unsigned m=0;m<2;m++)for(unsigned i=0;i<3;i++) {
        const struct pab_module *mdata=&pab_state.modules[m];
        rows[m*3+i]=(struct pa_policy_site){mdata->binding.object_id,mdata->page_offset+128+32*i,kinds[i],0};
    }
    pab_need(!raw(SYS_mprotect,(long)rows,PAGE,PROT_READ,0,0,0),29);
    pa_policy_context=(struct pa_policy_context){.sites=rows,.count=6,.scripted=PA_POLICY_SCRIPTED,.rounds=PA_WORKLOAD_ROUNDS};
    __asm__ volatile("":::"memory");pab_state.complete=1;
}
