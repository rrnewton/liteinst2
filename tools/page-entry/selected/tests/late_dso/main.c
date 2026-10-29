#define _GNU_SOURCE
#include "late.h"
#include <asm/prctl.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern const ptrdiff_t __rseq_offset __attribute__((weak));
extern const unsigned int __rseq_size __attribute__((weak));
extern const unsigned int __rseq_flags __attribute__((weak));
struct ld_inventory {
    uint64_t objects, matches[2], base[2], phnum[2], adds, subs;
};
struct ld_effect {
    uint64_t row[12], before[17], after[17];
    unsigned char before_live[PA_LIVE], after_live[PA_LIVE];
};
struct ld_cycle {
    struct ld_inventory inventory[3];
    struct pa_image images[2];
    unsigned char before[2][PA_PAGE], after[2][PA_PAGE];
    struct ld_effect effects[6];
};
struct ld_record {
    uint64_t head[16], permission[2];
    uint32_t hardware[67][6];
    uint64_t machine[2][8], rseq[2][9], notes[6][4];
    struct ld_cycle cycles[LD_CYCLES];
    uint64_t end[8];
};
_Static_assert(sizeof(uintptr_t)==8 && sizeof(struct pa_image)==88, "Linux x86-64 wire");
_Static_assert(sizeof(struct ld_record)==91032 && sizeof(struct ld_record)<16U*1024U*1024U,
               "fixed record within original capture bound");
static struct ld_record record;
static uint32_t hardware[67][6];
static unsigned cycle_now, phase, note_count, note_error;
#include "profile.inc"

void li2_late_note(unsigned kind, uint64_t value) {
    /* Called by actual ELF constructors, the exported function, and destructor.
       Observed events are not loader or admission authority. */
    if(note_count>=6 || kind!=phase || kind!=note_count%3+1 ||
       cycle_now!=note_count/3 || value!=LD_LEAF_MAGIC+kind) {
        note_error=1;return;
    }
    uint64_t *n=record.notes[note_count++];n[0]=cycle_now;n[1]=kind;n[2]=value;n[3]=0;
}
static int failure(const char *stage,unsigned code) {
    fprintf(stderr,"LATE_DSO_FAILED %s %u\n",stage,code);return 99;
}
static int inventory_callback(struct dl_phdr_info *info,size_t bytes,void *argument) {
    struct ld_inventory *out=argument;
    if(bytes<offsetof(struct dl_phdr_info,dlpi_subs)+sizeof info->dlpi_subs || !info->dlpi_name)return 1;
    if(out->objects && (out->adds!=info->dlpi_adds || out->subs!=info->dlpi_subs))return 1;
    out->objects++;out->adds=info->dlpi_adds;out->subs=info->dlpi_subs;
    const char *name=info->dlpi_name;
    for(const char *p=name;*p;p++)if(*p=='/')name=p+1;
    for(unsigned i=0;i<2;i++)if(!strcmp(name,i?LD_LEAF:LD_SONAME)) {
        if(!info->dlpi_phnum || info->dlpi_phnum>32)return 1;
        out->matches[i]++;out->base[i]=info->dlpi_addr;out->phnum[i]=info->dlpi_phnum;
    }
    return 0;
}
static int inventory(struct ld_inventory *out,unsigned wanted) {
    if(dl_iterate_phdr(inventory_callback,out) || !out->objects ||
       out->matches[0]!=wanted || out->matches[1]!=wanted)return 1;
    return wanted && (!out->base[0] || !out->base[1] || out->base[0]==out->base[1]);
}
static void retain_effect(struct ld_effect *out,const struct pa_view *v,unsigned iteration,unsigned index) {
    out->row[0]=v->module;out->row[1]=v->kind;out->row[2]=iteration;
    out->row[3]=(uint64_t)iteration*6+index;out->row[4]=v->site;out->row[5]=v->next;
    out->row[6]=v->endpoint;out->row[7]=v->stack;out->row[8]=v->mask;out->row[9]=v->extent;
    for(unsigned i=0;i<5;i++)out->row[10]|=(uint64_t)v->restored[i]<<(8*i);
    memcpy(out->before,v->before,sizeof out->before);memcpy(out->after,v->after,sizeof out->after);
    memcpy(out->before_live,v->before_live,PA_LIVE);memcpy(out->after_live,v->after_live,PA_LIVE);
}
static int output(const void *p,size_t n) {
    const unsigned char *b=p;
    while(n) {
        ssize_t done=write(STDOUT_FILENO,b,n);
        if(done<0 && errno==EINTR)continue;
        if(done<=0)return 1;
        b+=(size_t)done;n-=(size_t)done;
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"native") && strcmp(argv[1],"scripted")))return failure("arguments",1);
    unsigned scripted=!strcmp(argv[1],"scripted"),cpu=0,node=0;
    uint64_t *h=record.head;h[0]=LD_MAGIC;h[1]=1;h[2]=scripted;h[3]=LD_CYCLES;h[4]=12;
    h[5]=(uint64_t)getpid();h[6]=(uint64_t)syscall(SYS_gettid);
    if(!h[5] || h[5]!=h[6] || syscall(SYS_getcpu,&cpu,&node,0))return failure("single_thread_cpu",2);
    h[7]=cpu;h[8]=node;
    unsigned error=(unsigned)format(&h[9],&h[10],record.permission);
    if(error)return failure("format",error);
    memcpy(record.hardware,hardware,sizeof hardware);
    if(machine(record.machine[0]) || registration(record.rseq[0],cpu))return failure("default_rseq",3);
    if(pa_main_setup(h[9],h[10]))return failure("main_setup",4);
    for(cycle_now=0;cycle_now<LD_CYCLES;cycle_now++) {
        struct ld_cycle *c=&record.cycles[cycle_now];
        if(inventory(&c->inventory[0],0))return failure("before_load_absence",cycle_now);
        phase=1;void *handle=dlopen(LD_SONAME,RTLD_NOW|RTLD_LOCAL);
        if(!handle || note_error || note_count!=cycle_now*3+1)return failure("dlopen_constructor",cycle_now);
        if(inventory(&c->inventory[1],1) || c->inventory[1].objects!=c->inventory[0].objects+2 ||
           c->inventory[1].adds!=c->inventory[0].adds+2 || c->inventory[1].subs!=c->inventory[0].subs)
            return failure("loaded_inventory",cycle_now);
        dlerror();
        const struct ld_api *(*get_api)(void)=(const struct ld_api *(*)(void))dlsym(handle,"li2_late_api");
        if(dlerror() || !get_api)return failure("dlsym",cycle_now);
        phase=2;const struct ld_api *api=get_api();
        if(note_error || note_count!=cycle_now*3+2 || !api || api->version!=1 ||
           !api->setup || !api->step || !api->image || !api->final || api->setup(h[9],h[10]))
            return failure("late_function_setup",cycle_now);
        pa_main_image(c->images);api->image(c->images+1);
        struct image_join join={.images=c->images};
        if(c->images[0].module!=0 || c->images[1].module!=1 ||
           dl_iterate_phdr(image_callback,&join) || join.matches[0]!=1 || join.matches[1]!=1 ||
           join.base[0]==join.base[1] || join.base[1]!=c->inventory[1].base[0] ||
           join.phnum[1]!=c->inventory[1].phnum[0])return failure("observed_images",cycle_now);
        if(!cycle_now) { h[12]=join.base[0];h[13]=join.phnum[0]; }
        else if(h[12]!=join.base[0] || h[13]!=join.phnum[0])return failure("main_image_changed",cycle_now);
        for(unsigned m=0;m<2;m++)memcpy(c->before[m],(const void *)(uintptr_t)c->images[m].page,PA_PAGE);
        for(unsigned m=0;m<2;m++)for(unsigned k=0;k<PA_KINDS;k++) {
            struct pa_view v={0};
            error=m?(unsigned)api->step(k,cycle_now,(int)scripted,h[5],hardware[0]+2,&v):
                    (unsigned)pa_main_step(k,cycle_now,(int)scripted,h[5],hardware[0]+2,&v);
            if(error)return failure("effect",cycle_now*10000+m*1000+k*100+error);
            retain_effect(c->effects+3*m+k,&v,cycle_now,3*m+k);
        }
        if(pa_main_final() || api->final())return failure("restored_source",cycle_now);
        for(unsigned m=0;m<2;m++) {
            memcpy(c->after[m],(const void *)(uintptr_t)c->images[m].page,PA_PAGE);
            if(memcmp(c->before[m],c->after[m],PA_PAGE))return failure("page_changed",cycle_now);
        }
        phase=3;
        if(dlclose(handle) || note_error || note_count!=cycle_now*3+3)return failure("dlclose_destructor",cycle_now);
        if(inventory(&c->inventory[2],0) || c->inventory[2].objects!=c->inventory[0].objects ||
           c->inventory[2].adds!=c->inventory[1].adds || c->inventory[2].subs!=c->inventory[1].subs+2)
            return failure("after_close_absence",cycle_now);
        /* No api/handle/source pointer is dereferenced after genuine dlclose. */
    }
    if(pa_main_final() || note_count!=6 || note_error || machine(record.machine[1]) ||
       memcmp(record.machine[0],record.machine[1],sizeof record.machine[0]) ||
       syscall(SYS_getcpu,&cpu,&node,0) || cpu!=h[7] || node!=h[8] ||
       registration(record.rseq[1],cpu) || memcmp(record.rseq[0],record.rseq[1],sizeof record.rseq[0]))
        return failure("terminal_identity",5);
    h[11]=note_count;h[14]=sizeof record;
    record.end[0]=LD_MAGIC^1;record.end[1]=1;record.end[2]=LD_CYCLES;record.end[3]=12;record.end[4]=6;
    return output(&record,sizeof record)?failure("output",6):0;
}
