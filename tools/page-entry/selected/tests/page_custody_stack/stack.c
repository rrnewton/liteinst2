/* Actual application observations, outside the measured/retained interval.
   The parser alone occupies a separate page; no synthetic maps or target. */
#include <stdint.h>
#include <stddef.h>
#include "record.h"
#define QUERY __attribute__((section(".text.stack_query"),noinline))
#define PARSE __attribute__((section(".text.stack_parse"),noinline))
struct pcs_stack_proof pcs_stack;
unsigned char pcs_setup_stack[16384] __attribute__((aligned(16)));
struct row { uint64_t first,end,offset,major,minor,inode,prot; };
static inline long raw(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;__asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static PARSE void pcs_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static PARSE int number(const unsigned char **at,const unsigned char *end,unsigned base,uint64_t *out) {
 const unsigned char *p=*at;uint64_t n=0;unsigned count=0;
 while(p<end) {
  unsigned c=*p,v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:base;
  if(v>=base)break;
  if(n>(UINT64_MAX-v)/base)return 0;
  n=n*base+v;++p;++count;
 }
 if(!count)return 0;
 *at=p;*out=n;return 1;
}
static PARSE int separator(const unsigned char **at,const unsigned char *end,unsigned char c) {
 if(*at==end || **at!=c)return 0;
 ++*at;return 1;
}
static PARSE uint64_t permissions(const unsigned char *p) {
 return (p[0]=='r')|((p[1]=='w')<<1)|((p[2]=='x')<<2)|((p[3]=='p')<<3);
}
static PARSE int parse(const struct pcs_maps *m,uintptr_t entry,struct row *stack,
                       struct row *body,uint64_t *previous) {
 const unsigned char *p=m->raw,*end=p+m->h[5];uint64_t last=0;unsigned stacks=0,bodies=0;
 while(p<end) {
  struct row r={0};
  if(!number(&p,end,16,&r.first)||!separator(&p,end,'-')||!number(&p,end,16,&r.end)||
     !separator(&p,end,' ')||r.first>=r.end||r.first<last||((r.first|r.end)&4095)||end-p<5)return 0;
  if((p[0]!='r'&&p[0]!='-')||(p[1]!='w'&&p[1]!='-')||(p[2]!='x'&&p[2]!='-')||(p[3]!='p'&&p[3]!='s')||p[4]!=' ')return 0;
  r.prot=permissions(p);p+=5;
  if(!number(&p,end,16,&r.offset)||!separator(&p,end,' ')||!number(&p,end,16,&r.major)||
     !separator(&p,end,':')||!number(&p,end,16,&r.minor)||!separator(&p,end,' ')||!number(&p,end,10,&r.inode))return 0;
  __asm__ volatile("nop");
  while(p<end&&*p==' ')++p;
  const unsigned char *name=p;while(p<end&&*p!='\n')++p;
  if(p==end)return 0;
  if(r.first<=entry&&entry<r.end) {
   static const unsigned char label[]="[stack]";
   if(p-name!=7||r.prot!=11||r.offset||r.major||r.minor||r.inode)return 0;
   for(unsigned i=0;i<7;i++)if(name[i]!=label[i])return 0;
   if(++stacks!=1)return 0;
   *stack=r;*previous=last;
  }
  if(r.first<=RN_BODY&&RN_BODY+4096<=r.end) {
   if(++bodies!=1||r.prot!=9||r.offset>UINT64_MAX-(RN_BODY-r.first))return 0;
   r.offset+=RN_BODY-r.first;*body=r;
  }
  last=r.end;++p;
 }
 return stacks==1&&bodies==1;
}
static QUERY int maps(struct pcs_maps *m) {
 m->h[0]=m->h[1]=1;
 long fd=raw(257,-100,(long)"/proc/self/maps",0x80000,0,0,0);
 m->h[2]=1;m->h[3]=(uint64_t)fd;
 if(fd<=3){m->h[10]=1;return 0;}
 int ok=0;
 while(m->h[4]<PCS_READS&&m->h[5]<PCS_MAP_BYTES) {
  size_t room=PCS_MAP_BYTES-m->h[5];if(room>4096)room=4096;
  long n=raw(0,fd,(long)(m->raw+m->h[5]),(long)room,0,0,0);
  m->reads[m->h[4]++]=n;
  if(n<0||(uint64_t)n>room)break;
  if(!n){m->h[6]=1;ok=1;break;}
  m->h[5]+=(uint64_t)n;
 }
 m->h[7]=1;m->h[9]=(uint64_t)raw(3,fd,0,0,0,0,0);m->h[8]=1;
 if(!ok||m->h[9]){m->h[10]=2;return 0;}
 return 1;
}
QUERY long pcs_stack_setup(void) {
 struct pcs_stack_proof *s=&pcs_stack;struct row stack={0},body={0};uint64_t previous=0;
 s->h[0]=PCS_MAGIC;s->h[1]=1;s->h[2]=sizeof *s;s->h[3]=rn_entry_rsp;
 s->h[4]=1;s->h[5]=(uint64_t)raw(302,0,3,0,(long)s->limit,0,0);s->h[6]=1;
 if(s->h[5]||!maps(&s->before)||!parse(&s->before,rn_entry_rsp,&stack,&body,&previous))return -1;
 if(stack.first<4096||stack.first-4096<previous||stack.first-4096-previous<2*1024*1024||
    stack.end-(stack.first-4096)>s->limit[0]||s->limit[0]>s->limit[1])return -2;
 s->h[7]=stack.first;s->h[8]=stack.end;s->h[9]=previous;s->h[10]=stack.first-4096;
 s->h[11]=s->h[10]+64;s->h[12]=body.major;s->h[13]=body.minor;s->h[14]=body.inode;s->h[15]=body.offset;
 long pid=raw(39,0,0,0,0,0,0);if(pid<=0)return -3;
 s->h[16]=(uint64_t)pid;rn_setup_pid=(uint64_t)pid;rn_stack_target=s->h[11];
 pcs_copy(s->adjacent_before,(const void *)(uintptr_t)s->h[7],4096);
 pcs_copy(s->code_before,(const void *)(uintptr_t)RN_BODY,4096);
 s->h[17]=1;return 0;
}
static PARSE int verify(const struct pcs_stack_proof *s) {
 const uint64_t marker=RN_DESCRIPTOR+1;
 for(size_t i=0;i<4096;i++) {
  unsigned char want=i>=64&&i<72?(unsigned char)(marker>>(8*(i-64))):0;
  if(s->grown[i]!=want||s->adjacent_before[i]!=s->adjacent_after[i]||s->code_before[i]!=s->code_after[i])return 0;
 }
 return 1;
}
QUERY long pcs_stack_finish(void) {
 struct pcs_stack_proof *s=&pcs_stack;struct row stack={0},body={0};uint64_t previous=0;
 if(s->h[17]!=1||s->h[18]||!maps(&s->after)||!parse(&s->after,rn_entry_rsp,&stack,&body,&previous))return -1;
 if(stack.first!=s->h[10]||stack.end!=s->h[8]||previous!=s->h[9]||body.major!=s->h[12]||
    body.minor!=s->h[13]||body.inode!=s->h[14]||body.offset!=s->h[15])return -2;
 pcs_copy(s->adjacent_after,(const void *)(uintptr_t)s->h[7],4096);
 pcs_copy(s->grown,(const void *)(uintptr_t)s->h[10],4096);
 pcs_copy(s->code_after,(const void *)(uintptr_t)RN_BODY,4096);
 if(!verify(s))return -3;
 s->h[18]=1;return 0;
}
QUERY long pcs_stack_write(void) {
 if(pcs_stack.h[17]!=1||pcs_stack.h[18]!=1||rn_query_result!=rn_setup_pid)return -1;
 size_t at=0;while(at<sizeof pcs_stack) {
  long n=raw(1,1,(long)((unsigned char *)&pcs_stack+at),sizeof pcs_stack-at,0,0,0);
  if(n<=0||(size_t)n>sizeof pcs_stack-at)return -2;
  at+=(size_t)n;
 }
 return 0;
}
