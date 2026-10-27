#define _GNU_SOURCE
#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <asm/prctl.h>
#include <linux/prctl.h>
#define PAGE 4096UL
#define MAX_FILE (16UL*1024*1024)
#define MAX_PHDR 32
extern long li2_raw6(long,long,long,long,long,long,long);
extern void li2_restorer(void);
extern char li2_gateway_start[],li2_gateway_end[];
long raw(long,long,long,long,long,long,long);
__attribute__((noreturn)) void li2_fail(const char *);
void require(int,const char *);
void *memory(size_t,int);
int equal(const void *,const void *,size_t);
void copy(void *,const void *,size_t);
enum image_kind { IMAGE_MAIN=1, IMAGE_INTERPRETER=2, IMAGE_BRIDGE=3 };
/* The main fd owns the actual NX carrier, while source is the authenticated
   reconstructed original. Interpreter fd/source describe the same sealed
   original bytes. Both descriptors and readonly source buffers remain owned
   through process exit. These headers are descriptive, not native permits. */
struct image {
    uintptr_t bias,entry;
    const Elf64_Phdr *ph;
    size_t n;
    const unsigned char *source;
    size_t source_size;
    int backing_fd;
    unsigned kind;
    unsigned char source_hash[32];
};
const char *const *bridge_environment(void);
/* Actual bridge mappings only: source=NULL and backing_fd=-1 are explicit. */
const struct image *bridge_runtime_image(void);
void runtime_arm(const struct image *,const struct image *,size_t);
