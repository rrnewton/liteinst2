#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <link.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(uintptr_t) == 8 && sizeof(long) == 8, "64-bit Linux ABI required");

/* Standalone original-code scalar control. No profiler objects or target warmup. */
#define RECORDS 2048U
#define FILE_CAP (16U * 1024U * 1024U)
#define MAP_CAP (1024U * 1024U)
#define OUTPUT_CAP (4U * 1024U * 1024U)
#define INPUT_CAP (12U + RECORDS * 65U)
struct input { unsigned char left[16], data[64], right[16]; size_t length; uint64_t fields; };
struct result { uint64_t left, csv, length, right; };
static struct input inputs[RECORDS], saved_inputs[RECORDS];
static struct result results[RECORDS];
static unsigned char frame[INPUT_CAP], file_image[FILE_CAP], maps_image[MAP_CAP];
static char output[OUTPUT_CAP];
static size_t used;
static uint64_t deadline;
static const uint64_t guard = UINT64_C(0x39a5c7e1b4628df0);
typedef uint64_t (*target_fn)(const unsigned char *, size_t);

static _Noreturn void fail(void) { _exit(1); }
static void require(bool condition) { if (!condition) fail(); }
static uint64_t now(void) {
    struct timespec ts;
    require(clock_gettime(CLOCK_MONOTONIC, &ts) == 0 && ts.tv_sec >= 0);
    require(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L);
    require((uint64_t)ts.tv_sec <= (UINT64_MAX - (uint64_t)ts.tv_nsec) / UINT64_C(1000000000));
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}
static void timely(void) { require(now() < deadline); }
static uint64_t number(const char *s) {
    require(*s && (*s != '0' || s[1] == '\0'));
    uint64_t n = 0;
    for (; *s; ++s) { require(*s >= '0' && *s <= '9'); unsigned digit = (unsigned)(*s - '0'); require(n <= (UINT64_MAX - digit) / 10); n = 10 * n + digit; }
    return n;
}
static size_t read_regular(int fd, unsigned char *data, size_t cap, struct stat *st) {
    require(fstat(fd, st) == 0 && S_ISREG(st->st_mode) && st->st_size >= 0 && (uint64_t)st->st_size <= cap);
    size_t length = (size_t)st->st_size, at = 0;
    while (at < length) { timely(); ssize_t n = pread(fd, data + at, length - at, (off_t)at); if (n < 0 && errno == EINTR) continue; require(n > 0); at += (size_t)n; }
    unsigned char extra; require(pread(fd, &extra, 1, (off_t)length) == 0);
    return length;
}
static void file_unchanged(int fd, const struct stat *original, size_t length) {
    struct stat st; require(fstat(fd, &st) == 0 && st.st_dev == original->st_dev && st.st_ino == original->st_ino && st.st_size == original->st_size);
    unsigned char scratch[4096]; size_t at = 0;
    while (at < length) { timely(); size_t count = length - at; if (count > sizeof scratch) count = sizeof scratch; ssize_t n = pread(fd, scratch, count, (off_t)at); if (n < 0 && errno == EINTR) continue; require(n == (ssize_t)count && memcmp(scratch, file_image + at, count) == 0); at += count; }
}
static void singleton(void) {
    require((pid_t)syscall(SYS_gettid) == getpid());
    DIR *directory = opendir("/proc/self/task"); require(directory != NULL);
    unsigned count = 0; struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        require(number(entry->d_name) == (uint64_t)getpid()); ++count;
    }
    require(errno == 0 && count == 1 && closedir(directory) == 0);
}
static void pin(unsigned cpu) {
    cpu_set_t before, selected, after;
    require(cpu < CPU_SETSIZE && sched_getaffinity(0, sizeof before, &before) == 0 && CPU_ISSET(cpu, &before));
    CPU_ZERO(&selected); CPU_SET(cpu, &selected);
    require(sched_setaffinity(0, sizeof selected, &selected) == 0 && sched_getaffinity(0, sizeof after, &after) == 0);
    require(CPU_COUNT(&after) == 1 && CPU_ISSET(cpu, &after));
}
static void pinned(unsigned cpu) {
    cpu_set_t set; require(sched_getaffinity(0, sizeof set, &set) == 0 && CPU_COUNT(&set) == 1 && CPU_ISSET(cpu, &set));
}
struct mapping { uintptr_t begin, end; uint64_t offset, inode; unsigned major, minor; };
static struct mapping mapping(uintptr_t address, size_t extent) {
    require(address <= UINTPTR_MAX - extent);
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC); require(fd >= 0);
    size_t at = 0;
    for (;;) { timely(); require(at < sizeof maps_image - 1); ssize_t n = read(fd, maps_image + at, sizeof maps_image - 1 - at); if (n < 0 && errno == EINTR) continue; require(n >= 0); if (n == 0) break; at += (size_t)n; }
    require(close(fd) == 0); maps_image[at] = 0;
    struct mapping found = {0}; unsigned count = 0; char *cursor = (char *)maps_image;
    while (*cursor) {
        char *end = strchr(cursor, '\n'); require(end != NULL); *end = 0;
        unsigned long begin, limit, offset, inode; unsigned maj, min; char perms[5];
        require(sscanf(cursor, "%lx-%lx %4s %lx %x:%x %lu", &begin, &limit, perms, &offset, &maj, &min, &inode) == 7);
        if (begin <= address && address + extent <= limit) {
            require(strcmp(perms, "r-xp") == 0 && inode != 0);
            found = (struct mapping){begin, limit, offset, inode, maj, min}; ++count;
        }
        cursor = end + 1;
    }
    require(count == 1); return found;
}
static void same_map(struct mapping a, struct mapping b) {
    require(a.begin == b.begin && a.end == b.end && a.offset == b.offset && a.inode == b.inode && a.major == b.major && a.minor == b.minor);
}
static uint64_t fields(const unsigned char *data, size_t length) {
    uint64_t count = 1; size_t at = 0;
    while (at < length) {
        if (data[at] == '"') {
            ++at; bool closed = false;
            while (at < length) {
                if (data[at++] != '"') continue;
                if (at < length && data[at] == '"') { ++at; continue; }
                closed = true; break;
            }
            require(closed && (at == length || data[at] == ','));
        } else {
            while (at < length && data[at] != ',') { require(data[at] != '"'); ++at; }
        }
        if (at < length) { require(data[at++] == ','); ++count; }
    }
    return count;
}
static uint64_t checksum(const unsigned char *data, size_t length) {
    uint64_t value = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) value = (value ^ data[i]) * UINT64_C(1099511628211);
    return value;
}
__attribute__((noinline, visibility("default")))
void liteinst_csv_call_and_store(target_fn target, const unsigned char *data, size_t length, volatile uint64_t *out) {
    *out = target(data, length);
}
static void text(const char *s) {
    size_t n = strlen(s); require(n <= sizeof output - used); memcpy(output + used, s, n); used += n;
}
static void decimal(uint64_t n) {
    char buffer[20]; size_t count = 0;
    do { buffer[count++] = (char)('0' + n % 10); n /= 10; } while (n);
    require(count <= sizeof output - used);
    while (count) output[used++] = buffer[--count];
}
static void cell(uint64_t n) { text(","); decimal(n); }
static void write_output(void) {
    int flags = fcntl(STDOUT_FILENO, F_GETFL); require(flags >= 0 && fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) == 0);
    size_t at = 0;
    while (at < used) {
        timely(); size_t count = used - at; if (count > 8192) count = 8192;
        ssize_t n = write(STDOUT_FILENO, output + at, count);
        if (n > 0) { at += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        struct pollfd p = {STDOUT_FILENO, POLLOUT, 0}; int rc = poll(&p, 1, 1);
        require(rc >= 0 || errno == EINTR);
        if (rc > 0) require((p.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0);
    }
    timely();
}
int main(int argc, char **argv) {
    uint64_t start = now(); require(start <= UINT64_MAX - UINT64_C(15000000000)); deadline = start + UINT64_C(15000000000);
    require(argc == 8 && argv[1][0] == '/' && argv[6][0] == '/');
    uint64_t va[2] = {number(argv[2]), number(argv[4])};
    uint64_t size[2] = {number(argv[3]), number(argv[5])};
    uint64_t cpu_number = number(argv[7]); require(cpu_number < CPU_SETSIZE); unsigned cpu = (unsigned)cpu_number;
    require(size[0] >= 5 && size[0] <= 256 && size[1] >= 5 && size[1] <= 80);
    require(va[0] > 0 && va[0] <= UINT64_MAX - size[0] && va[1] <= UINT64_MAX - size[1]);
    require(va[0] + size[0] <= va[1] && va[0] / 4096 == (va[1] + size[1] - 1) / 4096);
    singleton(); pin(cpu); require(sysconf(_SC_PAGESIZE) == 4096);
    int input_fd = open(argv[6], O_RDONLY | O_CLOEXEC | O_NOFOLLOW); require(input_fd >= 0);
    struct stat input_stat; size_t frame_length = read_regular(input_fd, frame, sizeof frame, &input_stat);
    require(frame_length >= 12 && memcmp(frame, "MODCSV1\0", 8) == 0);
    uint32_t count = (uint32_t)frame[8] | (uint32_t)frame[9] << 8 | (uint32_t)frame[10] << 16 | (uint32_t)frame[11] << 24;
    require(count <= RECORDS); size_t at = 12;
    for (uint32_t i = 0; i < count; ++i) {
        require(at < frame_length); size_t n = frame[at++]; require(n <= 64 && n <= frame_length - at);
        memset(&inputs[i], 0xa5, sizeof inputs[i]); inputs[i].length = n;
        memcpy(inputs[i].data, frame + at, n); at += n;
        for (size_t j = 0; j < n; ++j) require(inputs[i].data[j] >= 0x20 && inputs[i].data[j] <= 0x7e);
        inputs[i].fields = fields(inputs[i].data, n);
        saved_inputs[i] = inputs[i]; results[i] = (struct result){guard, UINT64_MAX, UINT64_MAX, guard};
    }
    require(at == frame_length); /* All input is validated before dlopen or any target call. */
    int source_fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW); require(source_fd >= 0);
    struct stat source_stat; size_t file_length = read_regular(source_fd, file_image, sizeof file_image, &source_stat);
    require(file_length >= sizeof(Elf64_Ehdr)); Elf64_Ehdr eh; memcpy(&eh, file_image, sizeof eh);
    require(memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0 && eh.e_ident[EI_CLASS] == ELFCLASS64 && eh.e_ident[EI_DATA] == ELFDATA2LSB && eh.e_machine == EM_X86_64 && eh.e_type == ET_DYN);
    require(eh.e_phentsize == sizeof(Elf64_Phdr) && eh.e_phnum > 0 && eh.e_phoff <= file_length && eh.e_phnum <= (file_length - eh.e_phoff) / sizeof(Elf64_Phdr));
    uint64_t page_va = va[0] & ~UINT64_C(4095), page_offset = 0; unsigned loads = 0;
    for (unsigned i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph; memcpy(&ph, file_image + eh.e_phoff + i * sizeof ph, sizeof ph);
        if (ph.p_type != PT_LOAD || ph.p_flags != (PF_R | PF_X)) continue;
        require(ph.p_vaddr <= UINT64_MAX - ph.p_filesz && ph.p_offset <= file_length && ph.p_filesz <= file_length - ph.p_offset);
        if (ph.p_vaddr <= va[0] && va[1] + size[1] <= ph.p_vaddr + ph.p_filesz) {
            require(ph.p_vaddr % 4096 == ph.p_offset % 4096 && page_va >= (ph.p_vaddr & ~UINT64_C(4095)));
            uint64_t relative = page_va - (ph.p_vaddr & ~UINT64_C(4095));
            require((ph.p_offset & ~UINT64_C(4095)) <= UINT64_MAX - relative);
            page_offset = (ph.p_offset & ~UINT64_C(4095)) + relative;
            require(page_offset <= file_length && 4096 <= file_length - page_offset); ++loads;
        }
    }
    require(loads == 1); timely();
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); require(handle != NULL);
    struct link_map *link = NULL; require(dlinfo(handle, RTLD_DI_LINKMAP, &link) == 0 && link != NULL);
    uintptr_t base = (uintptr_t)link->l_addr; require(base <= UINTPTR_MAX - va[1] - size[1]);
    uintptr_t entry[2] = {base + va[0], base + va[1]}, page = base + page_va;
    require(page % 4096 == 0);
    struct mapping source_map = mapping(page, 4096);
    require(source_map.inode == (uint64_t)source_stat.st_ino && source_map.major == major(source_stat.st_dev) && source_map.minor == minor(source_stat.st_dev));
    require(source_map.offset <= UINT64_MAX - (page - source_map.begin) && source_map.offset + (page - source_map.begin) == page_offset);
    require(memcmp((const void *)page, file_image + page_offset, 4096) == 0);
    uintptr_t caller = (uintptr_t)&liteinst_csv_call_and_store;
    struct mapping caller_map = mapping(caller, 1);
    size_t caller_length = caller_map.end - caller_map.begin; require(caller_length <= MAP_CAP);
    unsigned char *caller_image = malloc(caller_length); require(caller_image != NULL);
    memcpy(caller_image, (const void *)caller_map.begin, caller_length);
    file_unchanged(source_fd, &source_stat, file_length); singleton(); pinned(cpu); timely();
    for (uint32_t i = 0; i < count; ++i) {
        liteinst_csv_call_and_store((target_fn)entry[0], inputs[i].data, inputs[i].length, &results[i].csv);
        timely(); require(memcmp(&inputs[i], &saved_inputs[i], sizeof inputs[i]) == 0 && results[i].left == guard && results[i].right == guard);
        liteinst_csv_call_and_store((target_fn)entry[1], inputs[i].data, inputs[i].length, &results[i].length);
        timely(); require(results[i].csv == inputs[i].fields && results[i].length == inputs[i].length);
    }
    for (uint32_t i = 0; i < count; ++i) require(memcmp(&inputs[i], &saved_inputs[i], sizeof inputs[i]) == 0 && results[i].left == guard && results[i].right == guard);
    same_map(source_map, mapping(page, 4096)); same_map(caller_map, mapping(caller, 1));
    require(memcmp((const void *)page, file_image + page_offset, 4096) == 0 && memcmp((const void *)caller_map.begin, caller_image, caller_length) == 0);
    file_unchanged(source_fd, &source_stat, file_length); singleton(); pinned(cpu); timely();
    text("ORIGINAL_READY,module-original-v1"); cell((uint64_t)getpid()); cell((uint64_t)syscall(SYS_gettid)); cell(cpu);
    cell(entry[0]); cell(entry[0] + size[0]); cell(entry[1]); cell(entry[1] + size[1]); cell(caller); cell(count); text("\n");
    for (uint32_t i = 0; i < count; ++i) {
        text("ORIGINAL"); cell(i + 1); cell(inputs[i].length); cell(checksum(inputs[i].data, inputs[i].length)); cell(results[i].csv); cell(results[i].length); text("\n");
    }
    text("ORIGINAL_DONE"); cell(count); cell(2 * count); cell(2 * count); text("\n");
    write_output(); timely();
    /* handle, FDs, snapshots and guards remain owned until normal process exit. */
    return 0;
}
