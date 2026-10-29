/* Parent-only scalar reference. The old two-leaf entry point stays literal. */
#define main module_reference_main
#include "../ordinary-module-session/original.c"
#undef main

struct pair_function { uint64_t va, extent, returns[4]; unsigned ret_count; };
struct pair_geometry { struct pair_function functions[2]; uint64_t call, continuation, delta; };
struct pair_page { uint64_t va, offset; };
struct pair_result { uint64_t left, value, right; };
static struct pair_result pair_results[RECORDS];
static const char *const pair_symbols[2] = {"csv_summary", "csv_fields"};

static bool pair_geometry_ok(const struct pair_geometry *g) {
    for (unsigned i = 0; i < 2; ++i) {
        const struct pair_function *f = &g->functions[i];
        if (!f->va || f->extent < (i ? 1U : 5U) || f->extent > (i ? 256U : 80U) ||
            f->va > UINT64_MAX - f->extent || !f->ret_count || f->ret_count > (i ? 4U : 1U)) return false;
        for (unsigned j = 0; j < f->ret_count; ++j)
            if (f->returns[j] >= f->extent || (j && f->returns[j - 1] >= f->returns[j])) return false;
    }
    const struct pair_function *p = &g->functions[0], *c = &g->functions[1];
    return (p->va + p->extent <= c->va || c->va + c->extent <= p->va) &&
        p->returns[0] == p->extent - 1 && g->call > 0 && g->call <= p->extent - 5 &&
        g->continuation == g->call + 5 && g->continuation <= p->returns[0] &&
        (g->delta == 16 || g->delta == 32 || g->delta == 48 || g->delta == 64);
}
static bool pair_pages(const struct pair_geometry *g, struct pair_page pages[2], unsigned *count) {
    if (!pair_geometry_ok(g)) return false;
    unsigned n = 0;
    for (unsigned i = 0; i < 2; ++i) {
        const struct pair_function *f = &g->functions[i];
        uint64_t last = (f->va + f->extent - 1) & ~UINT64_C(4095);
        for (uint64_t page = f->va & ~UINT64_C(4095);; page += 4096) {
            if (page > UINT64_MAX - 4096) return false;
            unsigned at = 0; while (at < n && pages[at].va != page) ++at;
            if (at == n) { if (n == 2) return false; pages[n++] = (struct pair_page){page, 0}; }
            if (page == last) break;
        }
    }
    if (n == 2 && pages[0].va > pages[1].va) { struct pair_page swap = pages[0]; pages[0] = pages[1]; pages[1] = swap; }
    *count = n; return true;
}
static bool pair_span(uint64_t at, uint64_t size, size_t length) { return at <= length && size <= length - at; }
static bool pair_section(const unsigned char *data, size_t length, const Elf64_Ehdr *eh, unsigned i, Elf64_Shdr *out) {
    if (i >= eh->e_shnum || eh->e_shentsize != sizeof *out ||
        !pair_span(eh->e_shoff, (uint64_t)eh->e_shnum * sizeof *out, length)) return false;
    memcpy(out, data + eh->e_shoff + i * sizeof *out, sizeof *out); return true;
}
/* Complete selected ELF extents and file-backed canonical pages. The recipe must
 * separately authenticate the decoded heads, complete RET set and parent admission. */
static bool pair_elf(const unsigned char *data, size_t length, const struct pair_geometry *g,
                     struct pair_page pages[2], unsigned *page_count) {
    if (!pair_pages(g, pages, page_count) || length < sizeof(Elf64_Ehdr)) return false;
    Elf64_Ehdr eh; memcpy(&eh, data, sizeof eh);
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_version != EV_CURRENT || eh.e_ehsize != sizeof eh || eh.e_machine != EM_X86_64 || eh.e_type != ET_DYN ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || !eh.e_phnum || eh.e_phnum == PN_XNUM ||
        !pair_span(eh.e_phoff, (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr), length) ||
        !eh.e_shnum || eh.e_shnum >= SHN_LORESERVE || eh.e_shentsize != sizeof(Elf64_Shdr) ||
        !pair_span(eh.e_shoff, (uint64_t)eh.e_shnum * sizeof(Elf64_Shdr), length)) return false;
    for (unsigned p = 0; p < *page_count; ++p) {
        unsigned found = 0;
        for (unsigned i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr ph; memcpy(&ph, data + eh.e_phoff + i * sizeof ph, sizeof ph);
            if (ph.p_type != PT_LOAD) continue;
            if (ph.p_filesz > ph.p_memsz || ph.p_vaddr > UINT64_MAX - ph.p_memsz ||
                !pair_span(ph.p_offset, ph.p_filesz, length)) return false;
            if (!ph.p_memsz) continue;
            uint64_t start = ph.p_vaddr & ~UINT64_C(4095), end = ph.p_vaddr + ph.p_memsz;
            if (end > UINT64_MAX - 4095) return false;
            end = (end + 4095) & ~UINT64_C(4095);
            if (pages[p].va >= end || pages[p].va + 4096 <= start) continue;
            if (++found != 1 || ph.p_flags != (PF_R | PF_X) || ph.p_vaddr % 4096 != ph.p_offset % 4096) return false;
            uint64_t relative = pages[p].va - start, offset = ph.p_offset & ~UINT64_C(4095);
            if (offset > UINT64_MAX - relative || !pair_span(offset + relative, 4096, length)) return false;
            pages[p].offset = offset + relative;
        }
        if (found != 1) return false;
    }
    uint64_t body_offsets[2] = {0};
    for (unsigned f = 0; f < 2; ++f) {
        const struct pair_function *function = &g->functions[f]; unsigned loads = 0, definitions = 0;
        for (unsigned i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr ph; memcpy(&ph, data + eh.e_phoff + i * sizeof ph, sizeof ph);
            if (ph.p_type != PT_LOAD || ph.p_flags != (PF_R | PF_X)) continue;
            if (ph.p_vaddr <= function->va && function->va - ph.p_vaddr <= ph.p_filesz &&
                function->extent <= ph.p_filesz - (function->va - ph.p_vaddr)) {
                body_offsets[f] = ph.p_offset + function->va - ph.p_vaddr; ++loads;
            }
        }
        if (loads != 1 || !pair_span(body_offsets[f], function->extent, length)) return false;
        for (unsigned r = 0; r < function->ret_count; ++r)
            if (data[body_offsets[f] + function->returns[r]] != 0xc3) return false;
        for (unsigned i = 0; i < eh.e_shnum; ++i) {
            Elf64_Shdr sh; if (!pair_section(data, length, &eh, i, &sh)) return false;
            if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
            Elf64_Shdr strings;
            if (sh.sh_entsize != sizeof(Elf64_Sym) || sh.sh_size % sizeof(Elf64_Sym) ||
                !pair_span(sh.sh_offset, sh.sh_size, length) ||
                !pair_section(data, length, &eh, sh.sh_link, &strings) || strings.sh_type != SHT_STRTAB ||
                !pair_span(strings.sh_offset, strings.sh_size, length)) return false;
            for (uint64_t at = 0; at < sh.sh_size; at += sizeof(Elf64_Sym)) {
                Elf64_Sym sym; memcpy(&sym, data + sh.sh_offset + at, sizeof sym);
                if (sym.st_name >= strings.sh_size) return false;
                const char *name = (const char *)data + strings.sh_offset + sym.st_name;
                if (!memchr(name, 0, strings.sh_size - sym.st_name)) return false;
                if (strcmp(name, pair_symbols[f]) == 0) {
                    Elf64_Shdr section;
                    if (++definitions != 1 || sh.sh_type != SHT_SYMTAB || ELF64_ST_TYPE(sym.st_info) != STT_FUNC ||
                        ELF64_ST_BIND(sym.st_info) != STB_LOCAL || sym.st_other != STV_DEFAULT ||
                        sym.st_value != function->va || sym.st_size != function->extent || sym.st_shndx == SHN_UNDEF ||
                        sym.st_shndx >= SHN_LORESERVE || !pair_section(data, length, &eh, sym.st_shndx, &section) ||
                        section.sh_type != SHT_PROGBITS || (section.sh_flags & (SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE)) != (SHF_ALLOC | SHF_EXECINSTR) ||
                        !pair_span(section.sh_offset, section.sh_size, length) || section.sh_addr > function->va ||
                        function->va - section.sh_addr > section.sh_size || function->extent > section.sh_size - (function->va - section.sh_addr) ||
                        section.sh_offset + function->va - section.sh_addr != body_offsets[f]) return false;
                } else if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
                    if (sym.st_value > UINT64_MAX - sym.st_size) return false;
                    if ((sym.st_size && sym.st_value < function->va + function->extent && function->va < sym.st_value + sym.st_size) ||
                        (!sym.st_size && function->va <= sym.st_value && sym.st_value < function->va + function->extent)) return false;
                }
            }
        }
        if (definitions != 1) return false;
    }
    const unsigned char *body = data + body_offsets[0];
    if (body[g->call] != 0xe8) return false;
    int32_t relative; memcpy(&relative, body + g->call + 1, sizeof relative);
    uint64_t next = g->functions[0].va + g->continuation, target;
    if (relative < 0) { uint64_t back = (uint64_t)(-(int64_t)relative); if (next < back) return false; target = next - back; }
    else { if (next > UINT64_MAX - (uint32_t)relative) return false; target = next + (uint32_t)relative; }
    return target == g->functions[1].va;
}
/* Same restricted grammar as the inherited fields() helper, with a pure refusal
 * result for controls. Production rechecks accepted bytes using fields() below. */
static bool pair_csv(const unsigned char *data, size_t length) {
    size_t at = 0;
    while (at < length) {
        if (data[at] == '"') {
            ++at; bool closed = false;
            while (at < length) {
                if (data[at++] != '"') continue;
                if (at < length && data[at] == '"') { ++at; continue; }
                closed = true; break;
            }
            if (!closed || (at != length && data[at] != ',')) return false;
        } else {
            while (at < length && data[at] != ',') { if (data[at] == '"') return false; ++at; }
        }
        if (at < length) { if (data[at++] != ',') return false; }
    }
    return true;
}
static const char *pair_frame(const unsigned char *data, size_t length, uint32_t *count) {
    if (length < 12 || memcmp(data, "MODCSV1\0", 8)) return "bad_magic";
    uint32_t n = (uint32_t)data[8] | (uint32_t)data[9] << 8 | (uint32_t)data[10] << 16 | (uint32_t)data[11] << 24;
    if (n > RECORDS) return "count_over_2048";
    size_t at = 12;
    for (uint32_t i = 0; i < n; ++i) {
        if (at == length) return "truncated_length";
        size_t size = data[at++];
        if (size > 64) return "length_over_64";
        if (size > length - at) return "truncated_payload";
        for (size_t j = 0; j < size; ++j) if (data[at + j] < 0x20 || data[at + j] > 0x7e) return "non_ascii_payload";
        if (!pair_csv(data + at, size)) return "malformed_csv";
        at += size;
    }
    if (at != length) return "trailing_input_byte";
    *count = n; return NULL;
}
static void pair_call(const uintptr_t entries[2], const struct input *input, struct pair_result *result) {
    liteinst_csv_call_and_store((target_fn)entries[0], input->data, input->length, &result->value);
}
static bool pair_files_distinct(const struct stat *source, const struct stat *trusted) {
    return S_ISREG(source->st_mode) && S_ISREG(trusted->st_mode) && source->st_size >= 0 &&
        source->st_size == trusted->st_size && (source->st_dev != trusted->st_dev || source->st_ino != trusted->st_ino);
}
static bool pair_value_ok(const struct pair_result *result, const struct input *actual, const struct input *saved) {
    return actual->length <= 64 && actual->fields >= 1 && actual->fields <= 65 &&
        !memcmp(actual, saved, sizeof *actual) && result->left == guard && result->right == guard &&
        result->value == (((uint64_t)actual->length << 32) | actual->fields);
}
static bool pair_mapping_ok(struct mapping m, uintptr_t address, struct pair_page page,
                            const struct stat *file, struct mount_identity device) {
    return file->st_ino != 0 && m.begin <= address && address <= UINTPTR_MAX - 4096 && address + 4096 <= m.end &&
        m.inode == (uint64_t)file->st_ino && m.major == device.major && m.minor == device.minor &&
        m.offset <= UINT64_MAX - (address - m.begin) && m.offset + (address - m.begin) == page.offset;
}
static bool pair_page_equal(const void *actual, const unsigned char *expected) { return memcmp(actual, expected, 4096) == 0; }
static void pair_frame_unchanged(int fd, const struct stat *original, size_t length) {
    struct stat st; require(fstat(fd, &st) == 0 && st.st_dev == original->st_dev && st.st_ino == original->st_ino && st.st_size == original->st_size);
    unsigned char scratch[4096]; size_t at = 0;
    while (at < length) {
        timely(); size_t size = length - at; if (size > sizeof scratch) size = sizeof scratch;
        ssize_t got = pread(fd, scratch, size, (off_t)at); if (got < 0 && errno == EINTR) continue;
        require(got == (ssize_t)size && memcmp(scratch, frame + at, size) == 0); at += size;
    }
}
static void pair_returns(const char *value, struct pair_function *function) {
    size_t length = strlen(value), at = 0; require(length && length <= 83);
    while (at < length) {
        size_t start = at; while (at < length && value[at] != ',') ++at;
        require(function->ret_count < 4 && unsigned_part((struct part){(const unsigned char *)value + start, at - start}, UINT64_MAX, &function->returns[function->ret_count]));
        ++function->ret_count;
        if (at < length) { ++at; require(at < length); }
    }
}
int call_pair_reference_main(int argc, char **argv) {
    uint64_t start = now(); require(start <= UINT64_MAX - UINT64_C(15000000000)); deadline = start + UINT64_C(15000000000);
    require(argc == 14 && argv[1][0] == '/' && argv[2][0] == '/' && argv[3][0] == '/');
    uint64_t cpu_number = number(argv[4]); require(cpu_number < CPU_SETSIZE); unsigned cpu = (unsigned)cpu_number;
    struct pair_geometry geometry = {.functions = {{.va = number(argv[5]), .extent = number(argv[6]), .returns = {number(argv[12])}, .ret_count = 1},
        {.va = number(argv[7]), .extent = number(argv[8])}}, .call = number(argv[9]), .continuation = number(argv[10]), .delta = number(argv[11])};
    pair_returns(argv[13], &geometry.functions[1]); require(pair_geometry_ok(&geometry));
    singleton(); pin(cpu); require(sysconf(_SC_PAGESIZE) == 4096);
    int input_fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW); require(input_fd >= 0);
    struct stat input_stat; size_t frame_length = read_regular(input_fd, frame, sizeof frame, &input_stat);
    uint32_t count = 0; const char *reason = pair_frame(frame, frame_length, &count); if (reason) input_fail(reason);
    size_t at = 12;
    for (uint32_t i = 0; i < count; ++i) {
        size_t n = frame[at++]; memset(&inputs[i], 0xa5, sizeof inputs[i]); inputs[i].length = n;
        memcpy(inputs[i].data, frame + at, n); at += n; inputs[i].fields = fields(inputs[i].data, n);
        saved_inputs[i] = inputs[i]; pair_results[i] = (struct pair_result){guard, UINT64_MAX, guard};
    }
    require(at == frame_length); timely();
    int source_fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW), trusted_fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    require(source_fd >= 0 && trusted_fd >= 0);
    struct stat source_stat, trusted_stat; size_t file_length = read_regular(source_fd, file_image, sizeof file_image, &source_stat);
    require(fstat(trusted_fd, &trusted_stat) == 0 && pair_files_distinct(&source_stat, &trusted_stat));
    struct mount_identity source_device = mount_device(source_fd), trusted_device = mount_device(trusted_fd);
    source_unchanged(trusted_fd, &trusted_stat, file_length, trusted_device);
    struct pair_page pages[2]; unsigned page_count; require(pair_elf(file_image, file_length, &geometry, pages, &page_count));
    timely(); void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); require(handle != NULL);
    struct link_map *link = NULL; require(dlinfo(handle, RTLD_DI_LINKMAP, &link) == 0 && link != NULL);
    uintptr_t base = (uintptr_t)link->l_addr; require(base % 4096 == 0);
    uintptr_t entries[2], addresses[2]; struct mapping maps[2];
    for (unsigned i = 0; i < 2; ++i) { require(base <= UINTPTR_MAX - geometry.functions[i].va - geometry.functions[i].extent); entries[i] = base + geometry.functions[i].va; }
    for (unsigned p = 0; p < page_count; ++p) {
        require(base <= UINTPTR_MAX - pages[p].va - 4096); addresses[p] = base + pages[p].va; maps[p] = mapping(addresses[p], 4096);
        require(pair_mapping_ok(maps[p], addresses[p], pages[p], &source_stat, source_device));
        require(pair_page_equal((const void *)addresses[p], file_image + pages[p].offset));
    }
    uintptr_t caller = (uintptr_t)&liteinst_csv_call_and_store; struct mapping caller_map = mapping(caller, 1);
    size_t caller_length = caller_map.end - caller_map.begin; require(caller_length <= MAP_CAP);
    unsigned char *caller_image = malloc(caller_length); require(caller_image != NULL); memcpy(caller_image, (const void *)caller_map.begin, caller_length);
    source_unchanged(source_fd, &source_stat, file_length, source_device); source_unchanged(trusted_fd, &trusted_stat, file_length, trusted_device);
    pair_frame_unchanged(input_fd, &input_stat, frame_length); singleton(); pinned(cpu); timely();
    for (uint32_t i = 0; i < count; ++i) {
        /* Exactly one external target call: original E8 inside parent reaches child. */
        pair_call(entries, &inputs[i], &pair_results[i]);
        timely(); require(pair_value_ok(&pair_results[i], &inputs[i], &saved_inputs[i]));
    }
    for (uint32_t i = 0; i < count; ++i) require(pair_value_ok(&pair_results[i], &inputs[i], &saved_inputs[i]));
    for (unsigned p = 0; p < page_count; ++p) { same_map(maps[p], mapping(addresses[p], 4096)); require(pair_page_equal((const void *)addresses[p], file_image + pages[p].offset)); }
    same_map(caller_map, mapping(caller, 1)); require(memcmp((const void *)caller_map.begin, caller_image, caller_length) == 0);
    source_unchanged(source_fd, &source_stat, file_length, source_device); source_unchanged(trusted_fd, &trusted_stat, file_length, trusted_device);
    pair_frame_unchanged(input_fd, &input_stat, frame_length); singleton(); pinned(cpu); timely();
    text("ORIGINAL_READY,call-pair-original-v1"); cell((uint64_t)getpid()); cell((uint64_t)syscall(SYS_gettid)); cell(cpu);
    cell(entries[0]); cell(entries[0] + geometry.functions[0].extent); cell(entries[1]); cell(entries[1] + geometry.functions[1].extent); cell(caller); cell(count); text("\n");
    for (unsigned i = 0; i < 2; ++i) {
        const struct pair_function *f = &geometry.functions[i];
        text("ORIGINAL_FUNCTION"); cell(i); cell(f->va); cell(f->extent); cell(entries[i]); cell(entries[i] + f->extent); cell(f->ret_count); text("\n");
        for (unsigned j = 0; j < f->ret_count; ++j) { text("ORIGINAL_RET"); cell(i); cell(f->returns[j]); text("\n"); }
    }
    text("ORIGINAL_EDGE"); cell(entries[0] + geometry.call); cell(entries[1]); cell(entries[0] + geometry.continuation); cell(geometry.delta); text("\n");
    for (uint32_t i = 0; i < count; ++i) {
        text("ORIGINAL"); cell(i + 1); cell(inputs[i].length); cell(checksum(inputs[i].data, inputs[i].length)); cell(inputs[i].fields); cell(pair_results[i].value); text("\n");
    }
    text("ORIGINAL_DONE"); cell(count); cell(count); cell(count); text("\n"); write_output(); timely();
    /* FDs, loaded handle, source/caller snapshots and inputs remain owned to exit. */
    return 0;
}
#ifndef CALL_PAIR_REFERENCE_CONTROLS
int main(int argc, char **argv) { return call_pair_reference_main(argc, argv); }
#endif
