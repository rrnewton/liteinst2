/* Additive scalar reference. Keep the original two-function program literal. */
#define main pair_reference_main
#include "../ordinary-module-session/original.c"
#undef main

#define LEAVES 4U
struct leaf { uint64_t id, va, extent, returns[4]; unsigned op, policy, ret_count; };
struct leaf_result { uint64_t left, values[LEAVES], right; };
struct leaf_page { uint64_t va, offset; };
static const char *const leaf_ops[] = {"csv_fields", "length", "ascii_digits", "ascii_spaces"};
static const char *const leaf_symbols[] = {"csv_fields", "leaf_length", "leaf_ascii_digits", "leaf_ascii_spaces"};
static const char *const leaf_policies[] = {"certified", "whole"};
static struct leaf_result leaf_results[RECORDS];
static uint64_t leaf_expected[RECORDS][LEAVES];

static bool leaf_table_ok(const struct leaf *table, unsigned n) {
    if (n == 0 || n > LEAVES) return false;
    for (unsigned i = 0; i < n; ++i) {
        const struct leaf *f = &table[i];
        if (f->op >= LEAVES || f->policy > 1 || f->va == 0 || f->extent == 0 ||
            f->extent > (f->policy ? 80U : 256U) || (f->policy && f->extent < 5) ||
            f->va > UINT64_MAX - f->extent || f->ret_count == 0 || f->ret_count > 4) return false;
        if (i && table[i - 1].va + table[i - 1].extent > f->va) return false;
        for (unsigned j = 0; j < i; ++j)
            if (table[j].id == f->id || table[j].op == f->op) return false;
        for (unsigned j = 0; j < f->ret_count; ++j)
            if (f->returns[j] >= f->extent || (j && f->returns[j - 1] >= f->returns[j])) return false;
    }
    return true;
}
static bool leaf_pages(const struct leaf *table, unsigned n, struct leaf_page pages[2], unsigned *count) {
    if (!leaf_table_ok(table, n)) return false;
    unsigned used_pages = 0;
    for (unsigned i = 0; i < n; ++i) {
        uint64_t first = table[i].va & ~UINT64_C(4095);
        uint64_t last = (table[i].va + table[i].extent - 1) & ~UINT64_C(4095);
        for (uint64_t page = first;; page += 4096) {
            if (!used_pages || pages[used_pages - 1].va != page) {
                if (used_pages == 2 || page > UINT64_MAX - 4096) return false;
                pages[used_pages++] = (struct leaf_page){page, 0};
            }
            if (page == last) break;
        }
    }
    *count = used_pages; return true;
}
static bool leaf_span(uint64_t start, uint64_t size, size_t length) {
    return start <= length && size <= length - start;
}
static bool leaf_section(const unsigned char *data, size_t length, const Elf64_Ehdr *eh, unsigned i, Elf64_Shdr *out) {
    if (i >= eh->e_shnum || eh->e_shentsize != sizeof *out ||
        !leaf_span(eh->e_shoff, (uint64_t)eh->e_shnum * sizeof *out, length)) return false;
    memcpy(out, data + eh->e_shoff + i * sizeof *out, sizeof *out); return true;
}
/* Full selected FUNC/section/file/load extent joins. Instruction decoding and
 * the complete declared RET set remain separately authenticated parent inputs. */
static bool leaf_elf(const unsigned char *data, size_t length, const struct leaf *table,
                     unsigned n, struct leaf_page pages[2], unsigned *page_count) {
    if (!leaf_pages(table, n, pages, page_count) || length < sizeof(Elf64_Ehdr)) return false;
    Elf64_Ehdr eh; memcpy(&eh, data, sizeof eh);
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_version != EV_CURRENT || eh.e_ehsize != sizeof eh || eh.e_machine != EM_X86_64 || eh.e_type != ET_DYN ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 || eh.e_phnum == PN_XNUM ||
        !leaf_span(eh.e_phoff, (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr), length) ||
        eh.e_shnum == 0 || eh.e_shnum >= SHN_LORESERVE || eh.e_shentsize != sizeof(Elf64_Shdr) ||
        !leaf_span(eh.e_shoff, (uint64_t)eh.e_shnum * sizeof(Elf64_Shdr), length)) return false;
    for (unsigned p = 0; p < *page_count; ++p) {
        unsigned found = 0;
        for (unsigned i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr ph; memcpy(&ph, data + eh.e_phoff + i * sizeof ph, sizeof ph);
            if (ph.p_type != PT_LOAD) continue;
            if (ph.p_filesz > ph.p_memsz || ph.p_vaddr > UINT64_MAX - ph.p_memsz ||
                !leaf_span(ph.p_offset, ph.p_filesz, length)) return false;
            uint64_t start = ph.p_vaddr & ~UINT64_C(4095);
            if (ph.p_memsz == 0 || pages[p].va < start || pages[p].va >= ph.p_vaddr + ph.p_memsz) continue;
            if (++found != 1 || ph.p_flags != (PF_R | PF_X) || ph.p_vaddr % 4096 != ph.p_offset % 4096) return false;
            uint64_t relative = pages[p].va - start, offset = ph.p_offset & ~UINT64_C(4095);
            if (offset > UINT64_MAX - relative || !leaf_span(offset + relative, 4096, length)) return false;
            pages[p].offset = offset + relative;
        }
        if (found != 1) return false;
    }
    for (unsigned f = 0; f < n; ++f) {
        const struct leaf *leaf = &table[f]; unsigned definitions = 0, loads = 0;
        uint64_t body_offset = 0;
        for (unsigned i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr ph; memcpy(&ph, data + eh.e_phoff + i * sizeof ph, sizeof ph);
            if (ph.p_type != PT_LOAD || ph.p_flags != (PF_R | PF_X)) continue;
            if (ph.p_vaddr <= leaf->va && leaf->va - ph.p_vaddr <= ph.p_filesz &&
                leaf->extent <= ph.p_filesz - (leaf->va - ph.p_vaddr)) {
                body_offset = ph.p_offset + leaf->va - ph.p_vaddr; ++loads;
            }
        }
        if (loads != 1 || !leaf_span(body_offset, leaf->extent, length)) return false;
        for (unsigned r = 0; r < leaf->ret_count; ++r)
            if (data[body_offset + leaf->returns[r]] != 0xc3) return false;
        for (unsigned i = 0; i < eh.e_shnum; ++i) {
            Elf64_Shdr sh; if (!leaf_section(data, length, &eh, i, &sh)) return false;
            if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
            Elf64_Shdr strings;
            if (sh.sh_entsize != sizeof(Elf64_Sym) || sh.sh_size % sizeof(Elf64_Sym) ||
                !leaf_span(sh.sh_offset, sh.sh_size, length) ||
                !leaf_section(data, length, &eh, sh.sh_link, &strings) || strings.sh_type != SHT_STRTAB ||
                !leaf_span(strings.sh_offset, strings.sh_size, length)) return false;
            unsigned in_table = 0;
            for (uint64_t at = 0; at < sh.sh_size; at += sizeof(Elf64_Sym)) {
                Elf64_Sym sym; memcpy(&sym, data + sh.sh_offset + at, sizeof sym);
                if (sym.st_name >= strings.sh_size) return false;
                const char *name = (const char *)data + strings.sh_offset + sym.st_name;
                if (!memchr(name, 0, strings.sh_size - sym.st_name)) return false;
                bool selected = strcmp(name, leaf_symbols[leaf->op]) == 0;
                if (selected) {
                    Elf64_Shdr section;
                    if (++in_table != 1 || sh.sh_type != SHT_SYMTAB || ELF64_ST_TYPE(sym.st_info) != STT_FUNC || ELF64_ST_BIND(sym.st_info) != STB_LOCAL ||
                        sym.st_other != STV_DEFAULT || sym.st_value != leaf->va || sym.st_size != leaf->extent ||
                        sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE || !leaf_section(data, length, &eh, sym.st_shndx, &section) ||
                        section.sh_type != SHT_PROGBITS || (section.sh_flags & (SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE)) != (SHF_ALLOC | SHF_EXECINSTR) ||
                        !leaf_span(section.sh_offset, section.sh_size, length) || section.sh_addr > leaf->va ||
                        leaf->va - section.sh_addr > section.sh_size || leaf->extent > section.sh_size - (leaf->va - section.sh_addr) ||
                        section.sh_offset + leaf->va - section.sh_addr != body_offset) return false;
                    ++definitions;
                } else if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
                    if (sym.st_value > UINT64_MAX - sym.st_size) return false;
                    if ((sym.st_size && sym.st_value < leaf->va + leaf->extent && leaf->va < sym.st_value + sym.st_size) ||
                        (!sym.st_size && leaf->va <= sym.st_value && sym.st_value < leaf->va + leaf->extent)) return false;
                }
            }
        }
        if (definitions != 1) return false;
    }
    return true;
}
static uint64_t leaf_truth(unsigned op, const struct input *input) {
    if (op == 0) return input->fields;
    if (op == 1) return input->length;
    uint64_t value = 0;
    for (size_t i = 0; i < input->length; ++i)
        value += op == 2 ? (input->data[i] >= '0' && input->data[i] <= '9') : input->data[i] == ' ';
    return value;
}
static bool leaf_values_ok(const struct leaf_result *row, const uint64_t expected[LEAVES], unsigned completed) {
    if (completed > LEAVES || row->left != guard || row->right != guard) return false;
    for (unsigned i = 0; i < LEAVES; ++i)
        if (row->values[i] != (i < completed ? expected[i] : UINT64_MAX)) return false;
    return true;
}
static unsigned leaf_choice(const char *value, const char *const *choices, unsigned count) {
    for (unsigned i = 0; i < count; ++i) if (!strcmp(value, choices[i])) return i;
    fail();
}
static void leaf_returns(const char *text_value, struct leaf *leaf) {
    size_t length = strlen(text_value), at = 0; require(length && length <= 83);
    while (at < length) {
        size_t start = at; while (at < length && text_value[at] != ',') ++at;
        require(leaf->ret_count < 4 && unsigned_part((struct part){(const unsigned char *)text_value + start, at - start}, UINT64_MAX, &leaf->returns[leaf->ret_count]));
        ++leaf->ret_count;
        if (at < length) { ++at; require(at < length); }
    }
}
int leaf_reference_main(int argc, char **argv) {
    uint64_t start = now(); require(start <= UINT64_MAX - UINT64_C(15000000000)); deadline = start + UINT64_C(15000000000);
    require(argc >= 5 && argv[1][0] == '/' && argv[2][0] == '/');
    uint64_t cpu_value = number(argv[3]), count_value = number(argv[4]);
    require(cpu_value < CPU_SETSIZE && count_value >= 1 && count_value <= LEAVES);
    unsigned cpu = (unsigned)cpu_value, n = (unsigned)count_value; require(argc == 5 + 6 * (int)n);
    struct leaf table[LEAVES] = {0};
    for (unsigned i = 0; i < n; ++i) {
        char **v = argv + 5 + 6 * i;
        table[i] = (struct leaf){.id = number(v[0]), .op = leaf_choice(v[1], leaf_ops, LEAVES), .va = number(v[2]), .extent = number(v[3]), .policy = leaf_choice(v[4], leaf_policies, 2)};
        leaf_returns(v[5], &table[i]);
    }
    require(leaf_table_ok(table, n)); singleton(); pin(cpu); require(sysconf(_SC_PAGESIZE) == 4096);
    int input_fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW); require(input_fd >= 0);
    struct stat input_stat; size_t frame_length = read_regular(input_fd, frame, sizeof frame, &input_stat);
    input_require(frame_length >= 12 && memcmp(frame, "MODCSV1\0", 8) == 0, "bad_magic");
    uint32_t count = (uint32_t)frame[8] | (uint32_t)frame[9] << 8 | (uint32_t)frame[10] << 16 | (uint32_t)frame[11] << 24;
    input_require(count <= RECORDS, "count_over_2048"); require(count <= 4096 / n); size_t at = 12;
    for (uint32_t i = 0; i < count; ++i) {
        input_require(at < frame_length, "truncated_length"); size_t size = frame[at++];
        input_require(size <= 64, "length_over_64"); input_require(size <= frame_length - at, "truncated_payload");
        memset(&inputs[i], 0xa5, sizeof inputs[i]); inputs[i].length = size; memcpy(inputs[i].data, frame + at, size); at += size;
        for (size_t j = 0; j < size; ++j) input_require(inputs[i].data[j] >= 0x20 && inputs[i].data[j] <= 0x7e, "non_ascii_payload");
        inputs[i].fields = fields(inputs[i].data, size); saved_inputs[i] = inputs[i];
        leaf_results[i] = (struct leaf_result){guard, {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX}, guard};
        for (unsigned f = 0; f < n; ++f) leaf_expected[i][f] = leaf_truth(table[f].op, &inputs[i]);
    }
    input_require(at == frame_length, "trailing_input_byte");
    int source_fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW); require(source_fd >= 0);
    struct stat source_stat; size_t file_length = read_regular(source_fd, file_image, sizeof file_image, &source_stat);
    struct mount_identity source_device = mount_device(source_fd); struct leaf_page pages[2]; unsigned page_count;
    require(leaf_elf(file_image, file_length, table, n, pages, &page_count)); timely();
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); require(handle != NULL);
    struct link_map *link = NULL; require(dlinfo(handle, RTLD_DI_LINKMAP, &link) == 0 && link != NULL);
    uintptr_t base = (uintptr_t)link->l_addr; require(base % 4096 == 0);
    uintptr_t entries[LEAVES], addresses[2]; struct mapping maps[2];
    for (unsigned f = 0; f < n; ++f) { require(base <= UINTPTR_MAX - table[f].va - table[f].extent); entries[f] = base + table[f].va; }
    for (unsigned p = 0; p < page_count; ++p) {
        require(base <= UINTPTR_MAX - pages[p].va - 4096); addresses[p] = base + pages[p].va; maps[p] = mapping(addresses[p], 4096);
        require(maps[p].inode == (uint64_t)source_stat.st_ino && maps[p].major == source_device.major && maps[p].minor == source_device.minor);
        require(maps[p].offset <= UINT64_MAX - (addresses[p] - maps[p].begin) && maps[p].offset + addresses[p] - maps[p].begin == pages[p].offset);
        require(memcmp((const void *)addresses[p], file_image + pages[p].offset, 4096) == 0);
    }
    uintptr_t caller = (uintptr_t)&liteinst_csv_call_and_store; struct mapping caller_map = mapping(caller, 1);
    size_t caller_length = caller_map.end - caller_map.begin; require(caller_length <= MAP_CAP);
    unsigned char *caller_image = malloc(caller_length); require(caller_image != NULL); memcpy(caller_image, (const void *)caller_map.begin, caller_length);
    source_unchanged(source_fd, &source_stat, file_length, source_device); singleton(); pinned(cpu); timely();
    for (uint32_t i = 0; i < count; ++i) {
        for (unsigned f = 0; f < n; ++f) {
            liteinst_csv_call_and_store((target_fn)entries[f], inputs[i].data, inputs[i].length, &leaf_results[i].values[f]);
            timely(); require(memcmp(&inputs[i], &saved_inputs[i], sizeof inputs[i]) == 0 && leaf_values_ok(&leaf_results[i], leaf_expected[i], f + 1));
        }
    }
    for (uint32_t i = 0; i < count; ++i)
        require(memcmp(&inputs[i], &saved_inputs[i], sizeof inputs[i]) == 0 && leaf_values_ok(&leaf_results[i], leaf_expected[i], n));
    for (unsigned p = 0; p < page_count; ++p) { same_map(maps[p], mapping(addresses[p], 4096)); require(memcmp((const void *)addresses[p], file_image + pages[p].offset, 4096) == 0); }
    same_map(caller_map, mapping(caller, 1)); require(memcmp((const void *)caller_map.begin, caller_image, caller_length) == 0);
    source_unchanged(source_fd, &source_stat, file_length, source_device); singleton(); pinned(cpu); timely();
    text("LEAF_ORIGINAL_READY,leaf-original-v1"); cell((uint64_t)getpid()); cell((uint64_t)syscall(SYS_gettid)); cell(cpu); cell(n); cell(caller); cell(count); text("\n");
    for (unsigned f = 0; f < n; ++f) {
        text("LEAF_ORIGINAL_FUNCTION"); cell(f); cell(table[f].id); text(","); text(leaf_ops[table[f].op]); text(","); text(leaf_policies[table[f].policy]);
        cell(table[f].va); cell(table[f].extent); cell(entries[f]); cell(entries[f] + table[f].extent); cell(table[f].ret_count); text("\n");
        for (unsigned r = 0; r < table[f].ret_count; ++r) { text("LEAF_ORIGINAL_RET"); cell(f); cell(table[f].returns[r]); text("\n"); }
    }
    for (uint32_t i = 0; i < count; ++i) {
        text("LEAF_ORIGINAL"); cell(i + 1); cell(inputs[i].length); cell(checksum(inputs[i].data, inputs[i].length));
        for (unsigned f = 0; f < n; ++f) { cell(leaf_results[i].values[f]); } text("\n");
    }
    text("LEAF_ORIGINAL_DONE"); cell(count); cell((uint64_t)n * count); cell((uint64_t)n * count); text("\n"); write_output(); timely();
    /* The included fail path never unwinds; all file/code owners live to exit. */
    return 0;
}
#ifndef LEAF_REFERENCE_CONTROLS
int main(int argc, char **argv) { return leaf_reference_main(argc, argv); }
#endif
