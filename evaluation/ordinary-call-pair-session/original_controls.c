/* Fabricated metadata/ordinary stub controls; no loaded-owner or subject credit. */
#define CALL_PAIR_REFERENCE_CONTROLS
#include "original.c"
#include <assert.h>
#ifdef NDEBUG
#error "assertions required"
#endif
static struct pair_geometry control_geometry(void) {
    return (struct pair_geometry){.functions = {{.va = 4096, .extent = 16, .returns = {15}, .ret_count = 1},
        {.va = 12288, .extent = 8, .returns = {7}, .ret_count = 1}}, .call = 4, .continuation = 9, .delta = 16};
}
static void control_image(unsigned char image[16384], struct pair_geometry *g) {
    *g = control_geometry(); memset(image, 0, 16384);
    Elf64_Ehdr eh = {.e_type = ET_DYN, .e_machine = EM_X86_64, .e_version = EV_CURRENT,
        .e_ehsize = sizeof eh, .e_phoff = 64, .e_phentsize = sizeof(Elf64_Phdr), .e_phnum = 2,
        .e_shoff = 256, .e_shentsize = sizeof(Elf64_Shdr), .e_shnum = 5};
    memcpy(eh.e_ident, ELFMAG, SELFMAG); eh.e_ident[EI_CLASS] = ELFCLASS64; eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT; memcpy(image, &eh, sizeof eh);
    for (unsigned i = 0; i < 2; ++i) {
        Elf64_Phdr ph = {.p_type = PT_LOAD, .p_flags = PF_R | PF_X, .p_offset = g->functions[i].va,
            .p_vaddr = g->functions[i].va, .p_filesz = 4096, .p_memsz = 4096, .p_align = 4096};
        memcpy(image + 64 + i * sizeof ph, &ph, sizeof ph);
    }
    Elf64_Shdr sections[5] = {{0}, {.sh_type = SHT_PROGBITS, .sh_flags = SHF_ALLOC | SHF_EXECINSTR, .sh_addr = 4096, .sh_offset = 4096, .sh_size = 4096},
        {.sh_type = SHT_PROGBITS, .sh_flags = SHF_ALLOC | SHF_EXECINSTR, .sh_addr = 12288, .sh_offset = 12288, .sh_size = 4096},
        {.sh_type = SHT_SYMTAB, .sh_offset = 768, .sh_size = 3 * sizeof(Elf64_Sym), .sh_link = 4, .sh_info = 3, .sh_entsize = sizeof(Elf64_Sym)},
        {.sh_type = SHT_STRTAB, .sh_offset = 1024, .sh_size = 256}};
    memcpy(image + 256, sections, sizeof sections); size_t name_at = 1;
    for (unsigned i = 0; i < 2; ++i) {
        size_t size = strlen(pair_symbols[i]) + 1; memcpy(image + 1024 + name_at, pair_symbols[i], size);
        Elf64_Sym sym = {.st_name = (Elf64_Word)name_at, .st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC),
            .st_shndx = (Elf64_Section)(i + 1), .st_value = g->functions[i].va, .st_size = g->functions[i].extent};
        memcpy(image + 768 + (i + 1) * sizeof sym, &sym, sizeof sym); name_at += size;
        memset(image + g->functions[i].va, 0x90, (size_t)g->functions[i].extent);
        image[g->functions[i].va + g->functions[i].returns[0]] = 0xc3;
    }
    image[g->functions[0].va + g->call] = 0xe8;
    int32_t relative = (int32_t)(g->functions[1].va - (g->functions[0].va + g->continuation));
    memcpy(image + g->functions[0].va + g->call + 1, &relative, sizeof relative);
}
static void parent_reference_requires_exact_selected_edge_and_complete_pages(void) {
    unsigned char image[16384]; struct pair_geometry g; struct pair_page pages[2]; unsigned n;
    control_image(image, &g); assert(pair_elf(image, sizeof image, &g, pages, &n));
    assert(n == 2 && pages[0].va == 4096 && pages[1].va == 12288 && pages[1].offset == 12288);
    for (unsigned change = 0; change < 12; ++change) {
        control_image(image, &g); Elf64_Sym sym; Elf64_Shdr sh; Elf64_Phdr ph;
        memcpy(&sym, image + 768 + 2 * sizeof sym, sizeof sym);
        memcpy(&sh, image + 256 + 3 * sizeof sh, sizeof sh);
        memcpy(&ph, image + 64 + sizeof ph, sizeof ph);
        switch (change) {
            case 0: image[g.functions[0].va + g.call] = 0x90; break;
            case 1: image[g.functions[0].va + g.call + 1] ^= 1; break;
            case 2: image[g.functions[1].va + 7] = 0x90; break;
            case 3: --sym.st_size; memcpy(image + 768 + 2 * sizeof sym, &sym, sizeof sym); break;
            case 4: sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC); memcpy(image + 768 + 2 * sizeof sym, &sym, sizeof sym); break;
            case 5: sh.sh_type = SHT_DYNSYM; memcpy(image + 256 + 3 * sizeof sh, &sh, sizeof sh); break;
            case 6: ph.p_flags |= PF_W; memcpy(image + 64 + sizeof ph, &ph, sizeof ph); break;
            case 7: ph.p_vaddr = 4096; ph.p_memsz = 12288; memcpy(image + 64 + sizeof ph, &ph, sizeof ph); break;
            case 8: ++ph.p_offset; memcpy(image + 64 + sizeof ph, &ph, sizeof ph); break;
            case 9: g.continuation++; break;
            case 10: g.delta = 8; break;
            case 11: g.functions[0].returns[0]--; break;
        }
        assert(!pair_elf(image, sizeof image, &g, pages, &n));
    }
    control_image(image, &g); assert(!pair_elf(image, sizeof image - 1, &g, pages, &n));
    /* Reversed logical roles preserve sorted pages; three pages and overflow refuse. */
    g.functions[0].va = 12288; g.functions[1].va = 4096;
    assert(pair_pages(&g, pages, &n) && n == 2 && pages[0].va == 4096);
    g.functions[0].va = 8190; g.functions[1].va = 12288; assert(!pair_pages(&g, pages, &n));
    g.functions[0].va = UINT64_MAX - 8; assert(!pair_pages(&g, pages, &n));
}
static unsigned parent_calls, child_direct_calls;
static uint64_t control_parent(const unsigned char *data, size_t length) {
    ++parent_calls; return ((uint64_t)length << 32) | fields(data, length);
}
static uint64_t control_child(const unsigned char *data, size_t length) { ++child_direct_calls; return fields(data, length); }
static void parent_reference_calls_only_parent_and_checks_packed_value(void) {
    struct input input; memset(&input, 0xa5, sizeof input); input.length = 3; memcpy(input.data, "a,b", 3); input.fields = 2;
    struct input saved = input; struct pair_result result = {guard, UINT64_MAX, guard};
    uintptr_t entries[2] = {(uintptr_t)&control_parent, (uintptr_t)&control_child};
    parent_calls = child_direct_calls = 0; pair_call(entries, &input, &result);
    assert(parent_calls == 1 && child_direct_calls == 0 && result.value == (UINT64_C(3) << 32 | 2));
    assert(pair_value_ok(&result, &input, &saved));
    for (unsigned bit = 0; bit < 64; ++bit) { result.value ^= UINT64_C(1) << bit; assert(!pair_value_ok(&result, &input, &saved)); result.value ^= UINT64_C(1) << bit; }
    result.left ^= 1; assert(!pair_value_ok(&result, &input, &saved)); result.left ^= 1;
    result.right ^= 1; assert(!pair_value_ok(&result, &input, &saved)); result.right ^= 1;
    for (size_t i = 0; i < sizeof input; ++i) {
        unsigned char *bytes = (unsigned char *)&input; bytes[i] ^= 1;
        assert(!pair_value_ok(&result, &input, &saved)); input = saved;
    }
    input.data[0] = 'z'; assert(!pair_value_ok(&result, &input, &saved)); input = saved;
    input.length = 0; input.fields = 1; saved = input; result.value = 1;
    assert(pair_value_ok(&result, &input, &saved));
}
static void parent_reference_preserves_all_input_guards_frames_and_refusals(void) {
    unsigned char data[80] = {0}; memcpy(data, "MODCSV1\0", 8); uint32_t n = 99;
    assert(pair_frame(data, 12, &n) == NULL && n == 0);
    data[8] = 1; assert(pair_frame(data, 13, &n) == NULL && n == 1); /* One empty field. */
    const char *expected[] = {"bad_magic", "count_over_2048", "truncated_length", "truncated_payload", "length_over_64", "non_ascii_payload", "malformed_csv", "trailing_input_byte"};
    for (unsigned i = 0; i < 8; ++i) {
        memset(data, 0, sizeof data); memcpy(data, "MODCSV1\0", 8); size_t length = 12;
        switch (i) {
            case 0: data[0] = 'X'; break;
            case 1: data[8] = 1; data[9] = 8; break;
            case 2: data[8] = 1; break;
            case 3: data[8] = 1; data[12] = 2; data[13] = 'a'; length = 14; break;
            case 4: data[8] = 1; data[12] = 65; memset(data + 13, 'x', 65); length = 78; break;
            case 5: data[8] = 1; data[12] = 1; data[13] = 0xff; length = 14; break;
            case 6: data[8] = 1; data[12] = 1; data[13] = '"'; length = 14; break;
            case 7: data[12] = 'x'; length = 13; break;
        }
        n = 99; const char *reason = pair_frame(data, length, &n); assert(reason && !strcmp(reason, expected[i]) && n == 99);
    }
    for (unsigned char c = 0x20; c <= 0x7e; ++c) {
        unsigned char quoted[8] = {'"', c, '"', ',', 'x'}; size_t length = 5;
        if (c == '"') { quoted[2] = '"'; quoted[3] = '"'; quoted[4] = ','; quoted[5] = 'x'; length = 6; }
        assert(pair_csv(quoted, length) && fields(quoted, length) == 2);
    }
    uint64_t value; assert(unsigned_part((struct part){(const unsigned char *)"18446744073709551615", 20}, UINT64_MAX, &value) && value == UINT64_MAX);
    assert(!unsigned_part((struct part){(const unsigned char *)"18446744073709551616", 20}, UINT64_MAX, &value));
    assert(!unsigned_part((struct part){(const unsigned char *)"01", 2}, UINT64_MAX, &value));
    assert(checksum((const unsigned char *)"", 0) == UINT64_C(14695981039346656037));
}
static void parent_reference_refuses_source_mapping_and_last_page_mutation(void) {
    struct stat source = {.st_mode = S_IFREG | 0500, .st_size = 16384, .st_dev = 5, .st_ino = 7}, trusted = source;
    assert(!pair_files_distinct(&source, &trusted)); trusted.st_ino++;
    assert(pair_files_distinct(&source, &trusted)); trusted.st_size--; assert(!pair_files_distinct(&source, &trusted));
    struct mapping m = {.begin = 0x1000, .end = 0x3000, .offset = 4096, .inode = 7, .major = 2, .minor = 3};
    struct pair_page page = {.va = 12288, .offset = 8192}; struct mount_identity device = {.id = 10, .major = 2, .minor = 3};
    assert(pair_mapping_ok(m, 0x2000, page, &source, device));
    for (unsigned i = 0; i < 6; ++i) {
        struct mapping bad = m;
        switch (i) { case 0: bad.inode++; break; case 1: bad.major++; break; case 2: bad.minor++; break; case 3: bad.offset++; break; case 4: bad.end--; break; case 5: bad.offset = UINT64_MAX; break; }
        assert(!pair_mapping_ok(bad, 0x2000, page, &source, device));
    }
    unsigned char expected[4096], actual[4096]; memset(expected, 0xa5, sizeof expected); memcpy(actual, expected, sizeof actual);
    assert(pair_page_equal(actual, expected));
    for (size_t i = 0; i < sizeof actual; ++i) { actual[i] ^= 1; assert(!pair_page_equal(actual, expected)); actual[i] ^= 1; }
}
int main(void) {
    parent_reference_requires_exact_selected_edge_and_complete_pages();
    parent_reference_calls_only_parent_and_checks_packed_value();
    parent_reference_preserves_all_input_guards_frames_and_refusals();
    parent_reference_refuses_source_mapping_and_last_page_mutation();
    puts("CALL_PAIR_ORIGINAL_CONTROLS_PASS controls=4"); return 0;
}
