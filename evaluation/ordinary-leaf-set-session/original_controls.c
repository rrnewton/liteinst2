/* Pure metadata controls: no procfs, dlopen, executable mappings or target calls. */
#define LEAF_REFERENCE_CONTROLS
#include "original.c"
#include <assert.h>
#ifdef NDEBUG
#error "assertions required"
#endif

static struct leaf control_leaf(unsigned i) {
    return (struct leaf){.id = 11U * (i + 1), .va = 4096 + 32U * i, .extent = 8,
                        .returns = {7}, .op = i, .policy = i == 1, .ret_count = 1};
}
static void leaf_control_table_and_last_selection(void) {
    struct leaf table[4]; for (unsigned i = 0; i < 4; ++i) table[i] = control_leaf(i);
    for (unsigned n = 1; n <= 4; ++n) assert(leaf_table_ok(table, n));
    assert(!leaf_table_ok(table, 0) && !leaf_table_ok(table, 5));
    struct leaf saved = table[3];
    table[3].id = table[0].id; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].op = table[0].op; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].va = table[2].va + 1; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].extent = 257; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].policy = 1; table[3].extent = 81; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].returns[0] = 8; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].ret_count = 2; table[3].returns[1] = 7; assert(!leaf_table_ok(table, 4)); table[3] = saved;
    table[3].va = UINT64_MAX - 7; assert(!leaf_table_ok(table, 4));
    uint64_t parsed; assert(unsigned_part((struct part){(const unsigned char *)"18446744073709551615", 20}, UINT64_MAX, &parsed) && parsed == UINT64_MAX);
    assert(!unsigned_part((struct part){(const unsigned char *)"18446744073709551616", 20}, UINT64_MAX, &parsed));
    assert(!unsigned_part((struct part){(const unsigned char *)"01", 2}, UINT64_MAX, &parsed));
}
static void control_image(unsigned char image[8192], struct leaf table[4]) {
    memset(image, 0, 8192);
    Elf64_Ehdr eh = {.e_type = ET_DYN, .e_machine = EM_X86_64, .e_version = EV_CURRENT,
                    .e_ehsize = sizeof eh, .e_phoff = 64, .e_phentsize = sizeof(Elf64_Phdr), .e_phnum = 1,
                    .e_shoff = 128, .e_shentsize = sizeof(Elf64_Shdr), .e_shnum = 4};
    memcpy(eh.e_ident, ELFMAG, SELFMAG); eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB; eh.e_ident[EI_VERSION] = EV_CURRENT; memcpy(image, &eh, sizeof eh);
    Elf64_Phdr ph = {.p_type = PT_LOAD, .p_flags = PF_R | PF_X, .p_offset = 4096,
                    .p_vaddr = 4096, .p_filesz = 4096, .p_memsz = 4096, .p_align = 4096};
    memcpy(image + 64, &ph, sizeof ph);
    Elf64_Shdr sections[4] = {{0}, {.sh_type = SHT_PROGBITS, .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
        .sh_addr = 4096, .sh_offset = 4096, .sh_size = 4096}, {.sh_type = SHT_SYMTAB, .sh_offset = 512,
        .sh_size = 5 * sizeof(Elf64_Sym), .sh_link = 3, .sh_info = 5, .sh_entsize = sizeof(Elf64_Sym)},
        {.sh_type = SHT_STRTAB, .sh_offset = 1024, .sh_size = 256}};
    memcpy(image + 128, sections, sizeof sections); size_t name_at = 1;
    for (unsigned i = 0; i < 4; ++i) {
        table[i] = control_leaf(i); size_t size = strlen(leaf_symbols[i]) + 1;
        memcpy(image + 1024 + name_at, leaf_symbols[i], size);
        Elf64_Sym sym = {.st_name = (Elf64_Word)name_at, .st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC),
                        .st_shndx = 1, .st_value = table[i].va, .st_size = table[i].extent};
        memcpy(image + 512 + (i + 1) * sizeof sym, &sym, sizeof sym); name_at += size;
        image[table[i].va + 7] = 0xc3;
    }
}
static void leaf_control_complete_elf_selection(void) {
    unsigned char image[8192]; struct leaf table[4]; struct leaf_page pages[2]; unsigned count;
    control_image(image, table); assert(leaf_elf(image, sizeof image, table, 4, pages, &count) && count == 1 && pages[0].offset == 4096);
    Elf64_Sym sym, saved; memcpy(&saved, image + 512 + 4 * sizeof sym, sizeof sym);
    /* The fixed build localizes every selected definition: no GLOBAL/DYNSYM fallback. */
    sym = saved; sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC); memcpy(image + 512 + 4 * sizeof sym, &sym, sizeof sym);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count)); memcpy(image + 512 + 4 * sizeof sym, &saved, sizeof sym);
    Elf64_Shdr symbols; memcpy(&symbols, image + 128 + 2 * sizeof symbols, sizeof symbols);
    symbols.sh_type = SHT_DYNSYM; memcpy(image + 128 + 2 * sizeof symbols, &symbols, sizeof symbols);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count));
    symbols.sh_type = SHT_SYMTAB; memcpy(image + 128 + 2 * sizeof symbols, &symbols, sizeof symbols);
    /* Repeating a matching definition in a second symbol table is not a second authority. */
    memcpy(image + 128 + 4 * sizeof symbols, &symbols, sizeof symbols);
    Elf64_Ehdr header; memcpy(&header, image, sizeof header); header.e_shnum = 5; memcpy(image, &header, sizeof header);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count));
    header.e_shnum = 4; memcpy(image, &header, sizeof header);
    sym = saved; --sym.st_size; memcpy(image + 512 + 4 * sizeof sym, &sym, sizeof sym);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count)); memcpy(image + 512 + 4 * sizeof sym, &saved, sizeof sym);
    sym = saved; sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT); memcpy(image + 512 + 4 * sizeof sym, &sym, sizeof sym);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count)); memcpy(image + 512 + 4 * sizeof sym, &saved, sizeof sym);
    image[table[3].va + 7] = 0x90; assert(!leaf_elf(image, sizeof image, table, 4, pages, &count)); image[table[3].va + 7] = 0xc3;
    Elf64_Phdr ph; memcpy(&ph, image + 64, sizeof ph); ph.p_flags |= PF_W; memcpy(image + 64, &ph, sizeof ph);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count)); ph.p_flags = PF_R | PF_X; memcpy(image + 64, &ph, sizeof ph);
    Elf64_Shdr sh; memcpy(&sh, image + 128 + sizeof sh, sizeof sh); ++sh.sh_offset; memcpy(image + 128 + sizeof sh, &sh, sizeof sh);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count));
    control_image(image, table); assert(!leaf_elf(image, sizeof image - 1, table, 4, pages, &count));
    memcpy(&sym, image + 512 + 4 * sizeof sym, sizeof sym); sym.st_name = 0; memcpy(image + 512 + 4 * sizeof sym, &sym, sizeof sym);
    assert(!leaf_elf(image, sizeof image, table, 4, pages, &count));
}
static void leaf_control_canonical_page_union(void) {
    struct leaf table[3] = {control_leaf(0), control_leaf(1), control_leaf(2)};
    struct leaf_page pages[2]; unsigned count;
    table[1].va = 4096 * 3; assert(leaf_pages(table, 2, pages, &count));
    assert(count == 2 && pages[0].va == 4096 && pages[1].va == 4096 * 3);
    table[2].va = 4096 * 4; assert(!leaf_pages(table, 3, pages, &count));
    table[0].va = 8190; assert(leaf_pages(table, 1, pages, &count));
    assert(count == 2 && pages[0].va == 4096 && pages[1].va == 8192);
    table[1].va = 8200; assert(leaf_pages(table, 2, pages, &count) && count == 2);
    table[0].va = UINT64_MAX - 15; assert(!leaf_pages(table, 1, pages, &count));
}
static void leaf_control_all_values_and_guards(void) {
    static const unsigned char data[] = "\"1 2\", 3";
    struct input input = {.length = sizeof data - 1, .fields = 2}; memcpy(input.data, data, sizeof data - 1);
    uint64_t expected[4] = {2, 8, 3, 2};
    assert(fields(input.data, input.length) == 2 && checksum((const unsigned char *)"", 0) == UINT64_C(14695981039346656037));
    for (unsigned i = 0; i < 4; ++i) assert(leaf_truth(i, &input) == expected[i]);
    struct leaf_result row = {guard, {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX}, guard};
    for (unsigned done = 0; done <= 4; ++done) {
        if (done) row.values[done - 1] = expected[done - 1];
        assert(leaf_values_ok(&row, expected, done));
        for (unsigned i = 0; i < 4; ++i) { row.values[i] ^= 1; assert(!leaf_values_ok(&row, expected, done)); row.values[i] ^= 1; }
    }
    row.left ^= 1; assert(!leaf_values_ok(&row, expected, 4)); row.left ^= 1;
    row.right ^= 1; assert(!leaf_values_ok(&row, expected, 4)); row.right ^= 1;
    assert(!leaf_values_ok(&row, expected, 5));
    input.length = 0; input.fields = 1;
    assert(leaf_truth(0, &input) == 1 && leaf_truth(1, &input) == 0 && leaf_truth(2, &input) == 0 && leaf_truth(3, &input) == 0);
}
int main(void) {
    leaf_control_table_and_last_selection(); leaf_control_complete_elf_selection();
    leaf_control_canonical_page_union(); leaf_control_all_values_and_guards();
    puts("LEAF_ORIGINAL_CONTROLS_PASS controls=4"); return 0;
}
