KORTESTQ covers the canonical five-byte VEX spelling `c4 e1 f8 98 /r`, iced Code1935, with two mask-register sources. Both source roles include k0 through k7. The fixed population is eight self pairs and eight cyclic cross pairs at each of five fetch tails: 80 native/TF pairs, plus one unchanged startup pair in each of five processes. The observed libc spellings `c4e1f898c9` and `c4e1f898db` are included literally.

Each case asserts the exact 64-bit OR, ZF when that OR is zero, CF when it is all ones, and cleared OF/SF/AF/PF. Every other flag bit must equal its input. Zero, all-one, complementary and mixed inputs exercise all three possible ZF/CF outcomes; initial arithmetic flags and DF vary. The original full native/TF comparator is unchanged. All16 GPR, all8 K, all32 ZMM, original RSP, selectors, FS/GS, signal mask, initialized kernel FP, complete live XSAVE, stack/data and source bytes remain checked. KORTESTQ changes no register or memory bytes.

The full-vector entry/capture assembly is reused directly from `tests/vpxorq128/fixture.S`, and the generic owner/comparator from `tests/generic/fixture.c`. The donor's stronger actual F/BW/VL/BMI2 hardware profile remains required; KORTESTQ itself requires AVX512BW. The fixed21-slot record stores17 occupied samples, with every unused positive/negative slot zero. Each group has32 actual-before NONE-footprint queries. Each process keeps the original5 CPU-second,15 wall-second,512MiB address-space and16MiB file limits on one reserved CPU.

All177 donor refusals remain mandatory, along with the original Code2785 promotion and10 typed Code2791/NONE supplied promotions. Their original bytes and the existing promotion parser's `bzhi` donor selector remain exact. The new29 neighbors reject memory forms, other widths, vector length, VEX fields, legacy prefixes, truncated instructions and alternate encodings. Existing BZHI/vector and other qualification suites remain separate requirements; this fixture does not replace them or grant data-memory fault, application or performance credit.

Intel's KORTEST reference defines `TMP[63:0] := DEST[63:0] OR SRC[63:0]`, ZF/CF as above, and OF/SF/AF/PF zero: https://intel.github.io/SDM/data/sdm/KORTESTW-KORTESTB-KORTESTQ-KORTESTD.docbook . The source packet retains the exact fetched document and its digest.

After promotion, run on one allocated CPU:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B evaluation/inprocess/page_selected_kortestq.py --expect-revision FULL_COMMIT
```

The evaluator retains actual compiler/header/archive/ELF identities, complete raw records and process/capture/source closure. Its public projection contains counts and hashes. The Python record reader authenticates the complete emitted C oracle and its full records, CPUID and footprint observations; it is not a second independent implementation of the C full-state comparator. Actual execution status belongs to the resulting receipts.
