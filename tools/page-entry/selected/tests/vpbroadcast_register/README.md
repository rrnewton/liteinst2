Canonical unmasked EVEX512 VPBROADCASTB
======================================

This fixture covers all 32 ZMM destinations and all 16 source GPRs: 512 native/TF pairs in 32 processes, each with 16 broadcasts and one startup pair. The literal register matrix includes the observed ZMM17,ESI form. RSP is a real address inside the captured subject stack; its independently specified low byte is the broadcast input. All six fetch positions occur for RSP as well as across the matrix. The matrix has 84 page-ending and 428 crossing pairs. It does not claim all six geometries for every register pairing.

The existing `page_selected_vpbroadcast.py` is a mandatory companion at the same revision. Its 36 broadcasts still test six literal RSI values at all six fetch positions, plus two startup pairs. Its four former register-encoding refusals retain their exact byte rows and now require explicit Code3210/FALLTHROUGH/SIMD acceptance and a typed NONE footprint. The new matrix executes each of those four forms. All 47 common and 26 remaining original refusals are unchanged. Each matrix process also rejects a noncanonical X-bit encoding, including its typed footprint query.

Both lanes seed all 32 ZMM and 8 opmask registers. The C oracle compares complete native/TF GPRs, flags, selectors, FS/GS, kernel FP, live XSAVE, stack and data through the unchanged common comparator. Its independent effect check changes exactly 64 destination bytes; ZMM0–15 use three separately located standard XSAVE ranges. All other initialized bytes and header/BV fields remain exact. Each actual native and stepped before-frame also supplies a typed zero-write query. Source and endpoint pages must be NX on completion. No memory-operand fault, masked form, other width or performance claim is made.

Run both evaluators under one reserved CPU:

    python3 evaluation/inprocess/page_selected_vpbroadcast_register.py --expect-revision <full-commit>
    python3 evaluation/inprocess/page_selected_vpbroadcast.py --expect-revision <same-full-commit>

The new evaluator issues each of the 32 compile commands separately with the existing 5 CPU-second, 15 wall-second, 512 MiB address-space and 16 MiB file bounds. Native commands have those same unchanged bounds. It binds the current release decoder archive, actual compiler dependencies and lexical aliases, actual retained ELF record symbols, all raw records and final cleanup. The original 21 sample slots are retained: four unused slots and the separate negative sample must be zero. At the last qualified common sample size (721088 bytes), each new record is 15870600 bytes, and all 32 total 507859200 bytes; actual ELF sizes, not this estimate, control acceptance. The Python reader checks complete storage, CPUID/BV and query observations; it does not claim a second full architectural replay.
