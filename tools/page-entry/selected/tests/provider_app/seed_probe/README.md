# Independent x87 seed prerequisite

Run this prerequisite on the same reserved CPU and complete CPUID/XCR0/permission
profile as the native and gated application. Two distinct fixed-ELF
FNINIT/FLD1/FLDPI sequences produce four complete FXSAVE64 buffers: immediately
and after FNSTCW/FNSTSW. Exact nonempty tags, TOP, control and PI/one payloads
prevent a vacuous zero observation. All four buffers must be byte-equal and
FIP/FDP must be exactly zero. Different hardware behavior refuses this profile.

The enclosing process owner retains compiler/source/ELF identity, CPU, complete
stdout, empty stderr, exit status and reap under the existing native bounds.
`read.read(raw, elf, format_facts, xstate, cpu=..., pid=...)` authenticates the
profile. `read.require(...)` joins it to each lane; it cannot replace producer
or retained-byte authentication.

Native and gated readers then require exact zero FIP/FDP while retaining every
other seed/vector/tag check. Full native NT and unchanged B2 XSTATE comparators
still compare every architectural byte. No field is excluded or rewritten.
