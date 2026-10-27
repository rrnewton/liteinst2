# Controlled recording comparisons

The common-program replay supports an explicit `bounded-journal-v1` recording
profile for LiteInst, stock E9Patch, and the bootstrap-patched E9Patch reference.
It checks the effects of a selected hook before executing the original
instruction, including cases where that instruction faults.

The reference image and candidate start with the same initialized journal.
A selected hook must append exactly its original instruction PC; an unselected
head must leave the journal unchanged. Every comparison checks the complete
original LOAD image, including the 131,144-byte journal, guards, count, reserved
fields, and unused entries. The E9 comparison also derives all eleven words
left by its clean-call wrapper and compares the entire 64 KiB owned stack.
Registers, flags, canonical XSAVE, application data, mappings, faults, and child
closure retain their existing checks.

The native driver and witness commands select recording with the exact trailing
argument `--recording-profile=bounded-journal-v1`. The Python pair runners and
saved-content auditors accept `--recording-profile bounded-journal-v1`.
Their complete input and source bindings remain mandatory; a mode flag alone
does not admit an executable or a saved result.

Fresh canonical core verifiers include eight source members. Select their build
capability with `--verifier-capability bounded-journal-v1` in the core runner,
including for a null-hook run. This build capability does not enable recording:
the runtime recording profile is a separate argument. Legacy seven-source
verifier records remain tied to their historical builds.

The recording corpus has twelve artifacts: heap-write and jump-site selection,
each stripped and unstripped, for each of the three producers. Each artifact
requires 174 normal and two fault pairs: 2,112 pairs, 4,224 child executions,
and 6,336 state comparisons in total. The 704 core null-hook pairs remain a
separate requirement. These are corpus definitions, not reported results.

Callbacks use the existing 15-second, 20,000-stop child bounds. Their complete
code extent and executed instruction heads must match, control flow must stay
within the callback until its literal return, and the stack pointer must remain
unchanged before that return. Unsupported callback shapes refuse. Saved-content
audits check the complete callback bytes, path, journal, and stack effects;
intermediate callback register checks remain assertions in the live tracer.

These controlled comparisons do not establish execution through an arbitrary
ELF loader. Normally loaded tactic fixtures and whole-program output comparisons
are separate evidence cohorts. Keep raw captures under `ignored/`; publish only
the exact revision, reproducible commands, hardware, and compact numeric results.
