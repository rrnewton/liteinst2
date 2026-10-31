# Private sealed source loading

`LoadedNormalModule::load_sealed_selected_pair` and
`LoadedNormalLeafSet::load_sealed_selected` accept the existing independently
trusted final-ELF selections. They apply the same complete ELF, selected CFG,
page-union, loaded-object and mapping-provenance checks as the original path
constructors. They do not discover functions or accept additional dynamic
dependencies, constructors, relocations or instruction forms.

The new constructors copy the complete bounded ELF into a private memfd, verify
the bytes, and require all four seals: WRITE, GROW, SHRINK and SEAL. The copy is
sealed before `dlopen`. Its descriptor, exact identity and loader handle are
retained for process lifetime, including after post-load refusal; none is
exported. File identity uses the retained descriptor's Linux device/inode,
including memfd internal mounts absent from namespace mountinfo. Every original
LOAD/RELRO permission, file-offset and inode check still applies. The original
path-loader/mountinfo route and strict qualification consumer are unchanged.

These are **unsafe constructors**. File seals establish backing immutability;
they do not freeze ld.so's private COW mappings or exclude foreign mutation,
unload or protection changes. The existing ABI, readable inputs, selected-entry,
quiescence, ordinary CALL/RET, no-CET, signal and continuous mapping obligations
remain explicit. No selected function is invoked by loading. This addition does
not implement an owning session rendezvous, safe attachment/return checkpoint,
executable reclamation, timing accuracy or the complete A5 application contract.

The `sealed_source_tests` module contains six controls using actual kernel seals
and a retained admissible DSO, without invoking its selected code. They cover
write/resize/seal/shared-writer refusal, missing seals and changed/truncated/extra
bytes, independent copies, both public loader constructors, contract refusals,
and complete loaded device/inode/offset/permission joins. Existing path-loader,
parser, publication and session controls remain required.
