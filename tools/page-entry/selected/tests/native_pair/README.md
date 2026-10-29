# Two-page native execution oracle

This additive fixture compares the actual opt-in two-page owner with a native
signal reference executing the same fixed ELF and seeded architectural state.
It retains all GPRs, flags, initialized FP/XSTATE, source bytes, data, stack and
rseq page bytes. The independent reader models every leaf call and DEC separately.
No fixture observation grants publication or execution permission.

The fixed cases are 0 through 20, with a second case16 control. Cases0/1 are
unregistered; the remaining cases perform actual rseq registration. Native
and gated invocations share the same image: `image native` and `image`.
`build.sh METADATA OUTPUT CASE CONTROL` uses the required exact `LI2_CC`.
The enclosing evaluator owns construction, dependencies, one CPU, FD3, namespace,
source closure and the unchanged 5 CPU seconds/15 wall seconds/512 MiB/16 MiB limits.

The source requires real A/B/C NX, complete actual permission closure, genuine
first-byte refaults, selected CPUID/getpid boundaries, a real data fault and
nested tgkill. Cases12/20 deny real kernel revoke/sync operations using a
child-only filter. Case13 is separately a supplied sync result. Cases14 and
16/pin retain only a safe prefix before a supplied actual-word/pin mutation
on genuine ingress, followed by actual unsafe exit; they make no claim of
kernel-produced nonzero state. Copy/generation/overflow controls are supplied.

`prepare.py` produces exact, invertible observation views of the real production
translation units. `layout.py` reads full retained-ELF DWARF and an emitted
compiler member-alignment constant without starting an inferior. Complete
padding and unused fields remain part of the comparison. The native reference
performs real mprotect calls and compares complete actual frames around them.
The old one-page16, boundary4 and prerequisite6/49/17 populations remain separate
and mandatory; no old fixture, comparator, case or resource limit is replaced.
