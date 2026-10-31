# E9 startup/help parity failed

At `701c4c87`, the original printed 947 bytes of help and exited 0; the candidate died with **SIGSEGV (-11)** and empty streams. Each arm ran once with complete owner cleanup and zero rescues. [Exact receipt](receipt.json).

V1 refused the retained 0644 candidate before either ELF dispatch. V2 used a fresh 0500 copy with identical bytes; the capture and executable-mode check stayed unchanged. No native retry followed.

The candidate LOAD span is 8,857,190,400 bytes, above the fixed 1 GiB AS bound; summed LOAD memory is only 99,335 bytes. This suggests a load/address-space hypothesis, **not a proven cause**. No debugger ran.

[Script](../offline-corpus/run_e9_help_parity.py) bytes equal those executed. Keep it outside the clean exact-revision checkout, where it was not tracked. Supply absolute pinned inputs from the [backend result](../full-program-backend-result-v1/), an executable copy, and fresh OUT directly under target/evaluation.

Hold one HARD CPU within the 12-CPU lane cap. Expand receipt.outer_argv literally and submit it to evaluation/admission/processes.py::run_command with receipt.environment, a fresh target/evaluation log, wall60 s/log131072 B. Retain the owner through closure. The script enforces the recorded inner bounds and exact output/status comparison.

This finite help failure proves no all-2053-site coverage, whole-program parity, LI2 equivalence or performance. All prior failures remain failed; owner wall times are not CPU timings.
