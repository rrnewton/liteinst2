# Saved-target RET ordering diagnostic

This additive experiment observes five targets through three real-C3 routes: an unstepped original RET, the original RET with owned TF, and a private real RET consuming the once-loaded target with owned TF. The saved-target route poisons the original guest word after the one observed load, then seals the separate operand page read-only. It never rereads the original word. This is a finite hardware ordering diagnostic; it does not install a production pending owner, drain generated domains, deliver translated guest faults, or prove asynchronous recovery.

Use Linux x86-64, Python 3.11+ with assertions, GCC, GNU binutils and glibc. Keep one external CPU reservation and a clean checkout at the same full revision for the prerequisite and this command. The explicit `--cpu` must match singleton inherited affinity; the runner does not reserve a CPU itself.

First produce the complete [public RET observations](../ret_dispatch/README.md) at that same revision, CPU and hardware, including its original CALL217 prerequisite. Keep its complete private receipt, raw captures and artifacts. Supply that receipt and its whole SHA-256 below. This diagnostic reauthenticates the producer's fixed three-stage schedule and closure, then joins the complete RET32 reader result to the actual 32-lane PID/CPU/raw chunk. RET671 and RET16/24 remain separate finite results; neither grants production continuation authority. No archive is copied or built by this diagnostic.

```sh
python3 -B evaluation/inprocess/ret_resume_native/run.py \
  --expect-revision FULL_COMMIT_SHA \
  --ret-receipt PATH_TO_CLOSED_PUBLIC_RET_RECEIPT \
  --ret-receipt-sha256 FULL_RECEIPT_SHA256 \
  --cpu RESERVED_CPU \
  --output target/evaluation/inprocess/ret-ordering-attempt-1
```

The output must be new. There is one fixed 15-lane chunk and no selector or retry. The four producer/reader/recipe files and the load inspector are byte-identical to the reviewed successful private experiment. The portable runner changes source/prerequisite/path binding and adds a compact summary; it has not been executed. All semantic comparisons remain strict.

The existing bootstrap inspector checks the complete emitted reload/return machinery. The additional file-only inspector reconstructs every instruction byte of the complete actual handler from its ELF and disassembly, checks the exact frame prologue, and requires the five-instruction schedule: record original-SP pointer to RSI, record private-cell pointer to RDI, one qword load `[RSI]` to RAX, the checked handler-local store, and the same RAX to the saved-value record. No intervening instruction is skipped. The disassembler's recorded whole-file identity remains pinned; an unavailable or different tool, compiler schedule, unknown dependency form or missing byte fails explicitly.

All compiler-M sources/headers, compiler/subtools, prebound selected link inputs, interpreter aliases and dynamic dependencies are retained and compared with the authenticated RET32 toolchain. The original two-source strict recipe is unchanged. Build/metadata commands retain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB output; native/inspection/reader commands retain 5 CPU seconds, 15 wall seconds and the same memory/output bounds. The existing process owner requires exit zero, reaping and complete descriptor closure. Whole source/input/mode/alias/loader-presence/affinity checks cover the run.

The targets are RX, mapped NX, unmapped, and two high noncanonical values on the observed machine. Each of the 15 lanes retains complete before/after integer state, 65,536-byte FP storage, actual ucontext/siginfo/kernel-mask joins, TLS, 16 KiB guest stack, private operand page and code pages. The TF routes must agree in their full logical state after the independently checked private-SP translation. The reader reports the actual NX/unmapped priority rather than assuming it. RX must stop before its first instruction; noncanonical target faults retain original logical SP. All five saved-word lanes must preserve the captured target despite the guest-word poison.

`receipt.json`, complete raw and reader captures stay private. `summary.json` publishes only checked per-lane outcomes/deltas/raw digests, source/hardware identities and closure. The [historical summary](../results/2026-10-31-ret-saved-target-ordering.json) preserves both failed preflight attempts and the successful diagnostic separately. The installed command above is a later unexecuted portable recipe, not the original executed private command. Original RET32, RET16/24, CALL gates, 392/522 and real-program/performance obligations remain unchanged and unqualified by this observation.
