The retained test ELF associated with source `fa12329fd56f2181083ca640a7ace55e37447830` contains a nested constructor path with **2,810,352 bytes (2.680 MiB)** of explicit frame reservations. The [typed static summary](results/runtime-kernel-stack-fa12329.json) preserves the failed run's status and distinguishes the manually executed inspection from the then-proposed reproduction recipe. The separately preserved [script result](results/runtime-kernel-stack-reproduced-fa12329.json) records the subsequent successful read-only reproduction.

| Function | ELF-relative entry | Explicit frame bytes |
| --- | --- | ---: |
| `RuntimeOwner::prepare_kernel` | `0xc4dea0` | 862,536 |
| `PreparedRuntimeKernel::new` | `0x8c4970` | 410,920 |
| `core::array::from_fn::<ControlProfile, 11, …>` | `0xa4f440` | 384,232 |
| `core::array::try_from_fn::<NeverShortCircuit<ControlProfile>, 11, …>` | `0xa47630` | 1,152,664 |

Each inspected prologue probes in 4 KiB decrements and subtracts its remaining tail. The three direct calls link these functions in order. Their sum is a lower bound on frame reservations along that nested path if reached; it excludes other callers, deeper callees, return addresses, and additional stack use. The constructor call precedes the caller's inner `catch_unwind` call. No recorded fault address, actual stack extent, or proof of reaching the deepest call is available. This evidence does not establish the SIGSEGV location or prove stack overflow, and it is neither native qualification nor a benchmark.

The unchanged failed receipt is [20261026T204700.391376Z-fa12329fd56f.json](results/20261026T204700.391376Z-fa12329fd56f.json), SHA256 `dec7b726d50369473da97db2d29b2016f70f32c9b5c852741ed273a4bbadf688`. Its private workspace log names the retained executable and records the isolated cross-page kernel test child as SIGCHLD / CLD_DUMPED / SIGSEGV with the expected PID. The workspace command failed; its supervisor reported complete cleanup with five adopted descendants reaped. The original receipt did not hash the ELF. The separate post-run inspection binds the artifact actually read: 135,708,392 bytes, SHA256 `754ca894d1d71fc437c9bd3f06201c1b51f0d37851c374353cbe87f548f1fe81`.

The manual `array_from_fn` disassembly stopped at `0xa4f4d0`; the proposed script stops at `0xa4f4a0`. Both include the same prologue and direct call edge. `saved_inspection_commands` records the actual saved commands, while `proposed_reproduction` describes the unexecuted recipe. The current summary was assembled from the saved disassembly and receipt; it is not output from an unrun script.

The [read-only inspector](inspect_runtime_kernel_frames.py) requires the exact preserved ELF, failed receipt, and private workspace log. The recorded reproduction used the following invocation, with private input and output locations replaced by placeholders. The invoked copy of the script had the exact content hash recorded below:

```sh
python3 evaluation/admission/inspect_runtime_kernel_frames.py \
  --elf EXISTING_ELF \
  --receipt FAILED_RECEIPT_JSON \
  --workspace-log PRIVATE_WORKSPACE_LOG \
  --private-dir NEW_PRIVATE_OUTPUT \
  --summary NEW_PUBLIC_SUMMARY_JSON
```

The script is tied to that artifact's exact hash, symbol addresses, instructions, and call edges. The source revision and receipt alone cannot recreate its binary hash, and the private ELF and log are required inputs rather than publicly supplied artifacts. A different build requires a separate reviewed record; matching function names alone is insufficient.

GNU `nm` and `objdump` 2.37 must be on the tool search path and match the embedded executable hashes. A compatible Linux environment, dynamic loader, and shared libraries are also required. Executable hashes do not authenticate or make those dependencies hermetic. Build toolchain and hardware descriptions in the summary come from the existing receipt, while inspection tool identities are recorded separately.

Inputs and tools are opened read-only, hashed, and held during inspection. The ELF is supplied only as data to `nm` and `objdump`; the script neither builds nor executes it. Captures are bounded to 16 MiB for symbols, 1 MiB per disassembly, and 64 KiB per version query. Each tool has a 30-second deadline and bounded kill/reap on failure. The ELF is capped at 256 MiB; the receipt and private log are each capped at 8 MiB. These separate inspection bounds change no qualification command, runtime budget, or test deadline.

Raw tool output stays private. The public JSON contains no filesystem locations or raw log lines. Publication uses a complete, flushed temporary followed by an exclusive atomic hard link: an existing destination is refused, and a write failure cannot leave a partial public summary. The source-reviewed script subsequently completed with exit code 0 using the exact preserved inputs. Its SHA256 was `55f4205017777c92bc26bef5aaf79dd5a00df972de0005f31a4a3a3dafcb4104`; the separate reproduced summary SHA256 is `f5d439a3a1b7235af52e314556ef8c048da3dc1fbd8a985695a97e4155184f9f`. The historical manual summary remains unchanged, including its description of the recipe as unexecuted at that time. No recorder inventory or native passing result is added by this static evidence.
