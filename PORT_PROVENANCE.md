# LiteInst2 upstream port provenance

This port starts from LiteInst2 `4dab7f01d4d6d394e968fbfad842019f72743c81`
(`https://github.com/rrnewton/liteinst2.git`, `origin/main`). The only source
evidence is the working tree below:

- repository: Reverie
- path: `/home/newton/work/dev-hermit/worktrees/slots/dev-hermit-15-liteinst-bootstrap-rdtsc-01a0a13c`
- branch: `codex/liteinst-bootstrap-rdtsc-01a0a13c`
- preserved base and current `HEAD`: `6e3915b70a71657a08f0028b3f70d6074116206a`
- source subtree: `third_party/liteinst2`

The evidence tree is intentionally read-only, dirty, and not itself a LiteInst2
commit. Each input file is therefore bound by content hash. The manifest digest
is `61382f24a57f175eb5fa22ff781d99c8f8ceced577f7c57e56413809d47dff4d`.
It is SHA-256 over the 20 rows below, sorted bytewise and encoded as
`path<TAB>base_sha256<TAB>evidence_sha256<LF>` (2,989 bytes).

| Path | LiteInst2 base SHA-256 | Evidence SHA-256 | Port decision | Working SHA-256 |
| --- | --- | --- | --- | --- |
| `Cargo.toml` | `788de851082b1f2cf0f8d587a7d943bf290b5901443e4122d8cc9dffc1a3b870` | `61fada4252477b281a61fc5834f8a8fe30e0e74c9cac8ea77c90327bf202140a` | Exclude Reverie workspace removal; independently include the existing decision-tree document in the package | `b4920c8b8d2ee32aeaddfffd9d27311909786a0291ceff649ea5fa392d824118` |
| `LICENSE` | `912009bd482d070e6a956100f44a301a7bf6b78d0fe713960e554aae82839743` | `912009bd482d070e6a956100f44a301a7bf6b78d0fe713960e554aae82839743` | Identical; unchanged | `912009bd482d070e6a956100f44a301a7bf6b78d0fe713960e554aae82839743` |
| `README.md` | `38faee77d4cf805b06864d3c0f1568057edaecd47ecf61269370c4bd30f7aeb1` | `4d689ed144bf305ccf88ff7c9df4355ab70add9b46e8e13c597a9ff67b4111cb` | Port selected generic behavior and update for repairs | `d568205cc536dc3101a720dd0d41737b283199518cda75c54b7aeecc3f72f88e` |
| `examples/preload-consumer/.gitignore` | `c1e953ee360e77de57f7b02f1b7880bd6a3dc22d1a69e953c2ac2c52cc52d247` | `c1e953ee360e77de57f7b02f1b7880bd6a3dc22d1a69e953c2ac2c52cc52d247` | Identical; unchanged | `c1e953ee360e77de57f7b02f1b7880bd6a3dc22d1a69e953c2ac2c52cc52d247` |
| `examples/preload_consumer.rs` | `1e4d36e8df68535e0e0da3b05341378636b6d8eb6f32614ca18b249cb2958b69` | `dae2cc6a6e32a2256280a858b63dd9a9cc913abf95d2dd42386736e38d3145f6` | Formatting-only evidence delta excluded | `1e4d36e8df68535e0e0da3b05341378636b6d8eb6f32614ca18b249cb2958b69` |
| `examples/replace_first.rs` | `8bba6a2736cd9a4b9c9eab398b1c933b470650dde8c75e281070626924d5d30c` | `34decb5232d281ae808d3f9d95892662e7abf17bb1af018cec4f05ba4f7e0554` | Formatting-only evidence delta excluded | `8bba6a2736cd9a4b9c9eab398b1c933b470650dde8c75e281070626924d5d30c` |
| `src/cache_line.rs` | `f4e4d36fc94dceef748185de79a84f6d440d2ef74ce947bd9ff57c1faee31567` | `f4e4d36fc94dceef748185de79a84f6d440d2ef74ce947bd9ff57c1faee31567` | Identical; unchanged | `f4e4d36fc94dceef748185de79a84f6d440d2ef74ce947bd9ff57c1faee31567` |
| `src/lib.rs` | `a198ae742eb00e7002820324311ab670960246a5863b2c90dc75098a12387ccc` | `a198ae742eb00e7002820324311ab670960246a5863b2c90dc75098a12387ccc` | Identical; unchanged | `a198ae742eb00e7002820324311ab670960246a5863b2c90dc75098a12387ccc` |
| `src/patcher.rs` | `235797c060148545cd60d940a3cd120754bf75e755f6d8526dce3f7babcf028e` | `15a9d45e877248bf216837b6a6b0f091b2c8962fef66dfd36f067aa1e0d1c889` | Port the generic signal-runtime API and close its publication window | `aa1688f6f932e37576d3110d6a8ada224e9756e1b7d5518b7bed739ea7932cc0` |
| `src/planner.rs` | `1b24dcec335fd48bb7ec8cbd76dd92224c6efe1b6d8f410266e8689bf181459d` | `a39a8cebdd5713670a29e83b4b35d4c5c28f58e31f7ec1b40529b0f4eb3798c4` | Formatting-only evidence delta excluded | `1b24dcec335fd48bb7ec8cbd76dd92224c6efe1b6d8f410266e8689bf181459d` |
| `src/probe.rs` | `81ca94b6e99e5b4145ca537a5d91b1ef172a0d83b593e689625247b96da09c21` | `81ca94b6e99e5b4145ca537a5d91b1ef172a0d83b593e689625247b96da09c21` | Identical; unchanged | `81ca94b6e99e5b4145ca537a5d91b1ef172a0d83b593e689625247b96da09c21` |
| `src/rapid.rs` | `160d3d20168e39d7b70bacae11e8a80071fe6f5967ead793b457cf7382e8972d` | `e35c2d5f00ed7b3ac8c70b9231dc0ddc02ab60c75ae91e8fc0db7c9c8139aa41` | Formatting-only evidence delta excluded | `160d3d20168e39d7b70bacae11e8a80071fe6f5967ead793b457cf7382e8972d` |
| `src/scanner.rs` | `1c4526c092d8f2093c3ae0dac8788bd86b519e03ed39b5ce23dce74fa3f42330` | `4b974c9ad9830563bec607ee2ba52843ea56a1b9ffb50cf365090554dcf3081b` | Formatting-only evidence delta excluded | `1c4526c092d8f2093c3ae0dac8788bd86b519e03ed39b5ce23dce74fa3f42330` |
| `src/trampoline.rs` | `a0d3bc38acc4078721cddc0eafe2ee2805c2cb4f2d21212cea614eb1df58eeeb` | `bfb28c713f5ad9565df9a0db83127d2b9acb6e7beb786828f6faf77e1432a979` | Port generic layout, arena, and ptrace-stop mechanisms with the repairs below | `a931cfd7b352911dba1729a73aad3e8378b1a30d0418f9784ff10622f7cf07a4` |
| `src/trap.rs` | `a8d08e8e3953348bbde0168342193fc56b3eef2b17df777499c89021b1768a03` | `2766aab0645d22e6c317337dcf54d8ba095a7e6aac4419bfa86eddebfb1dddd9` | Port generic signal runtime; atomically bind mode and publish under a blocked mask | `e3b6fc59cf5c990ef3cfc1293ab25c18375bd2cfe960a38f1fc879e62dd4b9eb` |
| `tests/arena_fork.rs` | `25eb7398188f0ebc62bcdbc663c8f53b263499d215ee64db47be57472370b5e3` | `47234def54217a43610145e765a5deec824d6e9acb00ccfad4c4a12afbae6fd5` | Formatting-only evidence delta excluded | `25eb7398188f0ebc62bcdbc663c8f53b263499d215ee64db47be57472370b5e3` |
| `tests/stress.rs` | `38deca827ba5aa3a89e515911d911c9f624e89a5a12726dde986360de92de88a` | `43edbc67f43bcb227f592b5599faec597f584c19608bda3c0503852f3bed3a44` | Port authenticated fault receipt while retaining full signal stress | `411456c3e63dfa6e67566fe0b53158f5b8d05d7b579fed74d77b664492bb8c5e` |
| `tests/support/arena_fork_fixture.rs` | `0a6fdd2bff1aece1e1ea8707032238b9e17099508fff690dd4b0edb49a9b1070` | `cc708de772af8cd665492e862ec1ac2a22c0b9a2886c0873cd4f02ab102303bf` | Formatting-only evidence delta excluded | `0a6fdd2bff1aece1e1ea8707032238b9e17099508fff690dd4b0edb49a9b1070` |
| `tests/support/trampoline_tail_fixture.rs` | `7c179dd8364706ebeb71c0235842061413da731ad67b1eb46eb88d87552ba4af` | `c1ad28f1f6c34901559c8c0e0ed2bb92dc5f8c9cfb74155d5e179fc74bba05b6` | Formatting-only evidence delta excluded | `7c179dd8364706ebeb71c0235842061413da731ad67b1eb46eb88d87552ba4af` |
| `tests/trampoline_tail.rs` | `68b53355d83d183a35a4979baabada327ceefee1dceade49a3bbc3f2924dc132` | `3834de137eb3db51fa697d40cff04290a18d4b0cce7502df15e81dcae756a74d` | Formatting-only evidence delta excluded | `68b53355d83d183a35a4979baabada327ceefee1dceade49a3bbc3f2924dc132` |

## Deliberate repairs to the evidence implementation

- Ordinary `InstalledHook` APIs retain automatic global program-counter
  publication. Only the new external-controller mode leaves publication
  explicit. The evidence tree had inverted the old positive assertion.
- The live stress test drives 30,000 unrelated `SIGTRAP` deliveries during
  installation and toggling under an admitted prior `SIG_IGN` disposition.
  The two post-install waves (20,000 signals) necessarily traverse the router;
  custom-handler refusal is covered separately by isolated negative tests.
- Stack reservation and release use flag-preserving `LEA`; the evidence used
  arithmetic instructions that corrupted application flags.
- The ptrace execution test controls the test-worker TID, not the process
  leader, and owns bounded process-wide cleanup. It checks both authenticated
  stops, the owned-stack HookContext and saved-state descriptor/image, GPRs,
  the exact kernel XSTATE image, restored application RSP, and exit value 41.
- Signal installation mode is claimed atomically. The host installer retains a
  blocked SIGTRAP mask until the prior action is published, then restores the
  exact prior mask. Forced concurrency and pending-signal controls reject mixed
  modes and close the handler-publication window. The callback-backed entrypoint
  is unsafe so safe Rust cannot violate its initialization or signal contracts.
- The saved-state layout itself drives save/restore encoding. This avoids a
  240-byte asymmetric internal enum without suppressing Clippy.

## Exclusions and preserved upstream material

All Reverie code outside `third_party/liteinst2` is excluded. In particular,
there is no Reverie backend, ptrace-task, process, preload, manifest, syscall,
or Cargo-workspace glue in this port.

The evidence-only `third_party/liteinst2/Cargo.lock` is excluded (SHA-256
`3511346f5727cd74467f762af0e9d445a1424a418dd3c8c6d7c1ae169a5ebf30`).
The upstream LiteInst2 lockfile remains byte-identical to the base (SHA-256
`02047ef9518aa41d9d2dd8e3170a42653b04d2ca571571dcefb588518bc33d4b`).
Generated `target/` content is excluded.

Upstream-only `.github/workflows/ci.yml`, `.gitignore`,
`PATCH_SITE_DECISION_TREE.md`, and the entire `tools/rapid-profiler` workspace
are preserved. The formatting-only rows called out in the table remain at
their upstream bytes.

## Complete port delta

The complete product delta is exactly `Cargo.toml`, `README.md`,
`src/patcher.rs`, `src/trampoline.rs`, `src/trap.rs`, and `tests/stress.rs`.
This `PORT_PROVENANCE.md` file is the only additional path. No other tracked or
untracked path belongs to the port; `target/` is ignored build output.
