# Signal corpus (frozen at I1-H H1)

Every signal fixture of P1b I1-C through I1-G2, plus the I1-H
fixtures, under a stable ID. Each row gives the rule-matrix cell
the fixture covers, the oracle its test checks against, and the
SHA-256 of its exact bytes. Every test pins its fixture through
`tests/common/corpus.rs` before running anything, so changing a
fixture fails by ID until its row here is updated in a reviewed
edit. Fixtures whose bytes embed a run-dependent value are listed
as unpinned, with the reason.

## Oracles

- **native child**: the same bytes run natively in
  `liteinst-jit-signal-native-child`, with the same register,
  stack, and signal arrangement. Its guest-visible witness (the
  handler log, syscall results, ucontext words) must equal the
  translated run's. It is not a count oracle.
- **O1-S**: `liteinst_jit::o1::run_o1s` single-steps the same
  bytes natively in the remote fixture child, so the process
  signal state matches the translated run's. The kernel makes
  every delivery for real: the oracle re-injects each
  signal-delivery stop with `PTRACE_SINGLESTEP(sig)` and steps on
  through the handler, the restorer, and `rt_sigreturn`.
  - It counts every retired instruction and every retired
    conditional branch.
  - It credits an interrupted syscall the way the translated
    substrate does: once, at completion. A rewound restart is
    not credited; `-EINTR` is credited at the delivery.
  - It checks every step's decoded length and branch target
    against the next RIP the trap reports (the per-step RIP-delta
    check, coord7 Q4(b)). A mismatch fails the oracle.
  - Every differential test also runs O1-S and requires the
    following.
    - Its witness equals the native child's (a sanity check of
      O1-S itself).
    - Its counts equal the fixture's own instruction
      enumeration (its self-check).
    - The translated counts and final register image equal its
      own, with addresses compared as (region, offset).
- **pinned enumeration**: translated counts pinned to the
  fixture's instruction list, for shapes O1-S does not run:
  refusals, which have no native completion to compare.
- **named refusal**: the exact recovered stop or `Refuse` value
  the stage defines for an unadmitted shape, and where it says
  so, the native errno.
- **kernel readback**: the tracer's mirrored registry compared
  with what the kernel reports, for I1-C.
- **O1-S at k** (I1-H sweep): an arrival placed at a generated
  PC by the hardware-breakpoint seam is delivered translated.
  The seam records the recovered `(src_pc, instructions,
  branches)`. O1-S then sends the same signal after exactly
  `instructions` retired steps. Both runs must agree on:
  - the full handler-visible frame (siginfo, all 18 ucontext
    registers, the saved mask);
  - the final register image;
  - the counts;
  - the guest buffer.

### Known common-mode risk (coord7 Q4(a))

O1 and O1-S build their decoder with the same shared
`liteinst_x86::decoder64` as the translator. Their step
classification is their own: `src/o1.rs` imports no translator
module, and `o1_oracle_imports_no_translator_classification`
checks that from the source module graph. Instruction counts come
from single-step traps and need no decoding. Branch counts use
O1's own classification applied to the shared decode, so a shared
decoder error is a **common-mode risk for branch counts only**.

The per-step RIP-delta check bounds that risk:
- a wrong length on any retired instruction fails;
- so does a real branch, decoded as a non-branch, that is taken.

What the check cannot catch:
- a non-branch decoded as a branch (its fall-through looks
  correct);
- a real branch decoded as a non-branch that is never taken in
  the run.

Capstone cross-decoding stays optional, for the case where the
check ever disagrees (coord7 Q4(c)).

## Allowed refusal windows at H1

The sweep classifies each arrival's generated PC by its PC-map
class. At H1 the only named refusals it allows are:

- **W1**, the common exit: `resume_gen` refuses common-exit
  stages, so the run ends with a recovered AsyncSignal at the
  exit's source PC. `w1_common_exit_arrival_is_named_refusal_today`
  pins this at each of the mixed body's four post-install exits
  (the helper's `ret`, `write`, `cpuid`, main's `ret`), which are
  the common exit's hits 2 to 5; there is no hit 6;
- **W2**, generated PCs with no PC-map entry. This class is
  **empty** in the remote substrate:
  `w2_remote_translation_maps_every_generated_byte` shows that
  every byte the remote translation emits lies in exactly one
  PC-map entry, because the tracer enters blocks by setting
  registers and there is no generated entry bridge;
- **W3**, an arrival while the tracer steps an original
  `cpuid`. The breakpoint cannot place this one; it is held by
  the pre-original-step seam.

W5 (a stale mirrored mask during a handler) is held by
`w5_stale_mirror_stops_in_handler_today`. W1, W3 and W5 are closed
in H2, and their held tests then flip to delivered-and-equal.

## Regenerating hashes

Run the tests with `LITEINST_CORPUS_RECORD=/abs/path/file`. Each
pin then appends `ID SHA256` to that file instead of asserting.
Diff the result against the table and edit only the rows whose
fixture change was intended.

## Fixtures

| ID | Stage | Test | Cell | Oracle | SHA-256 |
|---|---|---|---|---|---|
| `C1 registry round trip` | I1-C | remote_registry.rs check_registry_round_trip | USR1 action install/query, mask set/query, altstack set/query; no delivery | kernel readback | `f13e0cf100d92f674a3566ac8ed48ef9a61a512079e936c0b961030cb4649fdc` |
| `C2 poll with handler` | I1-C | remote_registry.rs check_poll_with_handler_installed | USR1+USR2 blocked and self-sent with a handler installed, run past two polls; counter control | kernel readback + pinned enumeration | `3bb59bfb02e2be29e9c6a8f21cb9a9561c93d6932491b352123079a9c6b54bec` |
| `C3 oldact EFAULT action` | I1-C | remote_registry.rs check_oldfault_mutations | rt_sigaction installs, then copy-out EFAULT; the run ends there | kernel readback | `4d0718ee3c93e18ed91fd40b58b5208f115116b15cff15240322a3e8f63eb390` |
| `C3 oldact EFAULT action control` | I1-C | remote_registry.rs check_oldfault_mutations | same, plus a guest query | kernel readback | `d5563090b6d72544c8b9416a2595861fac5a17ec6c2770e099d452e9f01c5ef0` |
| `C3 oldmask EFAULT` | I1-C | remote_registry.rs check_oldfault_mutations | rt_sigprocmask sets the mask, then copy-out EFAULT | kernel readback | `61e27d7ad335d3a8e99b77ced9cf3b138890f7d5083d53b8b833052ad082b359` |
| `C3 oldmask EFAULT control` | I1-C | remote_registry.rs check_oldfault_mutations | same, plus a guest query | kernel readback | `b07f40abf94abbc8ab10738f83cb4b037c4a862d662d89c98323bdf846a311bf` |
| `C3 oldalt EFAULT` | I1-C | remote_registry.rs check_oldfault_mutations | sigaltstack sets, then copy-out EFAULT | kernel readback | `9845401a6583d7cf79af280b97f5c0f4652ab786ef3f8e9fa4c62786a3e634c1` |
| `C3 oldalt EFAULT control` | I1-C | remote_registry.rs check_oldfault_mutations | same, plus a guest query | kernel readback | `190d4dae9f0bfa7040b68f7123df2a8d4765bb0ef157805fee78184a17498cc6` |
| `C4 normalization` | I1-C | remote_registry.rs check_normalization_and_bad_inputs | dirty act words, SA_ONSTACK altstack readback | kernel readback | `c8c6a99f97b7ed7bf451e03eb0c5980eafdde694bc26eeb8b7b73cb46ee73b65` |
| `C5 partial act partial-default` | I1-C | remote_registry.rs check_normalization_and_bad_inputs | act straddling a PROT_NONE page (default word) | kernel readback | `7b9dc01426d860313b928c419ef712b5b0c7d2d7d183b9798732b7f142974989` |
| `C5 partial act partial-handler` | I1-C | remote_registry.rs check_normalization_and_bad_inputs | act straddling a PROT_NONE page (handler word) | kernel readback | `b5cbc4b00b67c482019ec54e90b426833e6eb826ddda416f1b5d032bde1744a6` |
| `D1 round trip` | I1-D | remote_signal.rs check_round_trip, check_no_send_control | USR1 blocked at spawn, parent kill, SA_SIGINFO handler, guest unblock; frame RIP/RBX/RSP/EFLAGS, ucontext R13 mutation | native child + O1-S | `a7baf981d2a9db600af00852bef1cfbe795e49550adf292bc981423c2a6dd26b` |
| `D2 ineligible no SA_SIGINFO` | I1-D | remote_signal.rs check_ineligible_shape | handler without SA_SIGINFO | named refusal | `b83201703ae11d621430a333583ac927838d9e7d08ae2f75507201e8a62af77d` |
| `D2 ineligible SA_RESETHAND` | I1-D | remote_signal.rs check_ineligible_shape | SA_RESETHAND handler | named refusal | `e6689315a7788e4d0d15e539c020cd5d87d243bc5a769b49cbbf153bbc98a452` |
| `D2 ineligible NOP-prefixed restorer` | I1-D | remote_signal.rs check_ineligible_fixture | restorer not the exact sigreturn trampoline | named refusal | `e93e4e27e9a0f48cfdaf69cc76729d0735ee3eddb1cb721274ad4b508753d9bc` |
| `D3 alias install` | I1-D | remote_signal.rs check_alias_install_mirrored | rt_sigaction through a high-32 syscall-number alias | native child + O1-S | `8ae651b858b93c82cfaa79daf66483530c9f9bbdda8c0e4c8d8f5744a6f01866` |
| `D4 oldact sentinel` | I1-D | remote_signal.rs check_oldact_sentinel_on_error | failed rt_sigaction query copies nothing out | kernel readback | `5011b36208e35af8fe786e640ff4f1eb6878dfa2d0f89f909034d6f1c993d1dc` |
| `E1 sync SIGSEGV` | I1-E | remote_signal.rs check_sync_segv | synchronous SIGSEGV at a copied load, handler repairs the frame | native child + O1-S | `c7cdfc1ac26f870e274e9583b4afbd78ccc1c87fe20134acd60c14fb1458e53f` |
| `E2 sync SIGFPE` | I1-E | remote_signal.rs check_sync_fpe | synchronous SIGFPE, si_addr in source form | native child + O1-S | `32f06475f1afd910949798ed47aa4cabf30ae17de144019c4f4575f0d88ffcb5` |
| `E3 async arbitrary phase` | I1-E | remote_signal.rs check_async_arbitrary_phase | 600 timed kills; completion and PC range only (timing-dependent; the H1 sweep is the deterministic replacement) | completion only | `e836ea1924a1c884adf487b77dafa1edb8f8d5e3b90a4418ab127c4d87bc6f8b` |
| `F1 SIGUSR2 round trip` | I1-F | remote_signal.rs check_usr2_round_trip | SIGUSR2 round trip | native child + O1-S | `cb83f644e435733168ebdb9d8c461361f4720b3b95da6beb8f56dc2dc03b00e6` |
| `F2 mask nodefer=false` | I1-F | remote_signal.rs check_mask | sa_mask applied, in-handler mask query | native child + O1-S | `4944ea02f08423aafa872f0295b9cfe6d63b0f661f19be88bdc3c1a1a439f1e1` |
| `F2 mask nodefer=true` | I1-F | remote_signal.rs check_mask | sa_mask with SA_NODEFER, in-handler mask query | native child + O1-S | `0f282c180d2985ae0aca3e1ca160ceebb024b81154628395682ffda1cd10d416` |
| `F3 altstack` | I1-F | remote_signal.rs check_altstack | SA_ONSTACK frame on an 8 KiB altstack | native child + O1-S | `8736807aa693c7daa4f3a663278a20fa63fa12ec67dd8e4b9476db07335797bf` |
| `F4 nested distinct` | I1-F | remote_signal.rs check_nested_distinct | distinct-signal nesting by self-send, LIFO order | native child + O1-S | `a37b1897760c67c24c9abbc333ea6e61560a725357f106346721d8669920066b` |
| `F5 same-signal reentry` | I1-F | remote_signal.rs check_same_signal_reentry | SA_NODEFER same-signal reentry | native child + O1-S | `992e5cca9109849fd772421c8d5045cc2508955bf7e0dc11308b828c8b01b160` |
| `F6 disposition change` | I1-F | remote_signal.rs check_disposition_change | disposition change under a live frame | native child + O1-S | `232f9bef906d51dd3737967c59aa3da36248e9b4c8df176a9de9cf1141363250` |
| `E1` | I1-G1 | remote_signal_rt.rs rt_order_retention_and_coalescing_match_native | lowest first, RT FIFO, standard coalescing, kill-sent RT, forged-sender SI_QUEUE; 6 deliveries | native child + O1-S | `4f3ee5a92df7ea1e2eac1d33d549c324e455ae6d6cd15d28f01bf12a6742b567` |
| `E2a` | I1-G1 | remote_signal_rt.rs back_to_back_standard_frames_match_native | kernel back-to-back standard frames | native child + O1-S | `64c859812f5105c709bb27dfb20ab273ca097179cc31b9a64ce34a5dd513453f` |
| `E2b` | I1-G1 | remote_signal_rt.rs back_to_back_rt_frames_match_native | kernel back-to-back RT frames | native child + O1-S | `ea703d34b1f231c9847bd0d095f2fdc12c681d53e1edeb54494cb0a4cd046bad` |
| `E2c` | I1-G1 | remote_signal_rt.rs back_to_back_ineligible_stops_at_source_handler_entry | back-to-back onto an ineligible (SA_RESETHAND) action | named refusal | `80053fe0fc097380edb8c80dcd9aef26f4277af8783307f16a6e33b411585f79` |
| `E3` | I1-G1 | remote_signal_rt.rs tgsigqueue_private_first_and_payload_match_native | rt_tgsigqueueinfo private-first order and payload | native child + O1-S | `7c20badf0e32824522f96f7ea419dd627ff7b795ae6b79b602b73fd8aa402e14` |
| `E3b kernel-refused queues` | I1-G1 | remote_signal_rt.rs kernel_refused_queue_calls_get_native_errno | queue calls the kernel refuses (foreign tgid/tid, forged code) | native errno | `1e13bbc970f6c9814e5b133f91be957a905593b4bcfed64fcee397ea39fb0779` |
| `E4b SI_USER` | I1-G1 | remote_signal_rt.rs forged_sicode_to_self_refused_by_name_diverging_from_native | forged si_code SI_USER to self | named refusal | `78655f934e79df3bc1958de21faecdbace06377776587bc4e512f909f6633a26` |
| `E4b SI_TKILL` | I1-G1 | remote_signal_rt.rs forged_sicode_to_self_refused_by_name_diverging_from_native | forged si_code SI_TKILL to self | named refusal | `77218ad4c7c51f62770c0482f4b5c16782c88083927e2a93f2bf1afd3a1a9fbf` |
| `E4b SI_KERNEL` | I1-G1 | remote_signal_rt.rs forged_sicode_to_self_refused_by_name_diverging_from_native | forged si_code SI_KERNEL to self | named refusal | `d7282290db84b5846daf869e2b9b5ecdc2cb49bd52c84ff0f03a76e03d8bd3c7` |
| `E4b positive 1` | I1-G1 | remote_signal_rt.rs forged_sicode_to_self_refused_by_name_diverging_from_native | forged si_code 1 to self | named refusal | `ed756264b358db7e659870cc12970ace40a542983f22ccca958f9a43d78778e1` |
| `E4b tg SI_KERNEL` | I1-G1 | remote_signal_rt.rs forged_sicode_to_self_refused_by_name_diverging_from_native | forged SI_KERNEL through rt_tgsigqueueinfo | named refusal | `645c51291bd90ed304f7249b37bc8154cb8e5678040f2d34736eae00eeafdbf7` |
| `E4c pid` | I1-G1 | remote_signal_rt.rs sigqueue_to_foreign_target_refused_by_name_even_where_native_errs | SI_QUEUE to a foreign pid | named refusal | `c7fa9f43b39d16677ea79673a23ee55785fb46cc6c7381fbba5fa3a55168cca4` |
| `E4c tid` | I1-G1 | remote_signal_rt.rs sigqueue_to_foreign_target_refused_by_name_even_where_native_errs | SI_QUEUE to a foreign tid | named refusal | `78e5281e66b30d2b83e966a5567d97cfcc5eef1041dc7d9c1b6207954474f849` |
| `E4d queue 32` | I1-G1 | remote_signal_rt.rs reserved_32_33_refused_for_queue_and_delivery | queue reserved signal 32 | named refusal | `7b8723bd7a46510e67cd3f77eebfd1d29d9bdb4639d8244dcdae153fb10f01d5` |
| `E4d queue 33` | I1-G1 | remote_signal_rt.rs reserved_32_33_refused_for_queue_and_delivery | queue reserved signal 33 | named refusal | `84d6060262873841a757f11cafcb55a067e9d4069d428abfd885eb7621aa0ede` |
| `E4e deliver 32` | I1-G1 | remote_signal_rt.rs reserved_32_33_refused_for_queue_and_delivery | deliver reserved signal 32 to a custom handler | named refusal | `fcc295d4ce62a273bb2a543268d3f680102200fb01ad186c554b0dd029115eed` |
| `E4e deliver 33` | I1-G1 | remote_signal_rt.rs reserved_32_33_refused_for_queue_and_delivery | deliver reserved signal 33 to a custom handler | named refusal | `c9c58a9f715f2ededd958d58dfd47c871cda77d61dcf4015e209c80b24dc7c02` |
| `E4f RESETHAND` | I1-G1 | remote_signal_rt.rs rt_resethand_unreadable_unadmitted_refused | RT delivery to an SA_RESETHAND action | named refusal | `a6261181df36849260c0f60a858056aa666b0aa5963bb84b6e7f486cf8e47868` |
| `E4f+ SA_RESTART admitted` | I1-G1 | remote_signal_rt.rs rt_resethand_unreadable_unadmitted_refused | RT delivery to an SA_RESTART action | native child + O1-S | `a64cda52fd4f72f4271247c84ad2f9d1545297b22c8292699fe2beac30a902dc` |
| `E4g unreadable` | I1-G1 | remote_signal_rt.rs rt_resethand_unreadable_unadmitted_refused | rt_sigqueueinfo with an unreadable siginfo | named refusal | `64df3b1e4b735ed9b7e0a26639a75324e7bcad094e5d12256d8d07f617feee13` |
| `E4h` | I1-G1 | remote_signal_rt.rs mismatched_si_signo_is_overwritten_like_native | queued si_signo differing from the signal | native child + O1-S | `605e6ce876accfa507e4909c94749248b44d8262610a94e800395fa7e3b230fd` |
| `E4i unadmitted SIGTERM` | I1-G1 | remote_signal_rt.rs rt_resethand_unreadable_unadmitted_refused | queue an unadmitted signal (SIGTERM) | named refusal | `28cac56ec587718f1f1abf062e4ffba6845e323ae8926a4fb7b0a7a466a2466d` |
| `E5a rt_sigqueueinfo rdx` | I1-G1 | remote_signal_rt.rs async_stop_before_sigqueue_entry_keeps_guest_info_pointer | async stop before a redirected rt_sigqueueinfo entry | named refusal (pre-step seam) | `f9ec08c68b529c34c360aff180fc9ddeefa055cc8aba9e3aa0ff99ce5f34b133` |
| `E5b rt_tgsigqueueinfo r10` | I1-G1 | remote_signal_rt.rs async_stop_before_tgsigqueue_entry_keeps_guest_info_pointer | async stop before a redirected rt_tgsigqueueinfo entry | named refusal (pre-step seam) | `9c3954d895fc8beb621ae32a8cb7941fecea8d3389ed40375e5cfb2b6afad377` |
| `E5c rt_sigaction rsi` | I1-G1 | remote_signal_rt.rs async_stop_before_sigaction_entry_keeps_guest_act_pointer | async stop before a redirected rt_sigaction entry | named refusal (pre-step seam) | `a9c1f631f4329e587683771447a4c22d14a0b45eba59b886cd6717ace7d23389` |
| `E5d seam inert` | I1-G1 | remote_signal_rt.rs pre_step_test_seam_is_inert_by_default | pre-step seam off by default | pinned enumeration | `990a0493b1e0542650337c973576b56c31c7b10ddf9cec4c796ee3c9e8a2ca15` |
| `G2a` | I1-G2 | remote_signal_rt.rs sigsuspend_interrupted_returns_eintr_like_native | rt_sigsuspend interrupted (-ERESTARTNOHAND to -EINTR) | native child + O1-S | `37c742909d488a47b9d2dda679387f106b32ce40a19fc3f8f380886ba618dfc6` |
| `G2a SA_RESTART` | I1-G2 | remote_signal_rt.rs sigsuspend_interrupted_returns_eintr_like_native | same with SA_RESTART (still -EINTR) | native child + O1-S | `f041c2d0dff2130c9ef51a1597e32a5fe7a739124884c6d037273227cb137203` |
| `G2e` | I1-G2 | remote_signal_rt.rs sigsuspend_back_to_back_frames_match_native | rt_sigsuspend releasing two back-to-back frames | native child + O1-S | `7dd4c63a89feb38ab7cef3b7a3730e79019e552ac7cd7ad86c1ac668e44a2a64` |
| `G2b restart` | I1-G2 | remote_signal_rt.rs futex_wait_restarts_only_with_sa_restart_like_native | FUTEX_WAIT_PRIVATE interrupted by an external sender, SA_RESTART restarts | native child + O1-S | `ac21fc3f2a288f01f998d483382f1b83b0b94027f5f0fbda3e46a80ef6f080f1` |
| `G2b restart at block start` | I1-G2 | remote_signal_rt.rs futex_wait_restarts_only_with_sa_restart_like_native | same, the syscall starting its own block | native child + O1-S | `58a8a5e92e645a3891fcd122f359e4bf7182defea7c08d2a092f6e80f9a0c2fe` |
| `G2c no SA_RESTART` | I1-G2 | remote_signal_rt.rs futex_wait_restarts_only_with_sa_restart_like_native | same without SA_RESTART (-EINTR) | native child + O1-S | `a6d1116f80580e6c82ecc57e70167849538d7e257124ce7378340372512f7fa2` |
| `G2d` | I1-G2 | remote_signal_rt.rs nanosleep_restartblock_is_eintr_even_with_sa_restart | nanosleep interrupted: RESTARTBLOCK is -EINTR even with SA_RESTART; remainder bracket | native child + O1-S | `4cdae5dbb956bfc6ba8945e20e54c8c114cf2cd326cc25c8a9c67cc529f45952` |
| `G2f futex RESTARTSYS` | I1-G2 | remote_signal_rt.rs no_handler_restart_refused_by_name | interrupting signal with no handler during futex | named refusal | `43d9829c25e08b656ad458c1a8e9fbd5e3264b02ab85214996f91718d1624c50` |
| `G2f nanosleep RESTARTBLOCK` | I1-G2 | remote_signal_rt.rs no_handler_restart_refused_by_name | interrupting signal with no handler during nanosleep | named refusal | `88835379f813c7c4cf1101cf43da37d676a0b54af910604a61783351d66eeaba` |
| `G2g clock_nanosleep` | I1-G2 | remote_signal_rt.rs unadmitted_blocking_shapes_refused_at_syscall | clock_nanosleep not passed through | named refusal | `2651de778b65d5f42f501b61e1f4347e49212c0c77679d7ec4001e10d3ad16ad` |
| `G2g FUTEX_WAIT_PRIVATE with timeout` | I1-G2 | remote_signal_rt.rs unadmitted_blocking_shapes_refused_at_syscall | timed futex wait not passed through | named refusal | `a01452650e2af9b0727dfd8088f2a8aa5d280ebb9dcc5a1a1c83be63c84b0475` |
| `G2g FUTEX_WAIT (shared)` | I1-G2 | remote_signal_rt.rs unadmitted_blocking_shapes_refused_at_syscall | shared futex wait not passed through | named refusal | `bbac947e767f22314a1095cc61805166c81efbc2a5bea1bc7870bf2ff7cb0ff7` |
| `G2g FUTEX_WAKE_PRIVATE` | I1-G2 | remote_signal_rt.rs unadmitted_blocking_shapes_refused_at_syscall | futex wake not passed through | named refusal | `5d85a1e242a4abf681d659912dbb5b5b06082d6003ef14c43326be9619540da1` |
| `G2h interrupted write` | I1-G2 | remote_signal_rt.rs interrupted_write_outside_restart_set_keeps_named_stop | blocking write outside the restart set, interrupted | named refusal + native child | `e89f47b0bedc1d3b8bf1f8c252f40cd2095a75964e4ae28089723c5fe0e2d1a5` |
| `G2i` | I1-G2 | remote_signal_rt.rs futex_high_alias_restarts_like_native | futex through the 0x1_000000ca alias, SA_RESTART restart | native child + O1-S | `ef11c049a2f467287700d4b86c26855b6eb2a49f5a64562d14f72e84e7699da4` |
| `G2j sender sleep proof` | I1-G2 | remote_signal_rt.rs sender_waits_for_sleep_not_syscall_entry_stop | harness: the sender waits for a real sleep, not a syscall-entry stop | harness proof | `43d9829c25e08b656ad458c1a8e9fbd5e3264b02ab85214996f91718d1624c50` |
| `W4` | I1-H W4 | remote_signal_rt.rs blocked_pending_signal_survives_polls_and_delivers_on_unblock | USR1 blocked, self-sent, run past two polls, delivered at unblock | native child + O1-S | `255c6e3ed97e595b77221232acf4c6e73aceb82e4358aa44b98d3803a1ebba5b` |
| `W4-RT` | I1-H W4 | remote_signal_rt.rs blocked_pending_rt_signal_survives_polls_and_delivers_on_unblock | same with SIGRTMIN | native child + O1-S | `17d7f54be7ef5ac91c6b825fe033cddf165061eb8b74cba9879be41fdcbb1a2a` |
| `H1 sweep mixed` | I1-H H1 | remote_signal_gate.rs sweep_mixed_exhaustive, w1_*, w3_* | every (generated PC, hit) after the install, every PC-map class; W1 and W3 held | O1-S at k | `52756a1c79aac1284ee0d419f562733ac492ec6bae225392491c3aefc2834248` |
| `H1 sweep loop 120` | I1-H H1 | remote_signal_gate.rs sweep_poll_loop_sampled | N=256 seeded (PC, hit) sample, plus the first pair of each executed class the sample missed, over a poll-crossing loop (poll budget 16) | O1-S at k | `33eaa465bc6d8c088f5e15a131aca8f4e36d218a9543b22ee67c1303d31823d9` |
| `H1 W5 stale mirror` | I1-H H1 | remote_signal_gate.rs w5_stale_mirror_stops_in_handler_today | handler sa_mask blocks USR2, self-sent, poll inside the handler | held named stop (flips in H2) | `05ffae9f92ddc2612063f2fad41ba3c0e431b802e208a74e57b6adc529cde1df` |

Unpinned: `E4c real foreign helper` (I1-G1, remote_signal_rt.rs sigqueue_to_foreign_target_refused_by_name_even_where_native_errs): the bytes embed the live helper's pid.
