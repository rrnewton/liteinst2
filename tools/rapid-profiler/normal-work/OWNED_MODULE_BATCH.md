# Owned ordinary module batches

The first supported caller is the complete compiled `module_caller.c` profile:
four ordinary indirect calls, four result stores and one outer RET. It is not
arbitrary caller discovery. The byte/continuation/store oracle is shared with
the existing native module fixture, which remains unchanged.

Load the subject with `LoadedNormalModule::load_sealed_selected_pair`, prepare
and publish its real `NormalModuleSitePreparation`, and activate the existing
`PreparedNormalModuleSessionController`. Load the independently trusted compiled
caller using `LoadedNormalModuleCaller::load_sealed`. Then, on the actual calling
thread, consume the client in unsafe `attach_owned(caller, order, registration,
stack, journal)`. `order` is `[0, 1]` or `[1, 0]`, mapping request positions to
canonical increasing-ELF function indices. A path-backed subject is refused.

That once-only admission covers **every** pair of immutable byte slices of
length 0..=64: arbitrary bytes, empty inputs and overlapping immutable slices.
Both target ABIs must be read-only, in bounds, nonrecursive and pointer-retaining
free for the entire domain. It also admits stack/save space, ordinary returns,
sole controlled entry, no signal/nonlocal exit/CET and continuous mapping and
permission ownership. Sealed backing does not protect against hostile unsafe
code modifying private executable mappings. These are explicit integration
contracts, not facts inferred from a digest or a callback count.

After admission, application work is safe:

```rust,ignore
let close = application.close_handle();
let inputs = NormalModuleInputs::new(csv_bytes, length_bytes)?;
let output = application.run_batch(inputs)?;
// output.values contains the four scalar results; output.sum wraps as u64.
// output.observations is the existing complete normal-module transfer.
close.request();                     // May also be sent from another thread.
let final_totals = application.finish()?; // Same-thread drain and explicit detach.
```

There is one SDK entry per application batch, with no wrapper around individual
selected calls. The static caller body bounds a batch to four calls before entry.
The original callback runtime observes 4 entries/4 pre-RETs/3 confirmations; the
real outer return permits one checked checkpoint to confirm the fourth. The
adapter checks actual continuation words, semantic function order, identity,
journal and sampled/unsampled conservation. It never requires four sampled rows.

Close linearizes against new batches. A close during Active permits that batch
to return and checkpoint but blocks every later batch. Only `finish` can set
Closed. A blocked invocation retains Active; error, panic or abandonment poisons
admission and retains owners. No timeout or Drop fabricates a return. Source,
caller, installed image and publication owners remain process-lived; this API
does not unload code or prove arbitrary-process quiescence. The existing public
unsafe attach/checkpoint contracts and strict snapshot-based fixture are unchanged.

## Explicit native integration control

`frontend_native::always_on::normal::module::owned::native::owned_module_native_four_call_batches_epochs_and_close`
requires one fresh reserved release libtest process, selected with `--exact
--ignored --test-threads=1 --nocapture`. This is an explicit native prerequisite,
not a skipped substitute for execution. The test uses the existing fixture file,
stack and affinity helpers, real sealed loaders/publication/session, three safe
batches across two epochs, 12 CALL/RET observations and 12 scalar stores, including
removed outcomes, report/reclaim and terminal close. Existing pure tests cover
wrong order/continuation, missing/extra observations, allocation refusal and close
during Active. The native test does not claim a hardware single-step or timing
qualification; the old full-state oracle remains separate.

The external owner builds the unchanged `csv_fields.c` + `strnlen.c` fixture with
`MODULE_FLAGS` from `evaluation/ordinary-module-native/reproduce.py`, and builds
the unchanged `module_caller.c` with `CALLER_FLAGS` from
`tools/rapid-profiler/verify_normal_interval.py`. It independently pins complete
ELFs, source/tool/dependency identities, exact selected extents and caller oracle,
copies distinct-inode expected files, and establishes inactive CET and exclusive
native/mapping ownership before running the test. No environment value supplies
that semantic approval by itself.

Required environment: `RAPID_OWNED_MODULE_{CANDIDATE,EXPECTED}`,
`RAPID_OWNED_CALLER_{CANDIDATE,EXPECTED}`, and canonical decimal
`RAPID_OWNED_CSV_{VA,LENGTH}`, `RAPID_OWNED_LENGTH_{VA,LENGTH}`,
`RAPID_OWNED_CALLER_VA`. The caller extent is fixed at 123. Absent or mismatched
inputs refuse. The test's original absolute wall deadline is 15 seconds;
external containment and cleanup remain the owner's responsibility.
