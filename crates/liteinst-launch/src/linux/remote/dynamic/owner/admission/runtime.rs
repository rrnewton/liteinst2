//! Initial runtime admission custody. Source capture supplies Partial entries;
//! a ready owner has no executable page, installed guard or release permit.
use super::super::bootstrap::{InitialBootstrapShape, PreparedInitialBootstrap};
use super::census::{InitialRuntimeReservation, initial_runtime_origin_charge};
use super::runtime_capture::{InitialCaptureProfile, PreparedInitialSources};
use super::*;
use crate::linux::remote::MAX_XSTATE;
use std::mem::size_of;

mod dispatch;
mod execute;
pub(super) mod instruction;
pub(super) mod maps;
#[cfg(test)]
mod native_tests;
mod ordinary;
pub(super) mod selected;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeStartOptions {
    pub(super) capture: InitialCaptureProfile,
    pub(super) limits: DynamicAdmissionLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeStage {
    Allocated,
    OriginalCapture,
    BootstrapAllocation,
    Bootstrap,
    RuntimeCapture,
    Reauthentication,
    Catalog,
    Census,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimePage {
    pub(super) address: u64,
    pub(super) window: usize,
    // Set only by a later separately authenticated native publication.
    pub(super) executable: bool,
}

/// Non-Clone. Owner installs this entire object before initialize(). Every
/// error/unwind retains source/bootstrap/progress/native/model custody here;
/// Owner remains the sole physical process/pidfd/broker cleanup authority.
pub(in crate::linux::remote::dynamic::owner) struct RuntimeOwner {
    until: Instant,
    started: Instant,
    stage: RuntimeStage,
    startup: InitialRuntimeReservation,
    sources: PreparedInitialSources,
    bootstrap: Option<PreparedInitialBootstrap>,
    native: Option<NativeLifecycle>,
    census: Option<ResumeCensus>,
    initial_origin: Option<OriginId>,
    control_lineage: Option<super::runtime_native::ControlLineage>,
    next_execution: u64,
    ordinary_attempts: Vec<Box<ordinary::RuntimeOrdinaryAttempt>>,
    selected_attempts: Vec<Box<selected::RuntimeSelectedAttempt>>,
    selected_pending: Option<usize>,
    metrics: DynamicAdmissionMetrics,
    pages: Vec<RuntimePage>,
    // Initialized before any original read/effect. One is moved into the
    // public ready observation; the other into the retained current-PC origin.
    ready_xstate: Vec<u8>,
    origin_xstate: Vec<u8>,
    ready_capacity: usize,
    origin_capacity: usize,
    ready_issued: bool,
}

fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b).ok_or(GateError::Refused(
        "runtime startup evidence size overflows",
    ))
}
fn mul(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_mul(b).ok_or(GateError::Refused(
        "runtime startup evidence size overflows",
    ))
}
fn storage<T>(count: usize) -> Result<Vec<T>, GateError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| GateError::Refused("runtime startup allocation failed"))?;
    Ok(result)
}
fn state_storage() -> Result<Vec<u8>, GateError> {
    let mut result = storage(MAX_XSTATE)?;
    result.resize(MAX_XSTATE, 0);
    Ok(result)
}

impl RuntimeOwner {
    pub(in crate::linux::remote::dynamic::owner) fn allocate(
        options: RuntimeStartOptions,
        until: Instant,
    ) -> Result<Self, GateError> {
        let started = Instant::now();
        let capture = options.capture.validate()?;
        let configured = options.limits.validate()?;
        let limits = census::Limits {
            epochs: configured.epochs,
            source_fact_bytes: configured.source_fact_bytes,
            reports: configured.reports,
            origins: configured.origins,
            witnesses: configured.witnesses,
            plan_history: configured.plan_history,
        };
        let mut startup = InitialRuntimeReservation::new(limits).map_err(census_error)?;
        let source_charge = PreparedInitialSources::reservation_charge(capture)?;
        startup.reserve(source_charge).map_err(census_error)?;
        let origin_charge = initial_runtime_origin_charge(MAX_XSTATE).map_err(census_error)?;
        startup.reserve(origin_charge).map_err(census_error)?;
        // This is an upper on the number of whole target pages, independent of
        // overlap source bytes. Capture validates the tighter actual partition.
        let max_pages = mul(capture.max_windows, capture.max_window_bytes / 4096)?;
        // The source header is charged by the immediately reserved component.
        // Root includes the entire bootstrap Option from birth; its later
        // component reservation excludes that same embedded header.
        let root_inline = size_of::<Self>()
            .checked_sub(size_of::<PreparedInitialSources>())
            .ok_or(GateError::Refused(
                "runtime startup embedded headers differ",
            ))?;
        let root_bytes = add(
            add(root_inline, mul(max_pages, size_of::<RuntimePage>())?)?,
            add(MAX_XSTATE, size_of::<DynamicAdmissionState>())?,
        )?;
        // origin_charge accounts both the full current/initial origin payloads;
        // the prepared origin buffer moves into one of them, without another
        // payload allocation or debit for that move.
        startup
            .reserve(BudgetCharge {
                source_fact_bytes: root_bytes,
                ..BudgetCharge::default()
            })
            .map_err(census_error)?;
        let sources = PreparedInitialSources::allocate(capture, until)?;
        let pages = storage(max_pages)?;
        let ready_xstate = state_storage()?;
        let origin_xstate = state_storage()?;
        if pages.capacity() > max_pages
            || ready_xstate.capacity() > MAX_XSTATE
            || origin_xstate.capacity() > MAX_XSTATE
        {
            return Err(GateError::Refused(
                "runtime startup capacity exceeds reservation",
            ));
        }
        Ok(Self {
            until,
            started,
            stage: RuntimeStage::Allocated,
            startup,
            sources,
            bootstrap: None,
            native: None,
            census: None,
            initial_origin: None,
            control_lineage: None,
            next_execution: 1,
            ordinary_attempts: Vec::new(),
            selected_attempts: Vec::new(),
            selected_pending: None,
            metrics: DynamicAdmissionMetrics::default(),
            pages,
            ready_capacity: ready_xstate.capacity(),
            origin_capacity: origin_xstate.capacity(),
            ready_xstate,
            origin_xstate,
            ready_issued: false,
        })
    }

    /// # Safety
    /// The initial runtime frontend supplies the unchanged immutable/private
    /// source ownership and singleton bootstrap envelope. No complete head
    /// census is inferred. This function never releases original execution.
    pub(in crate::linux::remote::dynamic::owner) unsafe fn initialize(
        &mut self,
        owner: &mut Owner,
        initial: &DynamicStop,
    ) -> Result<DynamicAdmissionState, GateError> {
        if self.stage != RuntimeStage::Allocated
            || self.ready_issued
            || owner.admission.is_some()
            || owner.lifecycle.is_some()
            || owner.lifecycle_options != Some(DynamicLifecycleOptions::default())
            || owner.exec_policy != DynamicExecPolicy::Refuse
            || owner.anchor_archive.is_some()
            || owner.signal_journal.is_some()
            || owner.exec_journal.is_some()
        {
            return Err(GateError::Refused(
                "runtime startup profile or phase differs",
            ));
        }
        owner.time_left(self.until, "initial runtime capture")?;
        self.stage = RuntimeStage::OriginalCapture;
        self.sources.capture_original(owner, initial)?;
        let (storage, progress) = self.sources.original_maps();
        if !self.sources.original_complete() {
            return Err(GateError::Refused(
                "runtime original map capture is incomplete",
            ));
        }
        // Keep the entire initialized diagnostic allocation, including an
        // incomplete suffix, in sources. Only observed bytes are parser input.
        let original = initial_maps_prefix(storage, progress)?;
        self.stage = RuntimeStage::BootstrapAllocation;
        let shape = InitialBootstrapShape::from_original(original)?;
        let bootstrap_payload = shape
            .reservation_bytes()?
            .checked_sub(size_of::<PreparedInitialBootstrap>())
            .ok_or(GateError::Refused(
                "runtime bootstrap embedded header differs",
            ))?;
        self.startup
            .reserve(BudgetCharge {
                source_fact_bytes: bootstrap_payload,
                ..BudgetCharge::default()
            })
            .map_err(census_error)?;
        self.bootstrap = Some(PreparedInitialBootstrap::allocate(
            shape, original, self.until,
        )?);
        owner.time_left(self.until, "initial runtime bootstrap allocation")?;
        self.stage = RuntimeStage::Bootstrap;
        // SAFETY: the frontend supplies the unchanged initial patch/writer
        // envelope; the adapter independently authenticates actual EXEC/EXIT.
        unsafe {
            owner.bootstrap_initial_runtime(
                initial,
                original,
                self.bootstrap
                    .as_mut()
                    .ok_or(GateError::Refused("runtime bootstrap storage missing"))?,
            )?;
        }
        // Custody moves before any subsequent fallible source/state operation.
        self.native = Some(owner.lifecycle.take().ok_or(GateError::Refused(
            "runtime bootstrap lost native lifecycle custody",
        ))?);
        #[cfg(test)]
        if std::mem::take(&mut owner.runtime_panic_after_bootstrap) {
            panic!("injected runtime unwind after actual bootstrap custody transfer");
        }
        let native = self
            .native
            .as_ref()
            .ok_or(GateError::Refused("runtime native custody missing"))?;
        let boot = self
            .bootstrap
            .as_ref()
            .and_then(PreparedInitialBootstrap::completed)
            .ok_or(GateError::Refused("runtime bootstrap did not complete"))?;
        self.stage = RuntimeStage::RuntimeCapture;
        // SAFETY: immutable source ownership is supplied by this method's caller.
        unsafe {
            self.sources.capture(owner, native, boot)?;
        }
        self.stage = RuntimeStage::Reauthentication;
        self.sources.reauthenticate(owner, native, boot)?;
        self.stage = RuntimeStage::Catalog;
        self.build_pages()?;
        self.finish_initial_census(owner)
    }

    fn build_pages(&mut self) -> Result<(), GateError> {
        if !self.sources.capture_complete()
            || !self.sources.recheck_complete()
            || !self.pages.is_empty()
        {
            return Err(GateError::Refused(
                "runtime source catalog is incomplete or repeated",
            ));
        }
        for index in 0..self.sources.window_count() {
            let window = self
                .sources
                .window(index)
                .ok_or(GateError::Refused("runtime source window is incomplete"))?;
            if window.entries.completeness() != liteinst_admission::entries::Completeness::Partial {
                return Err(GateError::Refused(
                    "runtime initial entries changed completeness",
                ));
            }
            let mut address = window.target.start();
            while address < window.target.end() {
                if self.pages.len() == self.pages.capacity()
                    || self
                        .pages
                        .last()
                        .is_some_and(|prior| prior.address >= address)
                {
                    return Err(GateError::Refused(
                        "runtime page directory exceeds its exact partition",
                    ));
                }
                self.pages.push(RuntimePage {
                    address,
                    window: index,
                    executable: false,
                });
                address = address
                    .checked_add(4096)
                    .ok_or(GateError::Refused("runtime page partition overflows"))?;
            }
        }
        if self.pages.is_empty() {
            return Err(GateError::Refused("runtime page directory is empty"));
        }
        Ok(())
    }

    fn finish_initial_census(&mut self, owner: &Owner) -> Result<DynamicAdmissionState, GateError> {
        self.stage = RuntimeStage::Census;
        let binding = self
            .sources
            .current_binding()
            .ok_or(GateError::Refused("runtime current source binding missing"))?;
        let xstate = self
            .sources
            .current_xstate()
            .ok_or(GateError::Refused("runtime current source state missing"))?;
        if xstate.len() < 512
            || xstate.len() >= MAX_XSTATE
            || self.ready_xstate.len() != MAX_XSTATE
            || self.origin_xstate.len() != MAX_XSTATE
            || !self.pages.iter().any(|page| {
                page.address <= binding.registers.rip && binding.registers.rip < page.address + 4096
            })
        {
            return Err(GateError::Refused(
                "runtime initial state or page extent differs",
            ));
        }
        self.native
            .as_ref()
            .ok_or(GateError::Refused("runtime native custody missing"))?
            .require_admission_stop(&binding.stop)?;
        owner.time_left(self.until, "initial runtime census")?;
        let (census, reservation) = self
            .startup
            .bind(owner.session, &binding.stop)
            .map_err(census_error)?;
        self.census = Some(census);
        self.ready_xstate[..xstate.len()].copy_from_slice(xstate);
        self.origin_xstate[..xstate.len()].copy_from_slice(xstate);
        self.ready_xstate.truncate(xstate.len());
        self.origin_xstate.truncate(xstate.len());
        let observed = ObservedStop {
            token: binding.stop.token.clone(),
            task: binding.stop.identity,
            logical_pc: binding.registers.rip,
            registers: binding.registers,
            xstate: std::mem::take(&mut self.origin_xstate),
            signal_mask: binding.signal_mask,
            phase: StopPhase::UserCheckpoint,
            signal: None,
        };
        let census = self
            .census
            .as_mut()
            .ok_or(GateError::Refused("runtime census custody missing"))?;
        self.initial_origin = Some(
            census
                .insert(
                    reservation,
                    OriginKind::CurrentHeldPc,
                    observed.logical_pc,
                    observed,
                )
                .map_err(census_error)?,
        );
        // Count new buffer capacities once. The origin was preallocated at MAX
        // and moved into the census; insert charges its logical initialized
        // extent. Retain the excess capacity debit here, without counting its
        // transferred bytes twice or claiming allocator metadata accounting.
        let root_inline = size_of::<Self>()
            .checked_sub(size_of::<PreparedInitialSources>())
            .ok_or(GateError::Refused(
                "runtime startup embedded headers differ",
            ))?;
        let bootstrap_payload = self
            .bootstrap
            .as_ref()
            .ok_or(GateError::Refused("runtime bootstrap custody missing"))?
            .allocated_bytes()?
            .checked_sub(size_of::<PreparedInitialBootstrap>())
            .ok_or(GateError::Refused(
                "runtime bootstrap embedded header differs",
            ))?;
        let origin_excess = self
            .origin_capacity
            .checked_sub(xstate.len())
            .ok_or(GateError::Refused("runtime origin capacity differs"))?;
        let bytes = add(
            add(self.sources.allocated_bytes()?, bootstrap_payload)?,
            add(
                add(
                    root_inline,
                    mul(self.pages.capacity(), size_of::<RuntimePage>())?,
                )?,
                add(
                    add(self.ready_capacity, size_of::<DynamicAdmissionState>())?,
                    origin_excess,
                )?,
            )?,
        )?;
        census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        owner.time_left(self.until, "initial runtime ready observation")?;
        self.stage = RuntimeStage::Ready;
        self.control_lineage = Some(super::runtime_native::ControlLineage::from_bootstrap(
            self.bootstrap
                .as_ref()
                .and_then(PreparedInitialBootstrap::completed)
                .ok_or(GateError::Refused("runtime bootstrap custody missing"))?,
        )?);
        self.ready_issued = true;
        self.metrics.pages.startup = self.started.elapsed();
        Ok(DynamicAdmissionState {
            task: binding.stop.identity,
            registers: binding.registers,
            xstate: std::mem::take(&mut self.ready_xstate),
            signal_mask: binding.signal_mask,
        })
    }
}

fn initial_maps_prefix<'a>(
    bytes: &'a [u8],
    progress: &source_identity::SourceReadProgress,
) -> Result<&'a [u8], GateError> {
    if !progress.started
        || !progress.attempted
        || !progress.complete
        || progress.failure.is_some()
        || progress.requested_bytes != bytes.len()
        || progress.copied_bytes == 0
        || progress.copied_bytes > bytes.len()
        || progress.filesystem_type != Some(libc::PROC_SUPER_MAGIC)
        || progress.last_request.is_none_or(|request| {
            request.result != 0 || request.errno.is_some() || request.count == 0
        })
    {
        return Err(GateError::Refused(
            "runtime original map capture is incomplete",
        ));
    }
    Ok(&bytes[..progress.copied_bytes])
}
