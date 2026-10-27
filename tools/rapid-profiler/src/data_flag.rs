//! Finite generation-bound point observations through real managed controls.
//!
//! This is ordinary-thread, non-unwinding callback code, not signal-safe code.
//! Source publication, generated-code lifetime and architectural qualification
//! remain the caller's existing controlled-emitter obligations. No entry/return
//! pairing, code writes, interval toggle, early flag gate or reclamation is added.
//! A separate admission-boundary result uses the registry lock. Shared physical
//! Visibility remains Eventual: no all-executor Boolean visibility or code
//! barrier is supplied, and already admitted callbacks can still be running.

use crate::frontend::{
    self, EpochHandle, FailurePoint, FunctionSpec, GroupSpec, Observation, Session,
};
use crate::frontend_tls::{self, PointObservation, ThreadRegistration};
use crate::generation::{Config, DeactivationRequest, FunctionId};
use liteinst2::contracts::{Epoch, Refusal, ToggleProbe, Visibility};
use liteinst2::controls::{ControlIdentity, ControlWriter, ControlledAction, ProbeControl};
use liteinst2::trampoline::{HookCallback, HookContext};
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

/// One optional observing point or mandatory callback in a fixed physical group.
#[derive(Clone, Copy)]
pub struct PointSpec {
    /// Exact original logical PC supplied by the controlled emitter.
    pub pc: u64,
    /// Physical-group index; groups are dense and never changed by this adapter.
    pub group: usize,
    /// Some identifies optional work; None is mandatory and is never toggled.
    pub function: Option<FunctionId>,
    /// Existing non-unwinding, application-state-preserving callback contract.
    pub callback: HookCallback,
}

struct Binding {
    session: Session,
    install: u64,
    specs: Vec<PointSpec>,
    controls: Vec<ProbeControl>,
    #[cfg(test)]
    pause: std::sync::Mutex<Option<tests::Pause>>,
}

/// Exclusive controller: it exposes no Session, EpochHandle or control writer.
/// Planner-visible clones are managed and refuse both public mutation methods.
///
/// ```compile_fail,E0616
/// use rapid_profiler::data_flag::DataFlagSession;
/// fn bypass(controller: &DataFlagSession) { let _ = &controller.binding; }
/// ```
pub struct DataFlagSession {
    binding: Arc<Binding>,
    writers: Vec<ControlWriter>,
    epochs: Vec<EpochHandle>,
    current: Option<Epoch>,
    sequence: u64,
}

/// Identity-bound transition ticket; its fields cannot be constructed externally.
pub struct Ticket {
    binding: Arc<Binding>,
    epoch: Epoch,
    sequence: u64,
    enabled: bool,
}

/// Registry/admission result, deliberately separate from physical Visibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionBoundary {
    /// Future successful registry acquisitions bind this current epoch. An
    /// executor may still miss an entry through a stale false outer flag.
    Current(Epoch),
    /// No new point can reserve this removed epoch; old reservations may run.
    Closed(Epoch),
}

fn backend(error: impl std::fmt::Debug) -> Refusal {
    Refusal::Backend(format!("{error:?}"))
}

// Called only while Session holds both writer and registry locks. Mandatory
// controls are deliberately absent from the supplied per-function state slice.
fn update(binding: &Binding, writers: &mut [ControlWriter], enabled: &[bool]) {
    let mut next = enabled.iter();
    for (spec, writer) in binding.specs.iter().zip(writers) {
        if spec.function.is_some() {
            writer.set_enabled(*next.next().expect("exact immutable function map"));
        }
    }
    assert!(next.next().is_none());
}

impl DataFlagSession {
    /// Construct finite point controls. Every executing observer thread must
    /// attach before use. This does not install code or accept interval hooks.
    pub fn new(
        install: u64,
        specs: &[PointSpec],
        limits: frontend::Limits,
    ) -> Result<Self, Refusal> {
        if specs.is_empty()
            || specs.len() > frontend::MAX_MODEL_FUNCTIONS
            || specs
                .iter()
                .any(|s| s.pc == 0 || s.group >= frontend::MAX_MODEL_FUNCTIONS)
            || specs.windows(2).any(|w| w[0].pc >= w[1].pc)
        {
            return Err(Refusal::InvalidPlan);
        }
        let count = specs.iter().map(|s| s.group).max().unwrap() + 1;
        let groups: Vec<_> = (0..count)
            .map(|group| GroupSpec {
                mandatory: specs
                    .iter()
                    .any(|s| s.group == group && s.function.is_none()),
            })
            .collect();
        let functions: Vec<_> = specs
            .iter()
            .filter_map(|s| {
                s.function.map(|function| FunctionSpec {
                    function,
                    group: s.group,
                })
            })
            .collect();
        // Each declared group must contain an optional point; mandatory-only
        // groups can use ordinary permanent controls outside this finite API.
        let session = Session::new(install, &functions, &groups, limits).map_err(backend)?;
        let mut controls = Vec::with_capacity(specs.len());
        let mut writers = Vec::with_capacity(specs.len());
        for spec in specs {
            let (control, writer) = if spec.function.is_some() {
                ProbeControl::new_managed_bound(point_callback, false)
            } else {
                ProbeControl::new_managed(spec.callback, true)
            };
            controls.push(control);
            writers.push(writer);
        }
        Ok(Self {
            binding: Arc::new(Binding {
                session,
                install,
                specs: specs.to_vec(),
                controls,
                #[cfg(test)]
                pause: std::sync::Mutex::new(None),
            }),
            writers,
            epochs: Vec::with_capacity(limits.epochs),
            current: None,
            sequence: 0,
        })
    }

    /// Immutable planning coordinates and read-only managed control identities.
    /// The trusted publisher must preserve their PC/control association.
    pub fn actions(&self) -> Vec<ControlledAction> {
        self.binding
            .specs
            .iter()
            .zip(&self.binding.controls)
            .map(|(s, control)| ControlledAction {
                logical_pc: s.pc,
                control: control.clone(),
            })
            .collect()
    }

    /// Stage a new immutable owner within the unchanged Session E/A/M/K limits.
    /// This first finite adapter retains staged epochs until controller Drop.
    pub fn stage(&mut self, config: Config) -> Result<Epoch, Refusal> {
        let owner = self.binding.session.stage(config).map_err(backend)?;
        let epoch = Epoch(owner.generation().get());
        self.epochs.push(owner);
        Ok(epoch)
    }

    fn owner(&self, epoch: Epoch) -> Result<&EpochHandle, Refusal> {
        self.epochs
            .iter()
            .find(|e| e.generation().get() == epoch.0)
            .ok_or(Refusal::StaleGeneration)
    }

    /// Inspect a final, retained metadata report; never claims code drainage.
    pub fn report(&self, epoch: Epoch) -> Result<Option<frontend::Report>, Refusal> {
        Ok(self.owner(epoch)?.try_report())
    }

    /// Apply a K-completion request under the same authority as publication.
    /// A stale request retains its model Stale row and performs no flag store.
    pub fn deactivate(&mut self, request: DeactivationRequest) -> Result<(), Refusal> {
        let current = self.current == Some(Epoch(request.generation.get()));
        let next = if current {
            self.sequence.checked_add(1).ok_or(Refusal::InvalidPlan)?
        } else {
            self.sequence
        };
        let binding = Arc::clone(&self.binding);
        binding
            .session
            .deactivate_with_controls(request, FailurePoint::None, |states| {
                update(&binding, &mut self.writers, states)
            })
            .map_err(backend)?;
        self.sequence = next;
        Ok(())
    }

    /// Bounded existing Session scan, so K closures need no notification queue
    /// and cannot be lost when multiple point callbacks complete before polling.
    pub fn scan_closed(&mut self) -> Result<usize, Refusal> {
        let next = self.sequence.checked_add(1).ok_or(Refusal::InvalidPlan)?;
        let binding = Arc::clone(&self.binding);
        let count = binding
            .session
            .scan_with_controls(|states| update(&binding, &mut self.writers, states))
            .map_err(backend)?;
        if count != 0 {
            self.sequence = next;
        }
        Ok(count)
    }

    /// Attach this actual thread using the existing TLS/model owner. No Session
    /// or mutable control handle escapes through the returned thread token.
    pub fn attach_current_thread(&self) -> Result<PointThread, Refusal> {
        attach_binding(&self.binding)
    }

    /// Join a current transition to the same writer/registry lock boundary used
    /// by acquisition. This is neither all-CPU flag visibility nor callback drain.
    pub fn admission_boundary(&mut self, ticket: &Ticket) -> Result<AdmissionBoundary, Refusal> {
        if !Arc::ptr_eq(&ticket.binding, &self.binding)
            || ticket.sequence != self.sequence
            || self.current
                != if ticket.enabled {
                    Some(ticket.epoch)
                } else {
                    None
                }
        {
            return Err(Refusal::StaleGeneration);
        }
        let expected = if ticket.enabled {
            Some(self.owner(ticket.epoch)?.generation())
        } else {
            None
        };
        self.binding
            .session
            .confirm_controls(expected)
            .map_err(backend)?;
        Ok(if ticket.enabled {
            AdmissionBoundary::Current(ticket.epoch)
        } else {
            AdmissionBoundary::Closed(ticket.epoch)
        })
    }
}

impl ToggleProbe for DataFlagSession {
    type Ticket = Ticket;

    fn arm(&mut self, epoch: Epoch) -> Result<Ticket, Refusal> {
        let owner = self.owner(epoch)?.clone();
        let next = self.sequence.checked_add(1).ok_or(Refusal::InvalidPlan)?;
        let binding = Arc::clone(&self.binding);
        binding
            .session
            .publish_with_controls(&owner, FailurePoint::None, |states| {
                update(&binding, &mut self.writers, states)
            })
            .map_err(backend)?;
        self.current = Some(epoch);
        self.sequence = next;
        Ok(Ticket {
            binding,
            epoch,
            sequence: next,
            enabled: true,
        })
    }

    fn disarm(&mut self, epoch: Epoch) -> Result<Ticket, Refusal> {
        let generation = self.owner(epoch)?.generation();
        if self.current != Some(epoch) {
            return Err(Refusal::StaleGeneration);
        }
        let next = self.sequence.checked_add(1).ok_or(Refusal::InvalidPlan)?;
        let binding = Arc::clone(&self.binding);
        binding
            .session
            .remove_with_controls(Some(generation), |states| {
                update(&binding, &mut self.writers, states)
            })
            .map_err(backend)?;
        self.current = None;
        self.sequence = next;
        Ok(Ticket {
            binding,
            epoch,
            sequence: next,
            enabled: false,
        })
    }

    fn complete(&mut self, ticket: &Ticket) -> Result<Visibility, Refusal> {
        self.admission_boundary(ticket)?;
        // Every optional callback must acquire this registry and reserve its
        // retained owner. Stale true flags cannot bypass that admission gate.
        // Old admitted callbacks may still run: this is not drain or reclamation.
        // A stale false outer gate can skip registry acquisition after ARM;
        // admission closure after DISARM also is not shared physical visibility.
        Ok(Visibility::Eventual)
    }

    fn close_and_drain(&mut self, epoch: Epoch) -> Result<(), Refusal> {
        self.owner(epoch)?;
        if self.current == Some(epoch) {
            self.disarm(epoch)?;
        }
        let owner = self.owner(epoch)?;
        owner.close();
        // Bounded, nonblocking refusal while a callback owns a reservation;
        // caller may poll again. Never spin or manufacture a completed drain.
        if owner.try_report().is_none() {
            return Err(backend("point callbacks still admitted"));
        }
        Ok(())
    }
}

impl Drop for DataFlagSession {
    fn drop(&mut self) {
        let binding = &self.binding;
        // Best-effort physical removal uses the same locks. Regardless of a
        // poisoned/terminal registry, atomic close prevents new reservations.
        // No completion receipt is produced by Drop and mandatory gates stay on.
        if self.current.is_some() {
            let _ = binding
                .session
                .remove_with_controls(None, |states| update(binding, &mut self.writers, states));
        }
        for owner in &self.epochs {
            owner.close();
        }
    }
}

struct Attached {
    binding: Arc<Binding>,
    registration: ThreadRegistration,
}
struct Local {
    attached: RefCell<Option<Attached>>,
    last: Cell<Option<PointOutcome>>,
    last_refusal: Cell<Option<PointOutcome>>,
    refusals: Cell<u64>,
}
thread_local! {
    static POINT: Local = const { Local { attached: RefCell::new(None), last: Cell::new(None), last_refusal: Cell::new(None), refusals: Cell::new(0) } };
}

fn attach_binding(binding: &Arc<Binding>) -> Result<PointThread, Refusal> {
    POINT
        .try_with(|local| {
            let mut slot = local.attached.try_borrow_mut().map_err(backend)?;
            if slot.is_some() {
                return Err(Refusal::OwnershipConflict);
            }
            let registration =
                frontend_tls::attach_current_thread(&binding.session).map_err(backend)?;
            let identity = registration.identity();
            *slot = Some(Attached {
                binding: Arc::clone(binding),
                registration,
            });
            local.last.set(None);
            local.last_refusal.set(None);
            local.refusals.set(0);
            Ok(PointThread {
                identity,
                _thread_bound: PhantomData,
            })
        })
        .map_err(backend)?
}

/// Exact point callback result; callback refusal never executes optional work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointOutcome {
    /// Existing completion and payload retain their original epoch identities.
    Completed {
        completion: crate::generation::Completion,
        payload: frontend::Payload,
    },
    /// No attached binding, reentrant TLS borrow, or foreign control/PC.
    BindingRefused,
    /// Registry or existing generation/TLS admission refused before work.
    AdmissionRefused(frontend_tls::BridgeError),
}

/// Bounded actual-thread diagnostics; records remain in their retained epochs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointDiagnostics {
    /// Last optional point result, including later successes after a refusal.
    pub last: Option<PointOutcome>,
    /// Most recent refusal, retained even if a later point completes.
    pub last_refusal: Option<PointOutcome>,
    /// Exact count of refused optional callbacks, with overflow fatal.
    pub refusals: u64,
}

/// Actual-thread token. Drop detaches an idle point attachment. If called from
/// inside its borrowed callback, the attachment remains until TLS destruction;
/// it does not fake detachment or cancel another owner.
pub struct PointThread {
    identity: u64,
    _thread_bound: PhantomData<Rc<()>>,
}
impl PointThread {
    /// Last result and number of refused optional callbacks on this attachment.
    pub fn diagnostics(&self) -> Result<PointDiagnostics, Refusal> {
        POINT
            .try_with(|local| {
                let slot = local.attached.try_borrow().map_err(backend)?;
                if slot.as_ref().map(|s| s.registration.identity()) != Some(self.identity) {
                    return Err(Refusal::StaleGeneration);
                }
                Ok(PointDiagnostics {
                    last: local.last.get(),
                    last_refusal: local.last_refusal.get(),
                    refusals: local.refusals.get(),
                })
            })
            .map_err(backend)?
    }
}
impl Drop for PointThread {
    fn drop(&mut self) {
        let _ = POINT.try_with(|local| {
            if let Ok(mut slot) = local.attached.try_borrow_mut() {
                if slot.as_ref().map(|s| s.registration.identity()) == Some(self.identity) {
                    drop(slot.take());
                }
            }
        });
    }
}

unsafe extern "C" fn point_callback(context: *mut HookContext, identity: ControlIdentity<'_>) {
    if context.is_null() {
        std::process::abort();
    }
    // SAFETY: the generated controlled dispatcher supplies its live saved frame.
    let pc = unsafe { (*context).instruction_pointer };
    let _ = POINT.try_with(|local| {
        let outcome = (|| {
            let Ok(slot) = local.attached.try_borrow_mut() else {
                return PointOutcome::BindingRefused;
            };
            let Some(attached) = slot.as_ref() else {
                return PointOutcome::BindingRefused;
            };
            let binding = &attached.binding;
            let Some(index) = binding
                .specs
                .iter()
                .zip(&binding.controls)
                .position(|(s, c)| s.pc == pc && c.has_identity(identity))
            else {
                return PointOutcome::BindingRefused;
            };
            let spec = binding.specs[index];
            let Some(function) = spec.function else {
                return PointOutcome::BindingRefused;
            };
            let owner = match binding
                .session
                .acquire(attached.registration.identity(), binding.install)
            {
                Ok(owner) => owner,
                Err(e) => {
                    return PointOutcome::AdmissionRefused(frontend_tls::BridgeError::Entry(e));
                }
            };
            #[cfg(test)]
            tests::pause(binding, pc, tests::Phase::BeforeReservation);
            let observed = attached
                .registration
                .observe_point(&owner, function, pc, || {
                    #[cfg(test)]
                    tests::pause(binding, pc, tests::Phase::AfterReservation);
                    // SAFETY: same full-state and non-unwinding callback contract.
                    unsafe { (spec.callback)(context) };
                    Observation::Value(pc)
                });
            match observed {
                PointObservation::Completed {
                    completion,
                    payload,
                } => PointOutcome::Completed {
                    completion,
                    payload,
                },
                PointObservation::Refused(e) => PointOutcome::AdmissionRefused(e),
                PointObservation::InvariantFailure => std::process::abort(),
            }
        })();
        local.last.set(Some(outcome));
        if !matches!(outcome, PointOutcome::Completed { .. }) {
            local.last_refusal.set(Some(outcome));
            local.refusals.set(
                local
                    .refusals
                    .get()
                    .checked_add(1)
                    .unwrap_or_else(|| std::process::abort()),
            );
        }
    });
}

/// Exclusive point-only code publication; physical operations run outside frontend locks.
pub mod code_toggle;

#[cfg(test)]
mod tests;
