//! Shape-checked multi-observation artifact emission, without planning authority.
use super::*;
use crate::emission::ArtifactImageView;

/// Ordered symbolic observations over an exact retained instruction interval.
///
/// This proves only instruction/head shape. The caller still owes source and
/// selected-population identity, instruction semantics, all entry/ownership and
/// loader obligations. Every observation uses the same caller-owned SymbolicHook
/// and Legacy128 application-stack envelope. In particular, an observation after
/// POP RSP needs valid helper scratch below the newly loaded RSP.
///
/// There is no live-plan, replacement, control, stack-profile or frame-export
/// constructor. Emission alone neither patches source bytes nor admits execution.
#[derive(Clone, Debug)]
pub struct ArtifactObservationWindow {
    base: TrampolinePlan,
    observation_pcs: Box<[u64]>,
}

/// Linked artifact bytes/maps and the exact ordered observation population.
/// No live image, source patch, ArtifactPlan or unwind/export capability escapes.
#[derive(Clone, Debug)]
pub struct ArtifactWindowImage {
    image: TrampolineImage,
    observation_pcs: Box<[u64]>,
}

impl ArtifactObservationWindow {
    /// Retain every instruction in [physical, end), observing each supplied head.
    /// The old symbolic-window boundary/minimum-length checks precede additional
    /// population checks; PCs must be nonempty, distinct and strictly increasing.
    pub fn checked(
        scan: &ScanResult,
        physical: u64,
        end: u64,
        observation_pcs: &[u64],
    ) -> Result<Self, TrampolineError> {
        let &first = observation_pcs
            .first()
            .ok_or_else(|| artifact_error("artifact observation window has no actions"))?;
        let base = TrampolinePlan::from_symbolic_window(scan, physical, first, end, false)?;
        if observation_pcs.windows(2).any(|pcs| pcs[0] >= pcs[1]) {
            return Err(artifact_error(
                "artifact observation heads must be ordered and distinct",
            ));
        }
        for &pc in observation_pcs {
            if !base
                .instructions
                .iter()
                .any(|instruction| instruction.ip() == pc)
            {
                return Err(TrampolineError::SiteNotFound { address: pc });
            }
        }
        Ok(Self {
            base,
            observation_pcs: observation_pcs.into(),
        })
    }

    /// Static PC order; actual callbacks follow the entered execution path.
    pub fn observation_pcs(&self) -> &[u64] {
        &self.observation_pcs
    }

    /// Encode once through the shared prepared IR, bounds and artifact linker.
    /// A binding, encoding or size refusal yields no partial image. No target
    /// address, callback readiness, writable helper stack or router is inferred.
    pub fn emit_at(
        &self,
        address: u64,
        input: &ArtifactEmission,
    ) -> Result<ArtifactWindowImage, TrampolineError> {
        let image =
            fitting::PreparedArtifact::for_observation_window(self, input)?.emit_at(address)?;
        Ok(ArtifactWindowImage {
            image,
            observation_pcs: self.observation_pcs.clone(),
        })
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn plan(&self) -> &TrampolinePlan {
        &self.base
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn prepare(
        &self,
        input: &ArtifactEmission,
    ) -> Result<OrderedPreparation, TrampolineError> {
        self.base
            .prepare_ordered_input(Some(input), false, false, Some(self))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn verify_preparation(
        &self,
        input: &ArtifactEmission,
        action_count: usize,
        preparation: &OrderedPreparation,
    ) -> Result<(), TrampolineError> {
        if action_count != self.observation_pcs.len()
            || preparation.fragments.len() != self.observation_pcs.len()
        {
            return Err(artifact_error("artifact window lost an observation"));
        }
        let hook = input
            .hook()
            .address
            .map(|address| artifact_target(input, address))
            .unwrap_or(Target::UnresolvedSymbol(input.hook().identity));
        for (&pc, (entry, fragment)) in self.observation_pcs.iter().zip(&preparation.fragments) {
            if !preparation
                .heads
                .iter()
                .any(|head| head.0 == pc && head.1 == *entry && !head.3)
                || fragment.fields.len() != 2
                || fragment
                    .fields
                    .iter()
                    .filter(|f| f.role == Role::LogicalPc && f.target == artifact_target(input, pc))
                    .count()
                    != 1
                || fragment
                    .fields
                    .iter()
                    .filter(|f| f.role == Role::HookCall && f.target == hook)
                    .count()
                    != 1
            {
                return Err(artifact_error("artifact window observation fields differ"));
            }
        }
        Ok(())
    }
}

impl ArtifactWindowImage {
    /// Immutable bytes, entries, restored boundaries and unresolved requirements.
    pub fn image(&self) -> ArtifactImageView<'_> {
        ArtifactImageView::from_direct(&self.image)
    }

    /// Exact requested population, not a complete-source or router certificate.
    pub fn observation_pcs(&self) -> &[u64] {
        &self.observation_pcs
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
