//! One save/callback/restore sequence shared by live and artifact callers.
//! Coordinates and final frame publication remain owned by each caller.
use super::{
    FrameStage, HelperFrames, InstrumentationEmission, ObservationStackProfile,
    SavedExtendedStateLayout, TrampolineError, encode_restore,
};

pub(super) struct Emission {
    pub(super) instrumentation_frames: HelperFrames,
    pub(super) restore_frames: HelperFrames,
    pub(super) instrumentation: InstrumentationEmission,
    pub(super) restore_address: u64,
    pub(super) restore: Vec<u8>,
}

pub(super) fn encode(
    extended_state: &SavedExtendedStateLayout,
    profile: ObservationStackProfile,
    recording: bool,
    instrumentation: impl FnOnce(
        Option<&mut HelperFrames>,
    ) -> Result<InstrumentationEmission, TrampolineError>,
    restore_coordinate: impl FnOnce(usize) -> Result<u64, TrampolineError>,
) -> Result<Emission, TrampolineError> {
    let mut instrumentation_frames = HelperFrames::with_profile(FrameStage::SaveAndCall, profile);
    let mut restore_frames = HelperFrames::with_profile(FrameStage::Restore, profile);
    let instrumentation = instrumentation(recording.then_some(&mut instrumentation_frames))?;
    // In particular, a later coordinate overflow must not hide an encoding
    // refusal or move the caller's callback/argument evaluation ahead of it.
    let restore_address = restore_coordinate(instrumentation.bytes.len())?;
    let restore = encode_restore(
        restore_address,
        extended_state,
        profile,
        recording.then_some(&mut restore_frames),
    )?;
    Ok(Emission {
        instrumentation_frames,
        restore_frames,
        instrumentation,
        restore_address,
        restore,
    })
}

#[cfg(test)]
mod tests;
