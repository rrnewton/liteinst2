//! Byte/version and holder refreshes under actual singleton exclusion.
use super::super::census::Reservation;
use super::*;

impl AdmissionOwner {
    pub(super) fn refresh_signal_frames(
        &mut self,
        owner: &Owner,
        reservation: Reservation,
        until: Instant,
    ) -> Result<(), GateError> {
        let Some(signal) = &self.signals else {
            return Ok(());
        };
        let Some(live) = &signal.live else {
            return Ok(());
        };
        let task = live.interrupted.task.task;
        let actual = self.observe_current(owner, task)?;
        let members = self.native.check_admission_mm(owner, task)?;
        if members.candidate.tasks != vec![task] || !self.running.is_empty() {
            return Err(GateError::Refused(
                "signal frame refresh lacks exact singleton exclusion",
            ));
        }
        let journal = owner.signal_journal.as_ref().ok_or(GateError::Refused(
            "signal frame refresh lost its owner journal",
        ))?;
        // Every changed or malformed byte remains in the raw archive before
        // the edit policy interprets it. No unavailable suffix is filled in.
        let bytes = journal.capture_frame(
            actual.token.tid,
            live.facts.address,
            live.facts.bytes.len(),
            until,
        )?;
        let bytes = live.captured.validate_current(bytes, false)?;
        let facts = if bytes == live.facts.bytes {
            Arc::clone(&live.facts)
        } else {
            Arc::new(census::FrameFacts {
                version: live
                    .facts
                    .version
                    .checked_add(1)
                    .ok_or(GateError::Refused("signal frame version exhausted"))?,
                bytes,
                ..live.facts.as_ref().clone()
            })
        };
        let origins = live.origins.clone();
        // The intermediate per-origin state is deliberately not releasable.
        // Publication's complete-set verifier accepts it only after this loop.
        for origin in origins {
            self.census
                .refresh_frame(reservation, origin, Arc::clone(&facts), actual.clone())
                .map_err(census_error)?;
        }
        self.signals.as_mut().unwrap().live.as_mut().unwrap().facts = facts;
        self.census
            .check_signal_obligations(&members.candidate.obligations)
            .map_err(census_error)?;
        owner.time_left(until, "signal frame refresh")?;
        Ok(())
    }
}
