//! Separate prepared-first-call facade over the same loader, worker and Schedule.
use super::*;

pub(crate) fn run(args: &[std::ffi::OsString]) {
    let outcome = (|| -> Result<(), String> {
        let (request, leaves, table) = selected::prepared_arguments(args)?;
        let leaves: [Selection; 1] = leaves.try_into().unwrap();
        let expectations = Expectations::frozen(table, leaves.map(|leaf| leaf.function));
        let policy = request.phase().policy();
        run_common_timing(
            args,
            policy.retained(),
            policy.epoch_limit(),
            leaves,
            expectations,
            Some(policy),
            (Some(request.phase()), Some(request)),
        )
    })();
    if let Err(error) = outcome {
        eprintln!("{} FAILED: {error}", phase::prepared::COMMAND);
        std::process::exit(1);
    }
}
fn remaining(until: Instant, now: Instant) -> Result<Duration, String> {
    until
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "prepared first-input/owner barrier exceeded original setup deadline".into())
}
/// Drain READY, accept just the first authenticated CSV row, transfer its owner,
/// and wait for actual guarded preparation. No Schedule exists yet. A producer
/// may buffer further bytes, but no second row is polled or acknowledged here.
/// The same absolute two-second attachment deadline bounds every iteration.
pub(super) fn prime<const N: usize>(
    app: &mut Application<N>,
    io: &mut Io,
    tx: &mpsc::SyncSender<input::Command>,
    until: Instant,
) -> Result<(), String> {
    assert_eq!(N, 1);
    assert_eq!(app.accepted_len(), 0);
    let gate = Arc::clone(app.prepared.as_ref().expect("prepared facade"));
    let mut pending = None;
    loop {
        remaining(until, Instant::now())?;
        io.write()?;
        if io.drained() && app.accepted_len() == 0 {
            if let Some(command) = app.input(io)? {
                if !matches!(command, input::Command::Record(_)) {
                    return Err("prepared profile requires first complete accepted record".into());
                }
                app.accept(&command)?;
                pending = Some(command);
            }
        }
        if let Some(command) = pending.take() {
            match tx.try_send(command) {
                Ok(()) => (),
                Err(mpsc::TrySendError::Full(command)) => pending = Some(command),
                Err(mpsc::TrySendError::Disconnected(command)) => {
                    pending = Some(command); // keep local plus accepted owner until fail-stop
                    assert!(pending.is_some());
                    return Err("prepared worker disconnected before barrier".into());
                }
            }
        }
        if gate.is_prepared() {
            remaining(until, Instant::now())?;
            assert!(pending.is_none());
            assert_eq!(app.accepted_len(), 1);
            return Ok(());
        }
        std::hint::spin_loop();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_setup_uses_one_absolute_deadline_without_input_or_owner_extension() {
        let start = Instant::now();
        let end = start + WAIT;
        assert_eq!(remaining(end, start).unwrap(), WAIT);
        let late_input = start + WAIT - Duration::from_nanos(1);
        assert_eq!(remaining(end, late_input).unwrap(), Duration::from_nanos(1));
        assert!(remaining(end, end).is_err());
        assert!(remaining(end, end + Duration::from_nanos(1)).is_err());
        // Reading a partial frame or receiving the worker receipt never resets end.
        assert!(remaining(end, late_input + Duration::from_nanos(2)).is_err());
    }
}
