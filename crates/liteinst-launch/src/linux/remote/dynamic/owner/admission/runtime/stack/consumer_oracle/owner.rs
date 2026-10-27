//! The real production wait-domain owner stays installed through every error.
//! This development observer does not construct stops or completion permits.
use super::artifact::PinnedArtifact;
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::AtomicU64;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RequestResult {
    pub(super) result: i64,
    pub(super) errno: i32,
}

/// Raw observations are retained separately from the predicates that use them.
/// Missing observations remain missing after a partial launch/cleanup failure.
struct PinEvidence {
    pid: Option<i32>,
    opened: Option<RequestResult>,
    pin: Option<OwnedFd>,
    polled: Option<RequestResult>,
    revents: Option<i16>,
    waited: Option<RequestResult>,
    wait_pid: Option<i32>,
    wait_code: Option<i32>,
    wait_status: Option<i32>,
    complete: bool,
}

/// A borrowed description of installed pin evidence, including failed prefixes.
/// Descriptor identity is observed while the original OwnedFd remains retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PinView {
    pub(super) pid: Option<i32>,
    pub(super) opened: Option<RequestResult>,
    pub(super) pin: Option<RawFd>,
    pub(super) polled: Option<RequestResult>,
    pub(super) revents: Option<i16>,
    pub(super) waited: Option<RequestResult>,
    pub(super) wait_pid: Option<i32>,
    pub(super) wait_code: Option<i32>,
    pub(super) wait_status: Option<i32>,
    pub(super) complete: bool,
}

impl PinEvidence {
    const fn empty() -> Self {
        Self {
            pid: None,
            opened: None,
            pin: None,
            polled: None,
            revents: None,
            waited: None,
            wait_pid: None,
            wait_code: None,
            wait_status: None,
            complete: false,
        }
    }

    fn view(&self) -> PinView {
        PinView {
            pid: self.pid,
            opened: self.opened,
            pin: self.pin.as_ref().map(AsRawFd::as_raw_fd),
            polled: self.polled,
            revents: self.revents,
            waited: self.waited,
            wait_pid: self.wait_pid,
            wait_code: self.wait_code,
            wait_status: self.wait_status,
            complete: self.complete,
        }
    }

    fn open(&mut self, pid: i32) -> Result<(), OracleError> {
        if pid <= 0 || self.pid.is_some() || self.opened.is_some() {
            return Err(OracleError::Invalid("oracle original pin reused"));
        }
        self.pid = Some(pid);
        // SAFETY: the caller retains the production owner's unreaped original
        // application or broker. No numeric identity is acquired after cleanup.
        let result = unsafe {
            *libc::__errno_location() = 0;
            libc::syscall(libc::SYS_pidfd_open, pid, 0)
        };
        let errno = unsafe { *libc::__errno_location() };
        self.opened = Some(RequestResult { result, errno });
        if result >= 0 {
            // Install before any fallible check. pidfd_open returns an int fd.
            self.pin = Some(unsafe { OwnedFd::from_raw_fd(result as i32) });
        }
        if result < 0 || result > i64::from(i32::MAX) || errno != 0 {
            return Err(OracleError::Io {
                operation: "oracle pin original process",
                errno: (errno != 0).then_some(errno),
            });
        }
        Ok(())
    }

    fn require_reaped(&mut self) -> Result<(), OracleError> {
        if self.complete || self.polled.is_some() || self.waited.is_some() {
            return Err(OracleError::Invalid("oracle pin proof repeated"));
        }
        let pin = self.pin.as_ref().ok_or(OracleError::Invalid(
            "oracle original pin was not installed",
        ))?;
        let mut event = libc::pollfd {
            fd: pin.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: one initialized entry names the retained original pidfd.
        let result = unsafe {
            *libc::__errno_location() = 0;
            libc::poll(&raw mut event, 1, 0)
        };
        let errno = unsafe { *libc::__errno_location() };
        self.polled = Some(RequestResult {
            result: i64::from(result),
            errno,
        });
        self.revents = Some(event.revents);
        if result != 1 || errno != 0 || event.revents != (libc::POLLIN | libc::POLLHUP) {
            return Err(OracleError::Invalid(
                "oracle original pin lacks terminal and physical HUP",
            ));
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: WNOWAIT never consumes another owner's status. The actual
        // owner cleanup must already have consumed both wait responsibilities.
        let result = unsafe {
            *libc::__errno_location() = 0;
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as libc::id_t,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        let errno = unsafe { *libc::__errno_location() };
        self.waited = Some(RequestResult {
            result: i64::from(result),
            errno,
        });
        self.wait_pid = Some(unsafe { info.si_pid() });
        self.wait_code = Some(info.si_code);
        self.wait_status = Some(unsafe { info.si_status() });
        if result != -1 || errno != libc::ECHILD {
            return Err(OracleError::Invalid(
                "oracle original terminal wait remains unconsumed",
            ));
        }
        self.complete = true;
        Ok(())
    }
}

pub(super) struct ArtifactOwner {
    // Explicit options retain partial initialization, including launch failure.
    owner: Option<Owner>,
    mask: Option<launch::BlockedSignals>,
    initial: Option<Ready>,
    application: PinEvidence,
    helper: PinEvidence,
    launch_started: bool,
    cleanup_started: bool,
    cleanup: Option<Result<DynamicCleanup, LaunchError>>,
    cleanup_failure: Option<OracleError>,
    cleanup_complete: bool,
    mask_restore: Option<Result<(), LaunchError>>,
}

/// Read-only access to the genuine owner's retained partial outcomes. This
/// does not turn an absent/failed launch, pin proof or cleanup into completion.
pub(super) struct OwnerView<'a> {
    pub(super) owner: Option<&'a Owner>,
    pub(super) application: PinView,
    pub(super) helper: PinView,
    pub(super) launch_started: bool,
    pub(super) cleanup: Option<&'a Result<DynamicCleanup, LaunchError>>,
    pub(super) cleanup_complete: bool,
    pub(super) mask_restore: Option<&'a Result<(), LaunchError>>,
}

impl ArtifactOwner {
    pub(super) const fn empty() -> Self {
        Self {
            owner: None,
            mask: None,
            initial: None,
            application: PinEvidence::empty(),
            helper: PinEvidence::empty(),
            launch_started: false,
            cleanup_started: false,
            cleanup: None,
            cleanup_failure: None,
            cleanup_complete: false,
            mask_restore: None,
        }
    }

    pub(super) fn launch_in_place(
        &mut self,
        file: &PinnedArtifact,
        until: Instant,
    ) -> Result<(), OracleError> {
        if self.launch_started || self.cleanup_started {
            return Err(OracleError::Invalid("oracle launch guard reused"));
        }
        self.launch_started = true;
        let session = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| OracleError::Invalid("oracle session namespace exhausted"))?;
        self.owner = Some(Owner::new(session, Arc::new(AtomicBool::new(false))));
        self.mask = Some(launch::BlockedSignals::new()?);
        let inherited = self.mask.as_ref().unwrap().original();
        self.owner.as_mut().unwrap().lifecycle_options = Some(DynamicLifecycleOptions::default());
        let command = file.command()?;
        // Same absolute deadline supplied by the lane, including preparation.
        // The production owner receives every partial broker/pidfd transition.
        self.initial = Some(launch::start(
            self.owner.as_mut().unwrap(),
            &command,
            inherited,
            until,
        )?);
        let owner = self.owner.as_ref().unwrap();
        let initial = self.initial.as_ref().unwrap();
        owner.time_left(until, "oracle retain launch identities")?;
        if initial.pid != owner.pid || initial.event.tid != owner.pid {
            return Err(OracleError::Invalid("oracle initial identity differs"));
        }
        owner.require_stop(initial.event.stop_token().ok_or(OracleError::Invalid(
            "oracle launch did not yield an actual stop",
        ))?)?;
        self.application.open(owner.pid)?;
        let helper = owner
            .broker
            .as_ref()
            .ok_or(OracleError::Invalid("oracle production broker is absent"))?;
        self.helper.open(helper.pid)?;
        file.verify()?;
        file.verify_running(owner, until)?;
        owner.time_left(until, "oracle launch identity retained")?;
        Ok(())
    }

    fn require_live_access(&self) -> Result<(), OracleError> {
        if self.cleanup_started {
            return Err(OracleError::Invalid(
                "oracle owner mutation follows cleanup",
            ));
        }
        Ok(())
    }

    pub(super) fn owner(&mut self) -> Result<&mut Owner, OracleError> {
        self.require_live_access()?;
        self.owner
            .as_mut()
            .ok_or(OracleError::Invalid("oracle owner is absent"))
    }

    pub(super) fn owner_ref(&self) -> Result<&Owner, OracleError> {
        self.owner
            .as_ref()
            .ok_or(OracleError::Invalid("oracle owner is absent"))
    }

    /// Disjoint borrows of the real installed owner and original Ready record;
    /// no cloned event or fabricated stop token is needed by the raw lane.
    pub(super) fn owner_and_initial(&mut self) -> Result<(&mut Owner, &Ready), OracleError> {
        self.require_live_access()?;
        let owner = self
            .owner
            .as_mut()
            .ok_or(OracleError::Invalid("oracle owner is absent"))?;
        let initial = self
            .initial
            .as_ref()
            .ok_or(OracleError::Invalid("oracle launch is incomplete"))?;
        Ok((owner, initial))
    }

    pub(super) fn partial_view(&self) -> OwnerView<'_> {
        OwnerView {
            owner: self.owner.as_ref(),
            application: self.application.view(),
            helper: self.helper.view(),
            launch_started: self.launch_started,
            cleanup: self.cleanup.as_ref(),
            cleanup_complete: self.cleanup_complete,
            mask_restore: self.mask_restore.as_ref(),
        }
    }

    pub(super) const fn temporary_bytes() -> usize {
        // All projections are fixed inline metadata. Existing owner payloads
        // remain borrowed; this does not account them as fresh allocations.
        std::mem::size_of::<OwnerView<'static>>() + 2 * std::mem::size_of::<PinView>()
    }

    pub(super) fn initial(&self) -> Result<&Ready, OracleError> {
        self.initial
            .as_ref()
            .ok_or(OracleError::Invalid("oracle launch is incomplete"))
    }

    pub(super) fn finish(&mut self) -> Result<(), OracleError> {
        if self.cleanup_started {
            return if self.cleanup_complete {
                Ok(())
            } else {
                Err(OracleError::Invalid("oracle cleanup failed or unwound"))
            };
        }
        self.cleanup_started = true;
        if let Some(owner) = &mut self.owner {
            // No new local deadline: production drains its actual physical
            // owner under the unchanged outer command containment.
            self.cleanup = Some(owner.cleanup());
            if self.cleanup.as_ref().is_some_and(Result::is_err) {
                return Err(OracleError::Invalid("oracle physical cleanup failed"));
            }
            let proof = self.check_cleanup();
            if let Err(error) = proof {
                self.cleanup_failure = Some(error);
                return Err(OracleError::Invalid(
                    "oracle original pin cleanup proof failed",
                ));
            }
        }
        self.cleanup_complete = true;
        Ok(())
    }

    fn check_cleanup(&mut self) -> Result<(), OracleError> {
        let cleanup = self
            .cleanup
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(OracleError::Invalid("oracle cleanup receipt is absent"))?;
        if let Some(initial) = &self.initial {
            if cleanup.reaped.as_slice() != [initial.pid] {
                return Err(OracleError::Invalid(
                    "oracle cleanup application set differs",
                ));
            }
        }
        // Only pins actually installed are observed. A launch failure with no
        // auxiliary pin cannot fabricate a two-pin success, even after drain.
        if self.application.pin.is_some() {
            self.application.require_reaped()?;
        }
        if self.helper.pin.is_some() {
            self.helper.require_reaped()?;
        }
        Ok(())
    }

    pub(super) fn cleanup(&self) -> Result<&DynamicCleanup, OracleError> {
        if !self.cleanup_complete || !self.application.complete || !self.helper.complete {
            return Err(OracleError::Invalid(
                "oracle full cleanup evidence is incomplete",
            ));
        }
        self.cleanup
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(OracleError::Invalid("oracle cleanup receipt is absent"))
    }

    /// Called only after retained evidence has been checked following cleanup.
    /// Both the first lane error and a separate restoration error stay owned.
    pub(super) fn restore_mask(&mut self) -> Result<(), OracleError> {
        if !self.cleanup_complete {
            return Err(OracleError::Invalid(
                "oracle mask restoration precedes cleanup",
            ));
        }
        if let Some(mask) = self.mask.take() {
            self.mask_restore = Some(mask.restore());
        }
        if self.mask_restore.as_ref().is_some_and(Result::is_err) {
            return Err(OracleError::Invalid("oracle host mask restoration failed"));
        }
        Ok(())
    }
}

impl Drop for ArtifactOwner {
    fn drop(&mut self) {
        // A panic cannot drop the host mask or physical owner ahead of drain.
        // A failed/unwound cleanup is fail-stop, including on a double unwind.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.finish()?;
            self.restore_mask()
        }));
        if !matches!(result, Ok(Ok(()))) {
            std::process::abort();
        }
    }
}
