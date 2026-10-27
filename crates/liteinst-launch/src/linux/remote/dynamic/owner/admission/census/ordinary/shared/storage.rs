use super::*;

impl PreparedOrdinaryHistory {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            archive: None,
            allocation: Progress::default(),
            installed_bytes: 0,
            transferred: false,
        }
    }
    /// Includes this retained preparation header, the exact Box payload header
    /// (all fourteen endpoint headers), and three exact MAX buffers.
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, SharedError> {
        checked(
            checked(size_of::<Self>(), size_of::<OrdinaryHistoryPayloads>())?,
            PAYLOADS
                .checked_mul(MAX_XSTATE_BYTES)
                .ok_or(SharedError::Capacity)?,
        )
    }
    /// Actual ownership still in preparation. A successful transfer moves the
    /// same Box to the census; integration must count that destination once.
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, SharedError> {
        let mut bytes = size_of::<Self>();
        if let Some(archive) = &self.archive {
            bytes = checked(bytes, size_of::<OrdinaryHistoryPayloads>())?;
            for payload in &archive.payloads {
                bytes = checked(bytes, payload.bytes.capacity())?;
            }
        }
        Ok(bytes)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn installed_bytes(&self) -> usize {
        self.installed_bytes
    }

    // Only the ordinary census parent can install a full binding. It still
    // validates actual current/reservation/serial before this descriptive copy.
    pub(in crate::linux::remote::dynamic::owner::admission::census::ordinary) fn allocate_payloads(
        &mut self,
        binding: Binding,
        owner: OriginId,
    ) -> Result<(), SharedError> {
        self.allocate_with(binding, owner, |_| Ok(()), |_| {})
    }
    pub(super) fn allocate_with(
        &mut self,
        binding: Binding,
        owner: OriginId,
        mut before: impl FnMut(usize) -> Result<(), SharedError>,
        mut after: impl FnMut(usize),
    ) -> Result<(), SharedError> {
        self.allocation.begin()?;
        let result = (|| {
            require(
                self.archive.is_none() && !self.transferred && self.installed_bytes == 0,
                SharedError::Reused,
            )?;
            require(
                binding.census != 0
                    && binding.reservation.census == binding.census
                    && binding.origin.census == binding.census
                    && binding.origin.serial != 0
                    && owner.census == binding.census
                    && owner.serial == binding.candidate_serial
                    && owner.serial != 0
                    && owner != binding.origin
                    && binding.execution.session != 0
                    && binding.execution.serial != 0,
                SharedError::Identity,
            )?;
            let next = checked(self.installed_bytes, size_of::<OrdinaryHistoryPayloads>())?;
            before(0)?;
            let archive = exact_storage::value(OrdinaryHistoryPayloads::empty(binding, owner))
                .map_err(allocation_error)?;
            self.archive = Some(archive);
            self.installed_bytes = next;
            self.allocation.filled = 1;
            after(0);
            for index in 0..PAYLOADS {
                let next = checked(self.installed_bytes, MAX_XSTATE_BYTES)?;
                before(index + 1)?;
                let bytes =
                    exact_storage::empty_bytes(MAX_XSTATE_BYTES).map_err(allocation_error)?;
                self.archive.as_mut().expect("installed archive").payloads[index].bytes = bytes;
                self.installed_bytes = next;
                self.allocation.filled = index + 2;
                after(index + 1);
            }
            self.allocation.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.allocation.fail(error);
        }
        result
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        if self.transferred {
            return;
        }
        if !self.allocation.complete {
            self.allocation.fail(SharedError::Aborted);
        }
        if let Some(archive) = &mut self.archive {
            for payload in &mut archive.payloads {
                if payload.copy.started && !payload.copy.complete {
                    payload.copy.fail(SharedError::Aborted);
                }
            }
            if archive.prior.started && !archive.prior.complete {
                archive.prior.fail(SharedError::Aborted);
            }
            if archive.native.started && !archive.native.complete {
                archive.native.fail(SharedError::Aborted);
            }
        }
    }
    pub(super) fn require_allocation(&self) -> Result<(), SharedError> {
        self.allocation.require_complete()?;
        require(
            !self.transferred
                && self.allocation.filled == PAYLOADS + 1
                && self.archive.is_some()
                && self.allocated_bytes()? == Self::reservation_bytes()?
                && checked(size_of::<Self>(), self.installed_bytes)? == Self::reservation_bytes()?,
            SharedError::Capacity,
        )
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn archive(
        &self,
    ) -> Result<&OrdinaryHistoryPayloads, SharedError> {
        self.require_allocation()?;
        self.archive.as_deref().ok_or(SharedError::Incomplete)
    }
    /// All fallible validation must precede the integration's no-fail commit
    /// section. A caller must immediately install the returned owner; dropping
    /// it after another fallible operation would violate retained custody.
    pub(in crate::linux::remote::dynamic::owner::admission::census::ordinary) fn take_complete(
        &mut self,
    ) -> Result<Box<OrdinaryHistoryPayloads>, SharedError> {
        self.archive()?.require_complete()?;
        let owner = self.archive.take().ok_or(SharedError::Incomplete)?;
        self.transferred = true;
        Ok(owner)
    }
}
impl OrdinaryHistoryPayloads {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn allocated_bytes(
        &self,
    ) -> Result<usize, SharedError> {
        self.payloads
            .iter()
            .try_fold(size_of::<Self>(), |sum, value| {
                checked(sum, value.bytes.capacity())
            })
    }
    pub(super) fn require_complete(&self) -> Result<(), SharedError> {
        self.prior.require_complete()?;
        self.native.require_complete()?;
        require(
            self.prior.filled == 1
                && self.native.filled == ENDPOINTS - 1
                && self.trace.is_some()
                && self.headers.iter().all(Option::is_some),
            SharedError::Incomplete,
        )?;
        for payload in &self.payloads {
            payload.copy.require_complete()?;
            require(
                payload.copy.filled == payload.bytes.len()
                    && (512..MAX_XSTATE_BYTES).contains(&payload.bytes.len())
                    && payload.bytes.capacity() == MAX_XSTATE_BYTES,
                SharedError::Extent,
            )?;
        }
        Ok(())
    }
}
