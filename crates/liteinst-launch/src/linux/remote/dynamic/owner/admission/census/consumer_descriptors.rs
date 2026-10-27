//! Feature-only descriptor ownership. This prepares storage, never a native seal.
use super::super::exact_storage;
use super::runtime_stack::consumer_oracle::storage::{checked_add, require};
use super::*;
use std::mem::{size_of, swap};

#[cfg(test)]
#[path = "consumer_descriptors/tests.rs"]
mod consumer_oracle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct ConsumerDescriptorDemand {
    pub(in super::super) origins: usize,
    pub(in super::super) history: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    pointer: usize,
    length: usize,
    capacity: usize,
}
impl Identity {
    fn of<T>(value: &Vec<T>) -> Self {
        Self {
            pointer: value.as_ptr() as usize,
            length: value.len(),
            capacity: value.capacity(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CensusIdentity {
    identity: u64,
    session: u64,
    space: AddressSpaceId,
    generation: u64,
    limits: Limits,
}
impl CensusIdentity {
    fn of(census: &ResumeCensus) -> Self {
        Self {
            identity: census.identity,
            session: census.session,
            space: census.space,
            generation: census.state.generation,
            limits: census.limits,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Shape {
    census: CensusIdentity,
    old: [Identity; 2],
    target: [usize; 2],
    demand: ConsumerDescriptorDemand,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Progress {
    planning_started: bool,
    allocation_started: [bool; 2],
    allocated: [bool; 2],
    complete: bool,
    first_failure: Option<CensusConsumerError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CensusStamp {
    identity: CensusIdentity,
    next_serial: u64,
    charged: BudgetCharge,
    used: BudgetCharge,
    reservation: Option<(Reservation, BudgetCharge)>,
    descriptors: [Identity; 2],
}
impl CensusStamp {
    fn of(census: &ResumeCensus) -> Self {
        Self {
            identity: CensusIdentity::of(census),
            next_serial: census.state.next_serial,
            charged: census.state.charged,
            used: census.state.used,
            reservation: census.state.reservation,
            descriptors: [
                Identity::of(&census.state.origins),
                Identity::of(&census.state.history),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct ConsumerDescriptorRetention {
    shape: Option<Shape>,
    progress: Progress,
    token: Option<Reservation>,
    installed: Option<[Identity; 2]>,
    owners: [Identity; 2],
    census: Option<CensusStamp>,
}

pub(in super::super) struct PreparedConsumerDescriptors {
    shape: Option<Shape>,
    progress: Progress,
    token: Option<Reservation>,
    installed: Option<[Identity; 2]>,
    // Before transfer: replacements. After transfer: empty original owners.
    origins: Vec<StoredOrigin>,
    history: Vec<HistoryRecord>,
    #[cfg(test)]
    fault: Option<consumer_oracle::Fault>,
}

fn bytes(origins: usize, history: usize) -> Result<usize, CensusConsumerError> {
    checked_add(
        origins
            .checked_mul(size_of::<StoredOrigin>())
            .ok_or(CensusConsumerError::Capacity)?,
        history
            .checked_mul(size_of::<HistoryRecord>())
            .ok_or(CensusConsumerError::Capacity)?,
    )
}

impl PreparedConsumerDescriptors {
    #[cfg(test)]
    pub(in super::super) fn supplied_model_for_test() -> ResumeCensus {
        consumer_oracle::seeded()
    }

    #[cfg(test)]
    pub(in super::super) fn set_allocation_fault(
        &mut self,
        before: Option<usize>,
        after: Option<usize>,
    ) {
        assert_eq!(self.progress, Progress::default());
        assert!(before.is_none_or(|index| index < 2));
        assert!(after.is_none_or(|index| index < 2));
        self.fault = Some(consumer_oracle::Fault { before, after });
    }

    pub(in super::super) fn empty() -> Self {
        Self {
            shape: None,
            progress: Progress::default(),
            token: None,
            installed: None,
            origins: Vec::new(),
            history: Vec::new(),
            #[cfg(test)]
            fault: None,
        }
    }

    fn fail(&mut self, error: CensusConsumerError) {
        self.progress.first_failure.get_or_insert(error);
    }

    pub(in super::super) fn plan(
        &mut self,
        census: &ResumeCensus,
        demand: ConsumerDescriptorDemand,
    ) -> Result<(), CensusConsumerError> {
        if self.progress != Progress::default() || self.shape.is_some() {
            return Err(CensusConsumerError::Reused);
        }
        self.progress.planning_started = true;
        let result = (|| {
            require(
                census.state.reservation.is_none()
                    && census.state.generation == 0
                    && census.state.origins.len() == 1
                    && census.state.history.is_empty()
                    && census.state.origins[0].active
                    && demand.origins > 0
                    && demand.history > 0,
            )?;
            let old = [
                Identity::of(&census.state.origins),
                Identity::of(&census.state.history),
            ];
            let needed = [
                checked_add(old[0].length, demand.origins)?,
                checked_add(old[1].length, demand.history)?,
            ];
            require(needed[0] <= census.limits.origins && needed[1] <= census.limits.witnesses)?;
            let target = [
                old[0].capacity.max(needed[0]),
                old[1].capacity.max(needed[1]),
            ];
            let shape = Shape {
                census: CensusIdentity::of(census),
                old,
                target,
                demand,
            };
            // Check every bound before installing a usable shape.
            bytes(
                checked_add(old[0].capacity, target[0])?,
                checked_add(old[1].capacity, target[1])?,
            )?;
            self.shape = Some(shape);
            Ok(())
        })();
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }

    pub(in super::super) fn reservation_bytes(&self) -> Result<usize, CensusConsumerError> {
        let shape = self.shape.ok_or(CensusConsumerError::Incomplete)?;
        checked_add(
            size_of::<Self>(),
            bytes(
                checked_add(shape.old[0].capacity, shape.target[0])?,
                checked_add(shape.old[1].capacity, shape.target[1])?,
            )?,
        )
    }

    pub(in super::super) fn allocated_bytes(
        &self,
        census: Option<&ResumeCensus>,
    ) -> Result<usize, CensusConsumerError> {
        let own = bytes(self.origins.capacity(), self.history.capacity())?;
        let actual = match census {
            Some(census) => {
                if let Some(shape) = self.shape {
                    require(shape.census == CensusIdentity::of(census))?;
                }
                bytes(
                    census.state.origins.capacity(),
                    census.state.history.capacity(),
                )?
            }
            None => {
                require(!self.progress.planning_started && self.shape.is_none() && own == 0)?;
                0
            }
        };
        checked_add(size_of::<Self>(), checked_add(own, actual)?)
    }

    pub(in super::super) fn allocate_in_place(
        &mut self,
        census: &mut ResumeCensus,
        token: Reservation,
    ) -> Result<(), CensusConsumerError> {
        if self.token.is_some()
            || self.progress.allocation_started != [false; 2]
            || self.progress.complete
            || self.progress.first_failure.is_some()
        {
            return Err(CensusConsumerError::Reused);
        }
        // The actual token is retained even when its validation refuses.
        self.token = Some(token);
        let result = (|| {
            let shape = self.shape.ok_or(CensusConsumerError::Incomplete)?;
            require(
                shape.census == CensusIdentity::of(census)
                    && shape.old
                        == [
                            Identity::of(&census.state.origins),
                            Identity::of(&census.state.history),
                        ]
                    && self.origins.is_empty()
                    && self.origins.capacity() == 0
                    && self.history.is_empty()
                    && self.history.capacity() == 0,
            )?;
            census.check_reserved(
                token,
                BudgetCharge {
                    source_fact_bytes: self.reservation_bytes()?,
                    ..BudgetCharge::default()
                },
            )?;
            self.progress.allocation_started[0] = true;
            #[cfg(test)]
            consumer_oracle::before(self.fault, 0)?;
            self.origins = exact_storage::empty_vec(shape.target[0])?;
            self.progress.allocated[0] = true;
            #[cfg(test)]
            consumer_oracle::after(self.fault, 0);
            self.progress.allocation_started[1] = true;
            #[cfg(test)]
            consumer_oracle::before(self.fault, 1)?;
            self.history = exact_storage::empty_vec(shape.target[1])?;
            self.progress.allocated[1] = true;
            #[cfg(test)]
            consumer_oracle::after(self.fault, 1);
            require(
                self.origins.capacity() == shape.target[0]
                    && self.history.capacity() == shape.target[1]
                    && self.origins.is_empty()
                    && self.history.is_empty()
                    && shape.old
                        == [
                            Identity::of(&census.state.origins),
                            Identity::of(&census.state.history),
                        ]
                    && shape.old[0].length <= self.origins.capacity()
                    && shape.old[1].length <= self.history.capacity()
                    && self.allocated_bytes(Some(census))? == self.reservation_bytes()?,
            )?;
            // Capacity has been proved. These complete element moves cannot
            // grow, allocate, call user code, or drop an initialized owner.
            // No fallible operation/hook occurs until both owners are installed.
            self.origins.append(&mut census.state.origins);
            swap(&mut self.origins, &mut census.state.origins);
            self.history.append(&mut census.state.history);
            swap(&mut self.history, &mut census.state.history);
            self.installed = Some([
                Identity::of(&census.state.origins),
                Identity::of(&census.state.history),
            ]);
            self.progress.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }

    pub(in super::super) fn mark_aborted(&mut self) {
        if self.progress.planning_started && !self.progress.complete {
            self.fail(CensusConsumerError::Aborted);
        }
    }

    pub(in super::super) fn require_complete(
        &self,
        census: &ResumeCensus,
    ) -> Result<(), CensusConsumerError> {
        let shape = self.shape.ok_or(CensusConsumerError::Incomplete)?;
        let installed = self.installed.ok_or(CensusConsumerError::Incomplete)?;
        let now = [
            Identity::of(&census.state.origins),
            Identity::of(&census.state.history),
        ];
        require(
            self.progress.complete
                && self.progress.allocated == [true; 2]
                && self.progress.first_failure.is_none()
                && self.token.is_some()
                && shape.census == CensusIdentity::of(census)
                && self.origins.is_empty()
                && self.history.is_empty()
                && Identity::of(&self.origins)
                    == Identity {
                        length: 0,
                        ..shape.old[0]
                    }
                && Identity::of(&self.history)
                    == Identity {
                        length: 0,
                        ..shape.old[1]
                    }
                && checked_add(shape.old[0].length, shape.demand.origins)? <= shape.target[0]
                && checked_add(shape.old[1].length, shape.demand.history)? <= shape.target[1]
                && now.iter().zip(installed).all(|(now, old)| {
                    now.pointer == old.pointer
                        && now.capacity == old.capacity
                        && old.length <= now.length
                        && now.length <= now.capacity
                })
                && self.allocated_bytes(Some(census))? == self.reservation_bytes()?,
        )
    }

    pub(in super::super) fn retention_snapshot(
        &self,
        census: Option<&ResumeCensus>,
    ) -> Result<ConsumerDescriptorRetention, CensusConsumerError> {
        self.allocated_bytes(census)?;
        if self.progress.complete {
            self.require_complete(census.ok_or(CensusConsumerError::Incomplete)?)?;
        }
        Ok(ConsumerDescriptorRetention {
            shape: self.shape,
            progress: self.progress,
            token: self.token,
            installed: self.installed,
            owners: [Identity::of(&self.origins), Identity::of(&self.history)],
            census: census.map(CensusStamp::of),
        })
    }

    pub(in super::super) fn require_retention(
        &self,
        census: Option<&ResumeCensus>,
        expected: &ConsumerDescriptorRetention,
    ) -> Result<(), CensusConsumerError> {
        require(self.retention_snapshot(census)? == *expected)
    }
}

/// Source-value envelope, including the allocator and this calculator itself.
/// Old/new heap overlap is retained and charged in reservation_bytes, not lost.
pub(in super::super) fn consumer_descriptor_temporary_bytes() -> Result<usize, CensusConsumerError>
{
    let terms = [
        size_of::<PreparedConsumerDescriptors>(),
        4 * size_of::<Shape>(),
        4 * size_of::<Progress>(),
        4 * size_of::<ConsumerDescriptorRetention>(),
        4 * size_of::<CensusStamp>(),
        4 * size_of::<ConsumerDescriptorDemand>(),
        8 * size_of::<Identity>(),
        size_of::<StoredOrigin>(),
        size_of::<HistoryRecord>(),
        4 * size_of::<Vec<StoredOrigin>>() + 4 * size_of::<Vec<HistoryRecord>>(),
        2 * size_of::<Result<Vec<StoredOrigin>, exact_storage::AllocationError>>(),
        2 * size_of::<Result<Vec<HistoryRecord>, exact_storage::AllocationError>>(),
        4 * size_of::<std::alloc::Layout>() + 4 * size_of::<std::alloc::LayoutError>(),
        8 * size_of::<*mut u8>() + 8 * size_of::<&ResumeCensus>(),
        4 * size_of::<BudgetCharge>() + 4 * size_of::<Reservation>(),
        12 * size_of::<Result<(), CensusConsumerError>>() + 4 * size_of::<CensusError>(),
        2 * size_of::<
            std::iter::Zip<std::slice::Iter<'static, Identity>, std::array::IntoIter<Identity, 2>>,
        >(),
        size_of::<[usize; 48]>() + size_of::<[bool; 16]>() + size_of::<[Option<usize>; 12]>(),
        size_of::<[Option<Shape>; 4]>() + size_of::<[Option<CensusStamp>; 4]>(),
        size_of::<[usize; 20]>() + size_of::<std::array::IntoIter<usize, 20>>(),
    ];
    terms.into_iter().try_fold(0, checked_add)
}
