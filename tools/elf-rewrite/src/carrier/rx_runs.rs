//! Checked geometry and backing for the opt-in Linux RX-run carrier profile.
use super::*;
use std::ops::Range;

struct Pages {
    image: usize,
    start: u64,
    end: u64,
    content_end: u64,
}

pub(super) struct Plan {
    pages: Vec<Pages>,
    runs: Vec<Range<usize>>,
}

impl Plan {
    pub(super) fn new(images: &[RxImage], policy: CarrierPolicy) -> Result<Self, Error> {
        let mut pages = Vec::with_capacity(images.len());
        for (image, item) in images.iter().enumerate() {
            if item.bytes.is_empty() {
                return Err(Error::InvalidImage { index: image });
            }
            let start = align_down(item.entry.0, policy.page_size);
            let content_end = add(
                item.entry.0,
                item.bytes.len() as u64,
                "image virtual extent",
            )?;
            let end = align_up(content_end, policy.page_size)?;
            if end > policy.user_address_limit {
                return Err(Error::AddressLimit { index: None });
            }
            pages.push(Pages {
                image,
                start,
                end,
                content_end,
            });
        }
        pages.sort_by_key(|page| page.start);
        let mut runs: Vec<Range<usize>> = Vec::new();
        for (index, page) in pages.iter().enumerate() {
            if index != 0 && page.start < pages[index - 1].end {
                return Err(Error::InvalidImage { index: page.image });
            }
            if let Some(run) = runs.last_mut() {
                if pages[run.end - 1].end == page.start {
                    run.end = index + 1;
                    continue;
                }
            }
            runs.push(index..index + 1);
        }
        Ok(Self { pages, runs })
    }

    pub(super) fn run_count(&self) -> usize {
        self.runs.len()
    }

    pub(super) fn file_offsets(
        &self,
        mut end: u64,
        page_size: u64,
    ) -> Result<(Vec<u64>, u64), Error> {
        let mut offsets = vec![0; self.pages.len()];
        for run in &self.runs {
            let start = self.pages[run.start].start;
            let offset = align_up(end, page_size)?;
            for page in &self.pages[run.clone()] {
                offsets[page.image] = add(offset, page.start - start, "packed image file page")?;
            }
            end = add(
                offset,
                self.pages[run.end - 1].content_end - start,
                "packed RX file extent",
            )?;
        }
        Ok((offsets, end))
    }

    pub(super) fn coalesce(&self, added: Vec<AddedLoad>) -> Result<Vec<AddedLoad>, Error> {
        let count = self.runs.len().checked_add(1).ok_or(Error::Arithmetic {
            operation: "packed load count",
        })?;
        let mut result: Vec<AddedLoad> = Vec::with_capacity(count);
        for load in added {
            if let Some(previous) = result.last_mut() {
                if previous.image.is_some()
                    && load.image.is_some()
                    && previous.flags == 5
                    && load.flags == 5
                    && previous.page_end == load.vaddr
                {
                    // The VA page union is already disjoint and owned. It must
                    // also be one linear file mapping, including zero padding.
                    let expected = add(
                        previous.offset,
                        load.vaddr - previous.vaddr,
                        "packed RX file continuity",
                    )?;
                    if load.offset != expected {
                        return Err(Error::OutputInvariant);
                    }
                    previous.size = add(
                        load.vaddr - previous.vaddr,
                        load.size,
                        "packed RX load extent",
                    )?;
                    previous.page_end = load.page_end;
                    continue;
                }
            }
            result.push(load);
        }
        if result.len() != count {
            return Err(Error::OutputInvariant);
        }
        Ok(result)
    }

    pub(super) fn assign_headers(&self, placements: &mut [ImagePlacement]) -> Result<(), Error> {
        if placements.len() != self.pages.len() {
            return Err(Error::OutputInvariant);
        }
        for run in &self.runs {
            let header = placements[self.pages[run.start].image].program_header;
            if header == usize::MAX {
                return Err(Error::OutputInvariant);
            }
            for page in &self.pages[run.clone()] {
                let placement = &mut placements[page.image];
                if placement.program_header != usize::MAX && placement.program_header != header {
                    return Err(Error::OutputInvariant);
                }
                placement.program_header = header;
            }
        }
        Ok(())
    }
}
