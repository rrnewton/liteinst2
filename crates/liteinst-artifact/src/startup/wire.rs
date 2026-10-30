//! Canonical little-endian catalog envelope. This is not a second ELF decoder.
use super::*;
const MAGIC: &[u8; 8] = b"LI2BOOT\0";
struct Writer(Vec<u8>);
impl Writer {
    fn n(&mut self, n: u64) {
        self.0.extend_from_slice(&n.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.n(b.len() as u64);
        self.0.extend_from_slice(b);
    }
    fn span(&mut self, s: Span) {
        self.n(s.start);
        self.n(s.len);
    }
    fn blob(&mut self, b: &Blob) {
        self.n(b.address);
        self.bytes(&b.bytes);
    }
    fn pairs(&mut self, p: &[(u64, u64)]) {
        self.n(p.len() as u64);
        for &(a, b) in p {
            self.n(a);
            self.n(b);
        }
    }
}
pub(super) fn encode(x: &Input) -> Result<Vec<u8>> {
    validate(x)?;
    let mut w = Writer(MAGIC.to_vec());
    w.n(2);
    w.n(x.program);
    let p = &x.policy;
    w.bytes(&p.interpreter);
    w.bytes(&p.bootstrap_dso);
    w.n(p.dependencies.len() as u64);
    for d in &p.dependencies {
        w.bytes(&d.path);
        w.0.extend_from_slice(&d.identity.0);
    }
    w.span(p.app_stack);
    w.n(p.hook_pc);
    w.n(p.hook_id);
    w.0.extend_from_slice(&p.qualification_contract.0);
    let s = &p.state;
    for n in [s.domain, s.format, s.allocation, s.image, s.mask] {
        w.n(n);
    }
    w.n(s.components.len() as u64);
    for &(a, b, c) in &s.components {
        w.n(a);
        w.n(b);
        w.n(c);
    }
    for b in [
        &x.original,
        &x.main,
        &x.selection,
        &x.metadata,
        &x.target,
        &x.ledger,
    ] {
        w.bytes(b);
    }
    w.n(x.heads.len() as u64);
    for &h in &x.heads {
        w.n(h);
    }
    w.n(x.steps.len() as u64);
    for s in &x.steps {
        w.n(s.selected_id);
        w.n(s.logical);
        w.n(s.physical);
        w.span(s.displaced);
        match s.kind {
            Kind::Relocation => w.n(0),
            Kind::GeneralizedPun(p) | Kind::PrefixedPun(p) => {
                w.n(if matches!(s.kind, Kind::GeneralizedPun(_)) {
                    1
                } else {
                    2
                });
                w.n(p.instruction_len);
                w.n(p.prefixes);
                w.span(p.consumed);
                w.span(p.target_window);
                w.span(p.store);
            }
        }
        match s.neighbor {
            None => w.n(0),
            Some(n) => {
                w.n(1);
                for v in [
                    n.selected,
                    n.selected_len,
                    n.victim,
                    n.victim_len,
                    n.relay,
                    n.rel8 as u8 as u64,
                    n.selected_target,
                    n.victim_target,
                ] {
                    w.n(v);
                }
            }
        }
        for list in [&s.reads, &s.writes] {
            w.n(list.len() as u64);
            for b in list {
                w.blob(b);
            }
        }
        w.n(s.dependencies.len() as u64);
        for &d in &s.dependencies {
            w.span(d);
        }
        w.span(s.allocation);
        w.n(s.image);
        w.n(s.obligations.len() as u64);
        for o in &s.obligations {
            w.n(o.original);
            match o.generated {
                None => {
                    w.n(0);
                    w.n(0)
                }
                Some(g) => {
                    w.n(1);
                    w.n(g)
                }
            }
        }
    }
    w.n(x.images.len() as u64);
    for i in &x.images {
        w.blob(&i.body);
        w.pairs(&i.entries);
        w.pairs(&i.requirements);
    }
    if w.0.len() > MAX_CATALOG - 32 {
        return Err(Error::Limit);
    }
    let id = ContentId::of(&w.0);
    w.0.extend_from_slice(&id.0);
    Ok(w.0)
}
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    records: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Limit)?;
        let b = self.b.get(self.at..end).ok_or(Error::Shape)?;
        self.at = end;
        Ok(b)
    }
    fn n(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Shape)?,
        ))
    }
    fn count(&mut self, cap: usize) -> Result<usize> {
        let n = usize::try_from(self.n()?).map_err(|_| Error::Limit)?;
        if n > cap { Err(Error::Limit) } else { Ok(n) }
    }
    fn records(&mut self, cap: usize) -> Result<usize> {
        let n = self.count(cap)?;
        self.records = self.records.checked_sub(n).ok_or(Error::Limit)?;
        Ok(n)
    }
    fn bytes(&mut self, cap: usize) -> Result<Vec<u8>> {
        let n = self.count(cap)?;
        Ok(self.take(n)?.to_vec())
    }
    fn span(&mut self) -> Result<Span> {
        Ok(Span {
            start: self.n()?,
            len: self.n()?,
        })
    }
    fn blob(&mut self) -> Result<Blob> {
        Ok(Blob {
            address: self.n()?,
            bytes: self.bytes(MAX_FILE)?,
        })
    }
    fn pairs(&mut self) -> Result<Vec<(u64, u64)>> {
        let n = self.records(MAX_RECORDS)?;
        (0..n).map(|_| Ok((self.n()?, self.n()?))).collect()
    }
    fn blobs(&mut self) -> Result<Vec<Blob>> {
        let n = self.records(MAX_RECORDS)?;
        (0..n).map(|_| self.blob()).collect()
    }
}
pub(super) fn decode(b: &[u8]) -> Result<Input> {
    if b.len() > MAX_CATALOG || b.len() < 56 {
        return Err(Error::Limit);
    }
    let (body, id) = b.split_at(b.len() - 32);
    if ContentId::of(body).0.as_slice() != id {
        return Err(Error::Identity);
    }
    let mut r = Reader {
        b: body,
        at: 0,
        records: MAX_RECORDS,
    };
    if r.take(8)? != MAGIC || r.n()? != 2 {
        return Err(Error::Shape);
    }
    let program = r.n()?;
    let interpreter = r.bytes(4095)?;
    let bootstrap_dso = r.bytes(4095)?;
    let n = r.records(16)?;
    let mut dependencies = Vec::new();
    for _ in 0..n {
        dependencies.push(Dependency {
            path: r.bytes(4095)?,
            identity: ContentId(r.take(32)?.try_into().map_err(|_| Error::Shape)?),
        });
    }
    let app_stack = r.span()?;
    let hook_pc = r.n()?;
    let hook_id = r.n()?;
    let qualification_contract = ContentId(r.take(32)?.try_into().map_err(|_| Error::Shape)?);
    let mut state = State {
        domain: r.n()?,
        format: r.n()?,
        allocation: r.n()?,
        image: r.n()?,
        mask: r.n()?,
        components: Vec::new(),
    };
    let n = r.records(64)?;
    for _ in 0..n {
        state.components.push((r.n()?, r.n()?, r.n()?));
    }
    let original = r.bytes(MAX_FILE)?;
    let main = r.bytes(MAX_FILE)?;
    let selection = r.bytes(1024 * 1024)?;
    let metadata = r.bytes(1024 * 1024)?;
    let target = r.bytes(65536)?;
    let ledger = r.bytes(MAX_FILE)?;
    let n = r.records(107)?;
    let heads = (0..n).map(|_| r.n()).collect::<Result<Vec<_>>>()?;
    let n = r.records(4096)?;
    let mut steps = Vec::new();
    for _ in 0..n {
        let selected_id = r.n()?;
        let logical = r.n()?;
        let physical = r.n()?;
        let displaced = r.span()?;
        let tag = r.n()?;
        let kind = match tag {
            0 => Kind::Relocation,
            1 | 2 => {
                let p = Pun {
                    instruction_len: r.n()?,
                    prefixes: r.n()?,
                    consumed: r.span()?,
                    target_window: r.span()?,
                    store: r.span()?,
                };
                if tag == 1 {
                    Kind::GeneralizedPun(p)
                } else {
                    Kind::PrefixedPun(p)
                }
            }
            _ => return Err(Error::Shape),
        };
        let neighbor = match r.n()? {
            0 => None,
            1 => {
                let selected = r.n()?;
                let selected_len = r.n()?;
                let victim = r.n()?;
                let victim_len = r.n()?;
                let relay = r.n()?;
                let rel8 = u8::try_from(r.n()?).map_err(|_| Error::Shape)? as i8;
                Some(Neighbor {
                    selected,
                    selected_len,
                    victim,
                    victim_len,
                    relay,
                    rel8,
                    selected_target: r.n()?,
                    victim_target: r.n()?,
                })
            }
            _ => return Err(Error::Shape),
        };
        let reads = r.blobs()?;
        let writes = r.blobs()?;
        let n = r.records(MAX_RECORDS)?;
        let dependencies = (0..n).map(|_| r.span()).collect::<Result<Vec<_>>>()?;
        let allocation = r.span()?;
        let image = r.n()?;
        let n = r.records(MAX_RECORDS)?;
        let mut obligations = Vec::new();
        for _ in 0..n {
            let original = r.n()?;
            let tag = r.n()?;
            let value = r.n()?;
            let generated = match (tag, value) {
                (0, 0) => None,
                (1, v) if v != 0 => Some(v),
                _ => return Err(Error::Shape),
            };
            obligations.push(Obligation {
                original,
                generated,
            });
        }
        steps.push(Step {
            selected_id,
            logical,
            physical,
            displaced,
            kind,
            neighbor,
            reads,
            writes,
            dependencies,
            allocation,
            image,
            obligations,
        });
    }
    let n = r.records(4096)?;
    let mut images = Vec::new();
    for _ in 0..n {
        images.push(Image {
            body: r.blob()?,
            entries: r.pairs()?,
            requirements: r.pairs()?,
        });
    }
    if r.at != body.len() {
        return Err(Error::Shape);
    }
    Ok(Input {
        program,
        policy: Policy {
            interpreter,
            bootstrap_dso,
            dependencies,
            app_stack,
            hook_pc,
            hook_id,
            state,
            qualification_contract,
        },
        original,
        main,
        selection,
        metadata,
        target,
        ledger,
        heads,
        steps,
        images,
    })
}
