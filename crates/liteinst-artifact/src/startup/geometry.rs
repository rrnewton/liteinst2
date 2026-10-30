//! Direct source-encoding checks, using the replay's pre-step byte view.
use super::*;

pub(super) fn near_target(elf: &Elf64<'_>, pc: u64, prefixes: u64, target: u64) -> Result<()> {
    if prefixes > 3 {
        return Err(Error::Route);
    }
    let b = elf
        .executable_bytes(ElfVaddr(pc), prefixes + 5)
        .map_err(|_| Error::Route)?;
    let p = prefixes as usize;
    if b[..p].iter().any(|&v| v != 0x2e) || b[p] != 0xe9 {
        return Err(Error::Route);
    }
    let d = i32::from_le_bytes(b[p + 1..p + 5].try_into().map_err(|_| Error::Route)?);
    if i128::from(pc) + i128::from(prefixes) + 5 + i128::from(d) != i128::from(target) {
        return Err(Error::Route);
    }
    Ok(())
}
fn jump(pc: u64, target: u64) -> Result<Vec<u8>> {
    let d = i32::try_from(i128::from(target) - i128::from(pc) - 5).map_err(|_| Error::Route)?;
    Ok([&[0xe9][..], &d.to_le_bytes()].concat())
}
fn bytes<'a>(old: &Elf64<'_>, view: &'a [u8], span: Span) -> Result<&'a [u8]> {
    let r = file_range(old, span.start, span.len, 5)?;
    view.get(r).ok_or(Error::Source)
}

pub(super) fn validate_neighbors(x: &Input, meta: &Metadata) -> Result<()> {
    for s in &x.steps {
        let Some(n) = s.neighbor else { continue };
        let selected = Span {
            start: n.selected,
            len: n.selected_len,
        };
        let victim = Span {
            start: n.victim,
            len: n.victim_len,
        };
        if !(2..=4).contains(&n.selected_len)
            || !(6..=15).contains(&n.victim_len)
            || selected.start < victim.end()? && victim.start < selected.end()?
            || n.relay != n.victim.checked_add(5).ok_or(Error::Route)?
            || i128::from(n.relay) - i128::from(n.selected) - 2 != i128::from(n.rel8)
            || n.selected_target == n.victim_target
            || meta
                .sites()
                .iter()
                .find(|m| m.id == s.selected_id)
                .map(|m| m.original_pc)
                != Some(n.selected)
        {
            return Err(Error::Route);
        }
        let pair = x
            .steps
            .iter()
            .filter(|t| t.selected_id == s.selected_id)
            .collect::<Vec<_>>();
        if pair.len() != 2
            || pair.iter().any(|t| {
                t.neighbor != Some(n) || t.kind != Kind::Relocation || t.logical != t.physical
            })
        {
            return Err(Error::Route);
        }
        for (pc, span, target) in [
            (n.selected, selected, n.selected_target),
            (n.victim, victim, n.victim_target),
        ] {
            let owners = pair
                .iter()
                .filter(|t| t.physical == pc && t.displaced == span && t.image == target)
                .collect::<Vec<_>>();
            if owners.len() != 1
                || owners[0].obligations
                    != [Obligation {
                        original: pc,
                        generated: None,
                    }]
            {
                return Err(Error::Route);
            }
        }
        // Neighbor bundles compose the original higher member first, including
        // a selected EB that lies in the short victim's unchanged fetch suffix.
        if pair[0].physical <= pair[1].physical {
            return Err(Error::Route);
        }
    }
    Ok(())
}

pub(super) fn validate_source_encoding(
    s: &Step,
    old: &Elf64<'_>,
    prior: &[u8],
    main: &Elf64<'_>,
) -> Result<Span> {
    if s.displaced.start != s.physical {
        return Err(Error::Source);
    }
    if let Some(n) = s.neighbor {
        if s.kind != Kind::Relocation {
            return Err(Error::Route);
        }
        let expected = if s.physical == n.selected {
            vec![0xeb, n.rel8 as u8]
        } else if s.physical == n.victim {
            [
                jump(n.victim, n.victim_target)?,
                jump(n.relay, n.selected_target)?,
            ]
            .concat()
        } else {
            return Err(Error::Route);
        };
        if s.writes
            != [Blob {
                address: s.physical,
                bytes: expected.clone(),
            }]
        {
            return Err(Error::Route);
        }
        let written = Span {
            start: s.physical,
            len: expected.len() as u64,
        };
        let current = bytes(old, prior, written)?;
        if s.physical == n.victim
            && n.victim_len < 10
            && current[n.victim_len as usize..] != expected[n.victim_len as usize..]
        {
            return Err(Error::Route);
        }
        if main
            .executable_bytes(ElfVaddr(s.physical), written.len)
            .map_err(|_| Error::Route)?
            != expected
        {
            return Err(Error::Route);
        }
        return Ok(s.displaced);
    }
    let p = match s.kind {
        Kind::Relocation => return Ok(s.displaced),
        Kind::GeneralizedPun(p) if p.prefixes == 0 => p,
        Kind::PrefixedPun(p) if p.prefixes > 0 => p,
        _ => return Err(Error::Route),
    };
    if !(1..=4).contains(&p.instruction_len)
        || p.prefixes >= p.instruction_len
        || s.logical != s.physical
        || s.displaced.len != p.instruction_len
        || p.consumed
            != (Span {
                start: s.physical,
                len: 5 + p.prefixes,
            })
        || s.physical / 64 != (s.displaced.end()? - 1) / 64
        || s.obligations.iter().any(|o| o.generated.is_some())
    {
        return Err(Error::Route);
    }
    let store_len = p.instruction_len.next_power_of_two();
    let store_address = s.physical.min((s.physical | 63) - (store_len - 1));
    if p.store
        != (Span {
            start: store_address,
            len: store_len,
        })
    {
        return Err(Error::Route);
    }
    let current = bytes(old, prior, p.consumed)?;
    let len = p.instruction_len as usize;
    let free = len - p.prefixes as usize - 1;
    if current[..len]
        != old
            .executable_bytes(ElfVaddr(s.physical), p.instruction_len)
            .map_err(|_| Error::Route)?[..]
    {
        return Err(Error::Route);
    }
    let mut fixed = [0u8; 4];
    fixed[free..].copy_from_slice(&current[len..]);
    let low = u64::try_from(i128::from(p.consumed.end()?) + i128::from(i32::from_le_bytes(fixed)))
        .map_err(|_| Error::Route)?;
    if p.target_window
        != (Span {
            start: low,
            len: 1u64 << (8 * free),
        })
        || !p.target_window.covers(Span {
            start: s.image,
            len: 1,
        })?
    {
        return Err(Error::Route);
    }
    let displacement = i32::try_from(i128::from(s.image) - i128::from(p.consumed.end()?))
        .map_err(|_| Error::Route)?
        .to_le_bytes();
    if displacement[free..] != fixed[free..] {
        return Err(Error::Route);
    }
    let mut patch = vec![0x2e; p.prefixes as usize];
    patch.push(0xe9);
    patch.extend_from_slice(&displacement[..free]);
    let mut stored = bytes(old, prior, p.store)?.to_vec();
    let within = (s.physical - store_address) as usize;
    stored[within..within + len].copy_from_slice(&patch);
    if s.writes
        != [
            Blob {
                address: s.physical,
                bytes: patch,
            },
            Blob {
                address: store_address,
                bytes: stored,
            },
        ]
    {
        return Err(Error::Route);
    }
    // This is the current composition view, not the original file: a T2 victim
    // redirect or an earlier accepted pun can own these preserved successor bytes.
    if main
        .executable_bytes(
            ElfVaddr(s.displaced.end()?),
            p.consumed.len - p.instruction_len,
        )
        .map_err(|_| Error::Route)?
        != &current[len..]
    {
        return Err(Error::Route);
    }
    near_target(main, s.physical, p.prefixes, s.image)?;
    Ok(p.consumed)
}
