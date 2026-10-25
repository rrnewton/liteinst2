#![deny(warnings)]
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
mod common;
mod inventory;
mod old {
    use old_core as li;
    include!("capture.rs");
}
mod new {
    use new_core as li;
    include!("capture.rs");
}
static OBSERVER_CALLS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn observer(_: *mut std::ffi::c_void) {
    OBSERVER_CALLS.fetch_add(1, Ordering::Relaxed);
}
fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(bytes.as_ref()).unwrap();
}
fn save(directory: &Path, record: &common::Record) {
    let p = directory.join(&record.name);
    std::fs::create_dir(&p).unwrap();
    write(&p.join("source.bin"), &record.source);
    write(&p.join("inputs.txt"), &record.inputs);
    write(&p.join("result.txt"), &record.result);
    for (i, image) in record.images.iter().enumerate() {
        write(&p.join(format!("image{i}.bin")), &image.bytes);
        write(
            &p.join(format!("image{i}.metadata.txt")),
            format!("address={}\n{}", image.address, image.metadata),
        );
    }
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 2);
    let output = std::path::PathBuf::from(&args[1]);
    assert!(!output.exists());
    assert!(output.parent().is_some_and(Path::is_dir));
    std::fs::create_dir(&output).unwrap();
    common::comparator_calibrations();
    write(
        &output.join("comparator-calibrations.txt"),
        "positive=1\nnegative=11\nno_pointer_normalization=true\n",
    );
    write(
        &output.join("inventory.tsv"),
        common::inventory(&inventory::ROWS),
    );
    write(
        &output.join("observer.txt"),
        format!("shared_observer={}\n", observer as *const () as usize),
    );
    let old_dir = output.join("old");
    let new_dir = output.join("new");
    std::fs::create_dir(&old_dir).unwrap();
    std::fs::create_dir(&new_dir).unwrap();
    let mut olds = vec![];
    let mut news = vec![];
    for (index, &row) in inventory::ROWS.iter().enumerate() {
        eprintln!("parity required row {index}: {}", row.name);
        let old = old::capture(row, index, observer);
        save(&old_dir, &old);
        let new = new::capture(row, index, observer);
        save(&new_dir, &new);
        common::compare(std::slice::from_ref(&old), std::slice::from_ref(&new)).unwrap();
        olds.push(old);
        news.push(new);
    }
    common::compare(&olds, &news).unwrap();
    assert_eq!(olds.len(), 72);
    assert_eq!(
        olds.iter()
            .filter(|r| r.expected == common::Outcome::Success)
            .count(),
        45
    );
    assert_eq!(
        olds.iter()
            .filter(|r| r.expected != common::Outcome::Success)
            .count(),
        27
    );
    assert_eq!(olds.iter().map(|r| r.images.len()).sum::<usize>(), 59);
    assert_eq!(OBSERVER_CALLS.load(Ordering::Relaxed), 0);
    write(
        &output.join("complete.txt"),
        "cases=72\nsuccesses=45\nrefusals=27\nimages_per_library=59\nexact_record_comparisons=72\nshared_observer_bindings_per_library=45\nobserver_calls=0\ngenerated_code_execution=0\npointer_normalization=0\n",
    );
    println!(
        "legacy planner parity complete: 72 exact records, 45 successes, 27 refusals, 59 images per library; no generated code executed"
    );
}
