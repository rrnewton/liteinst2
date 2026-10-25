//! Stop and inspect one ELF image, then terminate it without executing its code.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use liteinst_launch::{ExecCheckpoint, LaunchCommand};
    use std::time::{Duration, Instant};
    let mut args = std::env::args_os().skip(1);
    let program = args
        .next()
        .ok_or("usage: checkpoint /path/to/executable [args...]")?;
    let command = LaunchCommand {
        program: program.into(),
        args: args.collect(),
    };
    let start = Instant::now();
    let checkpoint = ExecCheckpoint::launch(&command, Duration::from_secs(5))?;
    let elapsed = start.elapsed();
    println!(
        "checkpoint_only=true resumed=false startup_ns={} first_image={:?} initial_pc={:#x} executable_entry={:#x} mappings={}",
        elapsed.as_nanos(),
        checkpoint.entries().first_image,
        checkpoint.entries().initial_instruction,
        checkpoint.entries().executable_entry,
        checkpoint.mappings().len()
    );
    checkpoint.terminate()?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("checkpoint requires Linux x86-64");
    std::process::exit(1);
}
