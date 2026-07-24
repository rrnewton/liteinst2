use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use rapid_profiler::{DEFAULT_SAMPLE_LIMIT, RapidProfiler};

struct Options {
    image: PathBuf,
    workload: String,
    iterations: u64,
    limit: u64,
    epochs: usize,
    epoch_ms: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rapid-profiler: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let options = parse_options(env::args().skip(1))?;
    let profiler = RapidProfiler::load(&options.image, &options.workload, options.limit)?;
    let reports = profiler.run_epochs(
        options.epochs,
        options.iterations,
        Duration::from_millis(options.epoch_ms),
    )?;
    for report in reports {
        println!(
            "epoch\t{}\tworkload_result\t{}",
            report.epoch, report.workload_result
        );
        for function in report.functions {
            println!("{}\t{}", function.function, function.count);
        }
    }
    Ok(())
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut arguments = arguments;
    let image = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    let mut options = Options {
        image,
        workload: "workload".to_owned(),
        iterations: 2_500,
        limit: DEFAULT_SAMPLE_LIMIT,
        epochs: 1,
        epoch_ms: 0,
    };
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}\n{}", usage()))?;
        match flag.as_str() {
            "--workload" => options.workload = value,
            "--iterations" => options.iterations = parse(&flag, &value)?,
            "--limit" => options.limit = parse(&flag, &value)?,
            "--epochs" => options.epochs = parse(&flag, &value)?,
            "--epoch-ms" => options.epoch_ms = parse(&flag, &value)?,
            _ => return Err(format!("unknown option {flag}\n{}", usage())),
        }
    }
    Ok(options)
}

fn parse<T>(flag: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn usage() -> String {
    "usage: rapid-profiler <linked-elf> [--workload SYMBOL] [--iterations N] [--limit K] [--epochs N] [--epoch-ms N]".to_owned()
}
