use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use rapid_profiler::{DEFAULT_SAMPLE_LIMIT, MetricSummary, RapidProfiler};

#[derive(Debug)]
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
            println!(
                "{}\t{}\tleaf={}\tnon_leaf={}\tleaf_instructions={}\tnon_leaf_instructions={}\tleaf_branches={}\tnon_leaf_branches={}\tleaf_l2_misses={}\tnon_leaf_l2_misses={}\tleaf_ticks={}\tnon_leaf_ticks={}\tnon_leaf_other_samples={}\tlast_return={}",
                function.function,
                function.count,
                function.leaf.samples,
                function.non_leaf.samples,
                metric(function.leaf.instructions),
                metric(function.non_leaf.instructions),
                metric(function.leaf.branches),
                metric(function.non_leaf.branches),
                metric(function.leaf.l2_misses),
                metric(function.non_leaf.l2_misses),
                metric(function.leaf.elapsed_ticks),
                metric(function.non_leaf.elapsed_ticks),
                metric(function.non_leaf.other_samples),
                function.last_return_value,
            );
        }
    }
    Ok(())
}

fn metric(summary: MetricSummary) -> String {
    if summary.samples == 0 {
        return "unavailable".to_owned();
    }
    format!(
        "n{}/min{}/avg{}/max{}",
        summary.samples,
        summary.min,
        summary.average(),
        summary.max
    )
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    parse_options_with_default(
        arguments,
        option_env!("RAPID_PROFILER_DEFAULT_FIXTURE").map(PathBuf::from),
    )
}

fn parse_options_with_default(
    arguments: impl Iterator<Item = String>,
    default_image: Option<PathBuf>,
) -> Result<Options, String> {
    let mut arguments = arguments.peekable();
    // With no positional ELF, fall back to the fixture that build.rs compiled at
    // build time, so `cargo run --release -p rapid-profiler` Just Works.
    let image = match arguments.peek() {
        Some(path) if !path.starts_with("--") => {
            PathBuf::from(arguments.next().expect("peeked argument must exist"))
        }
        _ => default_image.ok_or_else(usage)?,
    };
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
    "usage: rapid-profiler [linked-elf] [--workload SYMBOL] [--iterations N] [--limit K] [--epochs N] [--epoch-ms N]\n\
     (the linked-elf argument is optional: with none, the built-in fixture compiled by build.rs is profiled)".to_owned()
}

#[cfg(test)]
mod tests {
    use super::parse_options_with_default;
    use std::path::PathBuf;

    #[test]
    fn default_fixture_accepts_options_without_a_positional_image() {
        let options = parse_options_with_default(
            ["--iterations", "17", "--limit", "3"]
                .into_iter()
                .map(str::to_owned),
            Some(PathBuf::from("fixture")),
        )
        .unwrap();
        assert_eq!(options.image, PathBuf::from("fixture"));
        assert_eq!(options.iterations, 17);
        assert_eq!(options.limit, 3);
    }

    #[test]
    fn positional_image_overrides_the_default_fixture() {
        let options = parse_options_with_default(
            ["custom-elf"].into_iter().map(str::to_owned),
            Some(PathBuf::from("fixture")),
        )
        .unwrap();
        assert_eq!(options.image, PathBuf::from("custom-elf"));
    }

    #[test]
    fn missing_image_and_default_is_rejected() {
        let error = parse_options_with_default(std::iter::empty(), None).unwrap_err();
        assert!(error.starts_with("usage: rapid-profiler"), "{error}");
    }
}
