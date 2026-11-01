//! Proposed separate 80,000-step profile; strict parent run() remains literal.
//! Same cases, deadline, child, witness, controller and full-state comparisons.
use super::*;

fn save_plan(
    output: &Path,
    plan: &[(u64, Scenario, usize)],
    statuses: &[&str],
    k: usize,
    order: usize,
) {
    assert_eq!(plan.len(), statuses.len());
    let mut text = String::from("profile,index,scenario,k,seed,case,csv_index,status\n");
    for (index, ((seed, scenario, case), status)) in plan.iter().zip(statuses).enumerate() {
        text.push_str(&format!(
            "qualification-feature-optional-entry-80k-v1,{index},{},{k},{seed},{},{order},{status}\n",
            scenario.name(),
            case + 1
        ));
    }
    assert!(text.len() <= 65536);
    std::fs::write(output.join("early-entry-plan.csv"), text).unwrap();
}
pub(crate) fn run(
    inputs: Inputs<'_>,
    arguments: native_module::SessionArguments,
    mode: &str,
    output: &Path,
    mut deadline: Deadline,
) {
    let Inputs {
        subject,
        expected,
        caller_path,
        caller_expected,
        caller_va,
    } = inputs;
    current_single_main();
    let elf = trusted(subject, expected);
    let caller = trusted(caller_path, caller_expected);
    let csv = TrustedFunctionSelection::new(
        &elf,
        arguments.csv.elf_va,
        arguments.csv.length,
        native_module::CSV_LABEL,
    )
    .unwrap();
    let length = TrustedFunctionSelection::new(
        &elf,
        arguments.length.elf_va,
        arguments.length.length,
        native_module::LENGTH_LABEL,
    )
    .unwrap();
    let selections = if arguments.csv.elf_va < arguments.length.elf_va {
        [&csv, &length]
    } else {
        [&length, &csv]
    };
    let scenarios: &[Scenario] = match mode {
        "enabled" => &[Scenario::Enabled],
        "bypass" => &[Scenario::Bypass],
        "scheduled" => &[
            Scenario::LoadedTrueDisarm,
            Scenario::LoadedFalseArm,
            Scenario::AdmittedRearm,
            Scenario::ReturnedDisarm,
        ],
        _ => panic!("fixed early-entry qualification mode"),
    };
    let mut plan = Vec::new();
    for seed in SEEDS {
        for &scenario in scenarios {
            for index in 0..if scenario.scheduled() { 1 } else { 16 } {
                plan.push((
                    seed,
                    scenario,
                    if scenario.scheduled() { 15 } else { index },
                ));
            }
        }
    }
    let expected = if mode == "scheduled" { 8 } else { 32 };
    assert_eq!(plan.len(), expected);
    let mut statuses = vec!["UNOBSERVED"; plan.len()];
    let order = arguments.case(0).order[0];
    save_plan(output, &plan, &statuses, arguments.k, order);
    let mut rows = String::from(
        "profile,scenario,k,seed,case,csv_index,status,children,comparisons,original_steps,candidate_steps,candidate_physical_calls,candidate_observed_entries,candidate_pre_rets,controller_handshakes,value0,value1,value2,value3,sum\n",
    );
    let mut coverage = String::from(
        "profile,k,seed,csv_cases,length_cases,csv_observed_heads,csv_declared_heads,csv_observed_edges,csv_declared_edges,csv_returns,length_heads,length_edges,length_returns\n",
    );
    let mut population = early::OptionalEntry80kPopulation::default();
    let mut covered = 0;
    for (count, &(seed, scenario, index)) in plan.iter().enumerate() {
        if count != 0 {
            deadline = Deadline::start();
        }
        statuses[count] = "DISPATCHED";
        save_plan(output, &plan, &statuses, arguments.k, order);
        // Scheduled cases use the concrete nonempty maximum bounded fixtures;
        // all-return/head coverage is supplied by both full32 static populations.
        let case = arguments.case(index);
        let oracle = early::OptionalEntry80kOracle::new(seed, case, scenario, deadline);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            oracle.pair(|candidate, context| {
                std::panic::set_hook(Box::new(|info| {
                    eprintln!("early-entry-80k qualification FAILED: {info}");
                    std::process::abort();
                }));
                child(candidate, context, &elf, selections, &caller, caller_va)
            })
        }));
        let (pair, trace) = match result {
            Ok(pair) => pair,
            Err(error) => {
                statuses[count] = "FAILED";
                save_plan(output, &plan, &statuses, arguments.k, order);
                std::panic::resume_unwind(error)
            }
        };
        if !scenario.scheduled() {
            if let Some(c) = population.record(seed, case, &pair, &trace) {
                covered += 1;
                coverage.push_str(&format!(
                    "qualification-feature-optional-entry-80k-v1,{},{seed},16,8,{},{},{},{},{},{},{},{}\n",
                    arguments.k,
                    c.csv_heads,
                    c.csv_declared_heads,
                    c.csv_edges,
                    c.csv_declared_edges,
                    c.csv_returns,
                    c.length_heads,
                    c.length_edges,
                    c.length_returns
                ));
                std::fs::write(output.join("early-entry-coverage.csv"), &coverage).unwrap();
            }
        }
        rows.push_str(&format!(
            "qualification-feature-optional-entry-80k-v1,{},{},{},{},{},PASS,2,{},{},{},4,{},4,{},{},{},{},{},{}\n",
            scenario.name(),
            arguments.k,
            seed,
            case.csv.id(),
            case.order[0],
            pair.comparisons,
            pair.original_steps,
            pair.candidate_steps,
            scenario.observed().iter().filter(|b| **b).count(),
            usize::from(scenario.scheduled()),
            pair.values[0],
            pair.values[1],
            pair.values[2],
            pair.values[3],
            pair.outer_value
        ));
        assert!(rows.len() <= 65536);
        std::fs::write(output.join("early-entry-pairs.csv"), &rows).unwrap();
        statuses[count] = "PASS";
        save_plan(output, &plan, &statuses, arguments.k, order);
        drop(oracle);
        deadline.check();
    }
    assert!(statuses.iter().all(|s| *s == "PASS"));
    if mode != "scheduled" {
        assert_eq!(covered, 2);
        assert!(population.finish() > 0);
    } else {
        assert_eq!(covered, 0);
    }
    current_single_main();
    println!(
        "EARLY_ENTRY_QUALIFICATION profile=qualification-feature-optional-entry-80k-v1 mode={mode} k={} pairs={expected} children={} PASS",
        arguments.k,
        expected * 2
    );
}
