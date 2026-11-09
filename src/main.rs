//! The CPU reference miner: build blocks from a node's template and submit
//! them back. See `docs/architecture.md`.

use std::{env, process};

use puntominer::{constants::RESULTS_DIR, logger::Logger, runner::run, settings::Settings};

fn main() {
    // The line is read before anything else happens, because `--help` has to
    // answer on a machine with no node, no GPU and no writable `results/`, and
    // because a misspelled flag should not leave a log file behind it.
    let settings = match Settings::parse(env::args_os()) {
        Ok(settings) => settings,
        Err(error) => {
            let _ = error.print();
            // `--help` and `--version` arrive here too, as answers rather than
            // failures, which is what `use_stderr` tells apart.
            process::exit(i32::from(error.use_stderr()));
        }
    };

    let log_path = match settings.get("MINER_LOG", format!("{RESULTS_DIR}/log")) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("error: {message}");
            process::exit(1);
        }
    };
    let log = match Logger::open(&log_path) {
        Ok(log) => log,
        Err(message) => {
            eprintln!("error: {message}");
            process::exit(1);
        }
    };
    // A file is a third source, so a value beaten from somewhere the reader is
    // not looking is the surprise worth naming once. Nothing is said when no
    // file was read.
    if let Some(summary) = settings.config_summary() {
        log.log(summary);
    }
    if let Err(message) = run(&settings, &log) {
        // Relabelled once, on the way out, so that every refusal names the
        // spelling this run was given — including the ones raised in `gpu.rs`
        // and in the `parse` functions, none of which have any reason to know
        // how they were configured.
        log.error(format!("error: {}", settings.relabel(message)));
        process::exit(1);
    }
}
