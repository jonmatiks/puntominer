/// Scale a magnitude onto the largest suffix that keeps it under four digits,
/// so a count of 1_234_560 reads as `1.23M` rather than a row of digits.
///
/// Anything below a thousand is left unscaled: there is no suffix that shortens
/// it, and inventing one would only make small numbers harder to read.
pub fn format_scaled(value: f64, suffix_with_space: bool) -> String {
    const SUFFIXES: [&str; 5] = ["K", "M", "G", "T", "P"];

    if value < 1_000.0 {
        return format!("{value:.2}");
    }
    let mut scaled = value;
    let mut suffix = "";
    for next_suffix in SUFFIXES {
        scaled /= 1_000.0;
        suffix = next_suffix;
        if scaled < 1_000.0 {
            break;
        }
    }
    format!(
        "{:.2}{}{}",
        scaled,
        if suffix_with_space { " " } else { "" },
        suffix
    )
}

/// Name the CPU the way the GPU logs name the adapter, so a run's log says what
/// hardware produced its numbers. Benchmarks on this machine are only
/// comparable against runs from the same silicon, and the log is the only place
/// that record survives.
///
/// Reads the first `model name` line of `/proc/cpuinfo`; every core repeats the
/// same value on the mixed-core laptops this runs on, so the first is enough.
/// Anywhere that file is missing or unreadable the model is simply unknown, and
/// a missing label is never worth failing a search over.
pub fn cpu_model() -> String {
    const UNKNOWN: &str = "unknown CPU";

    let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") else {
        return UNKNOWN.to_string();
    };
    cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|value| value.split_once(':'))
        .map(|(_, model)| model.trim())
        .filter(|model| !model.is_empty())
        .unwrap_or(UNKNOWN)
        .to_string()
}

/// Format an elapsed duration for human-readable progress and completion logs.
pub fn format_duration(seconds: f64) -> String {
    let total_seconds = seconds.max(0.0).round() as u64;
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    if days > 0 {
        format!("{days}d{hours:02}h{minutes:02}m")
    } else if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}
