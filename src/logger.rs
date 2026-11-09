//! Console and file logging for the miner.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    sync::Mutex,
};

use chrono::{Local, SecondsFormat};

/// Writes each record to the console and the configured append-only log.
pub struct Logger {
    file: Mutex<File>,
}

impl Logger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("could not open {}: {error}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Emit an informational record to stdout and the log file.
    pub fn log(&self, text: impl std::fmt::Display) {
        self.write(text, false);
    }

    /// Emit an error record to stderr and the log file.
    pub fn error(&self, text: impl std::fmt::Display) {
        self.write(text, true);
    }

    fn write(&self, text: impl std::fmt::Display, stderr: bool) {
        let message = format!(
            "{} {text}",
            Local::now().to_rfc3339_opts(SecondsFormat::Millis, false)
        );
        if stderr {
            eprintln!("{message}");
        } else {
            println!("{message}");
        }
        let mut file = self.file.lock().expect("log mutex poisoned");
        writeln!(file, "{message}").expect("could not write log file");
        file.flush().expect("could not flush log file");
    }
}
