use chrono::{DateTime, Local, SecondsFormat, TimeZone, Utc};
use colored::*;
use env_filter::{Builder, Filter};
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::sync::Mutex;

pub const JETS_ACCESS_LIST: &str = "jets_access_list";

#[derive(PartialEq)]
pub enum Timestamp {
    None,
    Local,
    Utc,
}

/// Log target, either `stdout`, `stderr` or a custom pipe.
pub enum Target {
    /// Logs will be sent to standard output.
    Stdout,
    /// Logs will be sent to standard error.
    Stderr,
    /// Logs will be sent to a custom pipe.
    Pipe(Box<dyn std::io::Write + Send + 'static>),
}

enum WritableTarget {
    Stdout,
    Stderr,
    Pipe(Box<Mutex<dyn std::io::Write + Send + 'static>>),
}

impl From<Target> for WritableTarget {
    fn from(value: Target) -> Self {
        match value {
            Target::Stdout => Self::Stdout,
            Target::Stderr => Self::Stderr,
            Target::Pipe(pipe) => Self::Pipe(Box::new(Mutex::new(pipe))),
        }
    }
}

/// Implements [`Log`] and a set of simple builder methods for configuration.
///
/// Use the various "builder" methods on this struct to configure the logger,
/// then call [`init`] to configure the [`log`] crate.
pub struct Logger {
    filter: Filter,

    /// Control how timestamp are displayed.
    timestamp: Timestamp,
    timestamp_format: Option<String>,

    error_target: WritableTarget,
    access_target: WritableTarget,
}

impl Logger {
    pub fn new(filters: &str, error_target: Target, access_target: Target) -> Self {
        let mut builder = Builder::new();
        if let Ok(ref env) = std::env::var("RUST_LOG") {
            builder.parse(env)
        } else {
            builder.parse(filters)
        };

        Self {
            filter: builder.build(),
            timestamp: Timestamp::Local,
            timestamp_format: None,

            error_target: WritableTarget::from(error_target),
            access_target: WritableTarget::from(access_target),
        }
    }

    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_timestamp_format(mut self, format: String) -> Self {
        self.timestamp_format = Some(format);
        self
    }

    /// Configure the logger
    pub fn max_level(&self) -> LevelFilter {
        self.filter.filter()
    }

    /// 'Init' the actual logger and instantiate it,
    /// this method MUST be called in order for the logger to be effective.
    pub fn init(self) -> Result<(), SetLoggerError> {
        #[cfg(windows)]
        set_up_windows_color_terminal();
        use_stderr_for_colors();

        log::set_max_level(self.max_level());
        log::set_boxed_logger(Box::new(self))
    }
}

impl Default for Logger {
    /// See [this](struct.SimpleLogger.html#method.new)
    fn default() -> Self {
        Self::new("info", Target::Stdout, Target::Stdout)
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_string = if matches!(self.error_target, WritableTarget::Pipe(_)) {
                match record.level() {
                    Level::Error => format!("{:<5}", record.level().to_string()),
                    Level::Warn => format!("{:<5}", record.level().to_string()),
                    Level::Info => format!("{:<5}", record.level().to_string()),
                    Level::Debug => format!("{:<5}", record.level().to_string()),
                    Level::Trace => format!("{:<5}", record.level().to_string()),
                }
            } else {
                match record.level() {
                    Level::Error => format!("{:<5}", record.level().to_string())
                        .red()
                        .to_string(),
                    Level::Warn => format!("{:<5}", record.level().to_string())
                        .yellow()
                        .to_string(),
                    Level::Info => format!("{:<5}", record.level().to_string())
                        .green()
                        .to_string(),
                    Level::Debug => format!("{:<5}", record.level().to_string())
                        .blue()
                        .to_string(),
                    Level::Trace => format!("{:<5}", record.level().to_string())
                        .cyan()
                        .to_string(),
                }
            };

            let target = if !record.target().is_empty() {
                record.target()
            } else {
                record.module_path().unwrap_or_default()
            };

            let timestamp = match self.timestamp {
                Timestamp::None => "".to_string(),
                Timestamp::Local => to_string(Local::now(), &self.timestamp_format),
                Timestamp::Utc => to_string(Utc::now(), &self.timestamp_format),
            };

            if target == JETS_ACCESS_LIST {
                let message = format!("{} {}\r\n", timestamp, record.args());
                match &self.access_target {
                    WritableTarget::Stdout => println!("{}", message),
                    WritableTarget::Stderr => eprintln!("{}", message),
                    WritableTarget::Pipe(pipe) => {
                        let mut stream = pipe.lock().expect("no panics while held");
                        let _ = stream.write_all(message.as_bytes());
                        let _ = stream.flush();
                    }
                }
            } else {
                let message = format!(
                    "[{} {} {}] {}\r\n",
                    timestamp,
                    level_string,
                    target,
                    record.args()
                );
                match &self.error_target {
                    WritableTarget::Stdout => print!("{}", message),
                    WritableTarget::Stderr => eprint!("{}", message),
                    WritableTarget::Pipe(pipe) => {
                        let mut stream = pipe.lock().expect("no panics while held");
                        let _ = stream.write_all(message.as_bytes());
                        let _ = stream.flush();
                    }
                }
            }
        }
    }

    fn flush(&self) {}
}

#[cfg(windows)]
pub fn set_up_windows_color_terminal() {
    use std::io::{stdout, IsTerminal};

    if stdout().is_terminal() {
        unsafe {
            use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE,
                ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
            };

            let stdout = GetStdHandle(STD_OUTPUT_HANDLE);

            if stdout == INVALID_HANDLE_VALUE {
                return;
            }

            let mut mode: CONSOLE_MODE = 0;

            if GetConsoleMode(stdout, &mut mode) == 0 {
                return;
            }

            SetConsoleMode(stdout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

fn use_stderr_for_colors() {
    use std::io::{stderr, IsTerminal};

    colored::control::set_override(stderr().is_terminal());
}

fn to_string<Tz: TimeZone>(date_time: DateTime<Tz>, format: &Option<String>) -> String
where
    Tz::Offset: std::fmt::Display,
{
    if let Some(format) = format {
        format!("{}", date_time.format(format))
    } else {
        date_time.to_rfc3339_opts(SecondsFormat::Millis, true)
    }
}
