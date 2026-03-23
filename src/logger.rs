pub enum LogLevel {
    Info,
    Warn,
    Error,
    Security,
}

pub fn log(level: LogLevel, message: &str) {
    let prefix = match level {
        LogLevel::Info => "[INFO]",
        LogLevel::Warn => "[WARN]",
        LogLevel::Error => "[ERROR]",
        LogLevel::Security => "[SECURITY]",
    };

    println!("{} {}", prefix, message);
}