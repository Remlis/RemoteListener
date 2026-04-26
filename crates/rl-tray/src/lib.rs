//! rl-tray: system tray icon and menu.

pub mod tray;

pub use tray::{run_tray, TrayAction, TrayCommand, TrayStatus};
