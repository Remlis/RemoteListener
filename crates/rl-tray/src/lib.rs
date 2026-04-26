//! rl-tray: system tray icon and menu.

pub mod tray;

pub use tray::{TrayAction, TrayCommand, TrayStatus, run_tray};
