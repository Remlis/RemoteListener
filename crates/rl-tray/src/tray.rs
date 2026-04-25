//! System tray integration using tray-icon.

/// Tray menu item identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    ShowDeviceId,
    PairNewReceiver,
    OpenRecordingsDir,
    Quit,
}

/// Configuration for the system tray.
pub struct TrayConfig {
    pub device_id: String,
    pub recordings_dir: String,
}

/// Tray event handler trait.
pub trait TrayHandler: Send + Sync {
    fn on_action(&self, action: TrayAction);
}

/// A simple tray handler that logs actions.
pub struct LoggingTrayHandler;

impl TrayHandler for LoggingTrayHandler {
    fn on_action(&self, action: TrayAction) {
        tracing::info!("Tray action: {:?}", action);
    }
}

/// Create and run the system tray (stub for now).
pub fn run_tray(config: TrayConfig) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("System tray would show device ID: {}", config.device_id);
    // Full tray-icon integration requires a winit event loop,
    // which conflicts with tokio. This will be wired up properly
    // when integrating with the transmitter's async runtime.
    Ok(())
}
