//! System tray integration using tray-icon + winit.

use std::sync::mpsc;

use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder,
};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::WindowId;

/// Tray menu action identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    ShowDeviceId,
    OpenRecordingsDir,
    Quit,
}

/// Status information for the tray to display.
#[derive(Debug, Clone, Default)]
pub struct TrayStatus {
    pub device_id: String,
    pub device_name: String,
    pub channel_count: usize,
    pub recording_channels: usize,
    pub connected_receivers: usize,
}

/// Commands sent from the tokio runtime to the tray event loop.
#[derive(Debug)]
pub enum TrayCommand {
    UpdateStatus(TrayStatus),
    Quit,
}

/// Runs the system tray on the main thread with its own winit event loop.
/// Returns a sender that the tokio runtime can use to update the tray.
pub fn run_tray() -> Result<mpsc::Sender<TrayCommand>, Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel::<TrayCommand>();

    std::thread::spawn(move || {
        if let Err(e) = run_tray_inner(rx) {
            tracing::error!("Tray error: {}", e);
        }
    });

    Ok(tx)
}

struct TrayApp {
    tray_icon: Option<TrayIcon>,
    status: TrayStatus,
    command_rx: mpsc::Receiver<TrayCommand>,
    // Menu items that we need to reference for event handling
    quit_item: Option<MenuItem>,
    device_id_item: Option<MenuItem>,
    open_dir_item: Option<MenuItem>,
    status_item: Option<MenuItem>,
    channel_item: Option<MenuItem>,
    receiver_item: Option<MenuItem>,
    // Callback sender
    action_tx: mpsc::Sender<TrayAction>,
}

impl ApplicationHandler for TrayApp {
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if cause == StartCause::Init {
            self.build_tray();
        }
    }

    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // Process commands from tokio runtime
        while let Ok(cmd) = self.command_rx.try_recv() {
            match cmd {
                TrayCommand::UpdateStatus(status) => {
                    self.status = status;
                    self.update_menu();
                }
                TrayCommand::Quit => {
                    tracing::info!("Tray quit command received");
                    event_loop.exit();
                    return;
                }
            }
        }

        // Process menu events
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if let Some(quit_item) = &self.quit_item {
                if event.id == quit_item.id() {
                    let _ = self.action_tx.send(TrayAction::Quit);
                    event_loop.exit();
                    return;
                }
            }
            if let Some(device_id_item) = &self.device_id_item {
                if event.id == device_id_item.id() {
                    let _ = self.action_tx.send(TrayAction::ShowDeviceId);
                }
            }
            if let Some(open_dir_item) = &self.open_dir_item {
                if event.id == open_dir_item.id() {
                    let _ = self.action_tx.send(TrayAction::OpenRecordingsDir);
                }
            }
        }
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
    }
}

impl TrayApp {
    fn build_tray(&mut self) {
        let status_item = MenuItem::new("Status: Starting...", false, None);
        let channel_item = MenuItem::new("Channels: 0", false, None);
        let receiver_item = MenuItem::new("Receivers: 0", false, None);
        let device_id_item = MenuItem::new("Copy Device ID", true, None);
        let open_dir_item = MenuItem::new("Open Recordings Folder", true, None);
        let quit_item = MenuItem::new("Quit", true, None);

        let tray_menu = Menu::new();
        tray_menu
            .append_items(&[
                &status_item,
                &channel_item,
                &receiver_item,
                &PredefinedMenuItem::separator(),
                &device_id_item,
                &open_dir_item,
                &PredefinedMenuItem::separator(),
                &quit_item,
            ])
            .unwrap();

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("RemoteListener Transmitter")
            .with_icon(create_icon())
            .build()
            .unwrap();

        self.tray_icon = Some(tray_icon);
        self.status_item = Some(status_item);
        self.channel_item = Some(channel_item);
        self.receiver_item = Some(receiver_item);
        self.device_id_item = Some(device_id_item);
        self.open_dir_item = Some(open_dir_item);
        self.quit_item = Some(quit_item);
    }

    fn update_menu(&mut self) {
        if let Some(item) = &self.status_item {
            item.set_text(format!("Status: {} running", self.status.device_name));
        }
        if let Some(item) = &self.channel_item {
            item.set_text(format!(
                "Channels: {}/{} recording",
                self.status.recording_channels, self.status.channel_count
            ));
        }
        if let Some(item) = &self.receiver_item {
            item.set_text(format!(
                "Receivers: {} connected",
                self.status.connected_receivers
            ));
        }
        if let Some(tray) = &self.tray_icon {
            let tooltip = format!(
                "{} - {}/{} channels, {} receivers",
                self.status.device_name,
                self.status.recording_channels,
                self.status.channel_count,
                self.status.connected_receivers
            );
            let _ = tray.set_tooltip(Some(&tooltip));
        }
    }
}

/// Create a simple 16x16 green circle icon for the tray.
fn create_icon() -> tray_icon::Icon {
    let size = 16u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);

    // Draw a green circle on transparent background
    let cx = size as f32 / 2.0;
    let cy = size as f32 / 2.0;
    let radius = size as f32 / 2.0 - 1.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx + 0.5;
            let dy = y as f32 - cy + 0.5;
            let dist = (dx * dx + dy * dy).sqrt();

            if dist <= radius {
                // Green pixel with anti-aliasing at edges
                let alpha = if dist > radius - 1.0 {
                    ((radius - dist) * 255.0) as u8
                } else {
                    255u8
                };
                rgba.push(0); // R
                rgba.push(180); // G
                rgba.push(0); // B
                rgba.push(alpha); // A
            } else {
                rgba.push(0);
                rgba.push(0);
                rgba.push(0);
                rgba.push(0);
            }
        }
    }

    tray_icon::Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

fn run_tray_inner(rx: mpsc::Receiver<TrayCommand>) -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::Wait);

    let (action_tx, _action_rx) = mpsc::channel::<TrayAction>();

    let mut app = TrayApp {
        tray_icon: None,
        status: TrayStatus::default(),
        command_rx: rx,
        quit_item: None,
        device_id_item: None,
        open_dir_item: None,
        status_item: None,
        channel_item: None,
        receiver_item: None,
        action_tx,
    };

    event_loop.run_app(&mut app)?;
    Ok(())
}
