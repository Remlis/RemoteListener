//! rl-testtool: CLI tool for testing the RemoteListener transmitter.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rl-testtool", version, about = "RemoteListener test tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pair with a transmitter
    Pair {
        /// Transmitter address (host:port)
        addr: String,
    },
    /// List audio channels on a transmitter
    Channels {
        /// Transmitter address
        addr: String,
    },
    /// Fetch a recording from a transmitter
    Fetch {
        /// Transmitter address
        addr: String,
        /// Recording ID to fetch
        recording_id: String,
        /// Output file path
        #[arg(short, long)]
        output: String,
    },
    /// Decrypt a .rlrec recording file
    Decrypt {
        /// Input .rlrec file
        input: String,
        /// Output file (decrypted Opus data)
        output: String,
        /// Key file path
        #[arg(short, long)]
        keyfile: String,
    },
    /// Send a control command
    Control {
        /// Transmitter address
        addr: String,
        /// Control type (set-recording, set-bitrate, delete-recording, get-storage, set-auto-delete, restart)
        command: String,
        /// Channel ID (for channel-specific commands)
        #[arg(short, long)]
        channel: Option<String>,
        /// Value for the command
        #[arg(short, long)]
        value: Option<String>,
    },
    /// Export private key to an encrypted file
    ExportKey {
        /// Key file path
        keyfile: String,
        /// Output path for encrypted key blob
        output: String,
    },
    /// Import private key from an encrypted file
    ImportKey {
        /// Encrypted key blob path
        input: String,
        /// Output key file path
        output: String,
    },
    /// Start live audio listening (skeleton)
    Live {
        /// Transmitter address
        addr: String,
        /// Channel ID to listen to
        channel: String,
        /// Duration (e.g. 3s)
        #[arg(short, long, default_value = "10s")]
        duration: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pair { addr } => {
            println!("Pairing with {}...", addr);
            // TODO: TLS connect → PAIR_REQUEST → PAIR_RESPONSE → store key
            println!("Pairing not yet implemented. Connect to: {}", addr);
        }
        Commands::Channels { addr } => {
            println!("Listing channels from {}...", addr);
            // TODO: TLS connect → CHANNEL_LIST_REQUEST → display
            println!("Channel listing not yet implemented.");
        }
        Commands::Fetch {
            addr,
            recording_id,
            output,
        } => {
            println!("Fetching recording {} from {}...", recording_id, addr);
            // TODO: TLS connect → RECORDING_FETCH → write to file
            println!("Fetch not yet implemented. Would save to: {}", output);
        }
        Commands::Decrypt {
            input,
            output,
            keyfile,
        } => {
            println!("Decrypting {} → {} (key: {})", input, output, keyfile);
            // TODO: Load key, read .rlrec, decrypt, write output
            println!("Decrypt not yet implemented.");
        }
        Commands::Control {
            addr,
            command,
            channel,
            value,
        } => {
            println!("Sending {} to {}", command, addr);
            if let Some(ch) = channel {
                println!("  Channel: {}", ch);
            }
            if let Some(v) = value {
                println!("  Value: {}", v);
            }
            println!("Control not yet implemented.");
        }
        Commands::ExportKey { keyfile, output } => match do_export_key(&keyfile, &output) {
            Ok(()) => println!("Key exported to {}", output),
            Err(e) => eprintln!("Export failed: {}", e),
        },
        Commands::ImportKey { input, output } => match do_import_key(&input, &output) {
            Ok(()) => println!("Key imported to {}", output),
            Err(e) => eprintln!("Import failed: {}", e),
        },
        Commands::Live {
            addr,
            channel,
            duration,
        } => {
            println!(
                "Live audio from {} channel {} for {}",
                addr, channel, duration
            );
            println!("Live listen not yet implemented.");
        }
    }
}

fn do_export_key(keyfile: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = std::fs::read(keyfile)?;
    if key_bytes.len() != 32 {
        return Err("Key file must be exactly 32 bytes".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // Prompt for passphrase
    println!("Enter passphrase to encrypt the key:");
    let passphrase = rpassword::read_password()?;

    let exported = rl_crypto::key_export::export_key(&key, passphrase.as_bytes())?;
    std::fs::write(output, exported)?;
    Ok(())
}

fn do_import_key(input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let blob_bytes = std::fs::read(input)?;
    if blob_bytes.len() != 93 {
        return Err("Invalid key blob (expected 93 bytes)".into());
    }
    let mut blob = [0u8; 93];
    blob.copy_from_slice(&blob_bytes);

    println!("Enter passphrase to decrypt the key:");
    let passphrase = rpassword::read_password()?;

    let key = rl_crypto::key_export::import_key(&blob, passphrase.as_bytes())?;
    std::fs::write(output, key)?;
    Ok(())
}
