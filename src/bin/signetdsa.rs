//! `signetdsa` — command-line front end for the [`SignetDSA`] factory API.
//!
//! Generates keys, signs messages, and verifies signatures for any algorithm
//! known to [`Signet::from_name`]. Keys and signatures are stored as
//! hex-encoded text files so they're easy to inspect, diff, or paste.
//!
//! ```text
//! signetdsa list
//! signetdsa keygen --algo ed25519 --priv-out alice.key --pub-out alice.pub
//! signetdsa sign --algo ed25519 --key alice.key --message "hello" --sig-out hello.sig
//! signetdsa verify --algo ed25519 --pubkey alice.pub --message "hello" --sig hello.sig
//! ```

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use SignetDSA::Signet;

#[derive(Parser)]
#[command(name = "signetdsa", about = "Sign and verify messages with SignetDSA")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every algorithm name accepted by `--algo`.
    List,

    /// Generate a fresh keypair.
    Keygen {
        /// Algorithm name (see `signetdsa list`).
        #[arg(long)]
        algo: String,
        /// Where to write the hex-encoded private key.
        #[arg(long)]
        priv_out: PathBuf,
        /// Where to write the hex-encoded public key.
        #[arg(long)]
        pub_out: PathBuf,
    },

    /// Sign a message with a private key produced by `keygen`.
    Sign {
        #[arg(long)]
        algo: String,
        /// Path to a hex-encoded private key.
        #[arg(long)]
        key: PathBuf,
        /// Message to sign, given directly on the command line.
        #[arg(long, conflicts_with = "message_file")]
        message: Option<String>,
        /// Message to sign, read from a file instead of the command line.
        #[arg(long)]
        message_file: Option<PathBuf>,
        /// Where to write the hex-encoded signature (defaults to stdout).
        #[arg(long)]
        sig_out: Option<PathBuf>,
    },

    /// Verify a signature against a message and public key.
    Verify {
        #[arg(long)]
        algo: String,
        /// Path to a hex-encoded public key.
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long, conflicts_with = "message_file")]
        message: Option<String>,
        #[arg(long)]
        message_file: Option<PathBuf>,
        /// Path to a hex-encoded signature.
        #[arg(long)]
        sig: PathBuf,
    },
}

fn read_message(inline: Option<String>, file: Option<PathBuf>) -> Result<Vec<u8>, String> {
    match (inline, file) {
        (Some(m), None) => Ok(m.into_bytes()),
        (None, Some(path)) => {
            fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))
        }
        (None, None) => Err("provide either --message or --message-file".to_string()),
        (Some(_), Some(_)) => unreachable!("clap enforces these are mutually exclusive"),
    }
}

fn read_hex_file(path: &PathBuf) -> Result<Vec<u8>, String> {
    let contents =
        fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    hex::decode(contents.trim()).map_err(|e| format!("{} is not valid hex: {e}", path.display()))
}

fn write_hex_file(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, hex::encode(bytes)).map_err(|e| format!("writing {}: {e}", path.display()))
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Command::List => {
            for name in Signet::available() {
                println!("{name}");
            }
            Ok(())
        }

        Command::Keygen {
            algo,
            priv_out,
            pub_out,
        } => {
            let signer = Signet::from_name(&algo).ok_or_else(|| unknown_algo(&algo))?;
            let (sk, pk) = signer.generate_keys();
            write_hex_file(&priv_out, &sk)?;
            write_hex_file(&pub_out, &pk)?;
            println!(
                "Generated {algo} keypair -> private: {}, public: {}",
                priv_out.display(),
                pub_out.display()
            );
            Ok(())
        }

        Command::Sign {
            algo,
            key,
            message,
            message_file,
            sig_out,
        } => {
            let signer = Signet::from_name(&algo).ok_or_else(|| unknown_algo(&algo))?;
            let private_key = read_hex_file(&key)?;
            let message = read_message(message, message_file)?;
            let signature = signer.sign(&private_key, &message)?;

            match sig_out {
                Some(path) => {
                    write_hex_file(&path, &signature)?;
                    println!("Signature written to {}", path.display());
                }
                None => println!("{}", hex::encode(&signature)),
            }
            Ok(())
        }

        Command::Verify {
            algo,
            pubkey,
            message,
            message_file,
            sig,
        } => {
            let signer = Signet::from_name(&algo).ok_or_else(|| unknown_algo(&algo))?;
            let public_key = read_hex_file(&pubkey)?;
            let message = read_message(message, message_file)?;
            let signature = read_hex_file(&sig)?;

            match signer.verify(&public_key, &message, &signature) {
                Ok(true) => {
                    println!("VALID");
                    Ok(())
                }
                Ok(false) => Err("INVALID".to_string()),
                Err(e) => Err(format!("INVALID ({e})")),
            }
        }
    }
}

fn unknown_algo(algo: &str) -> String {
    format!(
        "unknown algorithm {algo:?}; available: {}",
        Signet::available().join(", ")
    )
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
