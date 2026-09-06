//! `signetdsa` — command-line front end for the [`SignetDSA`] factory API.
//!
//! Generates keys, signs messages, verifies signatures, recovers public keys,
//! aggregates BLS signatures, produces self-contained envelopes, and runs benchmarks.
//! Keys and signatures are stored as hex-encoded text files.
//!
//! ```text
//! signetdsa list
//! signetdsa keygen --algo ed25519 --priv-out alice.key --pub-out alice.pub
//! signetdsa sign --algo ed25519 --key alice.key --message "hello" --sig-out hello.sig
//! signetdsa verify --algo ed25519 --pubkey alice.pub --message "hello" --sig hello.sig
//! signetdsa bench --iterations 20
//! ```

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use SignetDSA::Signet;
use SignetDSA::algo::bls::Bls;
use SignetDSA::algo::ecdsa_secp256k1::EcdsaSecp256k1;
use SignetDSA::bench::{benchmark_algo, benchmark_all, format_table};
use SignetDSA::envelope::SignetEnvelope;

#[derive(Parser)]
#[command(
    name = "signetdsa",
    about = "Sign, verify, and benchmark digital signatures with SignetDSA"
)]
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

    /// Recover an ECDSA secp256k1 public key from a signature and recovery id.
    Recover {
        #[arg(long, conflicts_with = "message_file")]
        message: Option<String>,
        #[arg(long)]
        message_file: Option<PathBuf>,
        /// Path to a hex-encoded signature.
        #[arg(long)]
        sig: PathBuf,
        /// 1-byte recovery ID (0..3).
        #[arg(long)]
        recid: u8,
        /// Optional path to save the recovered public key.
        #[arg(long)]
        pub_out: Option<PathBuf>,
    },

    /// Aggregate multiple BLS signatures into a single compact signature.
    Aggregate {
        /// Paths to hex-encoded individual BLS signatures.
        #[arg(long, num_args = 1..)]
        sigs: Vec<PathBuf>,
        /// Where to write the hex-encoded aggregate signature.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify an aggregate BLS signature over distinct messages and public keys.
    VerifyAggregate {
        /// Path to hex-encoded aggregate signature.
        #[arg(long)]
        sig: PathBuf,
        /// Distinct messages signed by each participant.
        #[arg(long, num_args = 1..)]
        messages: Vec<String>,
        /// Paths to hex-encoded public keys corresponding to each message.
        #[arg(long, num_args = 1..)]
        pubkeys: Vec<PathBuf>,
    },

    /// Create a self-contained signed envelope (JSON).
    EnvelopeSign {
        #[arg(long)]
        algo: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long, conflicts_with = "message_file")]
        message: Option<String>,
        #[arg(long)]
        message_file: Option<PathBuf>,
        /// Output path for the envelope JSON file.
        #[arg(long)]
        out: PathBuf,
    },

    /// Verify a self-contained signed envelope JSON file.
    EnvelopeVerify {
        /// Path to the envelope JSON file.
        #[arg(long)]
        envelope: PathBuf,
    },

    /// Benchmark algorithm performance (latency, throughput, key/sig sizes).
    Bench {
        /// Optional specific algorithm name (benchmarks all if omitted).
        #[arg(long)]
        algo: Option<String>,
        /// Number of iterations to measure.
        #[arg(long, default_value_t = 10)]
        iterations: usize,
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

        Command::Recover {
            message,
            message_file,
            sig,
            recid,
            pub_out,
        } => {
            let message = read_message(message, message_file)?;
            let signature = read_hex_file(&sig)?;
            let vk = EcdsaSecp256k1::recover_public_key(&message, &signature, recid)
                .map_err(|e| format!("recovery failed: {e}"))?;
            let pk_point = vk.to_encoded_point(true);
            let pk_bytes = pk_point.as_bytes();

            match pub_out {
                Some(path) => {
                    write_hex_file(&path, pk_bytes)?;
                    println!("Recovered public key written to {}", path.display());
                }
                None => println!("Recovered public key: {}", hex::encode(pk_bytes)),
            }
            Ok(())
        }

        Command::Aggregate { sigs, out } => {
            let mut raw_sigs = Vec::new();
            for p in &sigs {
                raw_sigs.push(read_hex_file(p)?);
            }
            let agg = Bls::aggregate_signatures(&raw_sigs)
                .map_err(|e| format!("aggregation failed: {e}"))?;

            match out {
                Some(path) => {
                    write_hex_file(&path, &agg)?;
                    println!("Aggregate signature written to {}", path.display());
                }
                None => println!("{}", hex::encode(&agg)),
            }
            Ok(())
        }

        Command::VerifyAggregate {
            sig,
            messages,
            pubkeys,
        } => {
            let agg_bytes = read_hex_file(&sig)?;
            let msg_refs: Vec<&[u8]> = messages.iter().map(|s| s.as_bytes()).collect();
            let mut pk_bytes_vec = Vec::new();
            for p in &pubkeys {
                pk_bytes_vec.push(read_hex_file(p)?);
            }

            match Bls::verify_aggregated(&agg_bytes, &msg_refs, &pk_bytes_vec) {
                Ok(true) => {
                    println!("VALID AGGREGATE SIGNATURE");
                    Ok(())
                }
                _ => Err("INVALID AGGREGATE SIGNATURE".to_string()),
            }
        }

        Command::EnvelopeSign {
            algo,
            key,
            pubkey,
            message,
            message_file,
            out,
        } => {
            let signer = Signet::from_name(&algo).ok_or_else(|| unknown_algo(&algo))?;
            let private_key = read_hex_file(&key)?;
            let public_key = read_hex_file(&pubkey)?;
            let message = read_message(message, message_file)?;

            let envelope =
                SignetEnvelope::seal(signer.as_ref(), &private_key, &public_key, &message)?;
            fs::write(&out, envelope.to_json())
                .map_err(|e| format!("writing envelope {}: {e}", out.display()))?;

            println!("Signed envelope saved to {}", out.display());
            Ok(())
        }

        Command::EnvelopeVerify { envelope } => {
            let content = fs::read_to_string(&envelope)
                .map_err(|e| format!("reading {}: {e}", envelope.display()))?;
            let env = SignetEnvelope::from_json(&content)?;
            match env.verify() {
                Ok(true) => {
                    println!(
                        "VALID ENVELOPE [algo: {}, created_at: {}]",
                        env.algo, env.created_at
                    );
                    Ok(())
                }
                Ok(false) => Err("INVALID ENVELOPE SIGNATURE".to_string()),
                Err(e) => Err(format!("INVALID ENVELOPE ({e})")),
            }
        }

        Command::Bench { algo, iterations } => {
            match algo {
                Some(name) => {
                    let result = benchmark_algo(&name, iterations)?;
                    println!("{}", format_table(&[result]));
                }
                None => {
                    println!("Benchmarking all algorithms ({iterations} iterations)...");
                    let results = benchmark_all(iterations);
                    println!("{}", format_table(&results));
                }
            }
            Ok(())
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
