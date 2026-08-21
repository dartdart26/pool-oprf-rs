//! A client and a server for private set intersection, talking over QUIC.
//!
//! The server holds a set. A client connects with a set of its own and learns
//! which of its entries the server also has; the server learns how many entries
//! the client brought, and nothing else.
//!
//! See `README.md` to run it, including the sample sets and certificate.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use cryprot_net::Connection;
use pool_prf::params::N;
use pool_prf::prf::SecretKey;
use pool_psi::client::PsiClient;
use pool_psi::protocol::MaskedElement;
use pool_psi::server::PsiServer;
use s2n_quic::{Client, Server, client::Connect, provider::limits::Limits};
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

/// The TLS key exchange this binary was built with.
#[cfg(s2n_quic_enable_pq_tls)]
const TLS_POLICY: &str = "hybrid ML-KEM (default_pq)";
#[cfg(not(s2n_quic_enable_pq_tls))]
const TLS_POLICY: &str = "classical (default_tls13)";

#[derive(Parser)]
#[command(about, version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mask a set once, then answer every client that connects.
    Serve(Serve),
    /// Learn which of our own entries the server also holds.
    Lookup(Lookup),
    /// Write a PRF key for `serve --psi-key` to load.
    Keygen(Keygen),
}

#[derive(Args)]
struct Serve {
    /// Address to listen on
    #[arg(long)]
    listen: SocketAddr,
    /// The set to answer against
    #[arg(long)]
    set: PathBuf,
    /// TLS certificate chain, PEM
    #[arg(long)]
    cert: PathBuf,
    /// TLS private key, PEM
    #[arg(long)]
    key: PathBuf,
    /// Domain separator the masked set is built under
    #[arg(long, default_value = "pool-psi-tag-1")]
    tag: String,
    /// PRF key from `keygen`
    #[arg(long)]
    psi_key: PathBuf,
    /// Seconds a client gets for its whole session
    #[arg(long, default_value = "60", value_parser = seconds)]
    session_timeout: Duration,
    /// How many sessions to run at once
    #[arg(long, default_value_t = 64, value_parser = at_least_one)]
    max_sessions: usize,
}

fn seconds(arg: &str) -> Result<Duration, String> {
    match arg.parse() {
        Err(_) => Err(format!("`{arg}` is not a whole number of seconds")),
        Ok(0) => Err("must be at least 1 second".to_owned()),
        Ok(secs) => Ok(Duration::from_secs(secs)),
    }
}

fn at_least_one(arg: &str) -> Result<usize, String> {
    match arg.parse() {
        Err(_) => Err(format!("`{arg}` is not a whole number")),
        Ok(0) => Err("must be at least 1".to_owned()),
        Ok(n) => Ok(n),
    }
}

#[derive(Args)]
struct Lookup {
    /// Address of the server
    #[arg(long)]
    connect: SocketAddr,
    /// The set to look up
    #[arg(long)]
    set: PathBuf,
    /// The server's certificate, our only trust anchor
    #[arg(long)]
    cert: PathBuf,
    /// Name to verify that certificate against
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// Seconds to wait on the server before giving up
    #[arg(long, default_value = "60", value_parser = seconds)]
    timeout: Duration,
}

#[derive(Args)]
struct Keygen {
    /// Where to write the key
    #[arg(long)]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Lookup(args) => lookup(args).await,
        Command::Keygen(args) => keygen(args),
    }
}

async fn serve(args: Serve) -> Result<()> {
    let cert = read_pem(&args.cert)?;
    let key = read_pem(&args.key)?;
    let tag: Arc<str> = args.tag.into();

    let server = PsiServer::new(read_key(&args.psi_key)?);

    let started = Instant::now();
    let masked = Arc::new(mask_set_file(&server, tag.as_bytes(), &args.set)?);
    println!(
        "masked {} entries under tag {tag:?} in {:.2}s",
        masked.len(),
        started.elapsed().as_secs_f64()
    );

    let mut quic = Server::builder()
        .with_tls((cert.as_str(), key.as_str()))?
        .with_io(io(args.listen)?)?
        .with_limits(limits()?)?
        .start()?;
    println!("TLS key exchange: {TLS_POLICY}");
    println!("listening on {}", quic.local_addr()?);

    let sessions = Arc::new(Semaphore::new(args.max_sessions));
    while let Some(quic_conn) = quic.accept().await {
        let peer = quic_conn
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_owned());

        let Ok(permit) = Arc::clone(&sessions).try_acquire_owned() else {
            eprintln!("{peer}: refused, {} sessions in flight", args.max_sessions);
            continue;
        };

        let (conn, streams) = Connection::new(quic_conn);
        tokio::spawn(streams.start());

        let server = server.clone();
        let masked = Arc::clone(&masked);
        let tag = Arc::clone(&tag);
        let timeout = args.session_timeout;
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(timeout, session(&server, conn, &tag, &masked)).await {
                Ok(Ok(served)) => println!("{peer}: served {served} evaluations"),
                Ok(Err(e)) => eprintln!("{peer}: {e}"),
                Err(_) => eprintln!("{peer}: gave up after {}s", timeout.as_secs()),
            }
        });
    }
    Ok(())
}

/// Preprocess with one client and answer its evaluations, returning how many
/// it was sized for.
async fn session(
    server: &PsiServer,
    conn: Connection,
    tag: &str,
    masked: &[MaskedElement],
) -> Result<usize> {
    let mut session = server.session(conn).await?;
    let set_size = session.set_size();
    session.serve_masked(tag.as_bytes(), masked).await?;
    Ok(set_size)
}

/// Learn which of our own entries the server also holds.
async fn lookup(args: Lookup) -> Result<()> {
    let set = read_set(&args.set)?;
    let cert = read_pem(&args.cert)?;

    println!("TLS key exchange: {TLS_POLICY}");
    let client = Client::builder()
        .with_tls(cert.as_str())?
        .with_io(io("0.0.0.0:0".parse()?)?)?
        .with_limits(limits()?)?
        .start()?;
    let quic_conn = client
        .connect(Connect::new(args.connect).with_server_name(args.server_name))
        .await?;
    let (conn, streams) = Connection::new(quic_conn);
    tokio::spawn(streams.start());

    let run = async {
        let started = Instant::now();
        let psi = PsiClient::new(conn, set.len(), &mut rand::rng()).await?;
        println!(
            "preprocessed {} evaluations in {:.2}s",
            set.len(),
            started.elapsed().as_secs_f64()
        );

        let started = Instant::now();
        let found = psi.intersect(&set).await?;
        println!("online phase in {:.2}s", started.elapsed().as_secs_f64());
        Ok::<_, anyhow::Error>(found)
    };
    let found = tokio::time::timeout(args.timeout, run)
        .await
        .with_context(|| format!("the server went quiet for {}s", args.timeout.as_secs()))??;

    println!("\n{} of {} entries matched:", found.len(), set.len());
    for i in &found {
        println!("  {}", set[*i]);
    }
    Ok(())
}

/// Write a PRF key for `serve --psi-key` to load.
fn keygen(args: Keygen) -> Result<()> {
    let key = SecretKey::random(&mut rand::rng());

    // Never over an existing key.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.out)
        .and_then(|mut file| file.write_all(key.as_bits()))
        .with_context(|| format!("writing the key to {}", args.out.display()))?;

    println!("wrote {}", args.out.display());
    Ok(())
}

fn read_key(path: &Path) -> Result<SecretKey> {
    let mut bytes =
        std::fs::read(path).with_context(|| format!("reading the key {}", path.display()))?;
    let read = bytes.len();
    let mut bits = [0u8; N];
    if read == N {
        bits.copy_from_slice(&bytes);
    }
    bytes.zeroize();

    if read != N {
        bail!("{} is {read} bytes, expected {N}", path.display());
    }
    let key = SecretKey::from_bits(bits)
        .with_context(|| format!("{} is not a key: every byte must be a bit", path.display()));
    bits.zeroize();
    key
}

fn read_pem(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Mask the server's set straight off disk, a line at a time.
///
/// The plaintext is never held: the server has no use for its own entries once
/// they are masked.
fn mask_set_file(server: &PsiServer, tag: &[u8], path: &Path) -> Result<Vec<MaskedElement>> {
    let context = || format!("reading the set {}", path.display());
    let file = std::fs::File::open(path).with_context(context)?;

    // Masking cannot fail, so a read error ends the iterator and is raised
    // once it returns.
    let mut failed = None;
    let masked = server.mask(
        tag,
        std::io::BufReader::new(file)
            .lines()
            .map_while(|line| match line {
                Ok(line) => Some(line),
                Err(e) => {
                    failed = Some(e);
                    None
                }
            })
            .filter_map(|line| entry(&line).map(str::to_owned)),
    );

    if let Some(e) = failed {
        return Err(e).with_context(context);
    }
    if masked.is_empty() {
        bail!("{} has no entries", path.display());
    }
    Ok(masked)
}

/// Every entry in the file, in order.
fn read_set(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the set {}", path.display()))?;
    let set: Vec<String> = text.lines().filter_map(entry).map(str::to_owned).collect();
    if set.is_empty() {
        bail!("{} has no entries", path.display());
    }
    Ok(set)
}

/// A line's entry, unless it is blank or a `#` comment.
fn entry(line: &str) -> Option<&str> {
    let entry = line.trim();
    (!entry.is_empty() && !entry.starts_with('#')).then_some(entry)
}

const MAX_STREAMS: u64 = 512;

fn limits() -> Result<Limits> {
    const MIB: u32 = 1024 * 1024;
    Ok(Limits::new()
        .with_max_send_buffer_size(12 * MIB)?
        .with_max_open_local_unidirectional_streams(MAX_STREAMS)?
        .with_max_open_remote_unidirectional_streams(MAX_STREAMS)?)
}

fn io(addr: SocketAddr) -> Result<s2n_quic::provider::io::Default> {
    Ok(s2n_quic::provider::io::Default::builder()
        .with_receive_address(addr)?
        .build()?)
}
