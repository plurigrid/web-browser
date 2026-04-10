use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

mod capability;
mod greywall;
mod marginalia;
mod node;
mod quic_fetch;
mod yara;

#[derive(Parser)]
#[command(name = "web-browser", about = "QUIC-native browser with iroh P2P and marginalia.nu")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Search the independent web via marginalia.nu
    Search {
        query: String,
        #[arg(short, long, default_value = "10")]
        count: u32,
    },
    /// Fetch a URL over QUIC (HTTP/3) with fallback to HTTP/2
    Fetch {
        url: String,
        /// Show raw HTML instead of rendered text
        #[arg(long)]
        raw: bool,
    },
    /// Start an iroh P2P node for content sharing
    Node,
    /// List connected iroh peers
    Peers,
    /// Onboarding: show what this browser is about
    Onboard,
    /// Fetch URL through full greywall pipeline (marginalia gate → QUIC → YARA → capability)
    SafeFetch {
        url: String,
    },
    /// Scan a local file for suspicious content
    Scan {
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Search { query, count } => {
            marginalia::search(&query, count).await?;
        }
        Command::Fetch { url, raw } => {
            quic_fetch::fetch(&url, raw).await?;
        }
        Command::Node => {
            node::run().await?;
        }
        Command::Peers => {
            node::peers().await?;
        }
        Command::Onboard => {
            onboard().await?;
        }
        Command::SafeFetch { url } => {
            safe_fetch(&url).await?;
        }
        Command::Scan { path } => {
            scan_file(&path)?;
        }
    }

    Ok(())
}

async fn safe_fetch(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).context("invalid URL")?;
    let domain = parsed.host_str().unwrap_or("unknown");

    // 1. Greywall sandbox init
    let cache_dir = std::env::temp_dir().join("web-browser-cache");
    std::fs::create_dir_all(&cache_dir)?;
    let sandbox = greywall::Sandbox::init(greywall::Policy::default(), cache_dir)?;
    println!("[sandbox] {}", sandbox.policy_summary());

    // 2. Domain gate
    if !sandbox.check_domain(domain)? {
        println!("[BLOCKED] domain '{}' not in allowlist", domain);
        return Ok(());
    }
    println!("[sandbox] domain '{}' allowed", domain);

    // 3. QUIC fetch
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .user_agent("plurigrid-web-browser/0.1")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let resp = client.get(url).send().await.context("fetch failed")?;
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = resp.bytes().await?;
    println!("[fetch] {} bytes, {}", body.len(), content_type);

    // 4. YARA scan
    let verdict = yara::scan(&body, &content_type);
    match &verdict {
        greywall::Verdict::Clean => println!("[scan] clean"),
        greywall::Verdict::Suspicious(r) => println!("[scan] SUSPICIOUS: {}", r),
        greywall::Verdict::Malicious(r) => println!("[scan] MALICIOUS: {}", r),
    }

    // 5. Capability gate
    match capability::gate(&body, &verdict, false) {
        Some(cap) => {
            println!("[capability] {}", cap.summary());
            if cap.permits(&capability::Permission::Render) {
                let text = html2text::from_read(&body[..], 80);
                println!("\n{}", text);
            } else {
                println!("[render blocked] insufficient capability");
            }
        }
        None => {
            println!("[BLOCKED] no capability granted — content is malicious");
        }
    }

    sandbox.cleanup()?;
    Ok(())
}

fn scan_file(path: &str) -> Result<()> {
    let content = std::fs::read(path).context("failed to read file")?;
    let file_type = yara::detect_type(&content);
    println!("[type] {:?}", file_type);

    let verdict = yara::scan(&content, "application/octet-stream");
    match &verdict {
        greywall::Verdict::Clean => println!("[scan] clean"),
        greywall::Verdict::Suspicious(r) => println!("[scan] SUSPICIOUS: {}", r),
        greywall::Verdict::Malicious(r) => println!("[scan] MALICIOUS: {}", r),
    }

    match capability::gate(&content, &verdict, false) {
        Some(cap) => println!("[capability] {}", cap.summary()),
        None => println!("[BLOCKED] no capability — malicious content"),
    }

    Ok(())
}

async fn onboard() -> Result<()> {
    println!("web-browser onboarding");
    println!("======================\n");
    println!("Two things matter:\n");

    println!("1. QUIC");
    println!("   UDP-based transport. Multiplexed streams. 0-RTT resumption.");
    println!("   iroh gives you P2P QUIC with automatic hole punching.\n");

    println!("2. marginalia.nu");
    println!("   Independent search engine for the non-commercial web.");
    println!("   No ads. No tracking. Finds pages Google buries.\n");

    println!("--- Searching marginalia.nu for 'QUIC protocol' ---\n");
    marginalia::search("QUIC protocol", 5).await?;

    println!("\n--- Fetching marginalia.nu homepage ---\n");
    quic_fetch::fetch("https://www.marginalia.nu", false).await?;

    Ok(())
}
