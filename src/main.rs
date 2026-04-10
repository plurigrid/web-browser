use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

mod marginalia;
mod quic_fetch;
mod node;

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
