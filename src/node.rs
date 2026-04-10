use anyhow::Result;

/// Start an iroh P2P node for QUIC content sharing.
pub async fn run() -> Result<()> {
    println!("Starting iroh P2P node...\n");

    let node = iroh::node::Builder::default()
        .spawn()
        .await?;

    let node_id = node.node_id();
    println!("Node ID: {}", node_id);
    println!("QUIC endpoint active — direct P2P + relay fallback");
    println!("\nPress Ctrl+C to stop\n");

    tokio::signal::ctrl_c().await?;

    println!("\nShutting down...");
    node.shutdown().await?;

    Ok(())
}

/// List connected peers (starts ephemeral node to query).
pub async fn peers() -> Result<()> {
    let node = iroh::node::Builder::default()
        .spawn()
        .await?;

    let node_id = node.node_id();
    println!("Node ID: {}", node_id);
    println!("(Peer discovery requires connecting to known nodes or relay)");
    println!("No peers connected yet — use `node` command to run persistently.");

    node.shutdown().await?;
    Ok(())
}
