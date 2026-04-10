# web-browser

QUIC-native web browser built on [iroh](https://iroh.computer) P2P networking.

## Onboarding

Two endpoints. That's it.

1. **QUIC** — iroh node for P2P content distribution and direct QUIC connections
2. **[marginalia.nu](https://www.marginalia.nu)** — independent web search for the non-commercial internet

## Usage

```bash
# Search marginalia
cargo run -- search "category theory"

# Fetch a page over QUIC (HTTP/3 when available)
cargo run -- fetch https://www.marginalia.nu

# Start iroh P2P node for content sharing
cargo run -- node

# Browse cached content from peers
cargo run -- peers
```

## Architecture

```
┌─────────────────────────────────────┐
│           web-browser CLI           │
├──────────┬──────────┬───────────────┤
│ marginalia│  QUIC    │  iroh node   │
│ search API│  fetch   │  (P2P mesh)  │
├──────────┴──────────┴───────────────┤
│         reqwest (HTTP/3)            │
│         iroh (QUIC/P2P)             │
└─────────────────────────────────────┘
```

Content fetched via HTTP/3 (QUIC) is cached locally and can be shared peer-to-peer through iroh-blobs.
Search uses marginalia.nu API — no Google, no tracking.
