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

## Security: Graywall Integration

Run sandboxed with [graywall](https://github.com/plurigrid/graywall) (deny-by-default):

```bash
# Install greyproxy domain allowlist
cp config/greyproxy-web-browser.json ~/.config/greyproxy/web-browser.json

# Run sandboxed — only marginalia.nu + iroh relay allowed
graywall -- cargo run -- safe-fetch https://www.marginalia.nu

# Learn mode — discover what the browser actually needs
graywall --learning -- cargo run -- onboard
```

The `safe-fetch` pipeline:

```
URL → marginalia pre-filter → QUIC fetch → BLAKE3 hash
    → magic bytes + polyglot detection → YARA pattern scan
    → capability gate (clean=render, suspicious=read-only, malicious=blocked)
    → sandboxed render
```

```bash
# Scan a local file
cargo run -- scan suspicious.pdf

# Safe fetch with full pipeline
cargo run -- safe-fetch https://www.marginalia.nu
```
