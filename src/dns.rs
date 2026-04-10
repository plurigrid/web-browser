//! DNS filtering resolver for graywall integration.
//!
//! Runs on localhost:5353. Graywall's DnsBridge routes all sandbox DNS here.
//! We resolve only allowlisted domains, returning NXDOMAIN for everything else.
//! This gives the browser control over DNS before any network request is made.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::UdpSocket;

const LISTEN_ADDR: &str = "127.0.0.1:5353";
const UPSTREAM_DNS: &str = "1.1.1.1:53";

/// Domains the browser is allowed to resolve.
fn default_allowlist() -> HashSet<String> {
    [
        "api.marginalia.nu",
        "www.marginalia.nu",
        "api.marginalia-search.com",
        "relay.iroh.network",
        "dns.iroh.network",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Extract the queried domain name from a raw DNS packet.
/// DNS name format: length-prefixed labels ending with 0x00, starting at byte 12.
fn extract_query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&packet[pos..pos + len]).ok()?);
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }
    Some(labels.join(".").to_lowercase())
}

/// Build an NXDOMAIN response for a DNS query.
/// Copies the transaction ID and question, sets RCODE=3 (NXDOMAIN).
fn nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut resp = query.to_vec();
    // QR=1 (response), RCODE=3 (NXDOMAIN)
    resp[2] = 0x81; // QR=1, Opcode=0, AA=0, TC=0, RD=1
    resp[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
    // ANCOUNT = 0
    resp[6] = 0;
    resp[7] = 0;
    Some(resp)
}

/// Run the DNS filter as a blocking UDP server.
pub fn run(allowlist: Option<HashSet<String>>) -> Result<()> {
    let allowed = allowlist.unwrap_or_else(default_allowlist);
    let socket = UdpSocket::bind(LISTEN_ADDR).context(format!("failed to bind {}", LISTEN_ADDR))?;
    let upstream = UdpSocket::bind("0.0.0.0:0").context("failed to bind upstream socket")?;
    upstream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    println!("[dns] listening on {} ({} domains allowed)", LISTEN_ADDR, allowed.len());
    for domain in &allowed {
        println!("[dns]   + {}", domain);
    }

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let packet = &buf[..len];

        let domain = extract_query_name(packet).unwrap_or_default();

        // Check if domain or any parent domain is in allowlist
        let is_allowed = allowed.contains(&domain) || {
            let parts: Vec<&str> = domain.split('.').collect();
            (1..parts.len())
                .any(|i| allowed.contains(&parts[i..].join(".")))
        };

        if is_allowed {
            // Forward to upstream DNS
            if upstream.send_to(packet, UPSTREAM_DNS).is_ok() {
                let mut resp_buf = [0u8; 512];
                if let Ok((resp_len, _)) = upstream.recv_from(&mut resp_buf) {
                    let _ = socket.send_to(&resp_buf[..resp_len], src);
                    println!("[dns] ALLOW {} -> {}", domain, src);
                }
            }
        } else {
            // Return NXDOMAIN
            if let Some(resp) = nxdomain_response(packet) {
                let _ = socket.send_to(&resp, src);
                println!("[dns] DENY  {} -> NXDOMAIN ({})", domain, src);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_marginalia_domain() {
        // DNS query for api.marginalia.nu
        let mut packet = vec![0u8; 12]; // header
        // "api" label
        packet.push(3);
        packet.extend_from_slice(b"api");
        // "marginalia" label
        packet.push(10);
        packet.extend_from_slice(b"marginalia");
        // "nu" label
        packet.push(2);
        packet.extend_from_slice(b"nu");
        // terminator
        packet.push(0);

        assert_eq!(extract_query_name(&packet), Some("api.marginalia.nu".into()));
    }

    #[test]
    fn nxdomain_sets_rcode() {
        let query = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let resp = nxdomain_response(&query).unwrap();
        assert_eq!(resp[0], 0xAB); // transaction ID preserved
        assert_eq!(resp[1], 0xCD);
        assert_eq!(resp[3] & 0x0F, 3); // RCODE = NXDOMAIN
    }

    #[test]
    fn default_allowlist_has_marginalia() {
        let allowed = default_allowlist();
        assert!(allowed.contains("api.marginalia.nu"));
        assert!(allowed.contains("relay.iroh.network"));
        assert!(!allowed.contains("google.com"));
    }
}
