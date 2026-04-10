//! OCapN-inspired capability gate for fetched content.
//!
//! Each piece of fetched content gets an attenuated capability token
//! that encodes exactly what operations are permitted. No ambient authority.
//! The confused deputy problem vanishes because the token IS the permission.

use std::collections::HashSet;

/// What a capability holder is allowed to do with content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read the raw bytes
    Read,
    /// Render as HTML/text in sandbox
    Render,
    /// Write to cache directory
    Cache,
    /// Share via iroh-blobs P2P
    Share,
    /// Execute (never granted for web content)
    Execute,
}

/// Unforgeable capability token for a piece of content.
/// Capabilities propagate only through explicit introduction.
#[derive(Debug, Clone)]
pub struct Capability {
    /// BLAKE3 hash of the content this capability refers to
    content_hash: [u8; 32],
    /// Permitted operations
    permissions: HashSet<Permission>,
    /// Who granted this capability
    grantor: String,
    /// Whether this capability can be further delegated
    delegatable: bool,
}

impl Capability {
    /// Create a new capability for content with given permissions.
    pub fn new(content_hash: [u8; 32], grantor: &str, permissions: &[Permission]) -> Self {
        Self {
            content_hash,
            permissions: permissions.iter().cloned().collect(),
            grantor: grantor.to_string(),
            delegatable: false,
        }
    }

    /// Default capability for web content: read + render + cache, no execute.
    pub fn for_web_content(content_hash: [u8; 32]) -> Self {
        Self::new(
            content_hash,
            "greywall",
            &[Permission::Read, Permission::Render, Permission::Cache],
        )
    }

    /// Capability for P2P shared content: read + render + cache + share.
    pub fn for_p2p_content(content_hash: [u8; 32]) -> Self {
        Self::new(
            content_hash,
            "iroh-node",
            &[
                Permission::Read,
                Permission::Render,
                Permission::Cache,
                Permission::Share,
            ],
        )
    }

    /// Attenuate: return a new capability with fewer permissions.
    /// You can only remove permissions, never add.
    pub fn attenuate(&self, keep: &[Permission]) -> Self {
        let narrowed: HashSet<Permission> = self
            .permissions
            .intersection(&keep.iter().cloned().collect())
            .cloned()
            .collect();
        Self {
            content_hash: self.content_hash,
            permissions: narrowed,
            grantor: self.grantor.clone(),
            delegatable: false,
        }
    }

    /// Check if this capability permits an operation.
    pub fn permits(&self, perm: &Permission) -> bool {
        self.permissions.contains(perm)
    }

    /// Content hash this capability refers to.
    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Make this capability delegatable (can be passed to other actors).
    pub fn make_delegatable(mut self) -> Self {
        self.delegatable = true;
        self
    }

    pub fn is_delegatable(&self) -> bool {
        self.delegatable
    }

    pub fn summary(&self) -> String {
        let perms: Vec<&str> = self
            .permissions
            .iter()
            .map(|p| match p {
                Permission::Read => "read",
                Permission::Render => "render",
                Permission::Cache => "cache",
                Permission::Share => "share",
                Permission::Execute => "EXECUTE",
            })
            .collect();
        format!(
            "cap[{}] {} delegatable={}",
            hex::encode(&self.content_hash[..4]),
            perms.join("+"),
            self.delegatable,
        )
    }
}

/// Gate: given content bytes + verdict, produce an appropriate capability.
pub fn gate(content: &[u8], verdict: &crate::greywall::Verdict, is_p2p: bool) -> Option<Capability> {
    use crate::greywall::Verdict;

    // BLAKE3 hash of content
    let hash: [u8; 32] = blake3::hash(content).into();

    match verdict {
        Verdict::Malicious(_) => None, // No capability. No rendering. No pixels.
        Verdict::Suspicious(reason) => {
            // Read-only capability, no rendering
            Some(Capability::new(hash, "greywall-restricted", &[Permission::Read]))
        }
        Verdict::Clean => {
            if is_p2p {
                Some(Capability::for_p2p_content(hash))
            } else {
                Some(Capability::for_web_content(hash))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_content_cannot_execute() {
        let cap = Capability::for_web_content([0u8; 32]);
        assert!(!cap.permits(&Permission::Execute));
        assert!(cap.permits(&Permission::Render));
    }

    #[test]
    fn attenuation_only_removes() {
        let cap = Capability::for_p2p_content([0u8; 32]);
        assert!(cap.permits(&Permission::Share));

        let narrowed = cap.attenuate(&[Permission::Read]);
        assert!(narrowed.permits(&Permission::Read));
        assert!(!narrowed.permits(&Permission::Share));
        assert!(!narrowed.permits(&Permission::Render));
    }

    #[test]
    fn malicious_gets_no_capability() {
        let content = b"evil";
        let verdict = crate::greywall::Verdict::Malicious("test".into());
        assert!(gate(content, &verdict, false).is_none());
    }

    #[test]
    fn suspicious_gets_read_only() {
        let content = b"sketchy";
        let verdict = crate::greywall::Verdict::Suspicious("eval detected".into());
        let cap = gate(content, &verdict, false).unwrap();
        assert!(cap.permits(&Permission::Read));
        assert!(!cap.permits(&Permission::Render));
    }
}
