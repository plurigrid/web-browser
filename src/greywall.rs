//! Greywall sandbox integration — deny-by-default confinement for fetched content.
//!
//! Models the Lawvere theory T_safe: init → wrap → expose → cleanup → check.
//! Confinement at the syscall boundary (strace/eslogger profiles).

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Sandbox policy: what the browser process is allowed to do.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Domains allowed for network access
    pub allowed_domains: HashSet<String>,
    /// Ports exposed for iroh QUIC P2P (can't SOCKS-proxy QUIC)
    pub exposed_ports: Vec<u16>,
    /// Filesystem paths with read access
    pub read_paths: HashSet<PathBuf>,
    /// Filesystem paths with write access (cache only)
    pub write_paths: HashSet<PathBuf>,
    /// Blocked command patterns
    pub blocked_commands: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_domains: HashSet::from([
                "api.marginalia.nu".into(),
                "www.marginalia.nu".into(),
            ]),
            exposed_ports: vec![],
            read_paths: HashSet::new(),
            write_paths: HashSet::new(),
            blocked_commands: vec![
                "rm -rf".into(),
                "git push --force".into(),
                "chmod 777".into(),
            ],
        }
    }
}

/// Sandbox state machine: Uninitialized → Active → Torn down.
#[derive(Debug)]
pub struct Sandbox {
    policy: Policy,
    state: SandboxState,
    cache_dir: PathBuf,
}

#[derive(Debug, PartialEq)]
enum SandboxState {
    Uninitialized,
    Active,
    TornDown,
}

impl Sandbox {
    /// T_safe: init — create sandbox from policy.
    pub fn init(mut policy: Policy, cache_dir: PathBuf) -> Result<Self> {
        // Grant write to cache dir
        policy.write_paths.insert(cache_dir.clone());
        // Grant read to cache dir
        policy.read_paths.insert(cache_dir.clone());

        Ok(Self {
            policy,
            state: SandboxState::Active,
            cache_dir,
        })
    }

    /// T_safe: check — is the sandbox alive?
    pub fn is_active(&self) -> bool {
        self.state == SandboxState::Active
    }

    /// T_safe: expose — punch a hole for iroh QUIC port.
    pub fn expose_port(&mut self, port: u16) -> Result<()> {
        self.require_active()?;
        self.policy.exposed_ports.push(port);
        Ok(())
    }

    /// T_safe: wrap — check if a domain is allowed before fetch.
    pub fn check_domain(&self, domain: &str) -> Result<bool> {
        self.require_active()?;
        Ok(self.policy.allowed_domains.contains(domain))
    }

    /// Allow a new domain (e.g., discovered via marginalia results).
    pub fn allow_domain(&mut self, domain: String) -> Result<()> {
        self.require_active()?;
        self.policy.allowed_domains.insert(domain);
        Ok(())
    }

    /// T_safe: wrap — check if a filesystem path is readable.
    pub fn check_read(&self, path: &Path) -> bool {
        self.state == SandboxState::Active
            && self.policy.read_paths.iter().any(|p| path.starts_with(p))
    }

    /// T_safe: wrap — check if a filesystem path is writable (cache only).
    pub fn check_write(&self, path: &Path) -> bool {
        self.state == SandboxState::Active
            && self.policy.write_paths.iter().any(|p| path.starts_with(p))
    }

    /// Check if a command is blocked.
    pub fn check_command(&self, cmd: &str) -> bool {
        self.state == SandboxState::Active
            && !self.policy.blocked_commands.iter().any(|b| cmd.contains(b))
    }

    /// T_safe: cleanup — tear down the sandbox.
    pub fn cleanup(mut self) -> Result<()> {
        self.state = SandboxState::TornDown;
        Ok(())
    }

    /// Return current policy summary for display.
    pub fn policy_summary(&self) -> String {
        format!(
            "domains: {} allowed, ports: {:?}, read: {} paths, write: {} paths, blocked cmds: {}",
            self.policy.allowed_domains.len(),
            self.policy.exposed_ports,
            self.policy.read_paths.len(),
            self.policy.write_paths.len(),
            self.policy.blocked_commands.len(),
        )
    }

    fn require_active(&self) -> Result<()> {
        anyhow::ensure!(
            self.state == SandboxState::Active,
            "sandbox is not active (state: {:?})",
            self.state
        );
        Ok(())
    }
}

/// Verdict from content inspection pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Clean,
    Suspicious(String),
    Malicious(String),
}

impl Verdict {
    pub fn is_safe(&self) -> bool {
        matches!(self, Verdict::Clean)
    }
}
