// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt MMDS (Microvm Metadata Service) implementation.
// Provides IMDSv1/v2 compatible metadata access at 169.254.169.254.

pub mod tcp_stack;

use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{bail, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MMDS protocol version.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmdsVersion {
    V1,
    #[default]
    V2,
}

impl FromStr for MmdsVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "V1" => Ok(MmdsVersion::V1),
            "V2" => Ok(MmdsVersion::V2),
            _ => bail!("Invalid MMDS version: {}, expected 'V1' or 'V2'", s),
        }
    }
}

/// Sandbox metadata provided by external service.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MmdsData {
    #[serde(rename = "instanceID")]
    pub instance_id: String,
    #[serde(rename = "envID")]
    pub env_id: String,
    pub address: String,
    #[serde(rename = "accessTokenHash", skip_serializing_if = "Option::is_none")]
    pub access_token_hash: Option<String>,
}

/// MMDS service configuration.
#[derive(Clone, Debug)]
pub struct MmdsConfig {
    pub version: MmdsVersion,
    /// Network interface IDs on which MMDS traffic is intercepted.
    pub network_interfaces: Vec<String>,
    /// IPv4 address of the MMDS endpoint (default: 169.254.169.254).
    pub ipv4_address: [u8; 4],
}

impl Default for MmdsConfig {
    fn default() -> Self {
        MmdsConfig {
            version: MmdsVersion::V2,
            network_interfaces: Vec::new(),
            ipv4_address: [169, 254, 169, 254],
        }
    }
}

/// A single IMDSv2 session token with its TTL.
pub struct TokenEntry {
    pub token: String,
    pub expires_at: Instant,
}

impl TokenEntry {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Core MMDS data store.  Holds metadata and manages IMDSv2 tokens.
pub struct MmdsStore {
    data: MmdsData,
    pub config: MmdsConfig,
    tokens: HashMap<String, TokenEntry>,
    next_token_id: u64,
}

impl MmdsStore {
    pub fn new_default() -> Self {
        MmdsStore {
            data: MmdsData::default(),
            config: MmdsConfig::default(),
            tokens: HashMap::new(),
            next_token_id: 0,
        }
    }

    pub fn new_v2() -> Self {
        let mut s = Self::new_default();
        s.config.version = MmdsVersion::V2;
        s
    }

    /// Replace the entire data store.
    pub fn put(&mut self, data: MmdsData) -> Result<()> {
        self.data = data;
        Ok(())
    }

    /// Merge a partial JSON object into the store (only known fields).
    pub fn patch(&mut self, partial: Value) -> Result<()> {
        let obj = partial
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("patch argument must be a JSON object"))?;
        if let Some(v) = obj.get("instanceID").and_then(Value::as_str) {
            self.data.instance_id = v.to_string();
        }
        if let Some(v) = obj.get("envID").and_then(Value::as_str) {
            self.data.env_id = v.to_string();
        }
        if let Some(v) = obj.get("address").and_then(Value::as_str) {
            self.data.address = v.to_string();
        }
        if let Some(v) = obj.get("accessTokenHash").and_then(Value::as_str) {
            self.data.access_token_hash = Some(v.to_string());
        }
        Ok(())
    }

    pub fn get_json(&self) -> Value {
        serde_json::to_value(&self.data).unwrap_or(Value::Null)
    }

    /// Generate an IMDSv2 token valid for `ttl_seconds`.
    pub fn generate_token(&mut self, ttl_seconds: u32) -> String {
        // Purge expired tokens periodically.
        self.tokens.retain(|_, e| !e.is_expired());

        let token = format!("mmds-token-{:016x}", self.next_token_id);
        self.next_token_id += 1;

        let expires_at = if ttl_seconds == 0 {
            // Zero TTL → instantly expired; store with past instant.
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or(Instant::now())
        } else {
            Instant::now() + Duration::from_secs(u64::from(ttl_seconds))
        };
        self.tokens.insert(
            token.clone(),
            TokenEntry {
                token: token.clone(),
                expires_at,
            },
        );
        token
    }

    /// Returns true if the token exists and has not expired.
    pub fn validate_token(&self, token: &str) -> bool {
        self.tokens
            .get(token)
            .map(|e| !e.is_expired())
            .unwrap_or(false)
    }

    /// Returns true if the given network interface ID is MMDS-enabled.
    pub fn is_interface_enabled(&self, iface_id: &str) -> bool {
        self.config
            .network_interfaces
            .iter()
            .any(|id| id == iface_id)
    }

    /// Handle an HTTP GET request.
    /// `token` is Some(token_str) for V2; None is accepted for V1.
    pub fn handle_get_request(&self, token: Option<&str>) -> Result<Value> {
        if self.config.version == MmdsVersion::V2 {
            match token {
                None => bail!("IMDSv2 requires X-metadata-token header"),
                Some(t) if !self.validate_token(t) => {
                    bail!("Invalid or expired IMDSv2 token")
                }
                _ => {}
            }
        }
        Ok(self.get_json())
    }

    pub fn get_ipv4_address(&self) -> [u8; 4] {
        self.config.ipv4_address
    }
}

/// Parse a dotted-decimal IPv4 string into a 4-byte array.
/// Returns `None` if the string is not a valid IPv4 address.
pub fn parse_ipv4(addr: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut result = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        result[i] = part.parse().ok()?;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_str_valid() {
        assert_eq!(MmdsVersion::from_str("V1").unwrap(), MmdsVersion::V1);
        assert_eq!(MmdsVersion::from_str("V2").unwrap(), MmdsVersion::V2);
    }

    #[test]
    fn test_version_from_str_invalid() {
        assert!(MmdsVersion::from_str("v1").is_err());
        assert!(MmdsVersion::from_str("V3").is_err());
        assert!(MmdsVersion::from_str("").is_err());
    }

    #[test]
    fn test_put_and_get_json() {
        let mut store = MmdsStore::new_default();
        let data = MmdsData {
            instance_id: "inst-001".to_string(),
            env_id: "env-abc".to_string(),
            address: "10.0.0.1".to_string(),
            access_token_hash: None,
        };
        store.put(data).unwrap();
        let json = store.get_json();
        assert_eq!(json["instanceID"], "inst-001");
        assert_eq!(json["envID"], "env-abc");
        assert_eq!(json["address"], "10.0.0.1");
    }

    #[test]
    fn test_patch_updates_only_specified_fields() {
        let mut store = MmdsStore::new_default();
        store
            .put(MmdsData {
                instance_id: "original".to_string(),
                env_id: "env-orig".to_string(),
                address: "1.2.3.4".to_string(),
                access_token_hash: None,
            })
            .unwrap();
        store
            .patch(serde_json::json!({"instanceID": "updated"}))
            .unwrap();
        let json = store.get_json();
        assert_eq!(json["instanceID"], "updated");
        assert_eq!(json["envID"], "env-orig");
        assert_eq!(json["address"], "1.2.3.4");
    }

    #[test]
    fn test_patch_non_object_returns_error() {
        let mut store = MmdsStore::new_default();
        assert!(store
            .patch(serde_json::Value::String("bad".to_string()))
            .is_err());
        assert!(store.patch(serde_json::Value::Array(vec![])).is_err());
    }

    #[test]
    fn test_generate_and_validate_token() {
        let mut store = MmdsStore::new_v2();
        let token = store.generate_token(3600);
        assert!(store.validate_token(&token));
        assert!(!store.validate_token("nonexistent-token"));
    }

    #[test]
    fn test_token_zero_ttl_is_immediately_invalid() {
        let mut store = MmdsStore::new_v2();
        let token = store.generate_token(0);
        assert!(!store.validate_token(&token));
    }

    #[test]
    fn test_get_v1_succeeds_without_token() {
        let mut store = MmdsStore::new_default();
        store.config.version = MmdsVersion::V1;
        assert!(store.handle_get_request(None).is_ok());
    }

    #[test]
    fn test_get_v2_requires_valid_token() {
        let mut store = MmdsStore::new_v2();
        assert!(store.handle_get_request(None).is_err());
        assert!(store.handle_get_request(Some("bad-token")).is_err());
        let token = store.generate_token(3600);
        assert!(store.handle_get_request(Some(&token)).is_ok());
    }

    #[test]
    fn test_is_interface_enabled() {
        let mut store = MmdsStore::new_default();
        store.config.network_interfaces = vec!["eth0".to_string(), "eth1".to_string()];
        assert!(store.is_interface_enabled("eth0"));
        assert!(store.is_interface_enabled("eth1"));
        assert!(!store.is_interface_enabled("eth2"));
    }

    #[test]
    fn test_parse_ipv4_valid() {
        assert_eq!(parse_ipv4("169.254.169.254"), Some([169, 254, 169, 254]));
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("192.168.1"), None);
        assert_eq!(parse_ipv4("192.168.1.1.1"), None);
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("192.168.1.abc"), None);
        assert_eq!(parse_ipv4("192.168.1.-1"), None);
    }
}
