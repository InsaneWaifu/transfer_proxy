use std::{net::SocketAddr, time::Duration};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub routes: Vec<Route>,
}

#[derive(Debug, Deserialize)]
pub struct Route {
    #[serde(rename = "match")]
    pub pattern: String,
    pub status: StatusConfig,
    pub destination: Destination,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Destination {
    #[serde(rename = "transfer")]
    Transfer {
        host: String, port: u16,
        #[serde(default)]
        transfer_mode: TransferMode,
        #[serde(default)]
        rewrite_address: bool
    },
    #[serde(rename = "kick")]
    Kick { message: serde_json::Value },
}

#[derive(Debug, Deserialize, Default)]
#[serde(tag = "type")]
pub enum TransferMode {
    #[default]
    #[serde(rename = "transfer")]
    Transfer,
    #[serde(rename = "opportunistic")]
    Opportunistic {
        haproxy: bool,
    },
    #[serde(rename = "proxy")]
    Proxy {
        haproxy: bool,
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum StatusConfig {
    #[serde(rename = "static")]
    Static {
        json: serde_json::Value,
        fake_protocol_version: bool,
    },
    #[serde(rename = "fetch_from")]
    FetchFrom {
        host: String,
        port: u16,
        #[serde(default)]
        rewrite_address: bool,
        #[serde(default)]
        cache_ttl: Option<u64>,
    },
}

impl StatusConfig {
    pub fn cache_ttl(&self) -> Option<Duration> {
        match self {
            StatusConfig::FetchFrom { cache_ttl, .. } => cache_ttl.map(Duration::from_secs),
            _ => None,
        }
    }

    pub fn cache_key(&self, resolved_host: &str) -> Option<String> {
        match self {
            StatusConfig::FetchFrom {  port, .. } => Some(format!("{resolved_host}:{port}")),
            _ => None,
        }
    }
}

impl Config {
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn match_host(&self, address: &str) -> Option<&Route> {
        self.routes.iter().find(|x| x.matches(address))
    }
}

impl Route {
    fn matches(&self, address: &str) -> bool {
        if self.pattern == "*" {
            return true;
        }

        if let Some(suffix) = self.pattern.strip_prefix("*.") {
            return address == suffix || address.ends_with(&format!(".{suffix}"));
        }

        if let Some(prefix) = self.pattern.strip_suffix(".*") {
            return address.starts_with(prefix)
                && (address.len() == prefix.len()
                    || address.as_bytes().get(prefix.len()) == Some(&b'.'));
        }

        address == self.pattern
    }
}
