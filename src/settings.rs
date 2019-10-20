use cis_client::settings::CisSettings;
use config::{Config, ConfigError, Environment, File};
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct BugZilla {
    pub client_id: String,
    pub client_secret: String,
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GitHub {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Slack {
    pub client_id: String,
    pub client_secret: String,
    pub identity_scope: String,
    pub identity_redirect_uri: String,
    pub direct_message_uri: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Providers {
    pub github: GitHub,
    pub bugzilla: BugZilla,
    pub slack: Slack,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WhoAmI {
    pub domain: String,
    pub secret: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub providers: Providers,
    pub cis: CisSettings,
    pub whoami: WhoAmI,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let file = env::var("DPW_SETTINGS").unwrap_or_else(|_| String::from(".settings"));
        let mut s = Config::new();
        s.merge(File::with_name(&file))?;
        s.merge(Environment::new().separator("__"))?;
        s.try_into()
    }
}
