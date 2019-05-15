use config::{Config, ConfigError, Environment, File};
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct GitHub {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Providers {
    pub github: GitHub;
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub key: String,
    pub providers: Providers,
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
