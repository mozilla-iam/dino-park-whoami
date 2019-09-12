#[macro_use]
extern crate serde_derive;

mod bugzilla;
mod github;
mod healthz;
mod settings;
mod update;
mod userid;

use crate::bugzilla::app::bugzilla_app;
use crate::github::app::github_app;
use actix_web::middleware::Logger;
use actix_web::web;
use actix_web::App;
use log::info;
use std::sync::Arc;
use std::sync::RwLock;
use ttl_cache::TtlCache;

use actix_web::HttpServer;
use failure::Error;

fn main() -> Result<(), Error> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    info!("starting dino-park-whoami");
    let s = settings::Settings::new()?;
    let client = cis_client::CisClient::from_settings(&s.cis)?;
    info!("initialized cis_client");
    let secret = base64::decode(&s.whoami.secret)?;
    let ttl_cache = Arc::new(RwLock::new(TtlCache::<String, String>::new(2000)));
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default().exclude("/healthz"))
            .service(
                web::scope("/whoami/")
                    .service(github_app(
                        &s.providers.github,
                        &s.whoami,
                        &secret,
                        Arc::clone(&ttl_cache),
                        client.clone(),
                    ))
                    .service(bugzilla_app(
                        &s.providers.bugzilla,
                        &s.whoami,
                        &secret,
                        client.clone(),
                    )),
            )
            .service(healthz::healthz_app())
    })
    .bind("0.0.0.0:8084")?
    .run()
    .map_err(Into::into)
}
