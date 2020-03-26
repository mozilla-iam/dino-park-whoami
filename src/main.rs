mod bugzilla;
mod error;
mod github;
mod healthz;
mod settings;
mod update;

use crate::bugzilla::app::bugzilla_app;
use crate::github::app::github_app;
use actix_web::middleware::Logger;
use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;
use dino_park_gate::provider::Provider;
use dino_park_gate::scope::ScopeAndUserAuth;
use log::info;
use std::io::Error;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::RwLock;
use ttl_cache::TtlCache;

fn map_io_err(e: impl Into<failure::Error>) -> Error {
    Error::new(ErrorKind::Other, e.into())
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    info!("starting dino-park-whoami");
    let s = settings::Settings::new().map_err(map_io_err)?;
    let client = cis_client::CisClient::from_settings(&s.cis)
        .await
        .map_err(map_io_err)?;
    info!("initialized cis_client");
    let secret = base64::decode(&s.whoami.secret).map_err(map_io_err)?;
    let ttl_cache = Arc::new(RwLock::new(TtlCache::<String, String>::new(2000)));
    let provider = Provider::from_issuer("https://auth.mozilla.auth0.com/")
        .await
        .map_err(map_io_err)?;

    HttpServer::new(move || {
        let scope_middleware = ScopeAndUserAuth::new(provider.clone()).public();
        App::new()
            .wrap(Logger::default().exclude("/healthz"))
            .service(
                web::scope("/whoami/")
                    .wrap(scope_middleware)
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
    .await
}
