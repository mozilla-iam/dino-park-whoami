#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate actix_session;
extern crate actix_web;
extern crate base64;
extern crate chrono;
extern crate cis_client;
extern crate cis_profile;
extern crate env_logger;
extern crate futures;
extern crate rand;
extern crate serde_json;
extern crate url;

mod bugzilla;
mod github;
mod healthz;
mod update;
mod userid;
mod settings;

use crate::bugzilla::app::bugzilla_app;
use crate::github::app::github_app;
use actix_web::middleware::Logger;
use actix_web::App;
use actix_web::web;

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
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .service(
                web::scope("/whoami/")
                    .service(github_app(&s.providers.github, &s.whoami, &secret, client.clone()))
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
