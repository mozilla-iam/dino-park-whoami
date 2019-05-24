#[macro_use]
extern crate serde_derive;
extern crate actix_session;
extern crate actix_web;
extern crate base64;
extern crate chrono;
extern crate cis_client;
extern crate cis_profile;
extern crate failure;
extern crate futures;
extern crate oauth2;
extern crate rand;
extern crate serde_json;
extern crate url;

mod bugzilla;
mod github;
mod settings;
mod update;
mod userid;

use crate::bugzilla::app::bugzilla_app;
use crate::github::app::github_app;
use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;
use failure::Error;

fn main() -> Result<(), Error> {
    let s = settings::Settings::new()?;
    let client = cis_client::CisClient::from_settings(&s.cis)?;
    HttpServer::new(move || {
        App::new().service(
            web::scope("/whoami/")
                .service(github_app(&s.providers.github, &s.whoami, client.clone()))
                .service(bugzilla_app(&s.providers.bugzilla, &s.whoami, client.clone())),
        )
    })
    .bind("127.0.0.1:8084")?
    .run()
    .map_err(Into::into)
}
