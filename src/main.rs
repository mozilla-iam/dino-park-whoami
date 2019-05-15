#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate actix_web;
extern crate actix_session;
extern crate base64;
extern crate oauth2;
extern crate rand;
extern crate url;
extern crate failure;
extern crate futures;

mod github;

use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;

use github::github_app;

fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().service(
            web::scope("/whoami/").service(github_app()),
        )
    })
    .bind("127.0.0.1:8084")?
    .run()
}
