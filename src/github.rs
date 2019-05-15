use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::AuthUrl;
use oauth2::AuthorizationCode;
use oauth2::ClientId;
use oauth2::ClientSecret;
use oauth2::CsrfToken;
use oauth2::RedirectUrl;
use oauth2::Scope;
use oauth2::TokenResponse;
use oauth2::TokenUrl;
use std::env;
use std::sync::Arc;
use url::Url;

use actix_session::CookieSession;
use actix_session::Session;
use actix_web::client::Client;
use actix_web::cookie::SameSite;
use actix_web::dev::HttpServiceFactory;
use actix_web::http;
use actix_web::web;
use actix_web::Error;
use actix_web::HttpResponse;
use actix_web::Responder;
use futures::future;
use futures::Future;

#[derive(Deserialize)]
pub struct Auth {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct GitHubUser {
    login: String,
    node_id: String,
}

fn redirect(client: web::Data<Arc<BasicClient>>, session: Session) -> impl Responder {
    let (authorize_url, csrf_state) = client.authorize_url(CsrfToken::new_random);
    println!("settting: {}", csrf_state.secret());
    session
        .set("csrf_state", csrf_state.secret().clone())
        .map(|_| {
            HttpResponse::Found()
                .header(http::header::LOCATION, authorize_url.to_string())
                .finish()
        })
}

fn auth(
    client: web::Data<Arc<BasicClient>>,
    query: web::Query<Auth>,
    session: Session,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let code = AuthorizationCode::new(query.code.clone());
    let state = CsrfToken::new(query.state.clone());
    println!("remote: {}", state.secret());
    if let Some(ref must_state) = session.get::<String>("csrf_state").unwrap() {
        println!("session: {}", must_state);
        if must_state != state.secret() {
            return Box::new(future::ok(
                HttpResponse::Found()
                    .header(http::header::LOCATION, "/error")
                    .finish(),
            ));
        }
    } else {
        return Box::new(future::ok(
            HttpResponse::Found()
                .header(http::header::LOCATION, "/error")
                .finish(),
        ));
    }
    let token_res = client.exchange_code(code);

    if let Ok(token) = token_res {
        return Box::new(
            Client::default()
                .get("https://api.github.com/user")
                .bearer_auth(token.access_token().secret())
                .header(http::header::USER_AGENT, "fuck off")
                .send()
                .map_err(Into::into)
                .and_then(|mut res| {
                    println!("status: {}", res.status());
                    res.json::<GitHubUser>().map_err(Into::into)
                })
                .and_then(|j| {
                    println!("login: {}, id: {}", j.login, j.node_id);
                    HttpResponse::Found()
                        .header(http::header::LOCATION, "/e")
                        .finish()
                }),
        );
    }
    Box::new(future::ok(
        HttpResponse::Found()
            .header(http::header::LOCATION, "/error")
            .finish(),
    ))
}

pub fn github_app() -> impl HttpServiceFactory {
    let github_client_id = ClientId::new(
        env::var("GITHUB_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable."),
    );
    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET")
            .expect("Missing the GITHUB_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new(
        Url::parse("https://github.com/login/oauth/authorize")
            .expect("Invalid authorization endpoint URL"),
    );
    let token_url = TokenUrl::new(
        Url::parse("https://github.com/login/oauth/access_token")
            .expect("Invalid token endpoint URL"),
    );

    let client = Arc::new(
        BasicClient::new(
            github_client_id,
            Some(github_client_secret),
            auth_url,
            Some(token_url),
        )
        .add_scope(Scope::new("read:user".to_string()))
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://127.0.0.1:8084/whoami/github/auth").expect("Invalid redirect URL"),
        )),
    );

    return web::scope("/github/")
        .wrap(
            CookieSession::private(&[0; 32])
                .name("dpw_gh")
                .path("/whoami/github")
                .domain("127.0.0.1")
                .same_site(SameSite::Lax)
                .http_only(true)
                .secure(false)
                .max_age(300),
        )
        .data(client)
        .service(web::resource("/add").route(web::get().to(redirect)))
        .service(web::resource("/auth").route(web::get().to_async(auth)));
}
