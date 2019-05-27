use crate::settings::BugZilla;
use crate::settings::WhoAmI;
use crate::update::update_bugzilla;
use crate::userid::UserId;
use actix_session::CookieSession;
use actix_session::Session;
use actix_web::client::Client;
use actix_web::cookie::SameSite;
use actix_web::dev::HttpServiceFactory;
use actix_web::http;
use actix_web::middleware::cors::Cors;
use actix_web::web;
use actix_web::Error;
use actix_web::HttpResponse;
use actix_web::Responder;
use cis_client::getby::GetBy;
use cis_client::AsyncCisClientTrait;
use cis_profile::schema::Profile;
use future::IntoFuture;
use futures::future;
use futures::Future;
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::AuthUrl;
use oauth2::ClientId;
use oauth2::ClientSecret;
use oauth2::CsrfToken;
use oauth2::RedirectUrl;
use oauth2::Scope;
use oauth2::TokenUrl;
use std::sync::Arc;
use url::Url;

const AUTH_PATH: &str = "/oauth/authorize";
const TOKEN_PATH: &str = "/oauth/access_token";
const USER_PATH: &str = "/api/user/profile";

#[derive(Deserialize)]
pub struct Auth {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct BugZillaUser {
    id: String,
    login: String,
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

fn auth<T: AsyncCisClientTrait + 'static>(
    cis_client: web::Data<T>,
    bugzilla: web::Data<Arc<BugZilla>>,
    user_id: UserId,
    query: web::Query<Auth>,
    session: Session,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let state = CsrfToken::new(query.state.clone());
    info!("remote: {}", state.secret());
    if let Some(ref must_state) = session.get::<String>("csrf_state").unwrap() {
        info!("session: {}", must_state);
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
    // Looks like we get the access_token as code?!
    let token = query.code.clone();
    let get = cis_client.clone();
    let get_uid = user_id.user_id.clone();
    let url = format!("{}{}", bugzilla.base_url, USER_PATH);
    Box::new(
        Client::default()
            .get(url)
            .header(http::header::USER_AGENT, "whoami")
            //.bearer_auth(token.access_token().secret())
            .bearer_auth(token)
            .send()
            .map_err(Into::into)
            .and_then(|mut res| {
                info!("status: {}", res.status());
                res.json::<BugZillaUser>().map_err(Into::into)
            })
            .and_then(move |j| {
                info!("login: {}, id: {}", j.login, j.id);
                get.get_user_by(&get_uid, &GetBy::UserId, None)
                    .and_then(move |profile: Profile| {
                        update_bugzilla(j.id, j.login, profile, get.get_secret_store())
                            .into_future()
                            .map_err(Into::into)
                    })
                    .map_err(Into::into)
            })
            .and_then(move |profile: Profile| {
                cis_client
                    .update_user(&user_id.user_id, profile)
                    .map_err(Into::into)
            })
            .and_then(|_| {
                HttpResponse::Found()
                    .header(http::header::LOCATION, "/e")
                    .finish()
            }),
    )
}

pub fn bugzilla_app<T: AsyncCisClientTrait + 'static>(
    bugzilla: &BugZilla,
    whoami: &WhoAmI,
    secret: &[u8],
    cis_client: T,
) -> impl HttpServiceFactory {
    let bugzilla_client_id = ClientId::new(bugzilla.client_id.clone());
    let bugzilla_client_secret = ClientSecret::new(bugzilla.client_secret.clone());
    let auth_url = AuthUrl::new(
        Url::parse(&format!("{}{}", &bugzilla.base_url, AUTH_PATH))
            .expect("Invalid authorization endpoint URL"),
    );
    let token_url = TokenUrl::new(
        Url::parse(&format!("{}{}", &bugzilla.base_url, TOKEN_PATH))
            .expect("Invalid token endpoint URL"),
    );

    let client = Arc::new(
        BasicClient::new(
            bugzilla_client_id,
            Some(bugzilla_client_secret),
            auth_url,
            Some(token_url),
        )
        .add_scope(Scope::new("user:read".to_string()))
        .set_redirect_url(RedirectUrl::new(
            Url::parse(&format!("https://{}/whoami/bugzilla/auth", whoami.domain))
                .expect("Invalid redirect URL"),
        )),
    );

    web::scope("/bugzilla/")
        .wrap(
            Cors::new()
                .allowed_methods(vec!["GET", "POST"])
                .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                .allowed_header(http::header::CONTENT_TYPE)
                .max_age(3600),
        )
        .wrap(
            CookieSession::private(secret)
                .name("dpw_bz")
                .path("/whoami/bugzilla")
                .domain(whoami.domain.clone())
                .same_site(SameSite::Lax)
                .http_only(true)
                .secure(false)
                .max_age(300),
        )
        .data(client)
        .data(cis_client)
        .data(Arc::new(bugzilla.clone()))
        .service(web::resource("/add").route(web::get().to(redirect)))
        .service(web::resource("/auth").route(web::get().to_async(auth::<T>)))
}
