use crate::settings::Slack;
use crate::settings::WhoAmI;
use crate::update::update_slack;
use crate::userid::UserId;
use actix_cors::Cors;
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
use cis_client::getby::GetBy;
use cis_client::AsyncCisClientTrait;
use cis_profile::schema::Profile;
use futures::future;
use futures::Future;
use futures::IntoFuture;
use log::info;
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
use std::sync::RwLock;
use ttl_cache::TtlCache;
use url::Url;

const AUTH_URL: &str = "https://slack.com/oauth/authorize";
const TOKEN_URL: &str = "https://slack.com/api/oauth.access";

#[derive(Deserialize)]
pub struct Auth {
    code: String,
    state: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackUser {
    name: String,
    id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackTeam {
    id: String,
}

#[derive(Deserialize, Debug)]
pub struct SlackTokenResponse {
    ok: bool,
    access_token: String,
    scope: String,
    user: SlackUser,
    team: SlackTeam,
}

fn redirect(client: web::Data<Arc<BasicClient>>, session: Session) -> impl Responder {
    let (authorize_url, csrf_state) = client.authorize_url(CsrfToken::new_random);
    info!("Setting csrf_state: {}", csrf_state.secret().clone());
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
    user_id: UserId,
    query: web::Query<Auth>,
    slack_auth_params: web::Data<String>,
    session: Session,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let code = query.code.clone();
    let state = CsrfToken::new(query.state.clone());
    let slack_token_url = format!(
        "{}{}&code={}",
        TOKEN_URL,
        slack_auth_params.to_string(),
        code
    );
    if let Some(ref must_state) = session.get::<String>("csrf_state").unwrap() {
        if must_state != state.secret() {
            return Box::new(future::ok(
                HttpResponse::Found()
                    .header(http::header::LOCATION, "/e?identityAdded=error")
                    .finish(),
            ));
        }
    } else {
        return Box::new(future::ok(
            HttpResponse::Found()
                .header(http::header::LOCATION, "/e?identityAdded=error")
                .finish(),
        ));
    }
    let get = cis_client.clone();
    let get_uid = user_id.user_id.clone();
    return Box::new(
        Client::default()
            .get(slack_token_url)
            .header(http::header::USER_AGENT, "whoami")
            .send()
            .map_err(Into::into)
            .and_then(|mut res| res.json::<SlackTokenResponse>().map_err(Into::into))
            .and_then(move |j| {
                get.get_user_by(&get_uid, &GetBy::UserId, None)
                    .and_then(move |profile: Profile| {
                        update_slack(
                            format!("slack://user?team={}&id={}", j.team.id, j.user.id),
                            j.user.name,
                            profile,
                            get.get_secret_store(),
                        )
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
                    .header(http::header::LOCATION, "/e?identityAdded=slack")
                    .finish()
            }),
    );
}

pub fn slack_app<T: AsyncCisClientTrait + 'static>(
    slack: &Slack,
    whoami: &WhoAmI,
    secret: &[u8],
    ttl_cache: Arc<RwLock<TtlCache<String, String>>>,
    cis_client: T,
) -> impl HttpServiceFactory {
    let slack_client_id = ClientId::new(slack.client_id.clone());
    let slack_client_secret = ClientSecret::new(slack.client_secret.clone());
    let slack_auth_params = format!(
        "?client_id={}&client_secret={}&redirect_uri={}",
        &slack.client_id, &slack.client_secret, &slack.redirect_uri
    );
    let auth_url = AuthUrl::new(Url::parse(AUTH_URL).expect("Invalid authorization endpoint URL"));
    let token_url = TokenUrl::new(
        Url::parse(&format!("{}{}", TOKEN_URL, slack_auth_params))
            .expect("Invalid token endpoint URL"),
    );

    let client = Arc::new(
        BasicClient::new(
            slack_client_id,
            Some(slack_client_secret),
            auth_url,
            Some(token_url),
        )
        .add_scope(Scope::new(slack.scope.to_string()))
        .set_redirect_url(RedirectUrl::new(
            Url::parse(&slack.redirect_uri).expect("Invalid redirect URL"),
        )),
    );

    web::scope("/slack/")
        .wrap(
            Cors::new()
                .allowed_methods(vec!["GET", "POST"])
                .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                .allowed_header(http::header::CONTENT_TYPE)
                .max_age(3600),
        )
        .wrap(
            CookieSession::private(secret)
                .name("dpw_s")
                .path("/whoami/slack")
                .domain(whoami.domain.clone())
                .same_site(SameSite::Lax)
                .http_only(true)
                .secure(false)
                .max_age(300),
        )
        .data(client)
        .data(cis_client)
        .data(ttl_cache)
        .data(slack_auth_params)
        .service(web::resource("/add").route(web::get().to(redirect)))
        .service(web::resource("/auth").route(web::get().to_async(auth::<T>)))
}
