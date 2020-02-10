use crate::settings::GitHub;
use crate::settings::WhoAmI;
use crate::update::update_github;
use actix_cors::Cors;
use actix_session::CookieSession;
use actix_session::Session;
use actix_web::cookie::SameSite;
use actix_web::dev::HttpServiceFactory;
use actix_web::http;
use actix_web::web;
use actix_web::HttpResponse;
use actix_web::Responder;
use cis_client::getby::GetBy;
use cis_client::AsyncCisClientTrait;
use dino_park_gate::scope::ScopeAndUser;
use failure::Error;
use log::info;
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::AuthUrl;
use oauth2::AuthorizationCode;
use oauth2::ClientId;
use oauth2::ClientSecret;
use oauth2::CsrfToken;
use oauth2::RedirectUrl;
use oauth2::TokenResponse;
use oauth2::TokenUrl;
use reqwest::Client;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use ttl_cache::TtlCache;
use url::Url;

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";

const CACHE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Deserialize)]
pub struct Auth {
    code: String,
    state: String,
}

#[derive(Serialize)]
pub struct GitHubUsername {
    username: String,
}

#[derive(Deserialize)]
pub struct GitHubUser {
    id: i64,
    login: String,
    email: Option<String>,
    node_id: String,
}

async fn id_to_username(
    id: web::Path<String>,
    gtihub_auth_params: web::Data<GitHub>,
    cache: web::Data<Arc<RwLock<TtlCache<String, String>>>>,
) -> Result<HttpResponse, Error> {
    if let Some(username) = cache.read().ok().and_then(|c| c.get(&*id).cloned()) {
        info!("serving {} → {} from cache", &*id, &username);
        Ok(HttpResponse::Ok().json(GitHubUsername { username }))
    } else {
        let cache = Arc::clone(&*cache);
        let cache_id = (*id).clone();
        let res = Client::default()
            .get(&format!("{}/{}", USER_URL, id))
            .basic_auth(
                &gtihub_auth_params.client_id,
                Some(&gtihub_auth_params.client_secret),
            )
            .header(http::header::USER_AGENT, "whoami")
            .send()
            .await?;
        info!("status: {}", res.status());
        let user = res.json::<GitHubUser>().await?;
        if let Ok(mut c) = cache.write() {
            info!("caching {} → {}", &cache_id, &user.login);
            c.insert(cache_id, user.login.clone(), CACHE_DURATION);
        }
        Ok(HttpResponse::Ok().json(GitHubUsername {
            username: user.login,
        }))
    }
}

async fn redirect(client: web::Data<Arc<BasicClient>>, session: Session) -> impl Responder {
    let (authorize_url, csrf_state) = client.authorize_url(CsrfToken::new_random);
    info!("settting: {}", csrf_state.secret());
    session
        .set("csrf_state", csrf_state.secret().clone())
        .map(|_| {
            HttpResponse::Found()
                .header(http::header::LOCATION, authorize_url.to_string())
                .finish()
        })
}

async fn auth<T: AsyncCisClientTrait + 'static>(
    client: web::Data<Arc<BasicClient>>,
    scope_and_user: ScopeAndUser,
    cis_client: web::Data<T>,
    query: web::Query<Auth>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let code = AuthorizationCode::new(query.code.clone());
    let state = CsrfToken::new(query.state.clone());
    info!("remote: {}", state.secret());
    if let Some(ref must_state) = session.get::<String>("csrf_state").unwrap() {
        info!("session: {}", must_state);
        if must_state != state.secret() {
            return Ok(HttpResponse::Found()
                .header(http::header::LOCATION, "/e?identityAdded=error")
                .finish());
        }
    } else {
        return Ok(HttpResponse::Found()
            .header(http::header::LOCATION, "/e?identityAdded=error")
            .finish());
    }
    let token_res = client.exchange_code(code);

    if let Ok(token) = token_res {
        let get = cis_client.clone();
        let get_uid = scope_and_user.user_id.clone();
        let res = Client::default()
            .get(USER_URL)
            .bearer_auth(token.access_token().secret())
            .header(http::header::USER_AGENT, "whoami")
            .send()
            .await?;
        info!("status: {}", res.status());
        let j = res.json::<GitHubUser>().await?;
        info!("login: {}, id: {}", j.login, j.node_id);
        let profile = get.get_user_by(&get_uid, &GetBy::UserId, None).await?;
        let profile = update_github(
            j.node_id,
            format!("{}", j.id),
            j.email,
            j.login,
            profile,
            get.get_secret_store(),
        )?;
        cis_client
            .update_user(&scope_and_user.user_id, profile)
            .await?;
        return Ok(HttpResponse::Found()
            .header(http::header::LOCATION, "/e?identityAdded=github")
            .finish());
    }
    Ok(HttpResponse::Found()
        .header(http::header::LOCATION, "/e?identityAdded=error")
        .finish())
}

pub fn github_app<T: AsyncCisClientTrait + 'static>(
    github: &GitHub,
    whoami: &WhoAmI,
    secret: &[u8],
    ttl_cache: Arc<RwLock<TtlCache<String, String>>>,
    cis_client: T,
) -> impl HttpServiceFactory {
    let github_client_id = ClientId::new(github.client_id.clone());
    let github_client_secret = ClientSecret::new(github.client_secret.clone());
    let auth_url = AuthUrl::new(Url::parse(AUTH_URL).expect("Invalid authorization endpoint URL"));
    let token_url = TokenUrl::new(Url::parse(TOKEN_URL).expect("Invalid token endpoint URL"));

    let client = Arc::new(
        BasicClient::new(
            github_client_id,
            Some(github_client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_url(RedirectUrl::new(
            Url::parse(&format!("https://{}/whoami/github/auth", whoami.domain))
                .expect("Invalid redirect URL"),
        )),
    );

    web::scope("/github/")
        .wrap(
            Cors::new()
                .allowed_methods(vec!["GET", "POST"])
                .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                .allowed_header(http::header::CONTENT_TYPE)
                .max_age(3600)
                .finish(),
        )
        .wrap(
            CookieSession::private(secret)
                .name("dpw_gh")
                .path("/whoami/github")
                .domain(whoami.domain.clone())
                .same_site(SameSite::Lax)
                .http_only(true)
                .secure(false)
                .max_age(300),
        )
        .data(client)
        .data(cis_client)
        .data(ttl_cache)
        .data(github.clone())
        .service(web::resource("/add").route(web::get().to(redirect)))
        .service(web::resource("/auth").route(web::get().to(auth::<T>)))
        .service(web::resource("/username/{id}").route(web::get().to(id_to_username)))
}
