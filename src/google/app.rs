use crate::error::ApiError;
use crate::settings::Google;
use crate::settings::WhoAmI;
use crate::update::update_google;
use actix_session::CookieSession;
use actix_session::Session;
use actix_web::cookie::SameSite;
use actix_web::dev::HttpServiceFactory;
use actix_web::http;
use actix_web::web;
use actix_web::HttpResponse;
use actix_web::Responder;
use biscuit::ClaimsSet;
use biscuit::StringOrUri;
use cis_client::getby::GetBy;
use cis_client::AsyncCisClientTrait;
use dino_park_gate::provider::Provider;
use dino_park_gate::scope::ScopeAndUser;
use failure::Error;
use log::info;
use oauth2::basic::*;
use oauth2::reqwest::async_http_client;
use oauth2::AsyncCodeTokenRequest;
use oauth2::AuthUrl;
use oauth2::AuthorizationCode;
use oauth2::ClientId;
use oauth2::ClientSecret;
use oauth2::CsrfToken;
use oauth2::ExtraTokenFields;
use oauth2::RedirectUrl;
use oauth2::Scope;
use oauth2::StandardTokenResponse;
use oauth2::TokenUrl;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::convert::TryFrom;
use std::sync::Arc;

type GoogleOauthClient = oauth2::Client<
    BasicErrorResponse,
    StandardTokenResponse<IdToken, BasicTokenType>,
    BasicTokenType,
>;

#[derive(Deserialize, Serialize, Clone, Debug)]
struct IdToken {
    id_token: String,
}

impl ExtraTokenFields for IdToken {}

#[derive(Deserialize)]
struct Auth {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GoogleUser {
    id: String,
    email: String,
}

impl TryFrom<ClaimsSet<Value>> for GoogleUser {
    type Error = ApiError;
    fn try_from(mut cs: ClaimsSet<Value>) -> Result<Self, Self::Error> {
        let id = match cs.registered.subject {
            Some(StringOrUri::String(s)) => s,
            _ => return Err(ApiError::ProviderError),
        };
        let email = match cs.private["email"].take() {
            Value::String(s) => s,
            _ => return Err(ApiError::ProviderError),
        };
        Ok(GoogleUser { id, email })
    }
}

async fn redirect(client: web::Data<Arc<GoogleOauthClient>>, session: Session) -> impl Responder {
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .url();
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
    client: web::Data<Arc<GoogleOauthClient>>,
    scope_and_user: ScopeAndUser,
    cis_client: web::Data<T>,
    query: web::Query<Auth>,
    session: Session,
    provider: web::Data<Arc<Provider>>,
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
    let token_res = client
        .exchange_code(code)
        .request_async(async_http_client)
        .await;

    if let Ok(token) = token_res {
        let id_token = token.extra_fields();
        let id_token = provider
            .verify_and_decode(id_token.id_token.clone())
            .await?;
        let google_user = GoogleUser::try_from(id_token)?;
        let get = cis_client.clone();
        let get_uid = scope_and_user.user_id.clone();
        let profile = get.get_user_by(&get_uid, &GetBy::UserId, None).await?;
        let profile = update_google(
            google_user.id,
            google_user.email,
            profile,
            get.get_secret_store(),
        )?;
        cis_client
            .update_user(&scope_and_user.user_id, profile)
            .await?;
        return Ok(HttpResponse::Found()
            .header(http::header::LOCATION, "/e?identityAdded=google")
            .finish());
    }
    Ok(HttpResponse::Found()
        .header(http::header::LOCATION, "/e?identityAdded=error")
        .finish())
}

pub fn google_app<T: AsyncCisClientTrait + 'static>(
    google: &Google,
    provider: Provider,
    whoami: &WhoAmI,
    secret: &[u8],
    cis_client: T,
) -> impl HttpServiceFactory {
    let google_client_id = ClientId::new(google.client_id.clone());
    let google_client_secret = ClientSecret::new(google.client_secret.clone());
    let auth_url =
        AuthUrl::new(provider.auth_url.to_string()).expect("Invalid authorization endpoint URL");
    let token_url =
        TokenUrl::new(provider.token_url.to_string()).expect("Invalid token endpoint URL");
    let redirect_url = RedirectUrl::new(format!("https://{}/whoami/google/auth", whoami.domain))
        .expect("Invalid redirect URL");

    let client = Arc::new(
        GoogleOauthClient::new(
            google_client_id,
            Some(google_client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_url(redirect_url),
    );

    web::scope("/google/")
        .wrap(
            CookieSession::private(secret)
                .name("dpw_gg")
                .path("/whoami/google")
                .domain(whoami.domain.clone())
                .same_site(SameSite::Lax)
                .http_only(true)
                .secure(true)
                .max_age(300),
        )
        .data(client)
        .data(cis_client)
        .data(Arc::new(provider))
        .service(web::resource("/add").route(web::get().to(redirect)))
        .service(web::resource("/auth").route(web::get().to(auth::<T>)))
}
