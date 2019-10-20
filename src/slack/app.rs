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

const AUTH_URL: &str = "https://slack.com/oauth/authorize";
const TOKEN_URL: &str = "https://slack.com/api/oauth.access";

#[derive(Deserialize)]
pub struct Auth {
    code: String,
    state: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SlackUser {
    name: String,
    id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackUriData {
    identity_slack_auth_params: String,
    direct_message_uri: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SlackUserTokenResponse {
    ok: bool,
    access_token: String,
    scope: String,
    user_id: String,
    team_id: String,
    user: SlackUser,
}

fn send_response(url: &str) -> HttpResponse {
    HttpResponse::Found()
        .header(http::header::LOCATION, url)
        .finish()
}

fn send_error_response() -> HttpResponse {
    send_response("/e?identityAdded=error")
}

/**
 * First redirect that handles getting authorization for identity scopes
 */
fn redirect_identity(client: web::Data<Arc<BasicClient>>, session: Session) -> impl Responder {
    let (authorize_url, csrf_state) = client.authorize_url(CsrfToken::new_random);
    session
        .set("identity_csrf_state", csrf_state.secret().clone())
        .map(|_| send_response(&authorize_url.to_string()))
}

fn auth_identity<T: AsyncCisClientTrait + 'static>(
    cis_client: web::Data<T>,
    user_id: UserId,
    query: web::Query<Auth>,
    slack_uri_data: web::Data<SlackUriData>,
    session: Session,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let state = CsrfToken::new(query.state.clone());
    let slack_token_url = format!(
        "{}{}&code={}",
        TOKEN_URL,
        slack_uri_data.identity_slack_auth_params,
        query.code.clone()
    );
    // Check state token from im_crsf_state
    if let Some(ref must_state) = session.get::<String>("identity_csrf_state").unwrap() {
        if must_state != state.secret() {
            println!("Error: Identity csrf state mismatch");
            return Box::new(future::ok(send_error_response()));
        }
    } else {
        println!("Error: Missing identity csrf state");
        return Box::new(future::ok(send_error_response()));
    }

    let get = cis_client.clone();
    let get_uid = user_id.user_id.clone();
    // Begin slack requests by grabbing the user_id, and access_token
    Box::new(
        Client::default()
            .get(slack_token_url)
            .header(http::header::USER_AGENT, "whoami")
            .send()
            .map_err(Into::into)
            .and_then(move |mut res| res.json::<SlackUserTokenResponse>().map_err(Into::into))
            .and_then(move |sur| {
                // Now that we have the access_token, user data, and channel id, go put it in the profile
                get.get_user_by(&get_uid, &GetBy::UserId, None)
                    .and_then(move |profile: Profile| {
                        update_slack(
                            format!(
                                "{}?channel={}&team={}",
                                slack_uri_data.direct_message_uri, sur.user_id, sur.team_id
                            ),
                            sur.user.name.clone(),
                            profile,
                            get.get_secret_store(),
                        )
                        .into_future()
                        .map_err(Into::into)
                    })
                    .map_err(Into::into)
            })
            .and_then(move |profile: Profile| {
                // Now finally save the updated user profile
                cis_client
                    .update_user(&user_id.user_id, profile)
                    .map_err(Into::into)
            })
            .and_then(|_| send_response("/e?identityAdded=slack")),
    )
}

pub fn slack_app<T: AsyncCisClientTrait + 'static>(
    slack: &Slack,
    whoami: &WhoAmI,
    secret: &[u8],
    cis_client: T,
) -> impl HttpServiceFactory {
    let slack_client_id = ClientId::new(slack.client_id.clone());
    let slack_client_secret = ClientSecret::new(slack.client_secret.clone());
    let identity_slack_auth_params = format!(
        "?client_id={}&client_secret={}&redirect_uri={}",
        &slack.client_id, &slack.client_secret, &slack.identity_redirect_uri
    );
    let auth_url = AuthUrl::new(Url::parse(AUTH_URL).expect("Invalid authorization endpoint URL"));
    let identity_token_url = TokenUrl::new(
        Url::parse(&format!("{}{}", TOKEN_URL, identity_slack_auth_params))
            .expect("Invalid token endpoint URL"),
    );
    let identity_client = Arc::new(
        BasicClient::new(
            slack_client_id.clone(),
            Some(slack_client_secret.clone()),
            auth_url.clone(),
            Some(identity_token_url),
        )
        .add_scope(Scope::new(slack.identity_scope.clone()))
        .set_redirect_url(RedirectUrl::new(
            Url::parse(&slack.identity_redirect_uri).expect("Invalid redirect URL"),
        )),
    );
    let slack_uri_data: SlackUriData = SlackUriData {
        identity_slack_auth_params,
        direct_message_uri: slack.direct_message_uri.clone(),
    };

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
        .data(identity_client)
        .data(cis_client)
        .data(slack_uri_data)
        .service(web::resource("/add").route(web::get().to(redirect_identity)))
        .service(web::resource("/auth/identity").route(web::get().to_async(auth_identity::<T>)))
}
