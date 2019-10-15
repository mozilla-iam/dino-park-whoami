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
use serde_json::json;
use std::sync::Arc;
use url::Url;

const AUTH_URL: &str = "https://slack.com/oauth/authorize";
const TOKEN_URL: &str = "https://slack.com/api/oauth.access";
const OPEN_DM_URL: &str = "https://slack.com/api/im.open";
const USERS_IDENTITY_URL: &str = "https://slack.com/api/users.identity";

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

impl Clone for SlackUser {
    fn clone(&self) -> SlackUser {
        SlackUser {
            name: self.name.to_string(),
            id: self.id.to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SlackIDData {
    id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackChannelUserData {
    channel: SlackIDData,
    user: SlackUser,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackUserTokenData {
    token: String,
    user: SlackUser,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackUriData {
    slack_auth_params: String,
    direct_message_uri: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SlackIMResponse {
    ok: bool,
    channel: SlackIDData,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SlackTokenResponse {
    ok: bool,
    access_token: String,
    scope: String,
    user_id: String,
    team_id: String,
    team_name: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SlackUserResponse {
    ok: bool,
    user: SlackUser,
    team: SlackIDData,
}

#[derive(Debug)]
pub struct SlackClientHandlers {
    im: Arc<BasicClient>,
    identity: Arc<BasicClient>,
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
fn redirect_identity(client: web::Data<SlackClientHandlers>, session: Session) -> impl Responder {
    let (authorize_url, csrf_state) = client.identity.authorize_url(CsrfToken::new_random);
    session
        .set("identity_csrf_state", csrf_state.secret().clone())
        .map(|_| send_response(&authorize_url.to_string()))
}

/**
 * Second redirect that handles getting authorization for opening a channel for a direct message
 */
fn redirect_im(
    client: web::Data<SlackClientHandlers>,
    session: Session,
    query: web::Query<Auth>,
) -> impl Responder {
    let (authorize_url, csrf_state) = client.im.authorize_url(CsrfToken::new_random);
    let state = CsrfToken::new(query.state.clone());
    if let Some(ref must_state) = session.get::<String>("identity_csrf_state").unwrap() {
        if must_state != state.secret() {
            return session
                .set("im_csrf_state", "")
                .map(|_| send_error_response());
        }
    } else {
        return session
            .set("im_csrf_state", "")
            .map(|_| send_error_response());
    }
    session
        .set("im_csrf_state", csrf_state.secret().clone())
        .map(|_| send_response(&authorize_url.to_string()))
}

fn auth<T: AsyncCisClientTrait + 'static>(
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
        slack_uri_data.slack_auth_params,
        query.code.clone()
    );

    // Check state token from im_crsf_state
    if let Some(ref must_state) = session.get::<String>("im_csrf_state").unwrap() {
        if must_state != state.secret() {
            return Box::new(future::ok(send_error_response()));
        }
    } else {
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
            .and_then(move |mut res| res.json::<SlackTokenResponse>().map_err(Into::into))
            .and_then(move |j| {
                let user_uri = format!("{}?token={}", USERS_IDENTITY_URL, j.access_token.clone());
                // Now that we have the access_token, go get the user data: name, id
                Client::default()
                    .get(user_uri)
                    .header("Content-type", "application/json; charset=utf-8")
                    .header(
                        "Authorization",
                        format!("Bearer {}", j.access_token.clone()),
                    )
                    .send()
                    .map_err(Into::into)
                    .and_then(move |mut s| s.json::<SlackUserResponse>().map_err(Into::into))
                    .and_then(move |sur| {
                        Ok(SlackUserTokenData {
                            token: j.access_token,
                            user: sur.user,
                        })
                    })
            })
            .and_then(move |sutd| {
                // Now that we have the access_token and user data, go open a direct message channel and save the channel id
                Client::default()
                    .post(OPEN_DM_URL)
                    .header("Content-type", "application/json; charset=utf-8")
                    .header("Authorization", format!("Bearer {}", sutd.token))
                    .send_json(&json!({
                        "token": sutd.token.clone(),
                        "user": sutd.user.id.clone(),
                    }))
                    .map_err(Into::into)
                    .and_then(move |mut s| s.json::<SlackIMResponse>().map_err(Into::into))
                    .and_then(move |simr| {
                        Ok(SlackChannelUserData {
                            channel: simr.channel,
                            user: sutd.user,
                        })
                    })
            })
            .and_then(move |scu_data| {
                // Now that we have the access_token, user data, and channel id, go put it in the profile
                get.get_user_by(&get_uid, &GetBy::UserId, None)
                    .and_then(move |profile: Profile| {
                        update_slack(
                            format!(
                                "{}{}",
                                slack_uri_data.direct_message_uri, scu_data.channel.id
                            ),
                            scu_data.user.name.clone(),
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
    let im_slack_auth_params = format!(
        "?client_id={}&client_secret={}&redirect_uri={}",
        &slack.client_id, &slack.client_secret, &slack.im_redirect_uri
    );
    let auth_url = AuthUrl::new(Url::parse(AUTH_URL).expect("Invalid authorization endpoint URL"));
    let identity_token_url = TokenUrl::new(
        Url::parse(&format!("{}{}", TOKEN_URL, identity_slack_auth_params))
            .expect("Invalid token endpoint URL"),
    );
    let im_token_url = TokenUrl::new(
        Url::parse(&format!("{}{}", TOKEN_URL, im_slack_auth_params))
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
    let im_client = Arc::new(
        BasicClient::new(
            slack_client_id,
            Some(slack_client_secret),
            auth_url,
            Some(im_token_url),
        )
        .add_scope(Scope::new(slack.im_scope.clone()))
        .set_redirect_url(RedirectUrl::new(
            Url::parse(&slack.im_redirect_uri).expect("Invalid redirect URL"),
        )),
    );
    let client_data_handlers: SlackClientHandlers = SlackClientHandlers {
        im: im_client,
        identity: identity_client,
    };
    let slack_uri_data: SlackUriData = SlackUriData {
        slack_auth_params: im_slack_auth_params,
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
        .data(client_data_handlers)
        .data(cis_client)
        .data(slack_uri_data)
        .service(web::resource("/add").route(web::get().to(redirect_identity)))
        .service(web::resource("/add/im").route(web::get().to(redirect_im)))
        .service(web::resource("/auth").route(web::get().to_async(auth::<T>)))
}
