// DEBT: A warning for `ApiError`. `failure` is unmaintained, and I think we
// should move to using `thiserror`.
// Quoting the lint:
//
//  warning: non-local `impl` definition, `impl` blocks should be written
//  at the same level as their item
#![allow(non_local_definitions)]

use actix_web::error::ResponseError;
use actix_web::HttpResponse;
use cis_client::error::CisClientError;
use dino_park_trust::GroupsTrustError;
use dino_park_trust::TrustError;
use failure::Fail;
use log::warn;
use serde_json::json;
use serde_json::Value;
use std::fmt::Display;

#[derive(Fail, Debug)]
pub enum ApiError {
    #[fail(display = "Unknown error occurred.")]
    Unknown,
    #[fail(display = "Bad API request.")]
    GenericBadRequest(failure::Error),
    #[fail(display = "Scope Error: {}", _0)]
    ScopeError(TrustError),
    #[fail(display = "Groups scope Error: {}", _0)]
    GroupsScopeError(GroupsTrustError),
    #[fail(display = "CIS client error: {}", _0)]
    CisClient(CisClientError),
}

fn to_json_error(e: &impl Display) -> Value {
    json!({ "error": e.to_string() })
}

impl From<TrustError> for ApiError {
    fn from(e: TrustError) -> Self {
        ApiError::ScopeError(e)
    }
}

impl From<GroupsTrustError> for ApiError {
    fn from(e: GroupsTrustError) -> Self {
        ApiError::GroupsScopeError(e)
    }
}

impl From<failure::Error> for ApiError {
    fn from(e: failure::Error) -> Self {
        ApiError::GenericBadRequest(e)
    }
}

impl From<CisClientError> for ApiError {
    fn from(e: CisClientError) -> Self {
        ApiError::CisClient(e)
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            Self::GenericBadRequest(ref e) => {
                warn!("{}", e);
                HttpResponse::BadRequest().finish()
            }
            Self::ScopeError(ref e) => HttpResponse::Forbidden().json(to_json_error(e)),
            Self::GroupsScopeError(ref e) => HttpResponse::Forbidden().json(to_json_error(e)),
            _ => HttpResponse::InternalServerError().finish(),
        }
    }
}
