use crate::models::user::User;
use crate::{Config, Db};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use rocket::http::Status;
use rocket::log::private::error;
use rocket::serde::json::Json;
use rocket::{post, routes, State};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::ops::Add;

pub(crate) fn generate_password(password: &[u8]) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    Ok(argon2.hash_password(password, &salt)?.to_string())
}

/// This structure contains all information stored in the token
#[derive(Serialize, Deserialize, Debug)]
struct Validation {
    creation: DateTime<Utc>,
    user_id: String,
    valid_until: DateTime<Utc>,
}

fn generate_token(user: &User, secret_key: &str) -> Option<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret_key.as_bytes()).unwrap();
    let mut claims = std::collections::BTreeMap::new();
    claims.insert("creation", Utc::now().to_string());
    // Validity: 12h
    claims.insert(
        "valid_until",
        Utc::now().add(TimeDelta::hours(12)).to_string(),
    );
    claims.insert("user_id", user.id.clone());

    match claims.sign_with_key(&key) {
        Ok(token) => Some(token),
        Err(e) => {
            error!("Failed to generate token: {}", e);
            None
        }
    }
}

#[derive(Deserialize, Debug)]
pub(crate) struct Login {
    pub email: String,
    pub hashed_password: String,
}

#[derive(Serialize, Debug)]
struct LoginOkResult {
    token: String,
}

#[post("/login", format = "application/json", data = "<login>")]
async fn login_route(
    login: Json<Login>,
    db: Connection<Db>,
    config: &State<Config>,
) -> Result<Json<LoginOkResult>, Status> {
    match User::login(&login.0, db).await {
        Some(user) => {
            let token = generate_token(&user, &config.auth.secret_key);
            if token.is_none() {
                return Err(Status::InternalServerError);
            }
            let token = token.unwrap();

            Ok(Json(LoginOkResult { token }))
        }
        None => Err(Status::Unauthorized),
    }
}

#[derive(Debug)]
pub struct Authorization(pub String);

pub fn get_routes() -> Vec<rocket::Route> {
    routes![login_route]
}
