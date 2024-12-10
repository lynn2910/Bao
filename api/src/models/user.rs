use crate::authorization::Login;
use crate::Db;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rocket_db_pools::Connection;
use sqlx::{Executor, FromRow, SqliteConnection};
use std::ops::DerefMut;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub first_name: String,
    pub last_name: Option<String>,
    pub email: String,
    pub password: String,
}

impl User {
    /// Get the email and hashed password, and check if the user login is valid.
    ///
    /// Will return either the user or None if the login is invalid
    pub(crate) async fn login(data: &Login, mut db: Connection<Db>) -> Option<User> {
        let query = sqlx::query_as!(User, "SELECT * FROM users WHERE email = ?;", data.email);

        match db.fetch_one(query).await {
            Ok(row) => {
                let user = User::from_row(&row).expect("Failed to convert row to user");

                let parsed_hash = PasswordHash::new(&user.password);
                if parsed_hash.is_err() {
                    eprintln!("Failed to parse password hash");
                    return None;
                }

                Argon2::default()
                    .verify_password(data.hashed_password.as_bytes(), &parsed_hash.unwrap())
                    .ok()
                    .map(|_| user)
            }
            Err(_) => None,
        }
    }
}
