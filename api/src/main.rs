use crate::authorization::generate_password;
use rocket::fairing::AdHoc;
use rocket::serde::Serialize;
use rocket::{error, fairing, Build, Rocket};
use rocket_db_pools::Database;
use serde::Deserialize;

mod authorization;
mod models;

#[derive(Database)]
#[database("core")]
pub struct Db(sqlx::SqlitePool);

async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    // run the migrations
    match Db::fetch(&rocket) {
        Some(db) => match sqlx::migrate!("db/migrations").run(&**db).await {
            Ok(_) => Ok(rocket),
            Err(e) => {
                error!("Failed to run database migrations: {}", e);
                Err(rocket)
            }
        },
        None => Err(rocket),
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    auth: AuthConfig,
}
#[derive(Serialize, Deserialize, Debug)]
struct AuthConfig {
    secret_key: String,
}

#[tokio::main]
async fn main() {
    let config = {
        let raw_config = std::fs::read_to_string("config.toml").unwrap_or(String::new());
        match toml::from_str::<Config>(&raw_config) {
            Ok(config) => config,
            Err(e) => panic!(
                "Failed to parse config.toml: {}. Please check the file for errors.",
                e
            ),
        }
    };

    let migrations_fairing = AdHoc::try_on_ignite("SQLx Migrations", run_migrations);
    let api = rocket::build()
        .manage(config)
        .attach(Db::init())
        .attach(migrations_fairing)
        .mount("/hub", authorization::get_routes());

    api.launch().await.expect("API launch failed");
}
