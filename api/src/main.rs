use rocket::fairing::AdHoc;
use rocket::{error, fairing, Build, Rocket};
use rocket_db_pools::Database;

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

#[tokio::main]
async fn main() {
    let migrations_fairing = AdHoc::try_on_ignite("SQLx Migrations", run_migrations);
    let api = rocket::build()
        .attach(Db::init())
        .attach(migrations_fairing);

    api.launch().await.expect("API launch failed");
}
