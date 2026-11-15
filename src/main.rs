use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{FromRequestParts, Path, State},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    routing::{get, post},
    Json, Router,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, SqlitePool};
use std::time::{SystemTime, UNIX_EPOCH};

const JWT_SECRET: &[u8] = b"change-this-secret-later";

#[derive(Serialize, FromRow)]
struct Task {
    id: i64,
    title: String,
    done: bool,
}

#[derive(Deserialize)]
struct NewTask {
    title: String,
}

#[derive(Deserialize)]
struct UpdateTask {
    title: Option<String>,
    done: Option<bool>,
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(FromRow)]
struct UserRow {
    id: i64,
    password_hash: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    user_id: i64,
    exp: usize,
}

struct AuthUser {
    id: i64,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(AuthUser { id: data.claims.user_id })
    }
}

#[tokio::main]
async fn main() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite://tasks.db?mode=rwc")
        .await
        .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL,
            done BOOLEAN NOT NULL DEFAULT 0
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/tasks", post(create_task).get(list_tasks))
        .route("/tasks/{id}", get(get_task).put(update_task).delete(delete_task))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn register(
    State(pool): State<SqlitePool>,
    Json(input): Json<Credentials>,
) -> Result<StatusCode, StatusCode> {
    if input.username.trim().is_empty() || input.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(input.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(input.username)
        .bind(hash)
        .execute(&pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;
    Ok(StatusCode::CREATED)
}

async fn login(
    State(pool): State<SqlitePool>,
    Json(input): Json<Credentials>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, password_hash FROM users WHERE username = ?",
    )
    .bind(input.username)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    let parsed = PasswordHash::new(&user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Argon2::default()
        .verify_password(input.password.as_bytes(), &parsed)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let exp = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 86400) as usize;
    let token = encode(
        &Header::default(),
        &Claims { user_id: user.id, exp },
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(TokenResponse { token }))
}

async fn create_task(
    user: AuthUser,
    State(pool): State<SqlitePool>,
    Json(input): Json<NewTask>,
) -> Result<(StatusCode, Json<Task>), StatusCode> {
    if input.title.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let task = sqlx::query_as::<_, Task>(
        "INSERT INTO tasks (user_id, title) VALUES (?, ?) RETURNING id, title, done",
    )
    .bind(user.id)
    .bind(input.title)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::CREATED, Json(task)))
}

async fn list_tasks(
    user: AuthUser,
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<Task>>, StatusCode> {
    let tasks = sqlx::query_as::<_, Task>(
        "SELECT id, title, done FROM tasks WHERE user_id = ?",
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(tasks))
}

async fn get_task(
    user: AuthUser,
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
) -> Result<Json<Task>, StatusCode> {
    sqlx::query_as::<_, Task>(
        "SELECT id, title, done FROM tasks WHERE id = ? AND user_id = ?",
    )
    .bind(id)
    .bind(user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map(Json)
    .ok_or(StatusCode::NOT_FOUND)
}

async fn update_task(
    user: AuthUser,
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    Json(input): Json<UpdateTask>,
) -> Result<Json<Task>, StatusCode> {
    sqlx::query_as::<_, Task>(
        "UPDATE tasks SET title = COALESCE(?, title), done = COALESCE(?, done)
         WHERE id = ? AND user_id = ? RETURNING id, title, done",
    )
    .bind(input.title)
    .bind(input.done)
    .bind(id)
    .bind(user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map(Json)
    .ok_or(StatusCode::NOT_FOUND)
}

async fn delete_task(
    user: AuthUser,
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM tasks WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user.id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result.rows_affected() == 0 {
        Err(StatusCode::NOT_FOUND)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}