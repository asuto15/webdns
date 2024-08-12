mod dns;

use axum::{
    routing::{get},
    Router,
};

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let app = Router::new()
        .route("/", get(root))
        .route("/resolve", get(resolve));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    println!("Hello, world!");
    "Hello, World!"
}

async fn resolve() -> String {
    match dns::resolve_dns_query("google.com").await {
        Ok(addresses) => format!("Resolved addresses: {:?}", addresses),
        Err(e) => format!("Error resolving DNS: {}", e),
    }
}
