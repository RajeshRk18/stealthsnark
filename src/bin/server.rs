use std::sync::Arc;
use tokio::sync::RwLock;

use stealthsnark::protocol::server::{create_router, ServerState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(RwLock::new(ServerState::new()));
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind to port 3000");

    tracing::info!("StealthSnark server listening on :3000");
    axum::serve(listener, app)
        .await
        .expect("server error");
}
