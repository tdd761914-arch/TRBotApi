use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use trbotapi_server::{BotEntry, BotInfo, BotRegistry, HttpConfig, HttpServer, TestDcTransport};

fn main() {
    let bind = env::var("TRBOTAPI_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse::<SocketAddr>()
        .expect("TRBOTAPI_BIND must be host:port");
    let workers = env::var("TRBOTAPI_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| HttpConfig::default().workers);

    let registry = Arc::new(BotRegistry::new());
    if let Ok(token) = env::var("TRBOTAPI_BOT_TOKEN") {
        let id = env::var("TRBOTAPI_BOT_ID")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let first_name = env::var("TRBOTAPI_BOT_FIRST_NAME").unwrap_or_else(|_| "TR Bot".into());
        let username = env::var("TRBOTAPI_BOT_USERNAME").ok();
        let mut entry = BotEntry::new(BotInfo {
            id,
            first_name,
            username,
        });
        if env::var_os("TRBOTAPI_CONNECT_TEST_DC").is_some() {
            let api_id = env::var("TRBOTAPI_API_ID")
                .expect("TRBOTAPI_API_ID is required with TRBOTAPI_CONNECT_TEST_DC")
                .parse::<i32>()
                .expect("TRBOTAPI_API_ID must be an integer");
            let api_hash = env::var("TRBOTAPI_API_HASH")
                .expect("TRBOTAPI_API_HASH is required with TRBOTAPI_CONNECT_TEST_DC");
            let address = env::var("TRBOTAPI_TEST_DC")
                .unwrap_or_else(|_| "149.154.167.40:80".into())
                .parse::<SocketAddr>()
                .expect("TRBOTAPI_TEST_DC must be host:port");
            eprintln!("connecting bot session to Test DC at {address}");
            let transport = TestDcTransport::connect(api_id, &api_hash, &token, address)
                .expect("Test DC bot authorization failed")
                .with_bot_id(id);
            entry = entry.with_transport(Box::new(transport));
        }
        registry.register(token, entry);
    }

    eprintln!("TRBotApi listening on {bind} with {workers} workers");
    if registry.is_empty() {
        eprintln!("no bot token configured; set TRBOTAPI_BOT_TOKEN for the smoke profile");
    }
    let server = HttpServer::new(HttpConfig { bind, workers }, registry);
    if let Err(error) = server.run() {
        eprintln!("TRBotApi: {error}");
        std::process::exit(1);
    }
}
