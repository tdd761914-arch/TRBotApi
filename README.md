# TRBotApi

TRBotApi is a small Telegram Bot API edge built on the zero-copy MTProto
primitives from [TRLib](https://github.com/tdd761914-arch/TRLib).  It keeps the
HTTP/JSON contract at the edge and leaves authorization-key storage, sockets,
DC routing and update scheduling behind a transport trait.  The core has no
`serde`, Tokio, SQLite or allocator requirement.

This repository is an early high-throughput foundation, not a claim that one
blocking process already replaces Telegram's complete hosted Bot API.  The
reference edge is intentionally simple; a production deployment should use an
evented acceptor, sharded bot registry and a persistent MTProto reactor.

## Layout

- `trbotapi-core` — `no_std` bounded Bot API request parsing, JSON responses,
  `auth.importBotAuthorization`, `users.getFullUser`, text `sendMessage`, and
  `rpc_result` extraction.  All buffers are supplied by the caller.
- `trbotapi-server` — a small `std` HTTP/1.1 reference edge, per-bot locking,
  bounded update queues and a `BotTransport` hook for an epoll/io_uring
  MTProto implementation.
- `trbotapi.conf` — deployment profile without secrets.

## Run the reference edge

The smoke profile answers `getMe` for one configured bot.  It does not print
the token and it refuses to invent a Telegram network session:

```bash
export TRBOTAPI_BOT_TOKEN='123456:replace-me'
export TRBOTAPI_BOT_ID=123456
export TRBOTAPI_BOT_USERNAME=example_bot
export TRBOTAPI_BOT_FIRST_NAME='Example Bot'
cargo run --release -p trbotapi-server
```

Then:

```bash
curl -sS -X POST \
  'http://127.0.0.1:8080/bot123456:replace-me/getMe' \
  -H 'content-type: application/json' -d '{}'
```

The route shape and response envelope follow the Bot API.  The current edge
implements bounded request shapes for `getMe`, text `sendMessage`,
`getUpdates`, `setWebhook`, `deleteWebhook`, `getWebhookInfo`,
`answerCallbackQuery`, and integer-id `getChat`.  `getUpdates` is currently a
local queue hook; a transport reactor must feed it from MTProto updates.

For a Test-DC smoke connection, provide API credentials and opt in explicitly:

```bash
export TRBOTAPI_API_ID=29806415
export TRBOTAPI_API_HASH='your-api-hash'
export TRBOTAPI_CONNECT_TEST_DC=1
cargo run --release -p trbotapi-server
```

The bundled transport uses TRLib's fixed Test-DC auth-key path. Production DC
key provisioning and a shared evented reactor remain deployment work.

## Connecting MTProto

The core serializes the MTProto methods directly through TRLib:

```rust
use trbotapi_core::{write_import_bot_authorization, write_get_me};

let mut body = [0u8; 512];
let import_len = write_import_bot_authorization(
    &mut body,
    api_id,
    api_hash,
    bot_token,
)?;
// Send `body[..import_len]` through a TRLib auth-key session.
let get_me_len = write_get_me(&mut body)?;
```

`auth.importBotAuthorization` is the MTProto bot-login method.  The server
application supplies the API credentials and the bot token; store the resulting
auth key in TRLib's encrypted session document rather than in this repository.

Implement `BotTransport` for the actual runtime:

```rust
impl BotTransport for MyMtprotoReactor {
    fn call(&mut self, method: &[u8], output: &mut [u8])
        -> trbotapi_core::Result<usize> {
        // Queue `method` in a TRLib encrypted session and render a Bot API
        // result object into `output` after rpc_result/update decoding.
        # todo!()
    }
}
```

The reference edge deliberately does not hide a blocking socket or one OS
thread per bot.  For hundreds of thousands of mostly idle bots, keep only the
encrypted session metadata in the registry and activate a connection on demand;
for active bots, shard reactors by bot/session hash.

## Compatibility boundary

This is not the TDLib compatibility branch.  TRLib's TDLib adapter now lives on
the separate [`tdlib-compat` branch](https://github.com/tdd761914-arch/TRLib/tree/tdlib-compat),
while the TRLib `main` branch used here stays free of that code.

The current TRBotApi request layer is intentionally a Bot API subset.  Before
calling it a production-compatible Bot API server, add:

1. a production MTProto transport with DC migration, reconnect, server-salt
   repair and auth-key/session loading;
2. Bot API `Update` conversion and durable offset queues for long polling and
   webhook exclusivity;
3. media upload/download and file-id storage;
4. rate-limit/error mapping (`FLOOD_WAIT`, `SLOWMODE_WAIT`, retry-after);
5. result differential tests against the current official Bot API;
6. TLS termination, token hashing/rotation, metrics and an independent audit.

## Size and verification

The release profile uses `opt-level = "z"`, LTO, one codegen unit and aborting
panics.  The no-std core is checked separately from the std server:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo check -p trbotapi-core --no-default-features --locked
cargo build --release --locked -p trbotapi-server
```

TRBotApi is MIT licensed.
