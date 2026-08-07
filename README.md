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
  the current 185-method [Bot API catalogue](https://core.telegram.org/bots/api#available-methods),
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

The route shape and response envelope follow the Bot API.  All 185 current
method names are recognized case-insensitively.  The eight hot-path methods
(`getMe`, text `sendMessage`, `getUpdates`, `setWebhook`, `deleteWebhook`,
`getWebhookInfo`, `answerCallbackQuery`, and integer-id `getChat`) have bounded
typed parsing in the core.  The remaining methods are passed as borrowed JSON
to `BotTransport::call_bot_api`, so an embedding MTProto reactor can add a
mapping without changing the HTTP edge. `getUpdates` is currently a local
queue hook; a transport reactor must feed it from MTProto updates.

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

    fn call_bot_api(&mut self, method: &str, body: &[u8], output: &mut [u8])
        -> trbotapi_core::Result<usize> {
        // Map any of the 185 catalogued Bot API methods to TL and render the
        // result object directly into `output`.
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

The request layer recognizes the complete current method catalogue. The bundled
Test-DC transport has direct mappings for login, `getMe`/text `sendMessage`,
logout/close, message delete/forward/copy/edit/reaction, chat actions, and the
basic-group title/description/pin/leave/member-count subset. The remaining
media, sticker, payment, inline, business, passport and story methods are
forwarded to the transport hook but still require their method-specific TL and
Bot API result mappings. Before calling it a production-compatible Bot API
server, add:

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

### Recorded smoke benchmark

The following numbers were recorded on the development container on 2026-08-07
with the release profile above. They are a reference-edge measurement, not a
capacity promise for a production Bot API deployment:

| Check | Result |
| --- | ---: |
| `target/release/trbotapi-server` file size | 463,696 bytes |
| ELF `text + data + bss` (`size`) | 449,102 bytes |
| 20 sequential `getMe` POSTs, 2 workers, local loopback | 1.149 s |
| Same run, mean/request | 57.46 ms |
| Same run, requests/second | 17.40 |

The HTTP run used one fresh `curl` connection per request and the static
`getMe` profile, so it measures parsing, routing and response writing only; it
does not include Telegram network latency or MTProto encryption. Reproduce it
with the following command after starting the server on port `18080`:

```bash
start=$(date +%s%N); i=0
while [ "$i" -lt 20 ]; do
  curl --max-time 2 --no-keepalive -fsS -o /dev/null \
    -X POST 'http://127.0.0.1:18080/bot123456:replace-me/getMe' \
    -H 'content-type: application/json' -d '{}'
  i=$((i + 1))
done
end=$(date +%s%N)
awk -v n=20 -v ns="$((end - start))" \
  'BEGIN { printf "%.2f req/s, %.2f ms/request\n", n/(ns/1e9), ns/n/1e6 }'
```

For a live Telegram Test-DC run, supply a disposable test bot token and opt in
to the bundled transport. This benchmark is intentionally not run with a
credential stored in the repository:

```bash
export TRBOTAPI_API_ID=29806415
export TRBOTAPI_API_HASH='your-api-hash'
export TRBOTAPI_BOT_TOKEN='test-bot-token'
export TRBOTAPI_CONNECT_TEST_DC=1
time cargo run --release -p trbotapi-server
```

The command must complete `auth.importBotAuthorization` before serving HTTP;
record its wall time and then benchmark `getMe`/`sendMessage` against the
running edge. Production DC routing and a long-lived MTProto reactor are not
included in this Test-DC smoke path.

TRBotApi is MIT licensed.
