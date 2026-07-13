mod config;
mod packets;

use std::{
    any::type_name,
    backtrace::Backtrace,
    borrow::Cow,
    collections::HashMap,
    io::{Cursor, ErrorKind},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use mc_protocol::{
    packet::{PacketError, PacketId, RawPacket, UncompressedPacket},
    ser::{Deserialize, SerializationError, Serialize},
    varint::{VarInt, VarIntError},
};
use snafu::{ErrorCompat, OptionExt, ResultExt, Snafu, Whatever, ensure};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{error::Elapsed, timeout},
};
use tracing::{Instrument, error, info, trace, warn};
use tracing_subscriber::fmt::time::UtcTime;

use crate::{
    config::{Config, Destination, StatusConfig},
    packets::{
        C2SPluginMessage, ClientInformation, Handshake, LoginDisconnect, LoginStart, LoginSuccess,
        PingPong, S2CStatusResponse, Transfer,
    },
};

fn proxy_error_is_eof(err: &ProxyError) -> bool {
    match err {
        ProxyError::Protocol {
            source:
                PacketError::VarInt(VarIntError::Io(io))
                | PacketError::Io(io)
                | PacketError::Serialization(SerializationError::Io(io)),
            ..
        } => io.kind() == ErrorKind::UnexpectedEof,
        _ => false,
    }
}

#[derive(Debug, Snafu)]
enum ProxyError {
    #[snafu(display("Protocol: {source}"))]
    Protocol {
        source: PacketError,
        backtrace: Backtrace,
    },
    #[snafu(display("While attempting to (de)serialize {while_parsing:?}: {source}"))]
    Serde {
        source: SerializationError,
        while_parsing: Option<&'static str>,
        backtrace: Backtrace,
    },
    #[snafu(display(
        "Expected packet id 0x{expected:x} but found 0x{found:x} ({expected_name:?})"
    ))]
    UnexpectedPacket {
        found: i32,
        expected: i32,
        expected_name: Option<&'static str>,
    },
    #[snafu(display("bad programmer: {message}"))]
    BadProgram {
        message: Cow<'static, str>,
    },
    #[snafu(display("bad packet: {message}"))]
    BadPacket {
        message: Cow<'static, str>,
    },
    Timeout {
        source: Elapsed,
    },
    FetchingStatus {
        source: std::io::Error,
    },
}

type Result<T, E = ProxyError> = std::result::Result<T, E>;

fn packet_id_of<T: PacketId + Default>() -> i32 {
    T::default().packet_id()
}

fn deserialize_packet<T: mc_protocol::ser::Deserialize>(raw: &UncompressedPacket) -> Result<T> {
    T::deserialize(&mut Cursor::new(raw.payload.as_slice())).context(SerdeSnafu {
        while_parsing: Some(type_name::<T>()),
    })
}

fn make_raw<P: Serialize + PacketId>(packet: &P) -> Result<UncompressedPacket> {
    UncompressedPacket::from_packet(packet).context(ProtocolSnafu)
}

fn decode_packet_as<T>(packet: UncompressedPacket) -> Result<T>
where
    T: Deserialize + Default + PacketId,
{
    snafu::ensure!(
        packet.packet_id == packet_id_of::<T>(),
        UnexpectedPacketSnafu {
            expected_name: type_name::<T>(),
            expected: packet_id_of::<T>(),
            found: packet.packet_id
        }
    );

    deserialize_packet(&packet)
}

enum ConnectionState {
    Handshake,
    Login,
    Configuration,
}

struct Connection {
    stream: TcpStream,
    state: ConnectionState,
}

impl Connection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: ConnectionState::Handshake,
        }
    }

    async fn read_packet(&mut self) -> Result<UncompressedPacket> {
        RawPacket::read_async(&mut self.stream)
            .await
            .context(ProtocolSnafu)?
            .as_uncompressed()
            .context(ProtocolSnafu)
    }

    async fn write_packet(&mut self, packet: UncompressedPacket) -> Result<()> {
        packet
            .write_async(&mut self.stream)
            .await
            .context(ProtocolSnafu)
    }

    async fn read_packet_as<T>(&mut self) -> Result<T>
    where
        T: Deserialize + Default + PacketId,
    {
        let packet = self.read_packet().await?;
        decode_packet_as(packet)
    }
}

struct CachedStatus {
    response: UncompressedPacket,
    retrieved_at: Instant,
}

#[derive(Clone, Default)]
struct StatusCache {
    inner: Arc<RwLock<HashMap<String, CachedStatus>>>,
}

impl StatusCache {
    fn get(&self, key: &str, ttl: Duration) -> Option<UncompressedPacket> {
        let cache = self.inner.read().ok()?;
        let entry = cache.get(key)?;
        if entry.retrieved_at.elapsed() < ttl {
            Some(entry.response.clone())
        } else {
            None
        }
    }

    fn set(&self, key: String, response: UncompressedPacket) {
        if let Ok(mut cache) = self.inner.write() {
            cache.insert(
                key,
                CachedStatus {
                    response,
                    retrieved_at: Instant::now(),
                },
            );
        }
    }
}

struct Context {
    config: &'static Config,
    cache: StatusCache,
}

async fn handle(conn: &mut Connection, ctx: &Context) -> Result<()> {
    let handshake: Handshake = conn.read_packet_as().await?;
    trace!("{handshake:?}");
    tracing::Span::current().record("a", &handshake.server_address);

    // In the login state, we send disconnect messages as json components, which is easier than NBT
    // So we will match the target hostname here
    let Some(matched) = ctx.config.match_host(&handshake.server_address) else {
        info!("...did not match");
        if handshake.intent == Handshake::INTENT_LOGIN {
            const TEXT_COULD_NOT_FIND_A_DESTINATION: &str =
                r#"{"text": "Could not find a destination to transfer you to", "color": "red"}"#;
            conn.write_packet(make_raw(&LoginDisconnect {
                reason: TEXT_COULD_NOT_FIND_A_DESTINATION.to_owned(),
            })?)
            .await?;
        }
        return Ok(());
    };

    match handshake.intent {
        Handshake::INTENT_LOGIN => (),
        Handshake::INTENT_STATUS => {
            let status_request = conn.read_packet().await?;

            // magic number: status request
            ensure!(
                status_request.packet_id == 0,
                UnexpectedPacketSnafu {
                    found: status_request.packet_id,
                    expected: 0,
                    expected_name: "(fake) status request"
                }
            );

            match &matched.status {
                StatusConfig::Static {
                    json,
                    fake_protocol_version,
                } => {
                    let mut json = json.clone();
                    if *fake_protocol_version {
                        json.as_object_mut()
                            .expect("Expected an object for status json")
                            .get_mut("version")
                            .expect("Expected a 'version' field")
                            .as_object_mut()
                            .expect("Version should be an object")
                            .insert(
                                "protocol".to_owned(),
                                serde_json::Value::Number(serde_json::Number::from_i128(
                                    handshake.protocol_version.0 as _,
                                ).unwrap()),
                            );
                    }
                    let as_json = serde_json::to_string(&json).expect("valid json");
                    trace!("{}", as_json);
                    conn.write_packet(make_raw(&S2CStatusResponse { response: as_json })?)
                        .await?;
                }
                StatusConfig::FetchFrom {
                    host,
                    port,
                    rewrite_address,
                    ..
                } => {
                    let cache_key = matched.status.cache_key().unwrap();
                    let ttl = matched.status.cache_ttl().unwrap();
                    let response = match ctx.cache.get(&cache_key, ttl) {
                        Some(cached) => cached,
                        None => {
                            let mut fetch_from_stream = timeout(
                                Duration::from_secs(3),
                                TcpStream::connect((host.as_str(), *port)),
                            )
                            .await
                            .context(TimeoutSnafu)?
                            .context(FetchingStatusSnafu)?;
                            let mut handshake2 = handshake.clone();
                            if *rewrite_address {
                                handshake2.server_address = host.clone();
                                handshake2.server_port = *port;
                            }
                            make_raw(&handshake2)?
                                .write_async(&mut fetch_from_stream)
                                .await
                                .unwrap();
                            status_request
                                .write_async(&mut fetch_from_stream)
                                .await
                                .context(ProtocolSnafu)?;
                            let response = RawPacket::read_async(&mut fetch_from_stream)
                                .await
                                .context(ProtocolSnafu)?
                                .as_uncompressed()
                                .context(ProtocolSnafu)?;
                            let _: S2CStatusResponse = decode_packet_as(response.clone())?;
                            ctx.cache.set(cache_key, response.clone());
                            tokio::task::spawn(async move {
                                make_raw(&PingPong { timestamp: 0 })
                                    .unwrap()
                                    .write_async(&mut fetch_from_stream)
                                    .await
                                    .unwrap();
                                let _ = RawPacket::read_async(&mut fetch_from_stream).await;
                                drop(fetch_from_stream);
                            });
                            response
                        }
                    };
                    conn.write_packet(response).await?;
                }
            }

            let pong_request: PingPong = conn.read_packet_as().await?;
            conn.write_packet(make_raw(&pong_request)?).await?;
            return Ok(());
        }
        Handshake::INTENT_TRANSFER => {
            const TEXT_NOT_ACCEPTING_TRANSFERS: &str =
                r#"{"translate": "multiplayer.disconnect.transfers_disabled", "color": "red"}"#;
            conn.write_packet(make_raw(&LoginDisconnect {
                reason: TEXT_NOT_ACCEPTING_TRANSFERS.to_owned(),
            })?)
            .await?;
            return Ok(());
        }
        i => {
            return Err(BadPacketSnafu {
                message: format!("Unknown intent {i}"),
            }
            .build());
        }
    }

    // We are in login state immediately after receiving a handshake packet
    conn.state = ConnectionState::Login;

    let login_start: LoginStart = conn.read_packet_as().await?;
    trace!("{login_start:?}");
    tracing::Span::current().record("u", &login_start.username);
    info!("Identified");

    if let Destination::Kick {
        message: kick_message,
    } = &matched.destination
    {
        info!("Kicking with reason {kick_message}");
        conn.write_packet(make_raw(&LoginDisconnect {
            reason: serde_json::to_string(&kick_message).expect("valid json"),
        })?)
        .await?;
        return Ok(());
    }

    let outbound_success_packet = LoginSuccess {
        username: login_start.username.clone(),
        uuid: uuid::Uuid::new_v4().as_u128(),
        properties: Vec::new(),
    };
    let mut raw_success = make_raw(&outbound_success_packet)?;

    // The transfer packet was added in protocol version 766. Protocols 766-767 include an additional
    // boolean field "Strict Error Handling" at the end of the LoginSuccess packet, which was removed
    // in protocol 768
    if (766..=767).contains(&handshake.protocol_version.0) {
        // Set the flag to true
        raw_success.payload.push(1u8);
    }

    // In protocol 776 onwards, another UUID field was added to this packet, called the session id
    if handshake.protocol_version.0 >= 776 {
        let rand_id = uuid::Uuid::new_v4().as_u128();
        rand_id
            .serialize(&mut raw_success.payload)
            .context(SerdeSnafu {
                while_parsing: None,
            })?;
    }

    conn.write_packet(raw_success).await?;
    trace!("Sent outbound success packet");

    // Now we wait for a login acknowledge; the packet has no body, so we did not create a struct for it
    let raw_packet = conn.read_packet().await?;
    snafu::ensure!(
        raw_packet.packet_id == packets::PACKET_ID_LOGIN_ACK,
        UnexpectedPacketSnafu {
            found: raw_packet.packet_id,
            expected: packets::PACKET_ID_LOGIN_ACK,
            expected_name: Some("(fake) login acknowledged packet")
        }
    );

    conn.state = ConnectionState::Configuration;

    let Destination::Transfer { host, port } = &matched.destination else {
        unreachable!()
    };

    info!("Transferring to {host}:{port}");
    trace!("Received login ack; sending transfer");
    conn.write_packet(make_raw(&Transfer {
        host: host.to_owned(),
        port: VarInt(*port as i32),
    })?)
    .await?;

    loop {
        let packet = match conn.read_packet().await {
            Ok(p) => p,
            Err(e) if proxy_error_is_eof(&e) => {
                // Expected after a disconnect
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        match packet.packet_id {
            ClientInformation::PACKET_ID => {}
            C2SPluginMessage::PACKET_ID => {}
            x => warn!("unknown packet type of id 0x{x:x}"),
        }
    }
}

fn make_json_text(input: &str) -> String {
    let mut quoted = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\u{08}' => quoted.push_str("\\b"),
            '\u{0C}' => quoted.push_str("\\f"),
            c if c.is_control() => {
                quoted.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => quoted.push(c),
        }
    }

    format!(r#"{{"text": "{quoted}"}}"#)
}

fn make_nbt_string(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + input.len());
    out.push(8); // magic number: NBT string tag
    out.extend_from_slice(&(input.len() as u16).to_be_bytes());
    out.extend_from_slice(input.as_bytes());
    out
}

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    let default_filter = if cfg!(debug_assertions) {
        "trace"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(default_filter.parse().unwrap())
                .from_env_lossy(),
        )
        .with_timer(UtcTime::new(time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        )))
        .with_line_number(cfg!(debug_assertions))
        .with_file(cfg!(debug_assertions))
        .init();

    let argument = std::env::args()
        .nth(1)
        .whatever_context("expected the first argument to be a config path")?;
    let config_str = std::fs::read_to_string(&argument).whatever_context("while reading config")?;
    let config: Config = Config::parse(&config_str).whatever_context("while parsing config")?;
    let ctx: &'static Context = Box::leak(Box::new(Context {
        config: Box::leak(Box::new(config)),
        cache: StatusCache::default(),
    }));

    let listener = TcpListener::bind(&ctx.config.listen)
        .await
        .whatever_context("Failed to bind")?;
    loop {
        let (socket, addr) = listener
            .accept()
            .await
            .whatever_context("Failed to accept client")?;
        let span = tracing::info_span!("connection", ip = %addr, u = tracing::field::Empty, a = tracing::field::Empty);
        span.in_scope(|| info!("Connected"));
        tokio::spawn(async move {
            let mut conn = Connection::new(socket);
            match handle(&mut conn, ctx).instrument(span.clone()).await {
                Ok(_) => (),
                Err(e) => {
                    span.in_scope(|| {
                        error!("{e}");
                        if let Some(bt) = ErrorCompat::backtrace(&e) {
                            trace!("{bt:#?}");
                        } else {
                            trace!("<no backtrace>");
                        }
                    });
                    // Send error to client too
                    let raw_packet = match conn.state {
                        ConnectionState::Handshake => return,
                        ConnectionState::Login => {
                            match make_raw(&LoginDisconnect {
                                reason: make_json_text(&format!("{}", e)),
                            }) {
                                Ok(x) => x,
                                Err(e) => {
                                    error!("{e}");
                                    return;
                                }
                            }
                        }
                        ConnectionState::Configuration => {
                            // magic number: 0x2 = Disconnect (Configuration/Play)
                            UncompressedPacket::new(0x2, make_nbt_string(&format!("{}", e)))
                        }
                    };
                    match conn.write_packet(raw_packet).await {
                        Ok(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                        Err(e) => error!("{e}"),
                    }
                }
            }
        });
    }
}
