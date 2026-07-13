use mc_protocol::prelude::*;

// ---- Handshake Phase ----

#[derive(Packet, Debug, Default, Clone)]
#[packet(0x00)]
pub struct Handshake {
    pub protocol_version: VarInt,
    pub server_address: String,
    pub server_port: u16,
    pub intent: VarInt,
}

impl Handshake {
    pub const INTENT_STATUS: VarInt = VarInt(1);
    pub const INTENT_LOGIN: VarInt = VarInt(2);
    pub const INTENT_TRANSFER: VarInt = VarInt(3);
}

// ---- Status Phase ----

#[derive(Packet, Debug, Default)]
#[packet(0x0)]
pub struct S2CStatusResponse {
    pub response: String
}

#[derive(Packet, Debug, Default)]
#[packet(0x1)]
pub struct PingPong {
    pub timestamp: i64
}

// ---- Login Phase ----

#[derive(Packet, Debug, Default)]
#[packet(0x00)]
pub struct LoginStart {
    pub username: String,
    pub uuid: u128
}


#[derive(Packet, Debug, Default)]
#[packet(0x02)]
pub struct LoginSuccess {
    pub uuid: u128,
    pub username: String,
    pub properties: Vec<Property>,
}


#[derive(Packet, Debug, Default)]
pub struct Property {
    pub name: String,
    pub value: String,
    pub sig: Option<String>
}


pub const PACKET_ID_LOGIN_ACK: i32 = 3;

#[derive(Packet, Debug, Default)]
#[packet(0x0)]
pub struct LoginDisconnect {
    pub reason: String
}

// ---- Configuration Phase ----

#[derive(Packet, Debug, Default)]
#[packet(0xB)]
pub struct Transfer {
    pub host: String,
    pub port: VarInt
}

#[derive(Packet, Debug, Default)]
#[packet(0x2)]
pub struct C2SPluginMessage {
    pub channel: String,
    pub message: Vec<u8>
}

#[derive(Packet, Debug, Default)]
#[packet(0x0)]
pub struct ClientInformation {
    pub locale: String,
    pub view_distance: u8,
    pub chat_mode: VarInt,
    pub chat_colours: bool,
    pub skin_parts: u8,
    pub hand: VarInt,
    pub filtering: bool,
    pub allow_server_listing: bool,
    pub particle_status: VarInt
}


