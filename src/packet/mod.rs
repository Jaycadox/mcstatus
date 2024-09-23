pub mod configure;
mod encryption_request;
pub mod encryption_response;
pub mod handshake;
pub mod login_acknowledged;
pub mod login_start;
pub mod login_success;
pub mod set_compression;
pub mod status_request;
pub mod status_response;
use crate::write_varint;
use anyhow::{Context, Result};
use configure::*;
use encryption_request::EncryptionRequest;
use encryption_response::EncryptionResponse;
use handshake::Handshake;
use login_acknowledged::LoginAcknowledged;
use login_start::LoginStart;
use login_success::LoginSuccess;
use mc_varint::VarIntRead;
use set_compression::SetCompression;
use status_request::StatusRequest;
use status_response::StatusResponse;
use std::io::Cursor;

pub trait Id {
    const ID: u8;
}

pub trait Packet: Id {
    fn write_data(&self) -> Result<Vec<u8>>;
    fn read_data(data: &[u8]) -> Result<Self>
    where
        Self: Sized;
    fn id(&self) -> u8 {
        Self::ID
    }
}

macro_rules! register_c2s {
    // Match against a series of tuples
    ($(($type:ident, $id:expr)),*) => {
        $(
            impl Id for $type {
                const ID: u8 = $id;
            }
        )*
    };
}

pub trait PacketRegistry: Sized {
    fn read(id: i32, data: &[u8]) -> Result<Self>;
}

macro_rules! register_s2c {
    // Match against a series of tuples
    ($name:ident, $(($type:ident, $id:expr)),*) => {
        $(
            impl Id for $type {
                const ID: u8 = $id;
            }
        )*

        // Define the PacketRegistry enum
        pub enum $name {
            $(
                $type($type),
            )*
        }

        impl PacketRegistry for $name {
            fn read(id: i32, data: &[u8]) -> Result<Self> {
                match id {
                    $(
                        $id => Ok($name::$type($type::read_data(data)?)),
                    )*
                    _ => Err(anyhow::anyhow!("invalid packet id {id}")),
                }
            }
        }
    };
}

register_c2s!(
    (StatusRequest, 0x0),
    (LoginStart, 0x0),
    (Handshake, 0x0),
    (EncryptionResponse, 0x1),
    (LoginAcknowledged, 0x3),
    (ServerboundKnownPacks, 0x7),
    (AcknowledgeFinishConfiguration, 0x3)
);

register_s2c!(
    LoginPacketRegistry,
    (StatusResponse, 0x0),
    (EncryptionRequest, 0x1),
    (LoginSuccess, 0x2),
    (SetCompression, 0x3)
);

register_s2c!(
    ConfigurePacketRegistry,
    (PluginMessage, 0x1),
    (FeatureFlags, 0xC),
    (KnownPacks, 0xE),
    (RegistryData, 0x7),
    (UpdateTags, 0xD),
    (FinishConfiguration, 0x3)
);

pub fn read_packet_sized<T: PacketRegistry>(
    reader: &mut impl std::io::Read,
    size: i32,
) -> Result<T> {
    println!("1");
    let mut buf = vec![0; size as usize];
    println!("1");
    reader
        .read_exact(&mut buf)
        .context("unable to read entire packet")?;
    println!("1");
    let mut buf = Cursor::new(buf);
    let id = i32::from(buf.read_var_int().context("unable to read packet id")?);
    println!("1");
    let position = buf.position();
    let mut buf = buf.into_inner();
    buf.drain(0..(position as usize));
    println!("1");
    let packet = T::read(id, &buf)?;
    println!("2");

    Ok(packet)
}

pub fn read_packet<T: PacketRegistry>(reader: &mut impl std::io::Read) -> Result<T> {
    let size = i32::from(
        reader
            .read_var_int()
            .context("invalid packet size specified")?,
    );
    read_packet_sized(reader, size)
}

pub fn write_packet_with_transformation(
    packet: impl Packet,
    transform: impl Fn(&mut Vec<u8>),
) -> Result<Vec<u8>> {
    // First, get the packet data content
    let mut data = packet.write_data()?;
    let id = write_varint(packet.id() as i32)?;

    let mut id_with_data = id;
    id_with_data.append(&mut data);

    transform(&mut id_with_data);

    let length =
        write_varint(i32::try_from(id_with_data.len()).context("invalid packet size conversion")?)?;

    let mut full_packet = length;
    full_packet.append(&mut id_with_data);
    Ok(full_packet)
}

pub fn write_packet(packet: impl Packet) -> Result<Vec<u8>> {
    write_packet_with_transformation(packet, |_| {})
}
