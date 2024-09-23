use super::Packet;
use crate::{write_string, write_varint};
use anyhow::Result;

pub struct Handshake {
    protocol_version: i32,
    server_address: String,
    port: u16,
    next_state: u8,
}

impl Handshake {
    pub fn status(ip: String, port: u16) -> Self {
        Self {
            protocol_version: -1,
            server_address: ip,
            port,
            next_state: 1,
        }
    }
    pub fn login(ip: String, port: u16, protocol_version: i32) -> Self {
        Self {
            protocol_version,
            server_address: ip,
            port,
            next_state: 2,
        }
    }
}

impl Packet for Handshake {
    fn write_data(&self) -> Result<Vec<u8>> {
        let mut full_packet = write_varint(self.protocol_version)?;
        full_packet.append(&mut write_string(&self.server_address)?);
        full_packet.extend_from_slice(&mut self.port.to_ne_bytes());
        full_packet.append(&mut write_varint(self.next_state as i32)?);
        Ok(full_packet)
    }

    fn read_data(_data: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}
