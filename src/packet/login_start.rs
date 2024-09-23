use crate::utils;

use super::Packet;

pub struct LoginStart {
    name: String,
    uuid: u128,
}

impl LoginStart {
    pub fn new(name: String, uuid: u128) -> Self {
        Self { name, uuid }
    }
}

impl Packet for LoginStart {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![];
        buf.append(&mut utils::write_string(&self.name)?);
        buf.extend_from_slice(&self.uuid.to_be_bytes());
        Ok(buf)
    }

    fn read_data(_data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}
