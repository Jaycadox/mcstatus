use super::Packet;
use anyhow::Result;

pub struct StatusRequest;
impl Packet for StatusRequest {
    fn write_data(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn read_data(_data: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}
