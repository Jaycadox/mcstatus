use super::Packet;

pub struct LoginAcknowledged;

impl Packet for LoginAcknowledged {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn read_data(_data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}
