use mc_varint::VarIntWrite;

use super::Packet;

pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl Packet for EncryptionResponse {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![];
        buf.write_var_int((self.shared_secret.len() as i32).into())?;
        for byte in &self.shared_secret {
            buf.push(*byte);
        }
        buf.write_var_int((self.verify_token.len() as i32).into())?;
        for byte in &self.verify_token {
            buf.push(*byte);
        }
        Ok(buf)
    }

    fn read_data(_data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}
