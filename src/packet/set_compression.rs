use std::io::Cursor;

use mc_varint::VarIntRead;

use super::Packet;

#[derive(Debug)]
pub enum CompressionMode {
    MinimumSize(u32),
    Disabled,
}

pub struct SetCompression(pub CompressionMode);

impl Packet for SetCompression {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        unimplemented!()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut buf = Cursor::new(data);
        let min_length = i32::from(buf.read_var_int()?);
        if min_length < 0 {
            Ok(Self(CompressionMode::Disabled))
        } else {
            Ok(Self(CompressionMode::MinimumSize(min_length as u32)))
        }
    }
}
