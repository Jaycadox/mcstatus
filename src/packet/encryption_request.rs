use core::slice;
use std::io::{Cursor, Read};

use anyhow::anyhow;
use mc_varint::VarIntRead;

use crate::read_string;

use super::Packet;

#[derive(Debug)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
    pub should_authenticate: bool,
}

impl Packet for EncryptionRequest {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut data = Cursor::new(data);
        let server_id = read_string(&mut data)?;
        let pub_key_length = i32::from(data.read_var_int()?);
        let mut pub_key = vec![0; pub_key_length as usize];
        data.read_exact(&mut pub_key)?;
        let verify_length = i32::from(data.read_var_int()?);
        let mut verify = vec![0; verify_length as usize];
        data.read_exact(&mut verify)?;
        let mut should_authenticate = 0;
        data.read_exact(slice::from_mut(&mut should_authenticate))?;
        let should_authenticate = match should_authenticate {
            1 => true,
            0 => false,
            _ => return Err(anyhow!("invalid should authenticate value")),
        };

        Ok(Self {
            server_id,
            public_key: pub_key,
            verify_token: verify,
            should_authenticate,
        })
    }
}
