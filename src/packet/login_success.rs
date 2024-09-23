use core::slice;
use std::io::{Cursor, Read};

use anyhow::anyhow;
use mc_varint::VarIntRead;

use crate::read_string;

use super::Packet;

#[allow(unused)]
#[derive(Debug)]
pub struct LoginProperty {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

#[allow(unused)]
#[derive(Debug)]
pub struct LoginSuccess {
    pub uuid: u128,
    pub username: String,
    pub properties: Vec<LoginProperty>,
    pub strict_error_handling: bool,
}

impl Packet for LoginSuccess {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut data = Cursor::new(data);
        let mut uuid = [0; std::mem::size_of::<u128>()];
        data.read_exact(&mut uuid)?;
        let uuid = u128::from_be_bytes(uuid);
        let username = read_string(&mut data)?;
        let num_props = i32::from(data.read_var_int()?);
        let mut props = Vec::with_capacity(num_props as usize);
        for _ in 0..num_props {
            let prop_name = read_string(&mut data)?;
            let prop_value = read_string(&mut data)?;
            let mut is_signed: u8 = 0;
            data.read_exact(slice::from_mut(&mut is_signed))?;
            let signature = if is_signed == 1 {
                Some(read_string(&mut data)?)
            } else {
                None
            };
            props.push(LoginProperty {
                name: prop_name,
                value: prop_value,
                signature,
            });
        }
        let mut strict_error_handling: u8 = 1;
        let _ = data.read(slice::from_mut(&mut strict_error_handling))?;
        let strict_error_handling = match strict_error_handling {
            1 => true,
            0 => false,
            _ => return Err(anyhow!("invalid strict error handling value")),
        };

        Ok(LoginSuccess {
            uuid,
            username,
            properties: props,
            strict_error_handling,
        })
    }
}
