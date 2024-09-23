use core::str;
use std::io;

use anyhow::{Context, Result};
use mc_varint::VarIntRead;
use mc_varint::VarIntWrite;

pub fn write_varint(number: i32) -> Result<Vec<u8>> {
    let mut buffer = vec![];
    buffer
        .write_var_int(number.into())
        .context("failed to write varint")?;
    Ok(buffer)
}

pub fn write_string(contents: &str) -> Result<Vec<u8>> {
    let mut full_packet =
        write_varint(i32::try_from(contents.len()).context("invalid string size")?)?;
    full_packet.extend_from_slice(contents.as_bytes());
    Ok(full_packet)
}

pub fn read_string(contents: &mut impl io::Read) -> Result<String> {
    let len = i32::from(
        contents
            .read_var_int()
            .context("unable to read string length")?,
    ) as usize;

    let mut str_buf = vec![0; len];
    contents
        .read_exact(&mut str_buf)
        .context("failed to read string")?;
    Ok(String::from_utf8(str_buf).context("invalid string")?)
}
