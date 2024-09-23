use std::{
    fs::File,
    io::{Read, Write},
};

use anyhow::Result;

const STORE_FILE: &'static str = ".mcstatustoken";

pub fn get_saved_token() -> Result<String> {
    let mut contents = std::fs::read_to_string(STORE_FILE)?;

    Ok(contents)
}

pub fn save_token(token: &str) -> Result<()> {
    std::fs::write(STORE_FILE, token)?;
    Ok(())
}

pub fn remove_saved_token() -> Result<()> {
    std::fs::remove_file(STORE_FILE)?;
    Ok(())
}
