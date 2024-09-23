use anyhow::Result;

const STORE_FILE: &str = ".mcstatustoken";

pub fn get_saved_token() -> Result<String> {
    let contents = std::fs::read_to_string(STORE_FILE)?;

    Ok(contents)
}

pub fn save_token(token: &str) -> Result<()> {
    std::fs::write(STORE_FILE, token)?;
    Ok(())
}
