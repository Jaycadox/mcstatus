use std::io::Cursor;

use crate::read_string;

use super::Packet;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub version: Version,
    pub players: Option<Players>,
    pub description: Option<Description>,
    pub favicon: Option<String>,
    #[serde(rename = "enforcesSecureChat")]
    pub enforces_secure_chat: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    pub name: String,          // mandatory
    pub protocol: Option<u32>, // optional, can be omitted
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Players {
    pub max: Option<u32>,                  // optional
    pub online: Option<u32>,               // optional
    pub sample: Option<Vec<PlayerSample>>, // optional
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String, // player name
    pub id: String,   // player UUID
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)] // Allows deserialization from multiple formats
pub enum Description {
    Text { text: String },
    Plain(String),
}

pub struct StatusResponse(pub ServerResponse);
impl Packet for StatusResponse {
    fn write_data(&self) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn read_data(data: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let mut buf = Cursor::new(data);
        let contents = read_string(&mut buf)?;
        Ok(Self(
            serde_json::from_str::<ServerResponse>(&contents).map_err(|e| {
                println!("Status: {contents}");
                e
            })?,
        ))
    }
}
