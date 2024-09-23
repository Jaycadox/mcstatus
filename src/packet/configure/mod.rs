use std::{
    io::{Cursor, Read},
    slice,
};

use mc_varint::{VarInt, VarIntRead, VarIntWrite};
use quartz_nbt::{io::Flavor, NbtCompound};

use crate::{read_string, write_string};

use super::Packet;

pub struct PluginMessage {
    pub identifier: String,
    pub data: Vec<u8>,
}

impl Packet for PluginMessage {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let len = data.len();
        let mut buf = Cursor::new(data);
        let id = read_string(&mut buf)?;
        let vec_len = len - buf.position() as usize;
        let mut data = vec![0; vec_len];
        buf.read_exact(&mut data)?;
        Ok(Self {
            identifier: id,
            data,
        })
    }
}

pub struct FeatureFlags {
    pub flags: Vec<String>,
}

impl Packet for FeatureFlags {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut data = Cursor::new(data);
        let len = i32::from(data.read_var_int()?);
        let mut features = Vec::with_capacity(len as usize);
        for _ in 0..len {
            features.push(read_string(&mut data)?);
        }
        Ok(Self { flags: features })
    }
}

#[derive(Debug)]
pub struct Pack {
    pub namespace: String,
    pub id: String,
    pub version: String,
}

pub struct KnownPacks {
    pub packs: Vec<Pack>,
}

impl Packet for KnownPacks {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![];
        buf.write_var_int(VarInt::from(self.packs.len() as i32))?;
        for pack in &self.packs {
            buf.append(&mut write_string(&pack.namespace)?);
            buf.append(&mut write_string(&pack.id)?);
            buf.append(&mut write_string(&pack.version)?);
        }
        Ok(buf)
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut data = Cursor::new(data);
        let len = i32::from(data.read_var_int()?) as usize;
        let mut packs = Vec::with_capacity(len);
        for _ in 0..len {
            let namespace = read_string(&mut data)?;
            let id = read_string(&mut data)?;
            let version = read_string(&mut data)?;
            packs.push(Pack {
                namespace,
                id,
                version,
            });
        }
        Ok(Self { packs })
    }
}
pub struct ServerboundKnownPacks(pub KnownPacks);
impl Packet for ServerboundKnownPacks {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        self.0.write_data()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self(KnownPacks::read_data(data)?))
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct RegistryEntry {
    pub id: String,
    pub nbt: Option<NbtCompound>,
}

#[allow(unused)]
#[derive(Debug)]
pub struct RegistryData {
    // I think that this ID field can be something other than a string?
    pub id: String,
    pub entries: Vec<RegistryEntry>,
}

impl Packet for RegistryData {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let mut data = Cursor::new(data);
        let Ok(id) = read_string(&mut data) else {
            return Ok(Self {
                id: String::from("[error]"),
                entries: vec![],
            });
        };
        let len = i32::from(data.read_var_int()?) as usize;
        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            let Ok(id) = read_string(&mut data) else {
                break;
            };
            let mut has_nbt = 0;
            if data.read_exact(slice::from_mut(&mut has_nbt)).is_err() {
                break;
            }
            let nbt = if has_nbt == 1 {
                if let Ok(nbt) = quartz_nbt::io::read_nbt(&mut data, Flavor::Uncompressed) {
                    Some(nbt.0)
                } else {
                    // Unsure what to do from here, I suppose the rest of the packet should be skipped from here.
                    //eprintln!(
                    //    "Error while parsing NBT registry of: '{id}' in '{outer_id}', cancelling registry parse..."
                    //);
                    break;
                }
            } else {
                None
            };
            entries.push(RegistryEntry { id, nbt });
        }

        Ok(Self { id, entries })
    }
}

pub struct UpdateTags;
impl Packet for UpdateTags {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(_data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }
}

pub struct FinishConfiguration;
impl Packet for FinishConfiguration {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn read_data(_data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }
}

pub struct AcknowledgeFinishConfiguration;
impl Packet for AcknowledgeFinishConfiguration {
    fn write_data(&self) -> anyhow::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn read_data(_data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }
}
