use std::{
    io::{self, Cursor, Read, Write},
    net::TcpStream,
};

use aes::cipher::{AsyncStreamCipher, KeyIvInit, StreamCipher};
use anyhow::{anyhow, Result};
use mc_varint::{VarInt, VarIntRead, VarIntWrite};
use num_bigint::BigInt;
use rand::Rng;
use reqwest::header::CONTENT_TYPE;
use rsa::{pkcs8::DecodePublicKey, traits::PaddingScheme, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1_smol::Sha1;
use shadowsocks_crypto::v1::Cipher;
use zune_inflate::DeflateDecoder;

use crate::{
    encryption_response::EncryptionResponse,
    handshake::Handshake,
    login_start::LoginStart,
    login_success::LoginSuccess,
    packet, read_packet, read_packet_sized,
    set_compression::{CompressionMode, SetCompression},
    status_request::StatusRequest,
    status_response::StatusResponse,
    write_packet, Packet, PacketRegistry,
};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionServerJoinRequest {
    pub access_token: String,
    pub selected_profile: String,
    pub server_id: String,
}

trait ReadAndWrite: Read + Write {}
impl ReadAndWrite for TcpStream {}
impl ReadAndWrite for EncryptedTcpStream {}
impl ReadAndWrite for DummyStream {}

struct DummyStream;
impl Read for DummyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
    }
}

impl Write for DummyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> io::Result<()> {
        todo!()
    }
}

struct EncryptedTcpStream {
    tcp: Box<dyn ReadAndWrite>,
    encryption: Cipher,
    decryption: Cipher,
}

impl Read for EncryptedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.tcp.read(buf)?;
        if !self.decryption.decrypt_packet(buf) {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(bytes_read)
        }
    }
}

impl Write for EncryptedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buf = buf.to_owned();
        self.encryption.encrypt_packet(&mut buf);
        self.tcp.write(&buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

pub struct Connection {
    compression: CompressionMode,
    stream: Box<dyn ReadAndWrite>,
    token: Option<String>,
    uuid: u128,
}

impl Connection {
    pub fn ping_server(ip: String, port: Option<u16>) -> Result<StatusResponse> {
        let port = port.unwrap_or(25565);
        let ip_address = format!("{ip}:{port}");
        let mut tcp = TcpStream::connect(&ip_address)?;
        tcp.write_all(&packet::write_packet(Handshake::status(ip, port))?)?;
        tcp.write_all(&packet::write_packet(StatusRequest)?)?;
        let packet = read_packet(&mut tcp)?;
        match packet {
            PacketRegistry::StatusResponse(content) => Ok(content),
            _ => Err(anyhow!("bad packet for ping server")),
        }
    }

    pub fn connect(
        username: String,
        uuid: u128,
        ip: String,
        port: Option<u16>,
        protocol_version: Option<i32>,
        token: Option<String>,
    ) -> Result<Self> {
        let port = port.unwrap_or(25565);
        let protocol_version = match protocol_version {
            Some(version) => version,
            None => {
                let ping = Self::ping_server(ip.clone(), Some(port))?;
                let protocol_version = ping
                    .0
                    .version
                    .protocol
                    .ok_or(anyhow!("could not get protocol version automatically"))?
                    as i32;
                println!("Automatically found server protocol version: {protocol_version}");
                protocol_version
            }
        };
        let ip_address = format!("{ip}:{port}");
        println!("Connecting to: {ip_address}... as {username} (uuid = {uuid})");
        let mut tcp = TcpStream::connect(&ip_address)?;
        println!("Sending handshake...");
        tcp.write_all(&packet::write_packet(Handshake::login(
            ip,
            port,
            protocol_version,
        ))?)?;
        println!("Starting login sequence...");
        tcp.write_all(&packet::write_packet(LoginStart::new(username, uuid))?)?;
        Ok(Self {
            compression: CompressionMode::Disabled,
            stream: Box::new(tcp),
            token,
            uuid,
        })
    }

    fn read_next_packet(&mut self) -> Result<PacketRegistry> {
        match self.compression {
            CompressionMode::MinimumSize(_min_size) => {
                let full_packet_size = i32::from(self.stream.read_var_int()?);
                let data_size = i32::from(self.stream.read_var_int()?);
                // Minus the bytes of the data size from the full packet size to get the actual data size
                let remaining_packet_size = {
                    let mut buf = vec![];
                    let data_byes = VarInt::from(data_size);
                    buf.write_var_int(data_byes)?;
                    full_packet_size - buf.len() as i32
                };
                if data_size == 0 {
                    // Packet is uncompressed
                    read_packet_sized(&mut self.stream, remaining_packet_size)
                } else {
                    // Read compressed data
                    let mut compressed = vec![0; remaining_packet_size as usize];
                    self.stream.read_to_end(&mut compressed)?;
                    let mut decoder = DeflateDecoder::new(&compressed);
                    let data = decoder.decode_zlib()?;
                    read_packet_sized(&mut Cursor::new(&data), data.len() as i32)
                }
            }
            CompressionMode::Disabled => read_packet(&mut self.stream),
        }
    }

    fn send_packet(&mut self, packet: impl Packet) -> Result<()> {
        match self.compression {
            CompressionMode::MinimumSize(_) => {
                // As the vanilla client accepts uncompressed packets of any length from the client, we won't compress packets
                // But we need to send them in the new compressed format
                let mut buf = vec![];
                // Write 0 data size (uncompressed packet)
                buf.write_var_int(VarInt::from(0))?;
                buf.append(&mut packet::write_packet(packet)?);
                // Now to write the full size of the packet
                let mut full_packet = vec![];
                full_packet.write_var_int(VarInt::from(buf.len() as i32))?;
                full_packet.append(&mut buf);
                self.stream.write_all(&full_packet)?;
                Ok(())
            }
            CompressionMode::Disabled => {
                let packet_data = packet::write_packet(packet)?;
                self.stream.write_all(&packet_data)?;
                Ok(())
            }
        }
    }

    pub fn handle_next_packet(&mut self) -> Result<()> {
        let packet = self.read_next_packet()?;
        match packet {
            PacketRegistry::StatusResponse(_) => {
                Err(anyhow!("server sent status response in login sequence"))
            }
            PacketRegistry::SetCompression(SetCompression(new_compression)) => {
                println!("Server specified compression mode: {new_compression:?}");
                self.compression = new_compression;
                Ok(())
            }
            PacketRegistry::LoginSuccess(login) => {
                println!("{login:#?}");
                Ok(())
            }
            PacketRegistry::EncryptionRequest(encryption) => {
                println!("Establishing encrypted communications...");
                println!("\tReading server's public key...");
                let public_key = RsaPublicKey::from_public_key_der(&encryption.public_key)?;
                println!("\tGenerating shared secret...");
                let encrypt = rsa::Pkcs1v15Encrypt::default();
                let mut secret = [0; 16];
                rand::thread_rng().fill(&mut secret);
                println!("\tEncrypting secret & verify buffer...");
                let encrypted_secret =
                    encrypt.encrypt(&mut rand::thread_rng(), &public_key, &secret)?;
                let encrypted_verify = encrypt.encrypt(
                    &mut rand::thread_rng(),
                    &public_key,
                    &encryption.verify_token,
                )?;
                let resp = EncryptionResponse {
                    shared_secret: encrypted_secret,
                    verify_token: encrypted_verify,
                };

                // Send information off to Mojang
                if let Some(token) = self.token.as_ref() {
                    let mut sha1 = Sha1::new();
                    sha1.update(encryption.server_id.as_bytes());
                    sha1.update(&secret);
                    sha1.update(&encryption.public_key);
                    let hash = sha1.digest().bytes();
                    let hash = BigInt::from_signed_bytes_be(&hash).to_str_radix(16);
                    let body = serde_json::to_string(&SessionServerJoinRequest {
                        access_token: token.to_owned(),
                        selected_profile: BigInt::from(self.uuid).to_str_radix(16),
                        server_id: hash,
                    })?;
                    println!("\tRequesting authentication from Mojang...");
                    let client = reqwest::blocking::Client::new();
                    let resp = client
                        .post("https://sessionserver.mojang.com/session/minecraft/join")
                        .body(body)
                        .header(CONTENT_TYPE, "application/json")
                        .send()?;
                    if resp.status().as_u16() == 204 {
                        println!("\tMojang has accepted the authentication request");
                    } else {
                        println!("{resp:?}");
                        panic!("{:?}", resp.text());
                    }
                }
                println!("\tSending encryption response...");
                self.stream.write_all(&packet::write_packet(resp)?)?;

                let encryptor = Cipher::new(
                    shadowsocks_crypto::CipherKind::AES_128_CFB8,
                    &secret,
                    &secret,
                );

                let decryptor = Cipher::new(
                    shadowsocks_crypto::CipherKind::AES_128_CFB8,
                    &secret,
                    &secret,
                );
                let original_stream = std::mem::replace(&mut self.stream, Box::new(DummyStream));

                self.stream = Box::new(EncryptedTcpStream {
                    tcp: original_stream,
                    encryption: encryptor,
                    decryption: decryptor,
                });
                if let None = self.token {
                    println!("Attempting to connect in offline mode (ex: no authentication token). The server will probably reject the join attempt.")
                }

                Ok(())
            }
        }
    }
}
