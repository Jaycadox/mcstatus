mod auth;
mod connection;
mod packet;
mod token_store;
mod utils;
use clap::{Parser, Subcommand};
use connection::Connection;
use packet::*;
use status_response::Description;
use utils::*;

use anyhow::Result;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status {
        ip: String,
        port: Option<u16>,
    },
    Login {
        username: String,
        ip: String,
        port: Option<u16>,
        protocol_version: Option<i32>,
    },
    OnlineLogin {
        ip: String,
        port: Option<u16>,
        protocol_version: Option<i32>,
    },
}

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::OnlineLogin {
            ip,
            port,
            protocol_version,
        } => {
            let (token, resp) = auth::get_minecraft_access_key()?;
            let mut connection = Connection::connect(
                resp.name,
                u128::from_str_radix(&resp.id, 16)?,
                ip,
                port,
                protocol_version,
                Some(token),
            )?;
            loop {
                connection.handle_next_packet()?;
            }
        }
        Command::Login {
            username,
            ip,
            protocol_version,
            port,
        } => {
            let mut connection =
                Connection::connect(username, 0, ip, port, protocol_version, None)?;
            loop {
                connection.handle_next_packet()?;
            }
        }
        Command::Status { ip, port } => {
            let content = Connection::ping_server(ip, port)?.0;
            println!("Version:");
            println!("\tVersion String: {}", content.version.name);
            if let Some(protocol) = content.version.protocol {
                println!("\tVersion Protocol: {protocol}");
            }
            println!("Players:");
            if let Some(players) = content.players {
                let online = players
                    .online
                    .map(|x| x.to_string())
                    .unwrap_or(String::from("[unknown]"));
                let max = players
                    .max
                    .map(|x| x.to_string())
                    .unwrap_or(String::from("[unknown]"));
                println!("\tCapacity: {online}/{max}");
                players
                    .sample
                    .map(|sample| {
                        if sample.is_empty() {
                            return;
                        }
                        println!("\tSample:");
                        for player in sample {
                            println!("\t\tPlayer: {} (uuid = {})", player.name, player.id);
                        }
                    })
                    .unwrap_or_else(|| println!("\t[no player samples]"));
            }
            content
                .description
                .map(|description| {
                    let text = match description {
                        Description::Text { text } => text,
                        Description::Plain(text) => text,
                    };
                    println!("Description: {text}");
                })
                .unwrap_or_else(|| println!("Description: [unknown]"));
            println!(
                "Enforces Secure Chat: {}",
                content.enforces_secure_chat.unwrap_or(true)
            );
        }
    }

    Ok(())
}
