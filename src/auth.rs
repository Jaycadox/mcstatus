use std::io::Write;

use anyhow::{anyhow, Result};
use oauth2::{
    basic::BasicClient, reqwest::http_client, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope,
    StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::token_store;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XboxLiveAuthentication {
    #[serde(rename = "Properties")]
    pub properties: Properties,
    #[serde(rename = "RelyingParty")]
    pub relying_party: String,
    #[serde(rename = "TokenType")]
    pub token_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Properties {
    #[serde(rename = "AuthMethod")]
    pub auth_method: String,
    #[serde(rename = "SiteName")]
    pub site_name: String,
    #[serde(rename = "RpsTicket")]
    pub rps_ticket: String,
}

impl XboxLiveAuthentication {
    fn from_access_token(access_token: &str) -> Self {
        Self {
            properties: Properties {
                auth_method: "RPS".to_string(),
                site_name: "user.auth.xboxlive.com".to_string(),
                rps_ticket: format!("d={access_token}"),
            },
            relying_party: "http://auth.xboxlive.com".to_string(),
            token_type: "JWT".to_string(),
        }
    }
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XboxLiveAuthenticationResponse {
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "NotAfter")]
    pub not_after: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "DisplayClaims")]
    pub display_claims: DisplayClaims,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayClaims {
    pub xui: Vec<Xui>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Xui {
    pub uhs: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XstsTokenRequest {
    #[serde(rename = "Properties")]
    pub properties: XstsProperties,
    #[serde(rename = "RelyingParty")]
    pub relying_party: String,
    #[serde(rename = "TokenType")]
    pub token_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XstsProperties {
    #[serde(rename = "SandboxId")]
    pub sandbox_id: String,
    #[serde(rename = "UserTokens")]
    pub user_tokens: Vec<String>,
}

impl XstsTokenRequest {
    fn from_xbl_token(token: String) -> Self {
        Self {
            properties: XstsProperties {
                sandbox_id: "RETAIL".to_string(),
                user_tokens: vec![token],
            },
            relying_party: "rp://api.minecraftservices.com/".to_string(),
            token_type: "JWT".to_string(),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MinecraftAuthenticationRequest {
    #[serde(rename = "identityToken")]
    pub identity_token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MinecraftAuthenticationResponse {
    pub username: String,
    pub roles: Vec<Value>,
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "token_type")]
    pub token_type: String,
    #[serde(rename = "expires_in")]
    pub expires_in: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetMinecraftProfileResponse {
    pub id: String,
    pub name: String,
    skins: Vec<Value>,
    capes: Vec<Value>,
}

const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const MSA_AUTHORIZE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MSA_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

fn get_oath_access_token() -> Result<String> {
    // https://github.com/PrismLauncher/PrismLauncher/blob/4a5749f4d988cd6e7e65de3fd26f8f96b517ebf3/CMakeLists.txt#L259
    let client_id = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb".to_string(); // Prism Launcher client ID
    let client = BasicClient::new(
        ClientId::new(client_id),
        None,
        AuthUrl::new(MSA_AUTHORIZE_URL.to_string())?,
        Some(TokenUrl::new(MSA_TOKEN_URL.to_string())?),
    )
    .set_device_authorization_url(DeviceAuthorizationUrl::new(DEVICE_CODE_URL.to_string())?);

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()?
        .add_scope(Scope::new("XboxLive.signin offline_access".to_string()))
        .request(http_client)?;

    println!(
        "Verify at: {}\n\twith code: {}",
        details.verification_uri().to_string(),
        details.user_code().secret().to_string()
    );

    let token = client.exchange_device_access_token(&details).request(
        http_client,
        std::thread::sleep,
        None,
    )?;
    let access_token = token.access_token().secret();
    Ok(access_token.clone())
}

pub fn get_minecraft_access_key() -> Result<(String, GetMinecraftProfileResponse)> {
    let access_token = if let Ok(access_token) = token_store::get_saved_token() {
        print!("Saved access token found, would you like to use it (y/n, blank=y)? ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        match input.chars().nth(0) {
            Some('y') => access_token,
            Some('n') => get_oath_access_token()?,
            _ => access_token,
        }
    } else {
        get_oath_access_token()?
    };

    println!("Authenticating via Xbox Live...");

    let client = reqwest::blocking::Client::new();
    let xbox_auth = XboxLiveAuthentication::from_access_token(&access_token);
    let resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .body(serde_json::to_string(&xbox_auth)?)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .send()?;
    let resp = serde_json::from_str::<XboxLiveAuthenticationResponse>(&resp.text()?)?;
    let user_hash = resp
        .display_claims
        .xui
        .get(0)
        .ok_or(anyhow!("unable to get user hash"))?
        .uhs
        .clone();
    let xbl_token = resp.token;
    println!("Getting XSTS token...");
    let xsts_req = XstsTokenRequest::from_xbl_token(xbl_token);
    let resp = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .body(serde_json::to_string(&xsts_req)?)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .send()?;
    let resp = serde_json::from_str::<XboxLiveAuthenticationResponse>(&resp.text()?)?;
    println!("Authenticating with Minecraft...");
    let xsts_token = resp.token;
    let mc_auth = MinecraftAuthenticationRequest {
        identity_token: format!("XBL3.0 x={};{}", user_hash, xsts_token),
    };
    let resp = client
        .post("https://api.minecraftservices.com/authentication/login_with_xbox")
        .body(serde_json::to_string(&mc_auth)?)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .send()?;
    let resp = serde_json::from_str::<MinecraftAuthenticationResponse>(&resp.text()?)?;
    let old_access_token = access_token;
    let access_token = resp.access_token;
    println!("Getting Minecraft user profile...");
    let resp = client
        .get("https://api.minecraftservices.com/minecraft/profile")
        .bearer_auth(&access_token)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .send()?;
    let resp = serde_json::from_str::<GetMinecraftProfileResponse>(&resp.text()?)?;
    println!("Logged in as {} ({})", resp.name, resp.id);
    let _ = token_store::save_token(&old_access_token);
    Ok((access_token, resp))
}
