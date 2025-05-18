pub mod auth_error;

use std::{env, fmt};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use crate::permissions::encode_perm;
use crate::token::auth_error::PermLibError;

impl fmt::Display for PermsRole
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", match self
        {
            PermsRole::SuperAdmin => "SuperAdmin",
            PermsRole::Admin => "Admin",
            PermsRole::Client => "Client",
            PermsRole::Visitor => "Visitor",
        })
    }
}

impl FromStr for PermsRole
{
    type Err = ();

    fn from_str(input: &str) -> Result<PermsRole, Self::Err>
    {
        match input
        {
            "SuperAdmin" => Ok(PermsRole::SuperAdmin),
            "Admin" => Ok(PermsRole::Admin),
            "Client" => Ok(PermsRole::Client),
            "Visitor" => Ok(PermsRole::Visitor),
            _ => Err(()),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Hash, Eq)]
pub enum PermsRole
{
    SuperAdmin,
    Admin,
    Client,
    Visitor,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
    pub permissions: Vec<u64>,
    role: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Auth
{
    pub _id:         Option<String>,
    pub user_id: String,
    pub username:    String,
    pub email:       String,
    pub password:    String,
    pub roles: String,
    pub permissions: Vec<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Token
{
    pub token: String,
}

impl Token
{
    pub fn new(auth: Auth) -> Result<Token, PermLibError>
    {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        let exp = (since_the_epoch.as_secs() + 3600) as usize;
        let permission = encode_perm(auth.permissions);

        let claims = Claims {
            sub: auth.username,
            role: auth.roles,
            exp,
            permissions: permission,
        };

        let secret = env::var("SECRET_KEY").unwrap().to_string();
        let token =
            encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).map_err(|_| PermLibError::FailToCreateToken)?;

        Ok(Token{token})
    }
}