pub mod auth_error;
use std::{fmt, str::FromStr, time::{SystemTime, UNIX_EPOCH}};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use crate::domains_id::{AuthID, UserID};
use crate::token::auth_error::PermLibError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Hash, Eq, Copy)]
#[repr(u32)]
pub enum Role {
    SuperAdmin = 0,
    AgencyOwner = 1,
    AgencyAdmin = 2,
    AgencyMember = 3,
    TenantAdmin = 4,
    Editor = 5,
    Client = 6,
    Guest = 7,
}

impl Role {
    pub fn from_id(id: u32) -> Option<Role> {
        match id {
            0 => Some(Role::SuperAdmin),
            1 => Some(Role::AgencyOwner),
            2 => Some(Role::AgencyAdmin),
            3 => Some(Role::AgencyMember),
            4 => Some(Role::TenantAdmin),
            5 => Some(Role::Editor),
            6 => Some(Role::Client),
            7 => Some(Role::Guest),
            _ => None,
        }
    }

    pub fn to_id(&self) -> u32 {
        *self as u32
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Role::SuperAdmin => "SuperAdmin",
            Role::AgencyOwner => "AgencyOwner",
            Role::AgencyAdmin => "AgencyAdmin",
            Role::AgencyMember => "AgencyMember",
            Role::TenantAdmin => "TenantAdmin",
            Role::Editor => "Editor",
            Role::Client => "Client",
            Role::Guest => "Guest",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(input: &str) -> Result<Role, Self::Err> {
        match input {
            "SuperAdmin" => Ok(Role::SuperAdmin),
            "AgencyOwner" => Ok(Role::AgencyOwner),
            "AgencyAdmin" => Ok(Role::AgencyAdmin),
            "AgencyMember" => Ok(Role::AgencyMember),
            "TenantAdmin" => Ok(Role::TenantAdmin),
            "Editor" => Ok(Role::Editor),
            "Client" => Ok(Role::Client),
            "Guest" => Ok(Role::Guest),
            _ => Err(()),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // UserID o Username
    pub exp: usize,          // Expiración
    pub permissions: Vec<u32>,
    pub role_id: u32,        // ID numérico del rol
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Auth
{
    pub _id:         Option<AuthID>,
    pub user_id: UserID,
    pub username:    String,
    pub email:       String,
    pub password:    String,
    pub roles: Role,
    pub permissions: Vec<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Token
{
    pub token: String,
}

impl Token
{
    pub fn new(secret: String, auth: Auth) -> Result<Token, PermLibError>
    {
      
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        let exp = (since_the_epoch.as_secs() + 3600) as usize;

        let claims = Claims {
            sub: auth.username,
            role_id: auth.roles.to_id(),
            exp,
            permissions: auth.permissions,
        };
        
        let token =
            encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).map_err(|_| PermLibError::FailToCreateToken)?;

        Ok(Token{token})
    }

    pub fn verify(secret: String, token: &str) -> Result<Claims, PermLibError> {
        decode_token(token, &secret)
    }
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, PermLibError> {
    let validation = Validation::default();

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    ).map_err(|_| PermLibError::InvalidToken)?;
    Ok(token_data.claims)
}