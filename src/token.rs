pub mod auth_error;
use std::{fmt, str::FromStr, env, time::{SystemTime, UNIX_EPOCH}};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use crate::domains_id::{AuthID, UserID};
use crate::permissions::encode_perm;
use crate::token::auth_error::PermLibError;

impl fmt::Display for Role
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", match self
        {
            Role::SuperAdmin => "SuperAdmin",
            Role::Admin => "Admin",
            Role::Client => "Client",
            Role::Visitor => "Visitor",
        })
    }
}

impl FromStr for Role
{
    type Err = ();

    fn from_str(input: &str) -> Result<Role, Self::Err>
    {
        match input
        {
            "SuperAdmin" => Ok(Role::SuperAdmin),
            "Admin" => Ok(Role::Admin),
            "Client" => Ok(Role::Client),
            "Visitor" => Ok(Role::Visitor),
            _ => Err(()),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Hash, Eq)]
pub enum Role
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
    role: Role,
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
        let permission = encode_perm(auth.permissions);

        let claims = Claims {
            sub: auth.username,
            role: auth.roles,
            exp,
            permissions: permission,
        };
        
        let token =
            encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).map_err(|_| PermLibError::FailToCreateToken)?;

        Ok(Token{token})
    }
    pub fn verify(secret: String, token: &str) -> Result<Claims, PermLibError> {
        let validation = Validation::default();
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_ref()),
            &validation,
        ).map_err(|_| PermLibError::InvalidToken)?;
        Ok(token_data.claims)
    }

}