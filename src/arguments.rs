use clap::{
    Parser,
    Subcommand,
    Args
};
use std::{error::Error, net::Ipv4Addr};
use hex;

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Module to run
    #[command(subcommand)]
    pub mode: Mode,

    /// Set verbosity of the output
    #[arg(long, short, action = clap::ArgAction::Count)]
    pub verbose: u8
}

#[derive(Subcommand)]
pub enum Mode {
    Userbrute(UserbruteArgs),
    Stringtokey(StringtokeyArgs),
    Asktgt(AsktgtArgs)
}
// USER BRUTE ARGS ##############################################
#[derive(Args)]
pub struct UserbruteArgs {
    /// IP Address of the domain controller
    #[arg(long, short, value_parser = validate_ip)]
    pub ip: String,

    /// Domain name
    #[arg(long, short, value_parser = validate_ascii)]
    pub domain: String,

    #[command(flatten)]
    pub username: Username,

    /// Specify threads
    #[arg(long, short, default_value_t = 2)]
    pub threads: usize,

    #[arg(long)]
    pub npauth: bool
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct Username {
    /// Check validity of a single username
    #[arg(long, value_parser = validate_ascii)]
    pub username: Option<String>,

    /// Get usernames from a file
    #[arg(long)]
    pub userlist: Option<String>
}

// STRING TO KEY ARGS ##############################################
#[derive(Args)]
pub struct StringtokeyArgs {
    /// Password of the user
    #[arg(long, short)]
    pub password: String,

    /// Optional salt for the domain. If salt is not provided, it will be fetched from the pre-auth request
    #[arg(long, short)]
    pub salt: String,

    #[arg(long, short)]
    pub iteration: Option<u32>,

    #[command(flatten)]
    pub keytype: StringtokeyArgsKeytypeArgs
}

#[derive(Args)]
#[group(required = true, multiple = true)]
pub struct StringtokeyArgsKeytypeArgs {
    /// AES156 Key for the password
    #[arg(long)]
    pub aes256: bool,

    /// AES128 Key for the password
    #[arg(long)]
    pub aes128: bool
}



// ASKTGT ARGS ##############################################
#[derive(Args)]
pub struct AsktgtArgs {
    /// IP Address of the domain controller
    #[arg(long, short, value_parser = validate_ip)]
    pub ip: String,

    /// Domain name
    #[arg(long, short)]
    pub domain: Option<String>,

    /// username
    #[arg(long, short, value_parser = validate_ascii)]
    pub username: String,

    #[command(flatten)]
    pub key: Keyfortgt
}

#[derive(Args)]
#[group(required = true , multiple = false)]
pub struct Keyfortgt {
    /// AES256 Key of the user
    #[arg(long, value_parser = validate_aes256)]
    pub aes256: Option<String>,

    /// AES128 Key of the user
    #[arg(long, value_parser = validate_aes128)]
    pub aes128: Option<String>,

    /// Password for the user
    #[arg(long)]
    pub password: Option<String>,
}


// VALIDATORS
fn validate_ip(s: &str) -> Result<String, String> {
    let _ip = s.parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IP Address!".to_string())?;
    Ok(s.to_string())
}

fn validate_aes128(s: &str) -> Result<String, String> {
    let decoded = hex::decode(s)
        .map_err(|e| format!("Invalid hex value: [{e}]"))?;
    if decoded.len() != 16 {
        Err("Invalid key length!".to_string())
    } else {
        Ok(s.to_string())
    }
}

fn validate_aes256(s: &str) -> Result<String, String> {
    let decoded = hex::decode(s)
        .map_err(|e| format!("Invalid hex value [{e}]"))?;
    if decoded.len() != 32 {
        Err("Invalid key length!".to_string())
    } else {
        Ok(s.to_string())
    }
}

fn validate_ascii(s: &str) -> Result<String, String> {
     if s
        .chars()
        .all(|x| x.is_ascii()) {
        Ok(s.to_string())
    } else {
        Err("String has non ascii characters!".to_string())
    }
}
