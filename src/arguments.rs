use clap::{
    Parser,
    Subcommand,
    Args
};
use std::net::Ipv4Addr;
use hex;

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Module to execute
    #[command(subcommand)]
    pub mode: Mode,

    // #[arg(long, short, action = clap::ArgAction::Count)]
    // pub verbose: u8,

    /// Dont print Kerberust banner
    #[arg(long, default_value_t = false)]
    pub nobanner: bool
}

#[derive(Subcommand)]
pub enum Mode {
    Userenum(UserenumArgs),
    Stringtokey(StringtokeyArgs),
}

// USER ENUM ARGS
#[derive(Args)]
pub struct UserenumArgs {
    /// IP Address of the domain controller
    #[arg(long, short, value_parser = validate_ip)]
    pub ip: Option<String>,

    /// Target domain name
    #[arg(long, short, value_parser = validate_ascii)]
    pub domain: String,

    #[command(flatten)]
    pub username: Username,

    /// Number of parallel threads
    #[arg(long, short, default_value_t = 2)]
    pub threads: usize,

    /// Dump AS-REP hash for users that lack kerberos preauthentication
    #[arg(long)]
    pub npauth: bool,

    /// Do no negotiate RC4-HMAC etype.
    #[arg(long)]
    pub opsec: bool
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct Username {
    /// Single username
    #[arg(long, value_parser = validate_ascii)]
    pub username: Option<String>,

    /// Username file
    #[arg(long)]
    pub userlist: Option<String>
}

// STRING TO KEY ARGS
#[derive(Args)]
pub struct StringtokeyArgs {
    /// Password of the user
    #[arg(long, short)]
    pub password: String,

    /// Salt for the user
    #[arg(long, short)]
    pub salt: String,

    /// Optional iteration value for AES PBKDF2 computation. Default value = 4096
    #[arg(long, short)]
    pub iteration: Option<u32>,
}

// VALIDATORS
/// IP Address validator
fn validate_ip(s: &str) -> Result<String, String> {
    let _ip = s.parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IP Address!".to_string())?;
    Ok(s.to_string())
}

/// AES128 key validator
fn validate_aes128(s: &str) -> Result<String, String> {
    let decoded = hex::decode(s)
        .map_err(|e| format!("Invalid hex value: [{e}]"))?;
    if decoded.len() != 16 {
        Err("Invalid key length!".to_string())
    } else {
        Ok(s.to_string())
    }
}

/// AES256 key validator
fn validate_aes256(s: &str) -> Result<String, String> {
    let decoded = hex::decode(s)
        .map_err(|e| format!("Invalid hex value [{e}]"))?;
    if decoded.len() != 32 {
        Err("Invalid key length!".to_string())
    } else {
        Ok(s.to_string())
    }
}

/// ASCII string validator
fn validate_ascii(s: &str) -> Result<String, String> {
     if s
        .chars()
        .all(|x| x.is_ascii()) {
        Ok(s.to_string())
    } else {
        Err("String has non ascii characters!".to_string())
    }
}