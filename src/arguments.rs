use clap::{
    Parser,
    Subcommand,
    Args
};

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// Module to run
    #[command(subcommand)]
    pub mode: Mode,

    #[arg(long, short, action = clap::ArgAction::Count)]
    pub verbose: u8
}

#[derive(Subcommand)]
pub enum Mode {
    Userbrute(UserbruteArgs),
    Stringtokey(StringtokeyArgs),
    Asktgt(AsktgtArgs)
}

#[derive(Args)]
pub struct UserbruteArgs {
    /// IP Address of the domain controller
    #[arg(long, short)]
    pub ip: String,

    /// Domain name
    #[arg(long, short)]
    pub domain: Option<String>,

    /// Username file
    #[arg(long, short)]
    pub userlist: String,

    /// Specify threads
    #[arg(long, short, default_value_t = 2)]
    pub threads: u8
}

#[derive(Args)]
pub struct StringtokeyArgs {
    /// Password of the user
    #[arg(long, short)]
    pub password: String,

    /// Optional salt for the domain. If salt is not provided, it will be fetched from the pre-auth request
    #[arg(long, short)]
    pub salt: Option<String>
}

#[derive(Args)]
pub struct AsktgtArgs {
    /// IP Address of the domain controller
    #[arg(long, short)]
    pub ip: String,

    /// Domain name
    #[arg(long, short)]
    pub domain: Option<String>,

    /// username
    #[arg(long, short)]
    pub username: String,

    #[command(flatten)]
    pub key: Keyfortgt
}

#[derive(Args)]
#[group(required = false , multiple = false)]
pub struct Keyfortgt {
    /// AES256 Key of the user
    #[arg(long, group = "auth")]
    pub aes256: String,

    /// AES128 Key of the user
    #[arg(long, group = "auth")]
    pub aes128: String,

    /// Password for the user
    #[arg(long, group = "auth")]
    pub password: String,
}
