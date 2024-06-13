use krb5rs::{
    asn1::structures::*,
    errors::RespError,
    dns::resolve_dns
};
use hex;
use std::net::SocketAddr;
use std::process;

pub const BANNER: &str = "
  _  __         _                         _   
 | |/ /        | |                       | |  
 | ' / ___ _ __| |__   ___ _ __ _   _ ___| |_ 
 |  < / _ | '__| '_ \\ / _ | '__| | | / __| __|
 | . |  __| |  | |_) |  __| |  | |_| \\__ | |_ 
 |_|\\_\\___|_|  |_.__/ \\___|_|   \\__,_|___/\\__|
";

pub const P: &str = "[+] ";
pub const M: &str = "[-] ";

pub fn asrep_to_hash(asrep: AsRep) -> String {
    let etype = asrep.0.enc_part.etype;
    let cname = String::from_utf8(asrep.0.cname.name_string[0].to_vec()).unwrap();
    let realm = String::from_utf8(asrep.0.crealm.to_vec()).unwrap();
    let cp1 = hex::encode(&asrep.0.enc_part.cipher[..16]);
    let cp2 = hex::encode(&asrep.0.enc_part.cipher[16..]);
    format!(
        "$krb5asrep${}${}@{}:{}${}",
        etype,
        cname,
        realm,
        cp1,
        cp2
    )
}

pub fn getkrberror(resperror: RespError) -> KrbError {
    match resperror {
        RespError::IO(io_e) => {
            eprintln!("{M}Cannot connect to the domain controller: {io_e}");
            process::exit(0);
        },
        RespError::Decode(d_e) => {
            eprintln!("{M}Cannot parse response from server: {d_e}");
            process::exit(0);
        },
        RespError::Krb(krberror) => {
            krberror.clone()
        }
    }
}

pub fn try_resolve(domain: &str) -> SocketAddr {
    let mut domain = String::from(domain);
    domain.push_str(":88");
    resolve_dns(domain.as_ref())
        .unwrap_or_else(|e| {
            println!("Unable to resolve DNS: {e}");
            println!("Use --ip to specify IP address!");
            process::exit(0);
        })
        .unwrap_or_else(|| {
            println!("Unable to resolve DNS: No IP address found");
            println!("Use --ip to specify IP address!");
            process::exit(0);
        })
}
