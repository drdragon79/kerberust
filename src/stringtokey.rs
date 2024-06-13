use crate::arguments::StringtokeyArgs;
use krb5rs::crypto::Cipher;
use hex;
use crate::helpers::*;

pub fn start(args: StringtokeyArgs) {
    println!("{P}Using password: {}", args.password);
    println!("{P}Using salt: {}", args.salt);
    let password = args.password.as_bytes();
    let salt = args.salt.as_bytes();
    let aes = Cipher::AES256;
    let key = aes.string2key(password, salt, args.iteration);
    let hexed_key = hex::encode(key);
    println!("{P}AES256 Key: {hexed_key}");
    let aes = Cipher::AES128;
    let key = aes.string2key(password, salt, args.iteration);
    let hexed_key = hex::encode(key);
    println!("{P}AES128 Key: {hexed_key}");
    let rc4 = Cipher::RC4;
    let key = rc4.string2key(password, b"", None);
    let hexed_key = hex::encode(key);
    println!("{P}RC4 Key: {hexed_key}");
}
