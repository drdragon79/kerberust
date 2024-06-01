use crate::arguments::StringtokeyArgs;
use krb5rs::crypto::AES;
use hex;
use crate::helpers::*;

pub fn start(args: StringtokeyArgs) {
    println!("{P}Using password: {}", args.password);
    println!("{P}Using salt: {}", args.salt);
    let password = args.password.as_bytes();
    let salt = args.salt.as_bytes();
    if args.keytype.aes256 {
        let aes = AES::AES256;
        let key = aes.string2key(password, salt, args.iteration);
        let hexed_key = hex::encode(key);
        println!("{P}AES256 Key: {hexed_key}");
    }
    if args.keytype.aes128 {
        let aes = AES::AES128;
        let key = aes.string2key(password, salt, args.iteration);
        let hexed_key = hex::encode(key);
        println!("{P}AES128 Key: {hexed_key}");
    }

}
