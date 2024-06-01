use std::{
    fs::File, io::{BufRead, BufReader}, net::ToSocketAddrs, process
};
use krb5asn1::{
    structures::*,
    helpers::*,
    constants::*
};
use krb5rs::{
    builder::asreq,
    Kdc
};
use rayon::ThreadPoolBuilder;
use crate::arguments::UserbruteArgs;
use crate::helpers::*;

pub fn start(args: UserbruteArgs) {
    let sock_addr = (args.ip, 88u16).to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let dc = Kdc::new(sock_addr, args.domain);
    if args.username.username.is_some() {
        check_user(&dc, args.username.username.unwrap(), args.npauth);
    }
    if args.username.userlist.is_some() {
        let file = File::open(args.username.userlist.unwrap())
            .unwrap_or_else(|e| {
                println!("{M}Cannot read file: {}", e);
                process::exit(0);
            });
        let reader = BufReader::new(file);
        start_thread(&dc, reader, args.threads, args.npauth);
    }
}

fn start_thread(dc: &Kdc, reader: BufReader<File>, threads: usize, npauth: bool) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap_or_else(|e| {
            println!("Unable to build threadpool: {}", e);
            process::exit(0);
        });

    pool.install(|| {
        rayon::scope(|s| {
            for username in reader.lines() {
                s.spawn(|_| {
                    check_user(dc, username.unwrap(), npauth);
                })
            }
        })
    })
}

fn check_user(dc: &Kdc, username: String, npauth: bool) -> i32 {
    let asreq = asreq(
        KerberosString::from_bytes(username.as_bytes()).unwrap(),
        Realm::from_bytes(dc.realm.as_bytes()).unwrap(),
        None
    );
    let response = dc.talk_tcp(&asreq.derencoder().unwrap())
        .unwrap_or_else(|e|{
            println!("{M}Cannot connect to the domain controller: {}",e);
            process::exit(0)
        });
    let presponse = AsRep::derdecoder(&response)
        .map_err(|_| {
            KrbError::derdecoder(&response)
                .unwrap_or_else(|e| {
                    println!("{M}Cannot parse server's response! [{e}]");
                    println!("{M}Exiting!");
                    process::exit(0);
                })
        });
    match presponse {
        Ok(asrep) => {
            println!("{P}Valid User: {} - No Preauthentication required!", username);
            if npauth {
                dump_creds(asrep);
            }
            return 1
        },
        Err(krberr) => {
            let err_code = krberr.error_code;
            let error = krberr.geterrorvalue()
                .unwrap();
            if err_code == krberror::KDC_ERR_WRONG_REALM {
                println!("{M}Wrong Domain! Exiting!");
                process::exit(0);
            }
            let valiusererrorcodes = [
                krberror::KDC_ERR_PREAUTH_REQUIRED,
            ];
            if valiusererrorcodes.contains(&err_code) {
                println!("{P}Valid User: {} - [{}]", username, error);
                return 1;
            }
        }
    }
    0
}

fn dump_creds(asrep: AsRep) {
    todo!("implement npauth dump creds");
}
