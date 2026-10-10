//! Make the simulated Keycard at `host:port` ready for tests: its identity, PIN 123456, PUK
//! 987654321098 and the BIP39 test phrase's key. `--fresh` starts from a factory-fresh card first;
//! `--no-key` stops before the key; `--untrusted` has another CA sign its identity, as for a card
//! Keycard didn't make.

use keycard_module::sim::{self, Setup};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(addr) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: keycard-simulator-setup <host:port> [--fresh] [--no-key] [--untrusted]");
        std::process::exit(2);
    };
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let mut setup = Setup::default();
    if has("--no-key") {
        setup.phrase = None;
    }
    if has("--untrusted") {
        setup.ca = sim::OTHER_CA_SECRET;
        setup.identity = sim::OTHER_IDENTITY_SECRET;
    }
    let done = (if has("--fresh") {
        sim::fresh(addr)
    } else {
        Ok(())
    })
    .and_then(|()| sim::personalize(addr, &setup));
    match done {
        Ok(()) => println!("ready {addr}"),
        Err(e) => {
            eprintln!("keycard-simulator-setup: {e}");
            std::process::exit(1);
        }
    }
}
