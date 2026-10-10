//! A simulated Keycard made ready for tests, over the simulator's TCP link: the identity a 4.0
//! card carries from its factory, then INIT with a PIN and PUK, and a key from a phrase.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use keycard_rs::parsing::Mnemonic;
use keycard_rs::{ApduResponse, KeycardCommandSet, SecureChannelVersion};

use crate::link::{TcpLink, SIMULATOR_CA};

/// The applet tests' CA key, which signs simulated cards' identities only.
const TEST_CA_SECRET: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa7, 0xb8, 0xc9, 0xd0, 0xe1, 0xf2, 0xa3, 0xb4, 0xc5, 0xd6,
    0xe7, 0xf8, 0xa9, 0xb0, 0xc1, 0xd2, 0xe3, 0xf4, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xf0, 0xa1, 0xb2,
];

/// The simulated card's identity key; a real card makes its own at the factory.
const IDENTITY_SECRET: [u8; 32] = [0x1d; 32];

/// The Keycard applet's instance, and the identity applet's, where a 4.0 card's certificate is.
const KEYCARD_AID: [u8; 9] = [0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01];
const IDENT_AID: [u8; 9] = [0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x04, 0x01];

/// The BIP39 test phrase, whose keys BIP84's and BIP86's published vectors use.
pub const TEST_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub struct Setup {
    pub pin: String,
    /// Applet 4.0 takes the PUK's first six digits as the alternate PIN, which opens a decoy
    /// wallet, so they must differ from the PIN.
    pub puk: String,
    /// A 3.x card's; a 4.0 card has none.
    pub pairing_password: String,
    /// The key to load; `None` leaves the card without one.
    pub phrase: Option<String>,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            pin: "123456".into(),
            puk: "987654321098".into(),
            pairing_password: "KeycardDefaultPairing".into(),
            phrase: Some(TEST_PHRASE.into()),
        }
    }
}

fn io(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn check(what: &str, r: Result<ApduResponse, keycard_rs::Error>) -> Result<(), String> {
    let r = r.map_err(|e| format!("{what}: {e}"))?;
    match r.sw() {
        0x9000 => Ok(()),
        sw => Err(format!("{what}: {sw:04x}")),
    }
}

/// Swap in a factory-fresh card: no identity, PIN or key.
pub fn fresh(addr: &str) -> Result<(), String> {
    let r = TcpLink::connect(addr)
        .map_err(io)?
        .exchange(&[0xff, 0x7f, 0, 0])
        .map_err(io)?;
    if r == [0x90, 0x00] {
        Ok(())
    } else {
        Err(format!("the simulator answered {}", hex::encode(r)))
    }
}

/// The certificate the test CA gives the simulated card: its identity key, compressed, then the
/// CA's recoverable signature over that key's SHA-256.
pub fn certificate() -> [u8; 98] {
    let secp = Secp256k1::new();
    let ident = SecretKey::from_slice(&IDENTITY_SECRET).expect("a valid key");
    let ca = SecretKey::from_slice(&TEST_CA_SECRET).expect("a valid key");
    let public = ident.public_key(&secp).serialize();
    let digest = sha256::Hash::hash(&public).to_byte_array();
    let (id, rs) = secp
        .sign_ecdsa_recoverable(&Message::from_digest(digest), &ca)
        .serialize_compact();
    let mut cert = [0u8; 98];
    cert[..33].copy_from_slice(&public);
    cert[33..97].copy_from_slice(&rs);
    cert[97] = id.to_i32() as u8;
    cert
}

/// Give the card its identity if it has none, set it up and load the key, as far as each is
/// still missing.
pub fn personalize(addr: &str, setup: &Setup) -> Result<(), String> {
    let mut raw = TcpLink::connect(addr).map_err(io)?;
    let select = |aid: &[u8]| {
        let mut c = vec![0x00, 0xa4, 0x04, 0x00, aid.len() as u8];
        c.extend_from_slice(aid);
        c
    };
    // A 4.0 card answers nothing until it holds a CA-signed identity, as from its factory.
    if raw
        .exchange(&select(&KEYCARD_AID))
        .map_err(io)?
        .ends_with(&[0x69, 0x85])
    {
        let r = raw.exchange(&select(&IDENT_AID)).map_err(io)?;
        if !r.ends_with(&[0x90, 0x00]) {
            return Err(format!("selecting the identity applet: {}", hex::encode(r)));
        }
        let mut store = vec![0x80, 0xe2, 0x00, 0x00, 130];
        store.extend_from_slice(&certificate());
        store.extend_from_slice(&IDENTITY_SECRET);
        let r = raw.exchange(&store).map_err(io)?;
        if r != [0x90, 0x00] {
            return Err(format!("storing the identity: {}", hex::encode(r)));
        }
    }
    drop(raw);

    let mut cmd = KeycardCommandSet::new_with_ca(TcpLink::connect(addr).map_err(io)?, SIMULATOR_CA);
    check("select", cmd.select())?;
    let v1 = cmd.secure_channel_version() == Some(SecureChannelVersion::V1);
    if !cmd.app_info().is_some_and(|i| i.is_initialized()) {
        let init = if v1 {
            cmd.init(&setup.pin, &setup.puk, &setup.pairing_password)
        } else {
            cmd.init_v2(&setup.pin, &setup.puk)
        };
        check("init", init)?;
        check("select", cmd.select())?;
    }
    if v1 {
        cmd.auto_pair(&setup.pairing_password)
            .map_err(|e| format!("pair: {e}"))?;
    }
    cmd.auto_open_secure_channel()
        .map_err(|e| format!("secure channel: {e}"))?;
    check("verify PIN", cmd.verify_pin(&setup.pin))?;
    let has_key = cmd.app_info().is_some_and(|i| i.has_master_key());
    if let (Some(phrase), false) = (&setup.phrase, has_key) {
        let seed = zeroize::Zeroizing::new(Mnemonic::binary_seed_from_phrase(phrase, ""));
        check("load key", cmd.load_key(&seed))?;
    }
    if v1 {
        cmd.auto_unpair().map_err(|e| format!("unpair: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_ca_is_the_one_the_simulator_link_trusts() {
        let secp = Secp256k1::new();
        let ca = SecretKey::from_slice(&TEST_CA_SECRET).unwrap();
        assert_eq!(ca.public_key(&secp).serialize(), SIMULATOR_CA);
        let cert = keycard_rs::parsing::Certificate::from_tlv(&certificate()).unwrap();
        assert_eq!(cert.public_key(), SIMULATOR_CA);
    }
}
