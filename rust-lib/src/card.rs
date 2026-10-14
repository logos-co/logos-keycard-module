//! One session with a Keycard, through keycard-rs: SELECT, the secure channel, the PIN, and the
//! public-key exports, administration commands and signing.

use std::str::FromStr;

use bitcoin::secp256k1::{ecdsa, schnorr, PublicKey};
use keycard_rs::constants::{export_key_p2, sign_p2};
use keycard_rs::parsing::key_path::KeyPath;
use keycard_rs::parsing::{ApplicationInfo, Bip32KeyPair, Certificate};
use keycard_rs::{ApduResponse, KeycardCommandSet, Pairing, SecureChannelVersion};
use serde::Serialize;

use crate::link::Channel;

/// Why a card did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardError {
    /// SELECT found no Keycard applet.
    NotKeycard,
    /// A 4.0 card whose identity no trusted CA signed, nor the person trusted: its identity key.
    Untrusted(Option<String>),
    NotInitialized,
    /// Initialised, but holding no key yet.
    NoKey,
    /// A 3.x card this module holds no working pairing for.
    NotPaired,
    WrongPin(u8),
    PinBlocked,
    WrongPuk(u8),
    PukBlocked,
    /// A wrong pairing password.
    WrongPairing,
    /// No free pairing slot on a 3.x card.
    NoPairingSlot,
    /// A status word the card refused the command with.
    Refused(u16),
    /// The reader, the card or the secure channel failed.
    Link(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::NotKeycard => f.write_str("this card is not a Keycard"),
            CardError::Untrusted(_) => {
                f.write_str("this card's identity is not signed by Keycard: it may not be genuine")
            }
            CardError::NotInitialized => f.write_str(
                "this Keycard is not set up yet: open Card administration to set its PIN",
            ),
            CardError::NoKey => f.write_str(
                "this Keycard holds no key yet: create or import one in Card administration",
            ),
            CardError::NotPaired => f.write_str("pair this Keycard in the Keycard app first"),
            CardError::WrongPin(n) => write!(f, "wrong PIN: {n} tries left"),
            CardError::PinBlocked => {
                f.write_str("the PIN is blocked: unblock it with the PUK in the Keycard app")
            }
            CardError::WrongPuk(n) => write!(f, "wrong PUK: {n} tries left"),
            CardError::PukBlocked => f.write_str("the PUK is blocked: this card can only be reset"),
            CardError::WrongPairing => f.write_str("wrong pairing password"),
            CardError::NoPairingSlot => f.write_str(
                "this Keycard has no free pairing slot: free one in Card administration",
            ),
            CardError::Refused(sw) => write!(f, "the Keycard answered {sw:04x}"),
            CardError::Link(why) => write!(f, "Keycard link: {why}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, CardError>;

fn link(e: keycard_rs::Error) -> CardError {
    match e {
        keycard_rs::Error::WrongPin(w) => CardError::WrongPin(w.retry_attempts),
        keycard_rs::Error::Apdu(a) => CardError::Refused(a.sw()),
        keycard_rs::Error::Protocol(m) if m.contains("certificate") => CardError::Untrusted(None),
        other => CardError::Link(other.to_string()),
    }
}

fn ok(r: &ApduResponse) -> Result<()> {
    match r.sw() {
        0x9000 => Ok(()),
        sw => Err(CardError::Refused(sw)),
    }
}

/// What SELECT tells, before any secret: nothing in it is secret either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardInfo {
    /// The applet's version, such as `3.1` or `4.0`.
    pub version: String,
    /// Physical-card guard, also available before a 3.x card is initialized.
    pub admin_id: String,
    pub capabilities: u8,
    pub free_pairing_slots: u8,
    pub initialized: bool,
    /// The SHA-256 of the card's master public key, hex; absent while it holds no key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_uid: Option<String>,
    /// A 3.x card's instance UID, which its pairing is kept by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_uid: Option<String>,
    /// 1 for a 3.x card, which needs pairing; 2 for a 4.0 card, which proves its identity.
    pub secure_channel: u8,
    /// Only a 4.0 card says before its PIN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_retries: Option<u8>,
    /// BIP340 signing, taproot's, needs applet 4.0.
    pub taproot: bool,
    /// A 4.0 card's identity key, compressed, hex, from its certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Keycard didn't sign this card's identity: it is used only because the person trusted it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub trusted_by_person: bool,
}

impl CardInfo {
    /// Identifies the card/applet, independently of the wallet seed it currently holds.
    pub fn id(&self) -> Option<String> {
        if self.secure_channel == 2 {
            self.identity.as_ref().map(|id| format!("identity:{id}"))
        } else {
            self.instance_uid
                .as_ref()
                .map(|id| format!("instance:{id}"))
        }
    }

    fn of(info: &ApplicationInfo, trusted_by_person: bool) -> CardInfo {
        let v2 = info.app_version() >= 0x0400;
        CardInfo {
            version: info.app_version_string(),
            admin_id: certificate(info)
                .map(|c| format!("identity:{}", hex::encode(c.ident_pub())))
                .or_else(|| {
                    info.instance_uid()
                        .map(|v| format!("instance:{}", hex::encode(v)))
                })
                .unwrap_or_else(|| {
                    use bitcoin::hashes::{sha256, Hash};
                    format!(
                        "setup:{}",
                        sha256::Hash::hash(info.secure_channel_pub_key().unwrap_or_default())
                    )
                }),
            capabilities: info.capabilities(),
            free_pairing_slots: info.free_pairing_slots(),
            initialized: info.is_initialized(),
            key_uid: info.has_master_key().then(|| hex::encode(info.key_uid())),
            instance_uid: info.instance_uid().map(hex::encode),
            secure_channel: if v2 { 2 } else { 1 },
            pin_retries: info.pin_retries(),
            taproot: v2,
            identity: certificate(info).map(|c| hex::encode(c.ident_pub())),
            trusted_by_person,
        }
    }
}

fn certificate(info: &ApplicationInfo) -> Option<Certificate> {
    Certificate::from_tlv(info.cert_data()?).ok()
}

/// A Keycard, selected.
pub struct Card {
    pub(crate) cmd: KeycardCommandSet,
    info: ApplicationInfo,
    trusted_by_person: bool,
}

impl Card {
    /// Select the Keycard applet. A 4.0 card's identity must be signed by one of `cas`, or be one
    /// of the identity keys in `trusted`, the cards the person chose to trust.
    pub fn select(channel: Channel, cas: Vec<[u8; 33]>, trusted: Vec<[u8; 33]>) -> Result<Card> {
        let mut cmd = KeycardCommandSet::new_with_cas(channel, cas.clone(), trusted);
        let r = match cmd.select() {
            Ok(r) => r,
            Err(e) => {
                return Err(match link(e) {
                    CardError::Untrusted(_) => CardError::Untrusted(
                        cmd.app_info()
                            .and_then(certificate)
                            .map(|c| hex::encode(c.ident_pub())),
                    ),
                    other => other,
                })
            }
        };
        if r.sw() != 0x9000 {
            return Err(CardError::NotKeycard);
        }
        let info = cmd.app_info().cloned().ok_or(CardError::NotKeycard)?;
        let trusted_by_person = certificate(&info)
            .is_some_and(|c| !cas.iter().any(|ca| c.public_key() == ca.as_slice()));
        Ok(Card {
            cmd,
            info,
            trusted_by_person,
        })
    }

    pub fn info(&self) -> CardInfo {
        CardInfo::of(&self.info, self.trusted_by_person)
    }

    fn v1(&self) -> bool {
        self.cmd.secure_channel_version() == Some(SecureChannelVersion::V1)
    }

    /// Open the secure channel: with this module's pairing on a 3.x card, by the card's
    /// certified identity on a 4.0 one.
    pub fn open(&mut self, pairing: Option<Pairing>) -> Result<()> {
        if !self.info.is_initialized() {
            return Err(CardError::NotInitialized);
        }
        if self.v1() {
            self.cmd.set_pairing(pairing.ok_or(CardError::NotPaired)?);
            return self
                .cmd
                .auto_open_secure_channel()
                .map_err(|e| match link(e) {
                    CardError::Link(_) | CardError::Refused(_) => CardError::NotPaired,
                    other => other,
                });
        }
        self.cmd.auto_open_secure_channel().map_err(link)
    }

    /// Pair a 3.x card with its pairing password, for this module to keep.
    pub fn pair(&mut self, password: &str) -> Result<Pairing> {
        if !self.v1() {
            return Err(CardError::Refused(0x6d00));
        }
        if !self.info.is_initialized() {
            return Err(CardError::NotInitialized);
        }
        if self.info.free_pairing_slots() == 0 {
            return Err(CardError::NoPairingSlot);
        }
        self.cmd.auto_pair(password).map_err(|e| match link(e) {
            CardError::Link(m) if m.contains("cryptogram") => CardError::WrongPairing,
            CardError::Refused(0x6a84) => CardError::NoPairingSlot,
            other => other,
        })?;
        self.cmd
            .pairing()
            .cloned()
            .ok_or_else(|| CardError::Link("pairing returned nothing".into()))
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        let r = self.cmd.verify_pin(pin).map_err(link)?;
        match r.sw() {
            0x9000 => Ok(()),
            0x63c0 | 0x6983 => Err(CardError::PinBlocked),
            sw if sw & 0xfff0 == 0x63c0 => Err(CardError::WrongPin((sw & 0x0f) as u8)),
            sw => Err(CardError::Refused(sw)),
        }
    }

    /// Change the PIN; the current one must be verified first.
    pub fn change_pin(&mut self, new_pin: &str) -> Result<()> {
        ok(&self.cmd.change_pin(new_pin).map_err(link)?)
    }

    /// Unblock the PIN with the PUK, setting a new PIN.
    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> Result<()> {
        let r = self.cmd.unblock_pin(puk, new_pin).map_err(link)?;
        match r.sw() {
            0x9000 => Ok(()),
            0x63c0 | 0x6983 => Err(CardError::PukBlocked),
            sw if sw & 0xfff0 == 0x63c0 => Err(CardError::WrongPuk((sw & 0x0f) as u8)),
            sw => Err(CardError::Refused(sw)),
        }
    }

    fn has_key(&self) -> Result<()> {
        if self.info.has_master_key() {
            Ok(())
        } else {
            Err(CardError::NoKey)
        }
    }

    fn export(&mut self, path: &str, p2: u8) -> Result<Bip32KeyPair> {
        self.has_key()?;
        let kp = KeyPath::from_str(path).map_err(link)?;
        let r = self
            .cmd
            .export_key_raw(kp.data(), kp.source(), false, p2)
            .map_err(link)?;
        ok(&r)?;
        Bip32KeyPair::from_tlv(r.data()).map_err(link)
    }

    /// The public key at `path`, such as `m` or `m/44'/60'/0'/0/0`.
    pub fn export_public(&mut self, path: &str) -> Result<PublicKey> {
        let kp = self.export(path, export_key_p2::PUBLIC_ONLY)?;
        PublicKey::from_slice(kp.public_key()).map_err(|e| CardError::Link(e.to_string()))
    }

    /// The public key and chain code at `path`: an xpub's parts.
    pub fn export_extended(&mut self, path: &str) -> Result<(PublicKey, [u8; 32])> {
        let kp = self.export(path, export_key_p2::EXTENDED_PUBLIC)?;
        let key =
            PublicKey::from_slice(kp.public_key()).map_err(|e| CardError::Link(e.to_string()))?;
        let code = kp
            .chain_code()
            .and_then(|c| <[u8; 32]>::try_from(c).ok())
            .ok_or_else(|| CardError::Link("no chain code in the export".into()))?;
        Ok((key, code))
    }

    /// An ECDSA signature over `digest` by the key at `path`, with the key the card says signed.
    pub fn sign_ecdsa(
        &mut self,
        path: &str,
        digest: &[u8; 32],
    ) -> Result<(PublicKey, ecdsa::Signature)> {
        self.has_key()?;
        let r = self
            .cmd
            .sign_with_path_and_algo(digest, path, sign_p2::ECDSA, false)
            .map_err(link)?;
        ok(&r)?;
        let (key, sig) = signed(r.data())?;
        let sig = ecdsa::Signature::from_der(&sig)
            .or_else(|_| ecdsa::Signature::from_der_lax(&sig))
            .map_err(|e| CardError::Link(format!("the card's signature: {e}")))?;
        Ok((key, sig))
    }

    /// A BIP340 signature over `digest` by the key at `path` tweaked by `tweak`, as taproot's key
    /// path signs. Applet 4.0 only. The key the card names is the untweaked one.
    pub fn sign_bip340(
        &mut self,
        path: &str,
        digest: &[u8; 32],
        tweak: &[u8; 32],
    ) -> Result<(PublicKey, schnorr::Signature)> {
        self.has_key()?;
        let r = self
            .cmd
            .sign_bip341_schnorr(digest, tweak, path)
            .map_err(link)?;
        ok(&r)?;
        let (key, sig) = signed(r.data())?;
        let sig = schnorr::Signature::from_slice(&sig)
            .map_err(|e| CardError::Link(format!("the card's signature: {e}")))?;
        Ok((key, sig))
    }
}

/// One BER-TLV element: its tag, its value and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x81 => {
            let (&l, rest) = rest.split_first()?;
            (usize::from(l), rest)
        }
        0x82 => {
            let l = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
            (usize::from(l), rest.get(2..)?)
        }
        l if l < 0x80 => (usize::from(l), rest),
        _ => return None,
    };
    let value = rest.get(..len)?;
    Some((tag, value, &rest[len..]))
}

/// SIGN's answer: the signature template with the signing key (tag 0x80), then a DER signature
/// (0x30) or a raw one (0x88), returned whole.
fn signed(data: &[u8]) -> Result<(PublicKey, Vec<u8>)> {
    let bad = || CardError::Link("an answer to SIGN that doesn't parse".into());
    let (tag, inner, _) = tlv(data).ok_or_else(bad)?;
    if tag != 0xa0 {
        return Err(bad());
    }
    let (tag, key, rest) = tlv(inner).ok_or_else(bad)?;
    if tag != 0x80 {
        return Err(bad());
    }
    let key = PublicKey::from_slice(key).map_err(|_| bad())?;
    let (tag, value, after) = tlv(rest).ok_or_else(bad)?;
    match tag {
        0x30 => Ok((key, rest[..rest.len() - after.len()].to_vec())),
        0x88 => Ok((key, value.to_vec())),
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sign_answer_parses_both_ways() {
        let key = hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )
        .unwrap();
        let der = hex::decode("3006020101020102").unwrap();
        let mut inner = vec![0x80, 65];
        inner.extend_from_slice(&key);
        inner.extend_from_slice(&der);
        let mut data = vec![0xa0, 0x81, inner.len() as u8];
        data.extend_from_slice(&inner);
        let (k, sig) = signed(&data).unwrap();
        assert_eq!(k.serialize_uncompressed().to_vec(), key);
        assert_eq!(sig, der);

        let mut inner = vec![0x80, 65];
        inner.extend_from_slice(&key);
        inner.extend_from_slice(&[0x88, 64]);
        inner.extend_from_slice(&[7u8; 64]);
        let mut data = vec![0xa0, 0x81, inner.len() as u8];
        data.extend_from_slice(&inner);
        assert_eq!(signed(&data).unwrap().1, vec![7u8; 64]);
    }
}
