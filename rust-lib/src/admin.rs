//! Physical-card administration. No signing and no persisted recovery material.
use crate::card::{Card, CardError};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{bip32::Xpriv, secp256k1::Secp256k1, Network};
use keycard_rs::{
    constants::{capability, get_status_p1, store_data_p1},
    parsing::{ApplicationStatus, Mnemonic},
    Metadata,
};
use logos_signer_interface::Secret;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Status,
    CheckIdentity,
    Initialize,
    Pair,
    ChangePin,
    ChangePuk,
    UnblockPin,
    ChangePairingPassword,
    Unpair,
    GeneratePhrase,
    LoadPhrase,
    VerifyPhrase,
    GenerateKey,
    RemoveKey,
    FactoryReset,
    ReadData,
    WriteData,
    SetName,
    SetNdef,
}

/// Every call names the physical card and the seed state the person reviewed. No default target.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub action: Action,
    pub reader: String,
    pub card_id: String,
    pub key_uid: String,
    #[serde(default)]
    pub pin: Option<Secret>,
    #[serde(default)]
    pub new_pin: Option<Secret>,
    #[serde(default)]
    pub puk: Option<Secret>,
    #[serde(default)]
    pub pairing_password: Option<Secret>,
    #[serde(default)]
    pub alternate_pin: Option<Secret>,
    #[serde(default)]
    pub phrase: Option<Secret>,
    #[serde(default)]
    pub passphrase: Option<Secret>,
    #[serde(default)]
    pub words: Option<u8>,
    #[serde(default)]
    pub slot: Option<u8>,
    #[serde(default)]
    pub data_type: u8,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub confirmation: String,
}

fn bad(message: &str) -> CardError {
    CardError::Link(message.into())
}
fn secret(value: &Option<Secret>) -> &str {
    value.as_ref().map(Secret::expose).unwrap_or("")
}
fn digits(s: &str, n: usize) -> Result<(), CardError> {
    if s.len() == n && s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(bad(if n == 6 {
            "PIN must be six digits"
        } else {
            "PUK must be twelve digits"
        }))
    }
}
fn check(
    r: Result<keycard_rs::ApduResponse, keycard_rs::Error>,
) -> Result<keycard_rs::ApduResponse, CardError> {
    let r = r.map_err(|e| bad(&e.to_string()))?;
    if r.sw() == 0x9000 {
        Ok(r)
    } else {
        Err(CardError::Refused(r.sw()))
    }
}
fn mnemonic(req: &Request) -> Result<bip39::Mnemonic, CardError> {
    let normalized = Zeroizing::new(
        secret(&req.phrase)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    );
    // Do not include parser errors: some contain words from the recovery phrase.
    bip39::Mnemonic::parse_in(bip39::Language::English, &*normalized)
        .map_err(|_| bad("Enter a valid English BIP39 recovery phrase with a valid checksum"))
}

pub(crate) const DEFAULT_PAIRING_PASSWORD: &str = "KeycardDefaultPairing";

impl Request {
    pub fn validate(&self) -> Result<(), CardError> {
        use Action::*;
        if self.reader.is_empty() || self.card_id.is_empty() {
            return Err(bad("Select a physical card"));
        }
        if self.text.len() > 4096
            || secret(&self.phrase).len() > 1024
            || secret(&self.passphrase).len() > 1024
        {
            return Err(bad("Input is too long"));
        }
        if self.needs_pin() {
            digits(secret(&self.pin), 6)?;
        }
        if matches!(self.action, Initialize | ChangePin | UnblockPin) {
            digits(secret(&self.new_pin), 6)?;
        }
        if matches!(self.action, Initialize | ChangePuk | UnblockPin) {
            digits(secret(&self.puk), 12)?;
        }
        if self.action == Initialize && self.alternate_pin.is_some() {
            digits(secret(&self.alternate_pin), 6)?;
            if secret(&self.new_pin) == secret(&self.alternate_pin) {
                return Err(bad("Use a different alternate PIN"));
            }
        }
        if (matches!(self.action, Pair | ChangePairingPassword)
            || (self.action == Initialize && self.pairing_password.is_some()))
            && (secret(&self.pairing_password).is_empty()
                || secret(&self.pairing_password).len() > 128)
        {
            return Err(bad("Enter a pairing password of 1 to 128 bytes"));
        }
        if self.action == GeneratePhrase && !matches!(self.words, Some(12 | 15 | 18 | 21 | 24)) {
            return Err(bad("Choose 12, 15, 18, 21 or 24 words"));
        }
        if matches!(self.action, LoadPhrase | VerifyPhrase) {
            mnemonic(self)?;
        }
        let needed = match self.action {
            FactoryReset => "RESET",
            RemoveKey => "ERASE",
            GenerateKey => "NO BACKUP",
            LoadPhrase => "BACKED UP",
            WriteData => "WRITE",
            _ => "",
        };
        if !needed.is_empty() && self.confirmation != needed {
            return Err(bad("Confirm the operation first"));
        }
        if self.action == Unpair && self.slot.is_none_or(|s| s > 9) {
            return Err(bad("Choose a pairing slot from 0 to 9"));
        }
        if matches!(self.action, ReadData | WriteData) && !matches!(self.data_type, 0 | 2) {
            return Err(bad("Choose public or Cash data"));
        }
        if self.action == WriteData && hex::decode(&self.text).ok().is_none_or(|d| d.len() > 127) {
            return Err(bad("Data must be hexadecimal, at most 127 bytes"));
        }
        if self.action == SetName
            && (!self.text.is_ascii()
                || self.text.len() > 20
                || self.text.chars().any(char::is_control))
        {
            return Err(bad(
                "Card name must be at most 20 printable ASCII characters",
            ));
        }
        if self.action == SetNdef && self.text.len() > 120 {
            return Err(bad("NFC message must be at most 120 UTF-8 bytes"));
        }
        Ok(())
    }
    pub fn needs_pin(&self) -> bool {
        !matches!(
            self.action,
            Action::CheckIdentity
                | Action::Initialize
                | Action::Pair
                | Action::Status
                | Action::UnblockPin
                | Action::FactoryReset
                | Action::ReadData
        )
    }
    pub fn pin(&self) -> &str {
        secret(&self.pin)
    }
    pub fn pairing_password(&self) -> &str {
        if self.action == Action::Initialize && self.pairing_password.is_none() {
            DEFAULT_PAIRING_PASSWORD
        } else {
            secret(&self.pairing_password)
        }
    }
}

/// Called only after an exact physical-card + current seed check and, where needed, PIN check.
pub(crate) fn execute(card: &mut Card, req: &Request) -> Result<Value, CardError> {
    use Action::*;
    let info = card.info();
    let caps = info.capabilities;
    let required = match req.action {
        Initialize | ChangePin | ChangePuk | UnblockPin => capability::CREDENTIALS_MANAGEMENT,
        GeneratePhrase | LoadPhrase | GenerateKey | RemoveKey => capability::KEY_MANAGEMENT,
        FactoryReset => capability::FACTORY_RESET,
        SetNdef => capability::NDEF,
        _ => 0,
    };
    if caps & required != required {
        return Err(bad("This operation is not supported by this card"));
    }
    if matches!(req.action, Pair | ChangePairingPassword | Unpair) && info.secure_channel != 1 {
        return Err(bad("This card does not use pairings"));
    }
    if matches!(req.action, LoadPhrase | GenerateKey) && info.key_uid.is_some() {
        return Err(bad("This card already holds a wallet. Erase its keys explicitly before loading another wallet"));
    }
    let result = match req.action {
        CheckIdentity => unreachable!("Identity is checked before opening a pairing"),
        Initialize => {
            if info.initialized {
                return Err(bad("This card is already initialized"));
            }
            if info.secure_channel == 1 {
                if req.pairing_password().is_empty() || req.pairing_password().len() > 128 {
                    return Err(bad("Set a pairing password of 1 to 128 bytes"));
                }
                if req.alternate_pin.is_some() {
                    return Err(bad("Alternate PIN setup requires Keycard 4.0"));
                }
                check(card.cmd.init(
                    secret(&req.new_pin),
                    secret(&req.puk),
                    req.pairing_password(),
                ))?;
            } else {
                let alt = req.alternate_pin.as_ref().map(Secret::expose);
                if alt.unwrap_or(&secret(&req.puk)[..6]) == secret(&req.new_pin) {
                    return Err(bad("The alternate PIN must differ from the main PIN; by default it is the first six PUK digits"));
                }
                check(card.cmd.init_v2_with_options(
                    secret(&req.new_pin),
                    alt,
                    secret(&req.puk),
                    if alt.is_some() { 3 } else { 0 },
                    if alt.is_some() { 5 } else { 0 },
                ))?;
            }
            json!({"message":"Card initialized. Pair it if requested, then create or import its recovery keys."})
        }
        Status => {
            let r = check(card.cmd.get_status(get_status_p1::APPLICATION))?;
            let s =
                ApplicationStatus::from_tlv(r.data()).map_err(|_| bad("Invalid card status"))?;
            let card_name = card
                .cmd
                .get_data(store_data_p1::PUBLIC)
                .ok()
                .filter(|r| r.sw() == 0x9000)
                .and_then(|r| Metadata::from_data(r.data()).ok())
                .map(|m| m.card_name().to_owned());
            json!({"cardName":card_name, "pinRetries":s.pin_retry_count(), "pukRetries":s.puk_retry_count(), "hasKey":s.has_master_key(), "freePairingSlots":info.free_pairing_slots,
                "pairingSlot":card.cmd.pairing().map(|p|p.pairing_index()), "message":"Card status read."})
        }
        Pair => {
            return Err(bad("Pairing is handled before opening the channel"));
        }
        ChangePin => {
            card.change_pin(secret(&req.new_pin))?;
            json!({"message":"PIN changed."})
        }
        UnblockPin => {
            card.unblock_pin(secret(&req.puk), secret(&req.new_pin))?;
            json!({"message":"PIN unblocked and changed."})
        }
        ChangePuk => {
            check(card.cmd.change_puk(secret(&req.puk)))?;
            json!({"message":"PUK changed."})
        }
        ChangePairingPassword => {
            check(card.cmd.change_pairing_password(req.pairing_password()))?;
            json!({"message":"Pairing password changed. Existing pairings still work."})
        }
        Unpair => {
            check(card.cmd.unpair(req.slot.unwrap()))?;
            json!({"message":"Pairing slot cleared."})
        }
        GeneratePhrase => {
            let r = check(card.cmd.generate_mnemonic(req.words.unwrap() / 3))?;
            if r.data().len() != req.words.unwrap() as usize * 2 {
                return Err(bad("Invalid recovery phrase response"));
            }
            let mut m = Mnemonic::from_card_response(r.data());
            m.set_bip39_english();
            let phrase = Zeroizing::new(
                m.to_phrase()
                    .map_err(|_| bad("Invalid word indexes from card"))?,
            );
            bip39::Mnemonic::parse(&*phrase).map_err(|_| bad("Invalid checksum from card"))?;
            json!({"phrase": &*phrase, "message":"Write down these words, then load them onto this card. They have not been loaded yet."})
        }
        LoadPhrase | VerifyPhrase => {
            let m = mnemonic(req)?;
            let seed = Zeroizing::new(m.to_seed(secret(&req.passphrase)));
            let mut master = Xpriv::new_master(Network::Bitcoin, &*seed)
                .map_err(|_| bad("Invalid recovery seed"))?;
            let uid = sha256::Hash::hash(
                &master
                    .private_key
                    .public_key(&Secp256k1::new())
                    .serialize_uncompressed(),
            )
            .to_string();
            if req.action == VerifyPhrase {
                // Root chain-code export is restricted on 4.0. A known derived public key
                // checks the chain code without extracting it (and detects the alternate PIN).
                let path = crate::accounts::EVM_PATH
                    .parse::<bitcoin::bip32::DerivationPath>()
                    .expect("constant BIP32 path");
                let mut child = master
                    .derive_priv(&Secp256k1::new(), &path)
                    .map_err(|_| bad("Could not derive recovery account"))?;
                let expected_child = child.private_key.public_key(&Secp256k1::new());
                child.private_key.non_secure_erase();
                master.private_key.non_secure_erase();
                let actual = card.export_public("m")?;
                let actual_child = card.export_public(crate::accounts::EVM_PATH)?;
                if sha256::Hash::hash(&actual.serialize_uncompressed()).to_string() != uid
                    || actual_child != expected_child
                {
                    return Err(bad(
                        "The recovery phrase and passphrase do not match this card's wallet",
                    ));
                }
                json!({"message":"Recovery phrase and passphrase match this card's wallet."})
            } else {
                master.private_key.non_secure_erase();
                check(card.cmd.load_key(&*seed))?;
                json!({"message":"Recovery keys loaded. Add accounts from the wallet to use them in apps."})
            }
        }
        GenerateKey => {
            check(card.cmd.generate_key())?;
            json!({"message":"Keys generated on the card. There is no recovery phrase or backup."})
        }
        RemoveKey => {
            check(card.cmd.remove_key())?;
            json!({"message":"Keys erased from this card. Saved accounts and names were retained."})
        }
        FactoryReset => {
            check(card.cmd.factory_reset())?;
            json!({"message":"Card reset. Set it up again before use. Saved accounts and names were retained."})
        }
        ReadData => {
            let r = check(card.cmd.get_data(req.data_type))?;
            json!({"data":hex::encode(r.data()), "message":"Card data read (hexadecimal)."})
        }
        WriteData => {
            check(
                card.cmd
                    .store_data(&hex::decode(&req.text).unwrap(), req.data_type),
            )?;
            json!({"message":"Card data written."})
        }
        SetName => {
            let r = check(card.cmd.get_data(store_data_p1::PUBLIC))?;
            let mut m = if r.data().is_empty() {
                Metadata::new(String::new())
            } else {
                Metadata::from_data(r.data()).map_err(|_| bad("Public data is not Keycard metadata. Read and back it up before replacing it with advanced data tools"))?
            };
            m.set_card_name(req.text.clone())
                .map_err(|_| bad("Invalid card name"))?;
            let data = m.to_bytes();
            check(card.cmd.store_data(&data, store_data_p1::PUBLIC))?;
            json!({"message":"Name written to the card; existing wallet metadata retained. Local wallet names are unchanged."})
        }
        SetNdef => {
            // A single well-known UTF-8 Text record, or an empty NDEF file to clear it.
            let mut data = Vec::new();
            if !req.text.is_empty() {
                data.extend_from_slice(&[0xd1, 1, (req.text.len() + 3) as u8, b'T', 2, b'e', b'n']);
                data.extend_from_slice(req.text.as_bytes());
            }
            check(card.cmd.set_ndef(&data))?;
            json!({"message":"NFC text saved. It can be read without your PIN."})
        }
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(action: &str, extra: Value) -> Request {
        let mut v = json!({"action":action,"reader":"test","cardId":"identity:test","keyUid":"","pin":"123456"});
        for (key, value) in extra.as_object().unwrap() {
            v[key] = value.clone();
        }
        serde_json::from_value(v).unwrap()
    }
    #[test]
    fn setup_defaults_pairing_but_preserves_explicit_custom_passwords() {
        let default = request("initialize", json!({"newPin":"123456","puk":"987654321098"}));
        assert!(default.validate().is_ok());
        assert_eq!(default.pairing_password(), DEFAULT_PAIRING_PASSWORD);
        let custom = request("initialize", json!({"newPin":"123456","puk":"987654321098","pairingPassword":"custom password"}));
        assert!(custom.validate().is_ok());
        assert_eq!(custom.pairing_password(), "custom password");
        let empty = request("initialize", json!({"newPin":"123456","puk":"987654321098","pairingPassword":""}));
        assert!(empty.validate().is_err());
        assert!(request("pair", json!({})).validate().is_err());
    }

    #[test]
    fn rejects_invalid_inputs_before_contacting_card() {
        for (action, extra) in [
            ("change_pin", json!({"newPin":"12"})),
            ("change_puk", json!({"puk":"123"})),
            (
                "load_phrase",
                json!({"phrase":"secret invalid phrase","confirmation":"BACKED UP"}),
            ),
            ("factory_reset", json!({})),
            ("remove_key", json!({})),
            ("generate_key", json!({})),
            ("generate_phrase", json!({"words":13})),
            ("write_data", json!({"confirmation":"WRITE","text":"zz"})),
            ("unpair", json!({"slot":10})),
            ("read_data", json!({"dataType":255})),
        ] {
            assert!(request(action, extra).validate().is_err(), "{action}");
        }
        let error = request("verify_phrase", json!({"phrase":"secret invalid phrase"}))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret invalid"));
    }
}
