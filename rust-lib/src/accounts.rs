//! The accounts a Keycard offers: an EVM address, and Bitcoin account xpubs built from what
//! EXPORT KEY gives, the account's key and chain code and its parent's key. Public material only.

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::NetworkKind;
use logos_signer_interface::{Account, Chain, Family};
use sha3::{Digest, Keccak256};

pub const HARDENED: u32 = 0x8000_0000;

/// The first EVM address.
pub const EVM_PATH: &str = "m/44'/60'/0'/0/0";

/// m/84' or m/86', then 0' for Bitcoin or 1' for the test networks, then the account.
pub fn bitcoin_path(family: Family, chain: Chain, account: u32) -> Option<String> {
    let purpose = match family {
        Family::Bitcoin => 84,
        Family::BitcoinTaproot => 86,
        Family::Evm => return None,
    };
    let coin = if chain == Chain::Main { 0 } else { 1 };
    (account < HARDENED).then(|| format!("m/{purpose}'/{coin}'/{account}'"))
}

/// A path without its last step: `m/84'/1'` for `m/84'/1'/0'`.
pub fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("m", |(parent, _)| parent)
}

/// The indexes of a path such as `m/84'/1'/0'/0/3`.
pub fn parse_path(s: &str) -> Option<Vec<u32>> {
    let rest = s.trim().strip_prefix('m')?;
    rest.split('/')
        .skip(1)
        .map(|step| {
            let (n, hard) = match step.strip_suffix(['\'', 'h']) {
                Some(n) => (n, HARDENED),
                None => (step, 0),
            };
            n.parse::<u32>()
                .ok()
                .filter(|n| *n < HARDENED)
                .map(|n| n | hard)
        })
        .collect()
}

/// The first four bytes of a key's HASH160: a master fingerprint, or an xpub's parent's.
pub fn fingerprint(key: &PublicKey) -> [u8; 4] {
    let h = hash160::Hash::hash(&key.serialize());
    [h[0], h[1], h[2], h[3]]
}

/// The xpub of hardened account `account`, three steps below the master.
pub fn xpub(
    chain: Chain,
    parent: &PublicKey,
    key: PublicKey,
    chain_code: [u8; 32],
    account: u32,
) -> Option<Xpub> {
    Some(Xpub {
        network: if chain == Chain::Main {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        },
        depth: 3,
        parent_fingerprint: Fingerprint::from(fingerprint(parent)),
        child_number: ChildNumber::from_hardened_idx(account).ok()?,
        public_key: key,
        chain_code: ChainCode::from(chain_code),
    })
}

/// The address a public key hashes to, in lowercase.
pub fn evm_address(key: &PublicKey) -> String {
    let hash = Keccak256::digest(&key.serialize_uncompressed()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn evm_account(address: &str, label: Option<String>) -> Account {
    let id = address.to_lowercase();
    Account {
        id: id.clone(),
        family: Family::Evm,
        chain: None,
        path: Some(EVM_PATH.into()),
        fingerprint: None,
        address: Some(id),
        xpub: None,
        label,
        available: true,
    }
}

pub fn bitcoin_account(
    master_fingerprint: [u8; 4],
    xpub: &Xpub,
    family: Family,
    chain: Chain,
    account: u32,
    label: Option<String>,
) -> Option<Account> {
    let path = bitcoin_path(family, chain, account)?;
    let fp = hex::encode(master_fingerprint);
    let purpose = if family == Family::Bitcoin { 84 } else { 86 };
    let coin = if chain == Chain::Main { 0 } else { 1 };
    Some(Account {
        id: format!("keycard-{fp}-{purpose}-{coin}-{account}"),
        family,
        chain: Some(chain),
        path: Some(path),
        fingerprint: Some(fp),
        address: None,
        xpub: Some(xpub.to_string()),
        label,
        available: true,
    })
}

/// A public-only display preview. Bitcoin accounts contain many addresses; preview /0/0
/// without changing their signer identity or requiring the card to be present.
pub fn address_preview(account: &Account) -> Result<serde_json::Value, &'static str> {
    use std::str::FromStr;
    use bitcoin::{Address, CompressedPublicKey, Network};
    use bitcoin::secp256k1::Secp256k1;
    if account.family == Family::Evm {
        return Ok(serde_json::json!({"address": account.address.as_deref().ok_or("Address unavailable")?,
            "path": account.path, "firstReceiving": false}));
    }
    let chain = account.chain.ok_or("Bitcoin network unavailable")?;
    let xpub = Xpub::from_str(account.xpub.as_deref().ok_or("Account public key unavailable")?)
        .map_err(|_| "Invalid account public key")?;
    let expected = if chain == Chain::Main { NetworkKind::Main } else { NetworkKind::Test };
    if xpub.network != expected { return Err("Account public key network mismatch"); }
    let secp = Secp256k1::verification_only();
    let child = xpub.derive_pub(&secp, &[ChildNumber::Normal {index:0}, ChildNumber::Normal {index:0}])
        .map_err(|_| "Could not derive the receiving address")?;
    let network = if chain == Chain::Main { Network::Bitcoin } else { Network::Testnet };
    let address = match account.family {
        Family::Bitcoin => Address::p2wpkh(&CompressedPublicKey(child.public_key), network),
        Family::BitcoinTaproot => Address::p2tr(&secp, child.public_key.x_only_public_key().0, None, network),
        Family::Evm => unreachable!(),
    };
    Ok(serde_json::json!({"address": address.to_string(),
        "path": account.path.as_ref().map(|p| format!("{p}/0/0")), "firstReceiving": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            bitcoin_path(Family::BitcoinTaproot, Chain::Test, 2).as_deref(),
            Some("m/86'/1'/2'")
        );
        assert_eq!(parent_path("m/84'/0'/0'"), "m/84'/0'");
        assert_eq!(parent_path("m/84'"), "m");
        assert_eq!(
            parse_path("m/84'/1'/0'/0/3"),
            Some(vec![HARDENED | 84, HARDENED | 1, HARDENED, 0, 3])
        );
        assert_eq!(parse_path("x/1"), None);
    }
}
