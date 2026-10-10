//! The card's signatures in the interface's shape: an EVM one with its recovery id, found by
//! trial since the card gives none; a native segwit one in low S; a taproot one naming the tweaked
//! output key, worked out here rather than read from the card's answer.

use std::sync::OnceLock;

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::ecdsa::{self, RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{schnorr, All, Message, PublicKey, Secp256k1};
use bitcoin::taproot::TapTweakHash;
use logos_signer_interface::Signature;

fn secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

/// BIP86's tweak for an internal key with no script tree: what the card adds to the key it holds.
pub fn tweak(internal: &PublicKey) -> [u8; 32] {
    let (x, _) = internal.x_only_public_key();
    TapTweakHash::from_key_and_tweak(x, None)
        .to_scalar()
        .to_be_bytes()
}

/// A signature by `key` over `digest`, in low S, with its recovery id when `evm` asks for one.
pub fn ecdsa(
    item: usize,
    mut sig: ecdsa::Signature,
    key: &PublicKey,
    digest: &[u8; 32],
    evm: bool,
) -> Result<Signature, String> {
    sig.normalize_s();
    let compact = sig.serialize_compact();
    let msg = Message::from_digest(*digest);
    secp()
        .verify_ecdsa(&msg, &sig, key)
        .map_err(|_| "the card's signature is not by the account's key".to_string())?;
    let recovery_id = if evm {
        let found = (0..2).find(|id| {
            RecoveryId::from_i32(*id)
                .and_then(|rid| RecoverableSignature::from_compact(&compact, rid))
                .and_then(|rs| secp().recover_ecdsa(&msg, &rs))
                .is_ok_and(|k| k == *key)
        });
        Some(found.ok_or("no recovery id leads to the account's key")? as u8)
    } else {
        None
    };
    Ok(Signature {
        item,
        signature: hex::encode(compact),
        recovery_id,
        pubkey: hex::encode(key.serialize()),
    })
}

/// A BIP340 signature by `internal` tweaked as BIP86 says, naming the output key.
pub fn bip86(
    item: usize,
    sig: schnorr::Signature,
    internal: &PublicKey,
    digest: &[u8; 32],
) -> Result<Signature, String> {
    let (x, _) = internal.x_only_public_key();
    let (output, _) = x.tap_tweak(secp(), None);
    let output = output.to_x_only_public_key();
    secp()
        .verify_schnorr(&sig, &Message::from_digest(*digest), &output)
        .map_err(|_| "the card's signature is not by the account's tweaked key".to_string())?;
    Ok(Signature {
        item,
        signature: hex::encode(sig.serialize()),
        recovery_id: None,
        pubkey: hex::encode(output.serialize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    #[test]
    fn answers_name_their_key_and_check() {
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let key = sk.public_key(secp());
        let digest = [9u8; 32];
        let msg = Message::from_digest(digest);

        let sig = secp().sign_ecdsa(&msg, &sk);
        let evm = ecdsa(0, sig, &key, &digest, true).unwrap();
        assert!(evm.recovery_id.is_some());
        assert_eq!(evm.pubkey, hex::encode(key.serialize()));
        let other = SecretKey::from_slice(&[8u8; 32])
            .unwrap()
            .public_key(secp());
        assert!(ecdsa(0, sig, &other, &digest, true).is_err());

        // What the card does: the key, negated to an even Y, plus the tweak, then BIP340.
        let t = SecretKey::from_slice(&tweak(&key)).unwrap();
        let tweaked = Keypair::from_secret_key(secp(), &sk)
            .add_xonly_tweak(secp(), &t.into())
            .unwrap();
        let sig = secp().sign_schnorr_no_aux_rand(&msg, &tweaked);
        let tr = bip86(1, sig, &key, &digest).unwrap();
        assert_eq!(
            tr.pubkey,
            hex::encode(tweaked.x_only_public_key().0.serialize())
        );
        assert!(bip86(1, sig, &other, &digest).is_err());
    }
}
