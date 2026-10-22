//! The module against the Keycard applet in jCardSim, built from its source: `sim/` serves it.
//! `KEYCARD_SIMULATOR=host:port` names a 4.0 card and `KEYCARD_SIMULATOR_V3` a 3.x one, which pairs.
//! Each test starts from a factory-fresh card, set up with PIN 123456 and the BIP39 test phrase's
//! key, so the tests share each card one at a time.

#![cfg(feature = "simulator")]

use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use keycard_module::accounts;
use keycard_module::link::Simulator;
use keycard_module::signer::{
    AddRequest, ChangePinRequest, KeycardSigner, PairRequest, Quiet, TrustRequest, UnblockRequest,
};
use keycard_module::sim::{self, Setup};
use keycard_module::store::Store;
use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::{
    verify, Account, Chain, ErrorCode, Family, HashItem, JobState, Payload, Scheme, Secret,
    SignRequest, Signer, UnlockKeyRequest,
};

/// BIP86's test vectors, from bitcoin/bips (fetched 2026-10-10), for the "abandon … about"
/// mnemonic: the root key, and account 0's xpub.
const BIP86_ROOTPRIV: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
const BIP86_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
/// BIP84's account 0 zpub, from the same fetch; compared past its version bytes.
const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

const PIN: &str = "123456";
const PUK: &str = "987654321098";

/// Each card is one, so the tests take turns at it.
fn turn() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(|e| e.into_inner())
}

fn turn_v3() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(|e| e.into_inner())
}

/// The simulator `var` names, or `None` to skip; CI sets `KEYCARD_SIMULATOR_REQUIRED` so that a
/// missing one fails instead.
fn named(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(a) if !a.trim().is_empty() => Some(a.trim().to_string()),
        _ if std::env::var_os("KEYCARD_SIMULATOR_REQUIRED").is_some() => {
            panic!("{var} names no simulator")
        }
        _ => {
            eprintln!("{var} names no simulator: skipped");
            None
        }
    }
}

fn simulator() -> Option<String> {
    named("KEYCARD_SIMULATOR")
}

/// A factory-fresh card set up with `setup`, and a signer in front of it.
fn rig(addr: &str, setup: &Setup) -> KeycardSigner {
    sim::fresh(addr).expect("a fresh card");
    sim::personalize(addr, setup).expect("the card set up");
    KeycardSigner::new(
        Box::new(Simulator::new(addr)),
        Store::new(),
        Box::new(Quiet),
    )
}

fn add(k: &KeycardSigner, families: Vec<Family>, chain: Chain) -> Vec<Account> {
    exported(k, add_request(families, chain)).unwrap_or_else(|e| panic!("export failed: {e}"))
}

/// An export's accounts, or why it failed, once it ends.
fn exported(k: &KeycardSigner, req: AddRequest) -> Result<Vec<Account>, String> {
    let job = k.add_accounts(req).map_err(|e| e.message)?;
    let start = Instant::now();
    loop {
        let st = k.add_status(&job).expect("the export's status");
        match st.state {
            "done" => return Ok(st.accounts),
            "failed" => return Err(st.error.unwrap_or_default()),
            _ => {}
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the export never ended"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn add_request(families: Vec<Family>, chain: Chain) -> AddRequest {
    AddRequest {
        families,
        chain,
        account: 0,
        label: None,
        reader: None,
        card_id: None,
        pin: Secret::new(PIN),
    }
}

fn settle(k: &mut KeycardSigner, job: &str) -> JobState {
    let start = Instant::now();
    loop {
        let st = k.status(job).expect("status");
        if st.state.is_final() {
            return st.state;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "job {job} never settled"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn request(account: &Account, pin: Option<&str>) -> SignRequest {
    SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(account),
        },
        secret: pin.map(Secret::new),
        xpub: None,
    }
}

#[test]
fn its_accounts_are_the_published_ones_for_the_test_phrase() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let k = rig(&addr, &Setup::default());
    let got = add(
        &k,
        vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        Chain::Main,
    );
    let secp = Secp256k1::new();
    let root = Xpriv::from_str(BIP86_ROOTPRIV).unwrap();
    let evm = root
        .derive_priv(
            &secp,
            &DerivationPath::from_str(accounts::EVM_PATH).unwrap(),
        )
        .unwrap();
    assert_eq!(
        got[0].address.as_deref(),
        Some(accounts::evm_address(&evm.private_key.public_key(&secp)).as_str())
    );
    let ours = bitcoin::base58::decode_check(got[1].xpub.as_deref().unwrap()).unwrap();
    let bip84 = bitcoin::base58::decode_check(BIP84_ZPUB).unwrap();
    assert_eq!(&ours[4..], &bip84[4..]);
    assert_eq!(got[2].xpub.as_deref(), Some(BIP86_XPUB));
    // Published BIP84/BIP86 first-receive vectors, not addresses computed by our helper.
    assert_eq!(
        accounts::address_preview(&got[0]).unwrap()["address"],
        got[0].address.as_deref().unwrap()
    );
    assert_eq!(
        accounts::address_preview(&got[0]).unwrap()["path"],
        accounts::EVM_PATH
    );
    assert_eq!(
        accounts::address_preview(&got[1]).unwrap()["address"],
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(
        accounts::address_preview(&got[1]).unwrap()["path"],
        "m/84'/0'/0'/0/0"
    );
    assert_eq!(
        accounts::address_preview(&got[2]).unwrap()["address"],
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    let mut offline = got[2].clone();
    offline.available = false;
    assert_eq!(
        accounts::address_preview(&offline).unwrap(),
        accounts::address_preview(&got[2]).unwrap()
    );
    offline.chain = Some(Chain::Test);
    assert!(
        accounts::address_preview(&offline).is_err(),
        "mismatched networks must not produce a copyable address"
    );
    let mut test_xpub = Xpub::from_str(offline.xpub.as_ref().unwrap()).unwrap();
    test_xpub.network = bitcoin::NetworkKind::Test;
    offline.xpub = Some(test_xpub.to_string());
    assert!(accounts::address_preview(&offline).unwrap()["address"]
        .as_str()
        .unwrap()
        .starts_with("tb1p"));
    offline.xpub = Some("invalid".into());
    assert!(accounts::address_preview(&offline).is_err());

    let fingerprint = hex::encode(Xpub::from_priv(&secp, &root).fingerprint().to_bytes());
    assert_eq!(got[1].fingerprint.as_deref(), Some(fingerprint.as_str()));
    assert_eq!(got[1].id, format!("keycard-{fingerprint}-84-0-0"));
    // The EVM address names the same wallet as the card's Bitcoin accounts.
    assert_eq!(got[0].fingerprint, got[1].fingerprint);
}

#[test]
fn it_passes_the_conformance_suite() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    add(
        &k,
        vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        Chain::Test,
    );
    conformance::run(
        &mut k,
        &Fixture {
            secret: Some(Secret::new(PIN)),
            wrong_secret: Some(Secret::new("654321")),
        },
        &mut |_, _| std::thread::sleep(Duration::from_millis(100)),
    );
}

#[test]
fn a_blocked_pin_is_unblocked_with_the_puk() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    let evm = add(&k, vec![Family::Evm], Chain::Test).remove(0);
    for left in [2, 1] {
        let e = k.sign(request(&evm, Some("000000"))).unwrap_err();
        assert_eq!(e.code, ErrorCode::WrongSecret);
        assert!(
            e.message.contains(&format!("{left} tries left")),
            "{}",
            e.message
        );
        let tries = k.cards()[0].card.as_ref().and_then(|c| c.pin_retries);
        assert_eq!(
            tries,
            Some(left),
            "the card is read again after each session"
        );
    }
    let e = k.sign(request(&evm, Some("000000"))).unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable, "{}", e.message);
    assert!(e.message.contains("blocked"), "{}", e.message);
    let e = k.sign(request(&evm, Some(PIN))).unwrap_err();
    assert!(
        e.message.contains("blocked"),
        "the right PIN no longer opens it: {}",
        e.message
    );

    let wrong = k.unblock_pin(UnblockRequest {
        reader: None,
        puk: Secret::new("000000000000"),
        new_pin: Secret::new("111111"),
    });
    assert_eq!(wrong.unwrap_err().code, ErrorCode::WrongSecret);
    k.unblock_pin(UnblockRequest {
        reader: None,
        puk: Secret::new(PUK),
        new_pin: Secret::new("111111"),
    })
    .expect("unblocked");
    let job = k
        .sign(request(&evm, Some("111111")))
        .expect("signs with the new PIN");
    assert_eq!(settle(&mut k, &job), JobState::Done);

    k.change_pin(ChangePinRequest {
        reader: None,
        pin: Secret::new("111111"),
        new_pin: Secret::new(PIN),
    })
    .expect("PIN changed back");
    let job = k.sign(request(&evm, Some(PIN))).expect("signs");
    assert_eq!(settle(&mut k, &job), JobState::Done);
}

#[test]
fn a_card_holding_another_key_signs_nothing_for_this_one() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    let accounts = add(&k, vec![Family::Evm, Family::Bitcoin], Chain::Test);
    assert!(k.accounts().unwrap().iter().all(|a| a.available));

    sim::fresh(&addr).unwrap();
    sim::personalize(
        &addr,
        &Setup {
            phrase: Some(
                "legal winner thank year wave sausage worth useful legal winner thank yellow"
                    .into(),
            ),
            ..Setup::default()
        },
    )
    .unwrap();
    k.refresh();
    assert!(k.accounts().unwrap().iter().all(|a| !a.available));
    for a in &accounts {
        let e = k.sign(request(a, Some(PIN))).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unavailable, "{}: {}", a.id, e.message);
    }
}

#[test]
fn a_bitcoin_item_signs_only_below_its_account() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    let tr = add(&k, vec![Family::BitcoinTaproot], Chain::Test).remove(0);
    let base = tr.path.clone().unwrap();
    for (path, scheme) in [
        (format!("{base}/0'/1"), Scheme::Bip86),
        ("m/86'/1'/1'/0/0".to_string(), Scheme::Bip86),
        (format!("{base}/0/1"), Scheme::Ecdsa),
    ] {
        let r = SignRequest {
            account: tr.id.clone(),
            payload: Payload::Hash {
                items: vec![HashItem {
                    path: Some(path.clone()),
                    scheme,
                    digest: hex::encode([5u8; 32]),
                }],
            },
            secret: Some(Secret::new(PIN)),
            xpub: None,
        };
        assert_eq!(k.sign(r).unwrap_err().code, ErrorCode::Invalid, "{path}");
    }
    // Change and receive keys both sign, and each signature checks against the account.
    let items: Vec<HashItem> = ["0/0", "1/7", "0/41"]
        .iter()
        .map(|tail| HashItem {
            path: Some(format!("{base}/{tail}")),
            scheme: Scheme::Bip86,
            digest: hex::encode([tail.len() as u8; 32]),
        })
        .collect();
    let job = k
        .sign(SignRequest {
            account: tr.id.clone(),
            payload: Payload::Hash {
                items: items.clone(),
            },
            secret: Some(Secret::new(PIN)),
            xpub: None,
        })
        .unwrap();
    assert_eq!(settle(&mut k, &job), JobState::Done);
    let sigs = k.result(&job).unwrap();
    assert_eq!(sigs.len(), 3);
    for s in &sigs {
        verify::check(&tr, &items[s.item], s).unwrap();
        assert_eq!(
            s.pubkey.len(),
            64,
            "a taproot answer names the x-only output key"
        );
    }
}

#[test]
fn the_alternate_pin_opens_another_wallet_and_signs_nothing_here() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    let evm = add(&k, vec![Family::Evm], Chain::Test).remove(0);
    // Applet 4.0 took the PUK's first six digits as the alternate PIN: it opens the card, whose
    // keys are then another wallet's.
    let job = k
        .sign(request(&evm, Some(&PUK[..6])))
        .expect("the alternate PIN opens the card");
    assert_eq!(settle(&mut k, &job), JobState::Failed);
    let e = k.status(&job).unwrap().error.unwrap();
    assert_eq!(e.code, ErrorCode::Unavailable, "{}", e.message);
    assert!(e.message.contains("alternate"), "{}", e.message);
    let job = k.sign(request(&evm, Some(PIN))).expect("the PIN signs");
    assert_eq!(settle(&mut k, &job), JobState::Done);
}

#[test]
fn a_3x_card_is_paired_once_then_signs() {
    let Some(addr) = named("KEYCARD_SIMULATOR_V3") else {
        return;
    };
    let _turn = turn_v3();
    let mut k = rig(&addr, &Setup::default());
    let card = k.cards().remove(0);
    let info = card.card.clone().expect("a Keycard");
    assert_eq!(info.secure_channel, 1, "{card:?}");
    assert!(!info.taproot && !card.paired, "{card:?}");

    let e = k
        .add_accounts(add_request(vec![Family::Evm], Chain::Test))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert!(e.message.contains("pair"), "{}", e.message);
    let wrong = k.pair(PairRequest {
        reader: None,
        pairing_password: Secret::new("not the password"),
    });
    assert_eq!(wrong.unwrap_err().code, ErrorCode::WrongSecret);
    k.pair(PairRequest {
        reader: None,
        pairing_password: Secret::new(Setup::default().pairing_password),
    })
    .expect("paired");
    assert!(k.cards()[0].paired);

    let e = exported(&k, add_request(vec![Family::BitcoinTaproot], Chain::Test)).unwrap_err();
    assert!(e.contains("4.0"), "taproot needs applet 4.0: {e}");
    let got = add(&k, vec![Family::Evm, Family::Bitcoin], Chain::Test);
    assert_eq!(got.len(), 2);
    conformance::run(
        &mut k,
        &Fixture {
            secret: Some(Secret::new(PIN)),
            wrong_secret: Some(Secret::new("654321")),
        },
        &mut |_, _| std::thread::sleep(Duration::from_millis(100)),
    );
}

#[test]
fn a_card_keycard_did_not_sign_is_used_only_once_the_person_trusts_it() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let unsigned = |identity| Setup {
        ca: sim::OTHER_CA_SECRET,
        identity,
        ..Setup::default()
    };
    let mut k = rig(&addr, &unsigned(sim::OTHER_IDENTITY_SECRET));
    let card = k.cards().remove(0);
    assert!(card.card.is_none(), "{card:?}");
    assert!(
        card.error
            .as_deref()
            .unwrap_or("")
            .contains("not signed by Keycard"),
        "{card:?}"
    );
    let identity = card.untrusted.clone().expect("its identity, to trust");
    assert!(exported(&k, add_request(vec![Family::Evm], Chain::Test)).is_err());

    let trust = |identity: &str| TrustRequest {
        reader: None,
        identity: identity.into(),
    };
    let e = k
        .trust_card(trust(&format!("02{}", "11".repeat(32))))
        .unwrap_err();
    assert_eq!(
        e.code,
        ErrorCode::Invalid,
        "only a card refused in a reader now"
    );
    k.trust_card(trust(&identity)).expect("trusted");
    let info = k.cards()[0].card.clone().expect("used once trusted");
    assert!(info.trusted_by_person);
    assert_eq!(info.identity.as_deref(), Some(identity.as_str()));
    let evm = add(&k, vec![Family::Evm], Chain::Test).remove(0);
    let job = k.sign(request(&evm, Some(PIN))).expect("signs");
    assert_eq!(settle(&mut k, &job), JobState::Done);

    assert!(k.forget_card(&identity).unwrap());
    let card = k.cards().remove(0);
    assert_eq!(
        card.untrusted.as_deref(),
        Some(identity.as_str()),
        "refused again"
    );
    assert!(!k.forget_card(&identity).unwrap());
    k.trust_card(trust(&identity)).expect("trusted again");

    // Another card Keycard didn't sign is still refused.
    sim::fresh(&addr).unwrap();
    sim::personalize(&addr, &unsigned([0x3c; 32])).unwrap();
    k.refresh();
    let other = k.cards().remove(0);
    assert!(other.card.is_none(), "{other:?}");
    assert!(other.untrusted.is_some() && other.untrusted != Some(identity));
}

#[test]
fn additional_evm_accounts_use_the_requested_path_and_reject_a_swapped_card() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    let first = add(&k, vec![Family::Evm], Chain::Main).remove(0);
    let mut req = add_request(vec![Family::Evm], Chain::Main);
    req.account = 1;
    req.card_id = Some("instance:not-the-selected-card".into());
    assert!(k.add_accounts(req.clone()).is_err());
    req.card_id = None;
    let second = exported(&k, req).unwrap().remove(0);
    assert_ne!(first.id, second.id);
    assert_eq!(second.path.as_deref(), Some("m/44'/60'/0'/0/1"));
    let req = request(&second, Some(PIN));
    let job = k.sign(req.clone()).unwrap();
    assert_eq!(settle(&mut k, &job), JobState::Done);
    let signatures = k.result(&job).unwrap();
    let Payload::Hash { items } = req.payload else {
        panic!("hash request")
    };
    for signature in &signatures {
        verify::check(&second, &items[signature.item], signature).unwrap();
    }
}

#[test]
fn applet_seed_identity_matches_hash_of_full_uncompressed_master_public_key() {
    use bitcoin::hashes::{sha256, Hash};
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let k = rig(&addr, &Setup::default());
    let root = Xpriv::from_str(BIP86_ROOTPRIV)
        .unwrap()
        .private_key
        .public_key(&Secp256k1::new());
    let expected = sha256::Hash::hash(&root.serialize_uncompressed()).to_string();
    assert_eq!(
        k.cards()[0].card.as_ref().unwrap().key_uid.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(k.card_groups()[0].id, format!("seed:{expected}"));
}

#[test]
fn a_public_offer_signs_through_a_matching_reader_without_importing_it() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let source = rig(&addr, &Setup::default());
    let accounts = add(
        &source,
        vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        Chain::Test,
    );
    let offers = source.routing_accounts();
    let mut target = KeycardSigner::new(
        Box::new(Simulator::new(&addr)),
        Store::new(),
        Box::new(Quiet),
    );
    for a in accounts {
        let v = &offers[&a.id];
        let offer = keycard_module::store::Offered {
            account: a.clone(),
            key_uid: v["masterKeyId"].as_str().unwrap().into(),
            key: v["key"].as_str().unwrap().into(),
        };
        let req = request(&a, Some(PIN));
        let Payload::Hash { items } = req.payload.clone() else {
            unreachable!()
        };
        let job = target.sign_offered(req, offer).unwrap();
        assert_eq!(settle(&mut target, &job), JobState::Done);
        for (item, sig) in items.iter().zip(target.result(&job).unwrap()) {
            verify::check(&a, item, &sig).unwrap();
        }
    }
    assert!(
        target.accounts().unwrap().is_empty(),
        "routing must not persist duplicate accounts"
    );
}

// Administration only: these tests never sign and never access a real reader.
fn admin_request(
    k: &KeycardSigner,
    action: &str,
    extra: serde_json::Value,
) -> keycard_module::admin::Request {
    let p = k.cards().into_iter().find(|p| p.card.is_some()).unwrap();
    let c = p.card.unwrap();
    let mut v = serde_json::json!({"action":action,"reader":p.reader,"cardId":c.admin_id,"keyUid":c.key_uid.unwrap_or_default()});
    for (key, value) in extra.as_object().unwrap() {
        v[key] = value.clone();
    }
    serde_json::from_value(v).unwrap()
}
fn admin(k: &KeycardSigner, action: &str, extra: serde_json::Value) -> serde_json::Value {
    k.administer(admin_request(k, action, extra))
        .unwrap_or_else(|e| panic!("{action}: {}", e.message))
}

#[test]
fn administration_v4_lifecycle_and_exact_card_guards() {
    let _turn = turn();
    let Some(addr) = simulator() else { return };
    let mut k = rig(&addr, &Setup::default());
    let offers = add(&k, vec![Family::Evm], Chain::Main);
    k.rename_account(&offers[0].id, "Keep my account name")
        .unwrap();
    assert_eq!(
        admin(&k, "check_identity", serde_json::json!({}))["genuine"],
        true
    );
    let original_uid = k.cards()[0].card.as_ref().unwrap().key_uid.clone();
    let mut stale = admin_request(
        &k,
        "change_pin",
        serde_json::json!({"pin":PIN,"newPin":"234567"}),
    );
    stale.card_id = "another-card".into();
    assert!(k.administer(stale).unwrap_err().message.contains("changed"));
    let mut stale_seed = admin_request(
        &k,
        "factory_reset",
        serde_json::json!({"confirmation":"RESET"}),
    );
    stale_seed.key_uid = "another-seed".into();
    assert!(k
        .administer(stale_seed)
        .unwrap_err()
        .message
        .contains("changed"));
    let s = admin(&k, "status", serde_json::json!({}));
    assert_eq!(s["pinRetries"], 3);
    assert!(k
        .administer(admin_request(&k, "factory_reset", serde_json::json!({})))
        .is_err());
    assert_eq!(k.cards()[0].card.as_ref().unwrap().key_uid, original_uid);
    admin(
        &k,
        "verify_phrase",
        serde_json::json!({"pin":PIN,"phrase":sim::TEST_PHRASE}),
    );
    assert!(
        k.administer(admin_request(
            &k,
            "verify_phrase",
            serde_json::json!({"pin":"987654","phrase":sim::TEST_PHRASE})
        ))
        .is_err(),
        "Alternate wallet shares a master public key but has a different chain code"
    );
    assert!(k
        .administer(admin_request(
            &k,
            "verify_phrase",
            serde_json::json!({"pin":PIN,"phrase":sim::TEST_PHRASE,"passphrase":"different"})
        ))
        .is_err());
    assert!(k
        .administer(admin_request(
            &k,
            "load_phrase",
            serde_json::json!({"pin":PIN,"phrase":sim::TEST_PHRASE,"confirmation":"BACKED UP"})
        ))
        .unwrap_err()
        .message
        .contains("already holds"));
    admin(
        &k,
        "change_pin",
        serde_json::json!({"pin":PIN,"newPin":"234567"}),
    );
    admin(
        &k,
        "change_puk",
        serde_json::json!({"pin":"234567","puk":"876543210987"}),
    );
    admin(
        &k,
        "set_name",
        serde_json::json!({"pin":"234567","text":"Travel card"}),
    );
    let data = admin(&k, "read_data", serde_json::json!({}));
    let meta =
        keycard_rs::Metadata::from_data(&hex::decode(data["data"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(meta.card_name(), "Travel card");
    admin(
        &k,
        "set_ndef",
        serde_json::json!({"pin":"234567","text":"Public contact"}),
    );
    admin(
        &k,
        "set_ndef",
        serde_json::json!({"pin":"234567","text":""}),
    );
    admin(
        &k,
        "write_data",
        serde_json::json!({"pin":"234567","text":"deadbeef","dataType":2,"confirmation":"WRITE"}),
    );
    assert_eq!(
        admin(&k, "read_data", serde_json::json!({"dataType":2}))["data"],
        "deadbeef"
    );
    admin(
        &k,
        "remove_key",
        serde_json::json!({"pin":"234567","confirmation":"ERASE"}),
    );
    assert!(k.cards()[0].card.as_ref().unwrap().key_uid.is_none());
    let old = k.accounts().unwrap();
    assert_eq!(old[0].label.as_deref(), Some("Keep my account name"));
    assert!(!old[0].available);
    let mut generated = admin(
        &k,
        "generate_phrase",
        serde_json::json!({"pin":"234567","words":24}),
    );
    assert_eq!(
        generated["phrase"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .count(),
        24
    );
    admin(
        &k,
        "load_phrase",
        serde_json::json!({"pin":"234567","phrase":generated["phrase"],"confirmation":"BACKED UP","passphrase":"é"}),
    );
    // Unicode normalization is BIP39 compatible.
    admin(
        &k,
        "verify_phrase",
        serde_json::json!({"pin":"234567","phrase":generated["phrase"],"passphrase":"e\u{301}"}),
    );
    generated = serde_json::Value::Null;
    let _ = generated;
    admin(
        &k,
        "factory_reset",
        serde_json::json!({"confirmation":"RESET"}),
    );
    assert!(!k.cards()[0].card.as_ref().unwrap().initialized);
    admin(
        &k,
        "initialize",
        serde_json::json!({"newPin":PIN,"puk":PUK,"alternatePin":"345678"}),
    );
    assert!(k.cards()[0].card.as_ref().unwrap().initialized);
    admin(
        &k,
        "generate_key",
        serde_json::json!({"pin":PIN,"confirmation":"NO BACKUP"}),
    );
    assert!(k.cards()[0].card.as_ref().unwrap().key_uid.is_some());
    assert_eq!(
        k.accounts().unwrap()[0].label.as_deref(),
        Some("Keep my account name")
    );
}

#[test]
fn administration_v3_pairing_setup_and_recovery() {
    let _turn = turn_v3();
    let Some(addr) = named("KEYCARD_SIMULATOR_V3") else {
        return;
    };
    let k = rig(&addr, &Setup::default());
    admin(
        &k,
        "pair",
        serde_json::json!({"pairingPassword":"KeycardDefaultPairing"}),
    );
    let status = admin(&k, "status", serde_json::json!({}));
    let slot = status["pairingSlot"].as_u64().unwrap();
    admin(
        &k,
        "change_pairing_password",
        serde_json::json!({"pin":PIN,"pairingPassword":"new test password"}),
    );
    admin(&k, "unpair", serde_json::json!({"pin":PIN,"slot":slot}));
    assert!(!k.cards()[0].paired);
    admin(
        &k,
        "pair",
        serde_json::json!({"pairingPassword":"new test password"}),
    );
    for _ in 0..3 {
        assert!(k
            .administer(admin_request(
                &k,
                "change_pin",
                serde_json::json!({"pin":"999999","newPin":"234567"})
            ))
            .is_err());
    }
    admin(
        &k,
        "unblock_pin",
        serde_json::json!({"puk":PUK,"newPin":"234567"}),
    );
    admin(
        &k,
        "verify_phrase",
        serde_json::json!({"pin":"234567","phrase":sim::TEST_PHRASE}),
    );
    admin(
        &k,
        "factory_reset",
        serde_json::json!({"confirmation":"RESET"}),
    );
    assert!(!k.cards()[0].paired);
    admin(
        &k,
        "initialize",
        serde_json::json!({"newPin":PIN,"puk":PUK,"pairingPassword":"fresh test password"}),
    );
    admin(
        &k,
        "pair",
        serde_json::json!({"pairingPassword":"fresh test password"}),
    );
    for words in [12, 15, 18, 21, 24] {
        let result = admin(
            &k,
            "generate_phrase",
            serde_json::json!({"pin":PIN,"words":words}),
        );
        assert_eq!(
            result["phrase"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .count(),
            words
        );
    }
    admin(
        &k,
        "load_phrase",
        serde_json::json!({"pin":PIN,"phrase":sim::TEST_PHRASE,"confirmation":"BACKED UP"}),
    );
    admin(
        &k,
        "verify_phrase",
        serde_json::json!({"pin":PIN,"phrase":sim::TEST_PHRASE}),
    );
}

#[test]
fn default_pairing_waits_for_store_and_survives_restart() {
    let Some(addr) = named("KEYCARD_SIMULATOR_V3") else {
        return;
    };
    let _turn = turn_v3();
    let k = rig(&addr, &Setup::default());
    assert!(!k.cards()[0].paired, "startup must wait for persistence");
    let dir = std::env::temp_dir().join(format!("keycard-default-pairing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    k.set_store(Store::open(&dir).unwrap());
    assert!(k.cards()[0].paired);
    let before = admin(&k, "status", serde_json::json!({}))["freePairingSlots"].clone();
    for _ in 0..5 {
        k.refresh();
        assert!(k.cards()[0].paired);
    }
    let got = add(&k, vec![Family::Evm], Chain::Test);
    assert_eq!(
        got.len(),
        1,
        "default pairing opens the account export channel"
    );
    drop(k);
    let k = KeycardSigner::new(
        Box::new(Simulator::new(&addr)),
        Store::new(),
        Box::new(Quiet),
    );
    k.set_store(Store::open(&dir).unwrap());
    assert!(k.cards()[0].paired);
    let status = admin(&k, "status", serde_json::json!({}));
    assert_eq!(
        status["freePairingSlots"], before,
        "restart must reuse the saved slot"
    );
    admin(
        &k,
        "unpair",
        serde_json::json!({"pin":PIN,"slot":status["pairingSlot"]}),
    );
    for _ in 0..5 {
        k.refresh();
        assert!(!k.cards()[0].paired, "explicit unpair must stay unpaired");
    }
    k.pair(PairRequest {
        reader: None,
        pairing_password: Secret::new("KeycardDefaultPairing"),
    })
    .unwrap();
    assert!(
        k.cards()[0].paired,
        "manual pairing remains available after explicit unpair"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn custom_pairing_falls_back_without_retries() {
    let Some(addr) = named("KEYCARD_SIMULATOR_V3") else {
        return;
    };
    let _turn = turn_v3();
    let k = rig(
        &addr,
        &Setup {
            pairing_password: "custom pairing password".into(),
            ..Setup::default()
        },
    );
    k.set_store(Store::new());
    assert!(!k.cards()[0].paired);
    // Another host changes the password to the default after our failed attempt. This
    // host must still wait for manual pairing, even though another attempt would work.
    let other = KeycardSigner::new(
        Box::new(Simulator::new(&addr)),
        Store::new(),
        Box::new(Quiet),
    );
    other
        .pair(PairRequest {
            reader: None,
            pairing_password: Secret::new("custom pairing password"),
        })
        .unwrap();
    admin(
        &other,
        "change_pairing_password",
        serde_json::json!({"pin":PIN,"pairingPassword":"KeycardDefaultPairing"}),
    );
    drop(other);
    for _ in 0..5 {
        k.refresh();
        assert!(
            !k.cards()[0].paired,
            "do not retry the default during polling"
        );
    }
    k.pair(PairRequest {
        reader: None,
        pairing_password: Secret::new("KeycardDefaultPairing"),
    })
    .unwrap();
    assert!(k.cards()[0].paired);
    assert_eq!(add(&k, vec![Family::Evm], Chain::Test).len(), 1);
}

#[test]
fn default_pairing_skips_v4_and_uninitialized_cards() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let k = rig(&addr, &Setup::default());
    k.set_store(Store::new());
    assert!(!k.cards()[0].paired);
    assert_eq!(add(&k, vec![Family::Evm], Chain::Test).len(), 1);
    admin(
        &k,
        "factory_reset",
        serde_json::json!({"confirmation":"RESET"}),
    );
    assert!(!k.cards()[0].card.as_ref().unwrap().initialized);
    assert!(k.cards()[0].error.is_none());
}

#[test]
fn v3_setup_without_custom_password_pairs_automatically() {
    let Some(addr) = named("KEYCARD_SIMULATOR_V3") else {
        return;
    };
    let _turn = turn_v3();
    let k = rig(&addr, &Setup::default());
    admin(
        &k,
        "factory_reset",
        serde_json::json!({"confirmation":"RESET"}),
    );
    k.set_store(Store::new());
    assert!(!k.cards()[0].paired);
    admin(
        &k,
        "initialize",
        serde_json::json!({"newPin":PIN,"puk":PUK}),
    );
    assert!(
        k.cards()[0].paired,
        "default setup should pair without another prompt"
    );
    admin(&k, "status", serde_json::json!({}));
}

#[test]
fn the_card_gives_its_phrases_unlock_key_after_its_pin_and_only_for_its_seed() {
    let Some(addr) = simulator() else { return };
    let _turn = turn();
    let mut k = rig(&addr, &Setup::default());
    let added = add(&k, vec![Family::Evm], Chain::Test);
    let seed = added[0].seed.clone().expect("the account names its seed");
    assert_eq!(
        k.accounts().unwrap()[0].seed.as_deref(),
        Some(seed.as_str())
    );

    // The phrase's own key at m/1280263247'/n', as any other holder of it gives.
    let secp = Secp256k1::new();
    let phrase = bip39::Mnemonic::parse(sim::TEST_PHRASE).unwrap();
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &phrase.to_seed("")).unwrap();
    let want = |n: u32| {
        let path = DerivationPath::from_str(&format!("m/1280263247'/{n}'")).unwrap();
        hex::encode(
            Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap())
                .public_key
                .serialize(),
        )
    };
    let key = |k: &mut KeycardSigner,
               seed: &str,
               n: u32,
               pin: Option<&str>|
     -> Result<String, ErrorCode> {
        let job = k
            .unlock_key(UnlockKeyRequest {
                seed: seed.into(),
                index: n,
                secret: pin.map(Secret::new),
            })
            .map_err(|e| e.code)?;
        for _ in 0..100 {
            let st = k.unlock_key_status(&job).unwrap();
            if st.state.is_final() {
                return match st.state {
                    JobState::Done => {
                        Ok(k.unlock_key_result(&job).unwrap().key.expose().to_string())
                    }
                    _ => Err(st.error.map(|e| e.code).unwrap_or(ErrorCode::Internal)),
                };
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the unlock key never came");
    };
    assert_eq!(key(&mut k, &seed, 0, Some(PIN)).unwrap(), want(0));
    assert_eq!(key(&mut k, &seed, 1, Some(PIN)).unwrap(), want(1));
    assert_eq!(
        key(&mut k, &seed, 0, Some("654321")).unwrap_err(),
        ErrorCode::WrongSecret
    );
    assert_eq!(key(&mut k, &seed, 0, None).unwrap_err(), ErrorCode::Locked);
    assert_eq!(
        key(&mut k, &"00".repeat(32), 0, Some(PIN)).unwrap_err(),
        ErrorCode::WrongSeed
    );
}
