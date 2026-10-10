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
    AddRequest, ChangePinRequest, KeycardSigner, PairRequest, Quiet, UnblockRequest,
};
use keycard_module::sim::{self, Setup};
use keycard_module::store::Store;
use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::{
    verify, Account, Chain, ErrorCode, Family, HashItem, JobState, Payload, Scheme, Secret,
    SignRequest, Signer,
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
    let fingerprint = hex::encode(Xpub::from_priv(&secp, &root).fingerprint().to_bytes());
    assert_eq!(got[1].fingerprint.as_deref(), Some(fingerprint.as_str()));
    assert_eq!(got[1].id, format!("keycard-{fingerprint}-84-0-0"));
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
