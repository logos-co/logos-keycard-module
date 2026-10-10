//! A bare Keycard behind `logos.signer/1`: the accounts the person offered from it, and the hashes
//! the signer manager computes, signed once the card's PIN opens it, one request at a time.
//!
//! A card session lives on one thread, since keycard-rs's command set can't move between threads.
//! `sign` waits for the PIN check, so a wrong PIN is refused at once and the person can try again.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use logos_signer_interface::jobs::JobTable;
use logos_signer_interface::{
    verify, Account, Chain, Collects, ErrorCode, Family, HashItem, JobState, JobStatus, Payload,
    RequestKind, Scheme, Secret, SignRequest, Signature, Signer, SignerError, SignerInfo,
    INTERFACE,
};
use serde::{Deserialize, Serialize};

use crate::accounts::{self, parse_path, EVM_PATH, HARDENED};
use crate::answers;
use crate::card::{Card, CardError, CardInfo};
use crate::link::Readers;
use crate::store::{Offered, Store};

/// How long a call waits for the card to check a PIN.
const PIN_PATIENCE: Duration = Duration::from_secs(90);

/// What the module announces; its glue turns these into events.
pub trait Events: Send + Sync {
    fn sign_progress(&self, job: &str, state: JobState);
    fn accounts_changed(&self, count: usize);
    fn device_changed(&self, connected: bool);
}

/// Announces nothing, for tests.
pub struct Quiet;

impl Events for Quiet {
    fn sign_progress(&self, _: &str, _: JobState) {}
    fn accounts_changed(&self, _: usize) {}
    fn device_changed(&self, _: bool) {}
}

fn test_chain() -> Chain {
    Chain::Test
}

/// What the Keycard's app asks for: accounts to export from the card, opened by its PIN.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddRequest {
    pub families: Vec<Family>,
    #[serde(default = "test_chain")]
    pub chain: Chain,
    #[serde(default)]
    pub account: u32,
    #[serde(default)]
    pub label: Option<String>,
    /// Which reader, when more than one holds a Keycard.
    #[serde(default)]
    pub reader: Option<String>,
    pub pin: Secret,
}

/// Pair a 3.x card, whose secure channel needs it, with its pairing password.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRequest {
    #[serde(default)]
    pub reader: Option<String>,
    pub pairing_password: Secret,
}

/// Change the PIN, with the current one.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePinRequest {
    #[serde(default)]
    pub reader: Option<String>,
    pub pin: Secret,
    pub new_pin: Secret,
}

/// Set a new PIN with the PUK, as a blocked PIN needs.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnblockRequest {
    #[serde(default)]
    pub reader: Option<String>,
    pub puk: Secret,
    pub new_pin: Secret,
}

/// Where an export stands: `working`, then `done` with the accounts or `failed`.
#[derive(Clone, Debug, Serialize)]
pub struct Added {
    pub state: &'static str,
    pub accounts: Vec<Account>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A reader holding a card, and what its SELECT told.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Present {
    pub reader: String,
    #[serde(skip)]
    pub epoch: Option<u64>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardInfo>,
    /// Whether this module keeps a pairing for it; only a 3.x card needs one.
    pub paired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Shared {
    readers: Box<dyn Readers>,
    store: Mutex<Store>,
    jobs: Mutex<JobTable>,
    adds: Mutex<HashMap<String, Added>>,
    cards: Mutex<Vec<Present>>,
    busy: AtomicBool,
    seq: AtomicU64,
    events: Box<dyn Events>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn err(code: ErrorCode, msg: impl Into<String>) -> SignerError {
    SignerError::new(code, msg)
}

/// What a card's refusal means to the manager.
fn card_error(e: CardError) -> SignerError {
    let code = match e {
        CardError::WrongPin(_) | CardError::WrongPuk(_) | CardError::WrongPairing => {
            ErrorCode::WrongSecret
        }
        CardError::Refused(_) => ErrorCode::Internal,
        _ => ErrorCode::Unavailable,
    };
    err(code, e.to_string())
}

/// A Keycard PIN is six digits and a PUK twelve: anything else is refused before the card counts
/// it as a wrong try.
fn digits(s: &Secret, n: usize, what: &str) -> Result<(), SignerError> {
    let s = s.expose();
    if s.len() == n && s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(err(
            ErrorCode::WrongSecret,
            format!("a Keycard {what} is {n} digits"),
        ))
    }
}

/// Holds the card for one operation; dropping it lets the next one in.
struct Hold(Arc<Shared>);

impl Drop for Hold {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::SeqCst);
    }
}

/// One hash to sign, checked before the card is touched.
enum Step {
    Evm {
        digest: [u8; 32],
        key: PublicKey,
    },
    Ecdsa {
        path: String,
        digest: [u8; 32],
        key: PublicKey,
    },
    Bip86 {
        path: String,
        digest: [u8; 32],
        internal: PublicKey,
    },
}

/// The steps a request's items ask of the card, each item's path checked against the account.
fn plan(offered: &Offered, items: &[HashItem]) -> Result<Vec<Step>, SignerError> {
    let invalid = |m: String| err(ErrorCode::Invalid, m);
    if items.is_empty() {
        return Err(invalid("no items to sign".into()));
    }
    let account = &offered.account;
    let secp = Secp256k1::verification_only();
    let mut steps = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let digest = verify::hex32(&item.digest)?;
        let step = match (account.family, item.scheme) {
            (Family::Evm, Scheme::Evm) => {
                if item.path.is_some() {
                    return Err(invalid(format!("item {i}: an EVM item has no path")));
                }
                let key = hex::decode(&offered.key)
                    .ok()
                    .and_then(|k| PublicKey::from_slice(&k).ok())
                    .ok_or_else(|| {
                        err(
                            ErrorCode::Internal,
                            "the account's key is missing: add it again",
                        )
                    })?;
                Step::Evm { digest, key }
            }
            (Family::Bitcoin, Scheme::Ecdsa) | (Family::BitcoinTaproot, Scheme::Bip86) => {
                let base = account.path.as_deref().unwrap_or_default();
                let path = item
                    .path
                    .clone()
                    .ok_or_else(|| invalid(format!("item {i}: a Bitcoin item names its path")))?;
                verify::relative(base, &path)?;
                let tail: Vec<ChildNumber> = parse_path(&path)
                    .zip(parse_path(base))
                    .map(|(full, b)| {
                        full[b.len()..]
                            .iter()
                            .map(|n| ChildNumber::from(*n))
                            .collect()
                    })
                    .ok_or_else(|| invalid(format!("item {i}: path {path}")))?;
                let xpub = account
                    .xpub
                    .as_deref()
                    .and_then(|x| Xpub::from_str(x).ok())
                    .ok_or_else(|| err(ErrorCode::Internal, "the account's xpub is missing"))?;
                let key = xpub
                    .derive_pub(&secp, &tail)
                    .map_err(|e| invalid(format!("item {i}: {e}")))?
                    .public_key;
                if item.scheme == Scheme::Ecdsa {
                    Step::Ecdsa { path, digest, key }
                } else {
                    Step::Bip86 {
                        path,
                        digest,
                        internal: key,
                    }
                }
            }
            (family, scheme) => {
                return Err(invalid(format!(
                    "item {i}: {scheme:?} for a {family:?} account"
                )))
            }
        };
        steps.push(step);
    }
    Ok(steps)
}

/// Have the card sign every step; each answer is checked as the manager will check it.
fn run(
    card: &mut Card,
    account: &Account,
    items: &[HashItem],
    steps: Vec<Step>,
) -> Result<Vec<Signature>, SignerError> {
    let other = || {
        err(
            ErrorCode::Unavailable,
            "this Keycard signs with another key than the account's: it holds another wallet, or the PIN entered opens its alternate one",
        )
    };
    let taproot = card.info().taproot;
    let mut out = Vec::with_capacity(steps.len());
    for (i, step) in steps.into_iter().enumerate() {
        let sig = match step {
            Step::Evm { digest, key } => {
                let path = account.path.as_deref().unwrap_or(EVM_PATH);
                let (said, sig) = card.sign_ecdsa(path, &digest).map_err(card_error)?;
                if said != key {
                    return Err(other());
                }
                answers::ecdsa(i, sig, &key, &digest, true)
            }
            Step::Ecdsa { path, digest, key } => {
                let (said, sig) = card.sign_ecdsa(&path, &digest).map_err(card_error)?;
                if said != key {
                    return Err(other());
                }
                answers::ecdsa(i, sig, &key, &digest, false)
            }
            Step::Bip86 {
                path,
                digest,
                internal,
            } => {
                if !taproot {
                    return Err(err(
                        ErrorCode::Unavailable,
                        "taproot signing needs a Keycard with applet 4.0",
                    ));
                }
                let tweak = answers::tweak(&internal);
                let (said, sig) = card
                    .sign_bip340(&path, &digest, &tweak)
                    .map_err(card_error)?;
                if said != internal {
                    return Err(other());
                }
                answers::bip86(i, sig, &internal, &digest)
            }
        }
        .map_err(|e| err(ErrorCode::Internal, e))?;
        verify::check(account, &items[i], &sig).map_err(|e| {
            err(
                ErrorCode::Internal,
                format!(
                    "item {i}: the card's signature does not check: {}",
                    e.message
                ),
            )
        })?;
        out.push(sig);
    }
    Ok(out)
}

impl Shared {
    fn hold(self: &Arc<Self>) -> Result<Hold, SignerError> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the Keycard is busy with another request",
            ));
        }
        Ok(Hold(Arc::clone(self)))
    }

    /// SELECT the card in a reader: nothing secret is asked or told.
    fn probe(&self, slot: &crate::link::Slot) -> Present {
        let looked = self
            .readers
            .connect(&slot.reader, true)
            .map_err(CardError::Link)
            .and_then(|ch| Card::select(ch, self.readers.trusted_cas()));
        let (card, error) = match looked {
            Ok(c) => (Some(c.info()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let paired = card
            .as_ref()
            .and_then(|c| c.instance_uid.as_deref())
            .is_some_and(|uid| lock(&self.store).pairing(uid).is_some());
        Present {
            reader: slot.reader.clone(),
            epoch: slot.epoch,
            card,
            paired,
            error,
        }
    }

    /// Look at the readers, reading a card again only once it was inserted again.
    fn refresh_cards(&self) {
        let slots = self.readers.present();
        let have = lock(&self.cards).clone();
        let next: Vec<Present> = slots
            .iter()
            .map(|slot| {
                have.iter()
                    .find(|p| {
                        p.reader == slot.reader && slot.epoch.is_some() && p.epoch == slot.epoch
                    })
                    .cloned()
                    .unwrap_or_else(|| self.probe(slot))
            })
            .collect();
        let keycards = |v: &[Present]| v.iter().filter(|p| p.card.is_some()).count();
        let (before, after) = (keycards(&have), keycards(&next));
        let changed = have != next;
        *lock(&self.cards) = next;
        if changed {
            if (before == 0) != (after == 0) {
                self.events.device_changed(after > 0);
            }
            self.events.accounts_changed(lock(&self.store).list().len());
        }
    }

    fn refresh_if_idle(&self) {
        if !self.busy.load(Ordering::SeqCst) {
            self.refresh_cards();
        }
    }

    /// A session may change what the card's SELECT says, its pairing or its PIN tries, while the
    /// reader's epoch stays: read it again at the next look.
    fn reread(&self, reader: &str) {
        for p in lock(&self.cards).iter_mut().filter(|p| p.reader == reader) {
            p.epoch = None;
        }
    }

    /// The reader holding a card with this key.
    fn reader_holding(&self, key_uid: &str) -> Result<String, SignerError> {
        lock(&self.cards)
            .iter()
            .find(|p| {
                p.card
                    .as_ref()
                    .and_then(|c| c.key_uid.as_deref())
                    .is_some_and(|k| k == key_uid)
            })
            .map(|p| p.reader.clone())
            .ok_or_else(|| {
                err(
                    ErrorCode::Unavailable,
                    "insert the Keycard holding this account",
                )
            })
    }

    /// The reader named, or the only one holding a Keycard.
    fn reader_named(&self, name: Option<&str>) -> Result<String, SignerError> {
        let cards = lock(&self.cards);
        let keycards: Vec<&Present> = cards.iter().filter(|p| p.card.is_some()).collect();
        match name {
            Some(n) => keycards
                .iter()
                .find(|p| p.reader == n)
                .map(|p| p.reader.clone())
                .ok_or_else(|| err(ErrorCode::Unavailable, format!("no Keycard in {n}"))),
            None => match keycards.as_slice() {
                [] => Err(err(ErrorCode::Unavailable, "insert a Keycard")),
                [one] => Ok(one.reader.clone()),
                _ => Err(err(
                    ErrorCode::Invalid,
                    "more than one Keycard: name its reader",
                )),
            },
        }
    }

    /// Select the card in `reader` and open its secure channel.
    fn open(&self, reader: &str) -> Result<Card, CardError> {
        let channel = self
            .readers
            .connect(reader, false)
            .map_err(CardError::Link)?;
        let mut card = Card::select(channel, self.readers.trusted_cas())?;
        let pairing = card
            .info()
            .instance_uid
            .as_deref()
            .and_then(|uid| lock(&self.store).pairing(uid));
        card.open(pairing)?;
        Ok(card)
    }

    /// Open the card in `reader` and verify `pin` on a thread of its own, then run `then` with the
    /// card there and `after` once the card is let go. Returns once the PIN is checked, with the
    /// card's refusal if it was wrong.
    fn with_pin<R, F, A>(
        self: &Arc<Self>,
        hold: Hold,
        reader: String,
        pin: Secret,
        then: F,
        after: A,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(&mut Card) -> R + Send + 'static,
        A: FnOnce(&Arc<Shared>, R) + Send + 'static,
    {
        let (checked_tx, checked_rx) = mpsc::channel();
        let s = Arc::clone(self);
        std::thread::spawn(move || {
            let opened = s.open(&reader).and_then(|mut card| {
                card.verify_pin(pin.expose())?;
                Ok(card)
            });
            match opened {
                Ok(mut card) => {
                    let _ = checked_tx.send(Ok(()));
                    let r = then(&mut card);
                    drop(card);
                    s.reread(&reader);
                    drop(hold);
                    after(&s, r);
                }
                Err(e) => {
                    s.reread(&reader);
                    drop(hold);
                    let _ = checked_tx.send(Err(card_error(e)));
                }
            }
        });
        checked_rx
            .recv_timeout(PIN_PATIENCE)
            .unwrap_or_else(|_| Err(err(ErrorCode::Unavailable, "the Keycard did not answer")))
    }

    fn next_id(&self, prefix: &str) -> String {
        format!("{prefix}_{}", self.seq.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

/// Export the requested accounts from an opened card.
fn export(card: &mut Card, req: &AddRequest) -> Result<Vec<Offered>, SignerError> {
    let info = card.info();
    let key_uid = info
        .key_uid
        .clone()
        .ok_or_else(|| card_error(CardError::NoKey))?;
    let mut master = None;
    let mut out = Vec::new();
    for family in &req.families {
        let label = req
            .label
            .clone()
            .or_else(|| Some(default_label(*family, req.chain)));
        let offered = match family {
            Family::Evm => {
                let key = card.export_public(EVM_PATH).map_err(card_error)?;
                Offered {
                    account: accounts::evm_account(&accounts::evm_address(&key), label),
                    key_uid: key_uid.clone(),
                    key: hex::encode(key.serialize()),
                }
            }
            Family::Bitcoin | Family::BitcoinTaproot => {
                if *family == Family::BitcoinTaproot && !info.taproot {
                    return Err(err(
                        ErrorCode::Unsupported,
                        format!(
                            "taproot needs a Keycard with applet 4.0; this one has {}",
                            info.version
                        ),
                    ));
                }
                let path = accounts::bitcoin_path(*family, req.chain, req.account)
                    .ok_or_else(|| err(ErrorCode::Invalid, "account index"))?;
                let fp = match master {
                    Some(fp) => fp,
                    None => {
                        let fp =
                            accounts::fingerprint(&card.export_public("m").map_err(card_error)?);
                        master = Some(fp);
                        fp
                    }
                };
                let parent = card
                    .export_public(accounts::parent_path(&path))
                    .map_err(card_error)?;
                let (key, code) = card.export_extended(&path).map_err(card_error)?;
                let account = accounts::xpub(req.chain, &parent, key, code, req.account)
                    .and_then(|x| {
                        accounts::bitcoin_account(fp, &x, *family, req.chain, req.account, label)
                    })
                    .ok_or_else(|| err(ErrorCode::Invalid, "account index"))?;
                Offered {
                    account,
                    key_uid: key_uid.clone(),
                    key: hex::encode(key.serialize()),
                }
            }
        };
        out.push(offered);
    }
    Ok(out)
}

fn default_label(family: Family, chain: Chain) -> String {
    let test = if chain == Chain::Test { " (test)" } else { "" };
    match family {
        Family::Evm => "Keycard EVM".into(),
        Family::Bitcoin => format!("Keycard native segwit{test}"),
        Family::BitcoinTaproot => format!("Keycard taproot{test}"),
    }
}

/// The module's state, shared with the sessions it runs.
#[derive(Clone)]
pub struct KeycardSigner {
    s: Arc<Shared>,
}

impl KeycardSigner {
    pub fn new(readers: Box<dyn Readers>, store: Store, events: Box<dyn Events>) -> Self {
        let s = Arc::new(Shared {
            readers,
            store: Mutex::new(store),
            jobs: Mutex::new(JobTable::new()),
            adds: Mutex::new(HashMap::new()),
            cards: Mutex::new(Vec::new()),
            busy: AtomicBool::new(false),
            seq: AtomicU64::new(0),
            events,
        });
        s.refresh_cards();
        KeycardSigner { s }
    }

    /// Look for cards inserted or removed every `every`, while this signer lives.
    pub fn watch(&self, every: Duration) {
        let weak = Arc::downgrade(&self.s);
        std::thread::spawn(move || loop {
            std::thread::sleep(every);
            let Some(s) = weak.upgrade() else { return };
            s.refresh_if_idle();
        });
    }

    /// Look at the readers now, as the watcher does every so often.
    pub fn refresh(&self) {
        self.s.refresh_if_idle();
    }

    /// Use what `store` keeps from now on, as when the module learns its directory.
    pub fn set_store(&self, store: Store) {
        *lock(&self.s.store) = store;
        self.s.refresh_if_idle();
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
    }

    /// The readers holding a card, and what each card's SELECT told.
    pub fn cards(&self) -> Vec<Present> {
        self.s.refresh_if_idle();
        lock(&self.s.cards).clone()
    }

    /// Export the requested accounts, once the card's PIN opens it.
    pub fn add_accounts(&self, req: AddRequest) -> Result<String, SignerError> {
        if req.families.is_empty() {
            return Err(err(ErrorCode::Invalid, "name at least one family"));
        }
        if req.account >= HARDENED {
            return Err(err(ErrorCode::Invalid, "account index out of range"));
        }
        digits(&req.pin, 6, "PIN")?;
        self.s.refresh_if_idle();
        let reader = self.s.reader_named(req.reader.as_deref())?;
        let hold = self.s.hold()?;
        let job = self.s.next_id("add");
        let name = job.clone();
        let pin = req.pin.clone();
        lock(&self.s.adds).insert(
            job.clone(),
            Added {
                state: "working",
                accounts: Vec::new(),
                error: None,
            },
        );
        let checked = self.s.with_pin(
            hold,
            reader,
            pin,
            move |card| export(card, &req),
            move |s, outcome| {
                let outcome = outcome.and_then(|offered| {
                    let accounts = offered.iter().map(|o| o.account.clone()).collect();
                    lock(&s.store)
                        .put(offered)
                        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
                    Ok(accounts)
                });
                let added = match outcome {
                    Ok(accounts) => Added {
                        state: "done",
                        accounts,
                        error: None,
                    },
                    Err(e) => Added {
                        state: "failed",
                        accounts: Vec::new(),
                        error: Some(e.message),
                    },
                };
                let done = added.state == "done";
                lock(&s.adds).insert(name, added);
                if done {
                    s.events.accounts_changed(lock(&s.store).list().len());
                }
            },
        );
        if let Err(e) = checked {
            lock(&self.s.adds).remove(&job);
            return Err(e);
        }
        Ok(job)
    }

    pub fn add_status(&self, job: &str) -> Option<Added> {
        lock(&self.s.adds).get(job).cloned()
    }

    /// Stop offering an account. Nothing on the card changes.
    pub fn remove_account(&self, id: &str) -> Result<bool, SignerError> {
        let gone = lock(&self.s.store)
            .remove(id)
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        if gone {
            self.s
                .events
                .accounts_changed(lock(&self.s.store).list().len());
        }
        Ok(gone)
    }

    /// Pair a 3.x card with its pairing password, and keep the pairing for its secure channel.
    pub fn pair(&self, req: PairRequest) -> Result<(), SignerError> {
        self.s.refresh_if_idle();
        let reader = self.s.reader_named(req.reader.as_deref())?;
        let _hold = self.s.hold()?;
        let channel = self
            .s
            .readers
            .connect(&reader, false)
            .map_err(|e| card_error(CardError::Link(e)))?;
        let mut card = Card::select(channel, self.s.readers.trusted_cas()).map_err(card_error)?;
        let uid = card
            .info()
            .instance_uid
            .ok_or_else(|| err(ErrorCode::Unsupported, "a 4.0 Keycard needs no pairing"))?;
        let pairing = card
            .pair(req.pairing_password.expose())
            .map_err(card_error)?;
        lock(&self.s.store)
            .put_pairing(&uid, &pairing)
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        drop(card);
        drop(_hold);
        self.s.reread(&reader);
        self.s.refresh_cards();
        Ok(())
    }

    /// Change the card's PIN, with the current one.
    pub fn change_pin(&self, req: ChangePinRequest) -> Result<(), SignerError> {
        digits(&req.pin, 6, "PIN")?;
        digits(&req.new_pin, 6, "PIN")?;
        self.s.refresh_if_idle();
        let reader = self.s.reader_named(req.reader.as_deref())?;
        let _hold = self.s.hold()?;
        let done = self.s.open(&reader).and_then(|mut card| {
            card.verify_pin(req.pin.expose())?;
            card.change_pin(req.new_pin.expose())
        });
        self.s.reread(&reader);
        done.map_err(card_error)
    }

    /// Set a new PIN with the PUK.
    pub fn unblock_pin(&self, req: UnblockRequest) -> Result<(), SignerError> {
        digits(&req.puk, 12, "PUK")?;
        digits(&req.new_pin, 6, "PIN")?;
        self.s.refresh_if_idle();
        let reader = self.s.reader_named(req.reader.as_deref())?;
        let _hold = self.s.hold()?;
        let done = self
            .s
            .open(&reader)
            .and_then(|mut card| card.unblock_pin(req.puk.expose(), req.new_pin.expose()));
        self.s.reread(&reader);
        done.map_err(card_error)
    }
}

impl Signer for KeycardSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            interface: INTERFACE.into(),
            kind: "keycard".into(),
            model: "Keycard".into(),
            families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
            request_kinds: vec![RequestKind::Hash],
            shows_request: false,
            collects: Collects::Pin,
        }
    }

    fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
        let inserted: Vec<String> = lock(&self.s.cards)
            .iter()
            .filter_map(|p| p.card.as_ref().and_then(|c| c.key_uid.clone()))
            .collect();
        Ok(lock(&self.s.store)
            .list()
            .iter()
            .map(|o| Account {
                available: inserted.contains(&o.key_uid),
                ..o.account.clone()
            })
            .collect())
    }

    fn sign(&mut self, request: SignRequest) -> logos_signer_interface::Result<String> {
        let offered = lock(&self.s.store)
            .find(&request.account)
            .cloned()
            .ok_or_else(|| {
                err(
                    ErrorCode::UnknownAccount,
                    format!("no account {}", request.account),
                )
            })?;
        let Payload::Hash { items } = request.payload else {
            return Err(err(
                ErrorCode::Unsupported,
                "a Keycard has no screen: it signs hashes only",
            ));
        };
        let steps = plan(&offered, &items)?;
        let pin = request
            .secret
            .ok_or_else(|| err(ErrorCode::Locked, "enter the Keycard's PIN"))?;
        digits(&pin, 6, "PIN")?;
        self.s.refresh_if_idle();
        let reader = self.s.reader_holding(&offered.key_uid)?;
        let hold = self.s.hold()?;
        let (job_tx, job_rx) = mpsc::channel::<String>();
        let account = offered.account;
        self.s.with_pin(
            hold,
            reader,
            pin,
            move |card| {
                let job = job_rx.recv().ok()?;
                Some((job, run(card, &account, &items, steps)))
            },
            |s, done| {
                let Some((job, outcome)) = done else { return };
                let state = {
                    let mut jobs = lock(&s.jobs);
                    let _ = jobs.finish(&job, outcome);
                    jobs.status(&job)
                        .map(|st| st.state)
                        .unwrap_or(JobState::Failed)
                };
                s.events.sign_progress(&job, state);
            },
        )?;
        let job = lock(&self.s.jobs).start(JobState::Working);
        let _ = job_tx.send(job.clone());
        Ok(job)
    }

    fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        lock(&self.s.jobs).status(job)
    }

    fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
        lock(&self.s.jobs).result(job)
    }

    /// The card signs in a moment; a cancelled job's signatures are dropped.
    fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        lock(&self.s.jobs).cancel(job)
    }
}
