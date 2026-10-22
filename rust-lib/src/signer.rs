//! A bare Keycard behind `logos.signer/1`: the accounts the person offered from it, and the hashes
//! the signer manager computes, signed once the card's PIN opens it, one request at a time.
//!
//! A card session lives on one thread, since keycard-rs's command set can't move between threads.
//! `sign` waits for the PIN check, so a wrong PIN is refused at once and the person can try again.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use logos_signer_interface::jobs::{JobTable, KeyJobs};
use logos_signer_interface::unlock::{is_reserved, roster_key, unlock_key_path};
use logos_signer_interface::wallets::DataKey;
use logos_signer_interface::{
    verify, Account, Chain, Collects, ErrorCode, Family, HashItem, JobState, JobStatus, Payload,
    RequestKind, Scheme, Secret, SignRequest, Signature, Signer, SignerError, SignerInfo,
    UnlockKey, UnlockKeyRequest, INTERFACE,
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
    /// Accounts of a seed were added, with its unlock key at index 0 when the card gave it: the
    /// glue registers the seed with the signer manager.
    fn seed_added(&self, _seed: &str, _unlock_key: Option<[u8; 33]>, _name: &str) {}
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
    #[serde(default)]
    pub card_id: Option<String>,
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

/// Trust a 4.0 card Keycard didn't sign, by the identity key `cards` shows for it.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustRequest {
    #[serde(default)]
    pub reader: Option<String>,
    pub identity: String,
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
    /// A 4.0 card refused because Keycard didn't sign its identity: that identity key, which the
    /// person may choose to trust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<String>,
}

/// Accounts grouped by a remembered card, including cards that are unplugged.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardGroup {
    pub id: String,
    pub name: String,
    pub version: String,
    pub connected: bool,
    pub legacy: bool,
    pub accounts: Vec<Account>,
    pub connections: Vec<serde_json::Value>,
    pub aliases: Vec<String>,
    /// Its accounts are sealed until the person unlocks the wallet in the Signer app.
    pub locked: bool,
}

struct Shared {
    readers: Box<dyn Readers>,
    store: Mutex<Store>,
    jobs: Mutex<JobTable>,
    /// Unlock-key jobs: read once, by the manager only, and announced nowhere.
    keys: Mutex<KeyJobs>,
    adds: Mutex<HashMap<String, Added>>,
    cards: Mutex<Vec<Present>>,
    scan: Mutex<()>,
    // No pairing before the module has loaded its persistent store.
    auto_pairing: AtomicBool,
    default_pairing_attempted: Mutex<HashSet<String>>,
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
                if is_reserved(&path) {
                    return Err(invalid(format!(
                        "item {i}: nothing signs under the unlock keys' purpose"
                    )));
                }
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
        let _scan = lock(&self.scan);
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the Keycard is busy with another request",
            ));
        }
        Ok(Hold(Arc::clone(self)))
    }

    /// Try the SDK default once per physical card in this process. Polling and reconnects
    /// must not consume more slots or repeatedly try a password that already failed.
    fn pair_default(&self, card: &mut Card) -> Result<(), CardError> {
        let info = card.info();
        if !self.auto_pairing.load(Ordering::SeqCst)
            || info.secure_channel != 1
            || !info.initialized
        {
            return Ok(());
        }
        let Some(uid) = info.instance_uid else {
            return Ok(());
        };
        if lock(&self.store).pairing(&uid).is_some()
            || !lock(&self.default_pairing_attempted).insert(uid.clone())
        {
            return Ok(());
        }
        let pairing = card.pair(crate::admin::DEFAULT_PAIRING_PASSWORD)?;
        lock(&self.store).put_pairing(&uid, &pairing).map_err(|_| {
            CardError::Link("Card paired, but the local pairing could not be saved".into())
        })
    }

    /// SELECT the card and, once persistence is ready, pair a new 3.x card if possible.
    fn probe(&self, slot: &crate::link::Slot) -> Present {
        let looked = self
            .readers
            .connect(&slot.reader, true)
            .map_err(CardError::Link)
            .and_then(|ch| Card::select(ch, self.readers.trusted_cas(), self.trusted()));
        let (card, error, untrusted) = match looked {
            Ok(mut c) => {
                let error = self.pair_default(&mut c).err().map(|e| {
                    format!("Automatic pairing could not complete: {e}. Pair this card manually.")
                });
                (Some(c.info()), error, None)
            }
            Err(CardError::Untrusted(identity)) => {
                (None, Some(CardError::Untrusted(None).to_string()), identity)
            }
            Err(e) => (None, Some(e.to_string()), None),
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
            untrusted,
        }
    }

    /// The identity keys of the cards the person trusted though Keycard didn't sign them.
    fn trusted(&self) -> Vec<[u8; 33]> {
        lock(&self.store).trusted()
    }

    /// Look at the readers, reading a card again only once it was inserted again.
    fn refresh_cards(&self) {
        let _scan = lock(&self.scan);
        if self.busy.load(Ordering::SeqCst) {
            return;
        }
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
        let infos: Vec<CardInfo> = next.iter().filter_map(|p| p.card.clone()).collect();
        if let Err(e) = lock(&self.store).remember_cards(&infos) {
            eprintln!("keycard_module: could not remember cards: {e}");
        }
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
    fn reader_holding(&self, key_uid: &str, family: Family) -> Result<String, SignerError> {
        lock(&self.cards)
            .iter()
            .filter(|p| {
                p.card
                    .as_ref()
                    .is_some_and(|c| c.key_uid.as_deref() == Some(key_uid))
            })
            .min_by_key(|p| {
                let c = p.card.as_ref().expect("matching card");
                // Prefer a usable connection, retaining a matching blocked/unpaired card
                // as a fallback so its specific recovery error reaches the user.
                (
                    family == Family::BitcoinTaproot && !c.taproot,
                    !(c.secure_channel == 2 || p.paired),
                    c.pin_retries == Some(0),
                )
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
        let mut card = Card::select(channel, self.readers.trusted_cas(), self.trusted())?;
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
        expected_card: Option<String>,
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
                if expected_card
                    .as_ref()
                    .is_some_and(|id| match id.strip_prefix("seed:") {
                        Some(uid) => card.info().key_uid.as_deref() != Some(uid),
                        None => card.info().id().as_ref() != Some(id),
                    })
                {
                    return Err(CardError::Link(
                        "The card in the reader changed. Insert the selected Keycard.".into(),
                    ));
                }
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

/// The accounts exported, and the seed's unlock key at index 0, read in the same PIN session.
struct Exported {
    offered: Vec<Offered>,
    unlock_key: Option<[u8; 33]>,
}

/// Export the requested accounts from an opened card.
fn export(card: &mut Card, req: &AddRequest) -> Result<Exported, SignerError> {
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
                let path = format!("m/44'/60'/0'/0/{}", req.account);
                let key = card.export_public(&path).map_err(card_error)?;
                let mut account = accounts::evm_account(&accounts::evm_address(&key), label);
                account.path = Some(path);
                // Names the wallet the address comes from; a card that won't export it still adds.
                account.fingerprint = master_fingerprint(card, &mut master).ok().map(hex::encode);
                Offered {
                    account,
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
                let fp = master_fingerprint(card, &mut master)?;
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
    // A card that won't export it still adds: its wallet then unlocks by a password.
    let unlock_key = unlock_key_path(0)
        .ok()
        .and_then(|path| card.export_public(&path).ok())
        .map(|k| k.serialize());
    Ok(Exported {
        offered: out,
        unlock_key,
    })
}

/// The card's master fingerprint, exported once per add.
fn master_fingerprint(
    card: &mut Card,
    cache: &mut Option<[u8; 4]>,
) -> Result<[u8; 4], SignerError> {
    if let Some(fp) = *cache {
        return Ok(fp);
    }
    let fp = accounts::fingerprint(&card.export_public("m").map_err(card_error)?);
    *cache = Some(fp);
    Ok(fp)
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
    pub fn sign_offered(
        &mut self,
        request: SignRequest,
        offered: Offered,
    ) -> logos_signer_interface::Result<String> {
        if !(if offered.account.family == Family::Evm {
            request.account.eq_ignore_ascii_case(&offered.account.id)
        } else {
            request.account == offered.account.id
        }) {
            return Err(err(
                ErrorCode::Invalid,
                "Routed account does not match the request",
            ));
        }
        if let (Some(brought), Some(listed)) =
            (request.xpub.as_deref(), offered.account.xpub.as_deref())
        {
            let (family, chain) = (offered.account.family, offered.account.chain);
            let same =
                roster_key(family, chain, brought).ok() == roster_key(family, chain, listed).ok();
            if !same {
                return Err(err(
                    ErrorCode::Invalid,
                    "the request's xpub is not this account's",
                ));
            }
        }
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
        let reader = self
            .s
            .reader_holding(&offered.key_uid, offered.account.family)?;
        let hold = self.s.hold()?;
        let (job_tx, job_rx) = mpsc::channel::<String>();
        let root_id = offered.key_uid.clone();
        let account = offered.account;
        self.s.with_pin(
            hold,
            reader,
            pin,
            Some(format!("seed:{}", offered.key_uid)),
            move |card| {
                let job = job_rx.recv().ok()?;
                let outcome = card
                    .export_public("m")
                    .map_err(card_error)
                    .and_then(|root| {
                        use bitcoin::hashes::{sha256, Hash};
                        if sha256::Hash::hash(&root.serialize_uncompressed()).to_string() != root_id
                        {
                            return Err(err(
                                ErrorCode::Unavailable,
                                "The alternate PIN opened a different seed",
                            ));
                        }
                        run(card, &account, &items, steps)
                    });
                Some((job, outcome))
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

    pub fn routing_accounts(&self) -> serde_json::Value {
        lock(&self.s.store)
            .list()
            .iter()
            .map(|o| {
                (
                    o.account.id.clone(),
                    serde_json::json!({
                        "account": o.account, "masterKeyId": o.key_uid, "key": o.key
                    }),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>()
            .into()
    }
    pub fn routing_connections(&self) -> serde_json::Value {
        let cards = self.cards();
        serde_json::json!({"transport": "reader", "connections": cards.iter().filter_map(|p| {
            let c = p.card.as_ref()?;
            let uid = c.key_uid.as_ref()?;
            Some(serde_json::json!({"masterKeyId": uid, "taproot": c.taproot,
                "available": (c.secure_channel == 2 || p.paired) && c.pin_retries != Some(0)}))
        }).collect::<Vec<_>>()})
    }

    pub fn new(readers: Box<dyn Readers>, store: Store, events: Box<dyn Events>) -> Self {
        let s = Arc::new(Shared {
            readers,
            store: Mutex::new(store),
            jobs: Mutex::new(JobTable::new()),
            keys: Mutex::new(KeyJobs::new()),
            adds: Mutex::new(HashMap::new()),
            cards: Mutex::new(Vec::new()),
            scan: Mutex::new(()),
            auto_pairing: AtomicBool::new(false),
            default_pairing_attempted: Mutex::new(HashSet::new()),
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

    /// Load the final store and enable automatic default pairing. Construction only probes,
    /// so it cannot allocate a pairing slot before saved pairings have been loaded.
    pub fn set_store(&self, store: Store) {
        {
            let _scan = lock(&self.s.scan);
            *lock(&self.s.store) = store;
            self.s.auto_pairing.store(true, Ordering::SeqCst);
            // The initial scan ran before persistence existed; recheck saved pairings.
            for p in lock(&self.s.cards).iter_mut() {
                p.epoch = None;
            }
        }
        self.s.refresh_if_idle();
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
    }

    /// The wallets whose accounts wait for their key from the signer manager, each with the
    /// generation its list is sealed under.
    pub fn closed_seeds(&self) -> Vec<(String, Option<u32>)> {
        lock(&self.s.store).closed()
    }

    /// A wallet's key arrived: its accounts are offered.
    pub fn open_seed(
        &self,
        seed: &str,
        box_key: &DataKey,
        current: &DataKey,
    ) -> std::io::Result<()> {
        let count = {
            let mut store = lock(&self.s.store);
            store.unlock(seed, box_key, current)?;
            store.list().len()
        };
        self.s.events.accounts_changed(count);
        Ok(())
    }

    /// Wallets were locked: none of their accounts is offered.
    pub fn lock_seeds(&self) {
        let count = {
            let mut store = lock(&self.s.store);
            store.lock();
            store.list().len()
        };
        self.s.events.accounts_changed(count);
    }

    /// The readers holding a card, and what each card's SELECT told.
    pub fn cards(&self) -> Vec<Present> {
        self.s.refresh_if_idle();
        lock(&self.s.cards).clone()
    }

    /// Origins for offered accounts, including absent cards and shared seeds. Public only.
    pub fn account_origins(&self) -> HashMap<String, serde_json::Value> {
        let store = lock(&self.s.store);
        store.list().iter().map(|o| {
            let devices: Vec<_> = store.cards().iter()
                .filter(|c| c.key_uids.contains(&o.key_uid))
                .map(|c| serde_json::json!({ "id": c.id, "name": c.name, "kind": "keycard" }))
                .collect();
            (o.account.id.clone(), serde_json::json!({
                "devices": devices, "phrase": { "id": format!("seed:{}", o.key_uid), "name": store.wallet_name(&o.key_uid) }, "kind": "derived"
            }))
        }).collect()
    }

    /// Keycard's key UID is SHA-256 of its full, uncompressed master public key.
    /// Physical card identity remains separate for pairing, trust and PIN operations.
    pub fn card_groups(&self) -> Vec<CardGroup> {
        self.s.refresh_if_idle();
        let present = lock(&self.s.cards).clone();
        let store = lock(&self.s.store);
        let mut groups = std::collections::BTreeMap::<String, CardGroup>::new();
        for saved in store.cards() {
            let current = present.iter().find_map(|p| {
                p.card
                    .as_ref()
                    .filter(|c| c.id().as_deref() == Some(&saved.id))
                    .map(|c| (p, c))
            });
            let uids = if saved.key_uids.is_empty() {
                vec![String::new()]
            } else {
                saved.key_uids.clone()
            };
            for uid in uids {
                let id = if uid.is_empty() {
                    saved.id.clone()
                } else {
                    format!("seed:{uid}")
                };
                let connected = current
                    .is_some_and(|(_, c)| uid.is_empty() || c.key_uid.as_deref() == Some(&uid));
                let g = groups.entry(id.clone()).or_insert_with(|| CardGroup {
                    id,
                    name: if uid.is_empty() {
                        saved.name.clone()
                    } else {
                        store.wallet_name(&uid)
                    },
                    version: saved.version.clone(),
                    connected: false,
                    legacy: false,
                    accounts: vec![],
                    connections: vec![],
                    aliases: vec![],
                    locked: !uid.is_empty() && store.is_locked(&uid),
                });
                g.connected |= connected;
                if !saved.name.is_empty() && !g.aliases.contains(&saved.name) {
                    g.aliases.push(saved.name.clone());
                }
                g.connections.push(serde_json::json!({"id": saved.id, "transport": "reader",
                    "connected": connected, "reader": current.map(|(p, _)| p.reader.clone()).unwrap_or_default()}));
            }
        }
        for o in store.list() {
            let id = format!("seed:{}", o.key_uid);
            let available = present.iter().any(|p| {
                p.card
                    .as_ref()
                    .is_some_and(|c| c.key_uid.as_deref() == Some(&o.key_uid))
            });
            let g = groups.entry(id.clone()).or_insert_with(|| CardGroup {
                id,
                name: store.wallet_name(&o.key_uid),
                version: String::new(),
                connected: false,
                legacy: false,
                accounts: vec![],
                connections: vec![],
                aliases: vec![],
                locked: false,
            });
            g.connected |= available;
            g.accounts.push(Account {
                available,
                ..o.account.clone()
            });
        }
        groups.into_values().collect()
    }

    pub fn rename_account(&self, id: &str, name: &str) -> Result<(), SignerError> {
        lock(&self.s.store)
            .rename_account(id, name)
            .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        Ok(())
    }

    pub fn rename_card(&self, id: &str, name: &str) -> Result<(), SignerError> {
        if let Some(uid) = id.strip_prefix("seed:") {
            lock(&self.s.store)
                .rename_wallet(uid, name)
                .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
            self.s
                .events
                .accounts_changed(lock(&self.s.store).list().len());
            return Ok(());
        }
        lock(&self.s.store)
            .rename_card(id, name)
            .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        Ok(())
    }

    /// Forget an absent card's local records. Reinserting it identifies it as a new card.
    pub fn forget_saved_card(&self, id: &str) -> Result<(), SignerError> {
        if let Some(uid) = id.strip_prefix("seed:") {
            let _hold = self.s.hold()?;
            self.s.refresh_cards();
            if lock(&self.s.cards).iter().any(|p| {
                p.card
                    .as_ref()
                    .is_some_and(|c| c.key_uid.as_deref() == Some(uid))
            }) {
                return Err(err(
                    ErrorCode::Invalid,
                    "Remove this wallet's Keycards from their readers before forgetting it.",
                ));
            }
            lock(&self.s.store)
                .forget_wallet(uid)
                .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
            self.s
                .events
                .accounts_changed(lock(&self.s.store).list().len());
            return Ok(());
        }
        let _hold = self.s.hold()?;
        // Probe under the operation hold; cached UI connection state is not sufficient.
        self.s.refresh_cards();
        if lock(&self.s.cards).iter().any(|p| {
            p.card.as_ref().and_then(CardInfo::id).as_deref() == Some(id)
                || p.untrusted
                    .as_ref()
                    .is_some_and(|key| id == format!("identity:{key}"))
        }) {
            return Err(err(
                ErrorCode::Invalid,
                "Remove this Keycard from its reader before forgetting it.",
            ));
        }
        let result = lock(&self.s.store).forget_saved_card(id).map_err(|e| {
            err(
                ErrorCode::Internal,
                format!("Could not finish forgetting this card: {e}. You can retry."),
            )
        });
        // A partial disk failure may already have removed offers; refresh consumers on either path.
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        result
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
            req.card_id.clone(),
            move |card| export(card, &req),
            move |s, outcome| {
                let outcome = outcome.and_then(|exported| {
                    let Exported {
                        offered,
                        unlock_key,
                    } = exported;
                    let accounts = offered
                        .iter()
                        .map(|o| Account {
                            seed: Some(o.key_uid.clone()),
                            ..o.account.clone()
                        })
                        .collect();
                    let seed = offered.first().map(|o| o.key_uid.clone());
                    lock(&s.store)
                        .put(offered)
                        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
                    if let Some(seed) = seed {
                        let name = Some(lock(&s.store).wallet_name(&seed))
                            .filter(|n| !n.is_empty())
                            .unwrap_or_else(|| "Keycard".into());
                        s.events.seed_added(&seed, unlock_key, &name);
                    }
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

    /// Administrative calls are serialized with all other card access. Validate target before
    /// any PIN attempt or mutation, including reset (which the card permits without a PIN).
    pub fn administer(&self, req: crate::admin::Request) -> Result<serde_json::Value, SignerError> {
        use crate::admin::Action;
        req.validate().map_err(card_error)?;
        self.s.refresh_if_idle();
        let hold = self.s.hold()?;
        let result = (|| {
            let channel = self
                .s
                .readers
                .connect(&req.reader, false)
                .map_err(|e| card_error(CardError::Link(e)))?;
            let mut card = Card::select(channel, self.s.readers.trusted_cas(), self.s.trusted())
                .map_err(card_error)?;
            let info = card.info();
            if info.admin_id != req.card_id || info.key_uid.as_deref().unwrap_or("") != req.key_uid
            {
                return Err(err(ErrorCode::Invalid, "The card or its wallet changed. Reopen Card administration and review the selected card."));
            }
            let pairing = info
                .instance_uid
                .as_deref()
                .and_then(|uid| lock(&self.s.store).pairing(uid));
            if req.action == Action::Pair {
                let paired = card.pair(req.pairing_password()).map_err(card_error)?;
                lock(&self.s.store)
                    .put_pairing(
                        info.instance_uid.as_deref().ok_or_else(|| {
                            err(ErrorCode::Unsupported, "This card needs no pairing")
                        })?,
                        &paired,
                    )
                    .map_err(|_| {
                        err(
                            ErrorCode::Internal,
                            "Card paired, but the local pairing could not be saved",
                        )
                    })?;
                return Ok(serde_json::json!({"message":"Card paired with this app."}));
            }
            if req.action == Action::CheckIdentity {
                if info.secure_channel == 2 {
                    card.open(None).map_err(card_error)?;
                    return Ok(
                        serde_json::json!({"genuine":!info.trusted_by_person, "message":if info.trusted_by_person {
                        "Card proved its identity, but Keycard did not certify it. You trusted it manually."
                    } else { "Card identity verified against a trusted Keycard certificate." }}),
                    );
                }
                let mut challenge = [0u8; 32];
                getrandom::getrandom(&mut challenge).map_err(|_| {
                    err(ErrorCode::Internal, "Could not generate identity challenge")
                })?;
                let r = card
                    .cmd
                    .identify_card(&challenge)
                    .map_err(|_| err(ErrorCode::Unavailable, "Card identity request failed"))?;
                if r.sw() != 0x9000 {
                    return Err(err(
                        ErrorCode::Unavailable,
                        "This card did not provide an identity proof",
                    ));
                }
                let ca = keycard_rs::parsing::Certificate::verify_identity(&challenge, r.data())
                    .ok()
                    .and_then(|bytes| PublicKey::from_slice(&bytes).ok())
                    .ok_or_else(|| err(ErrorCode::Invalid, "Card identity proof is invalid"))?;
                let genuine = self
                    .s
                    .readers
                    .trusted_cas()
                    .iter()
                    .any(|key| PublicKey::from_slice(key).ok() == Some(ca));
                return Ok(serde_json::json!({"genuine":genuine, "message":if genuine {
                    "Card identity verified against a trusted Keycard certificate."
                } else { "The identity proof is valid, but its issuer is not a trusted Keycard authority." }}));
            }
            let current_slot = pairing.as_ref().map(|p| p.pairing_index());
            if !matches!(req.action, Action::Initialize | Action::FactoryReset) {
                card.open(pairing).map_err(card_error)?;
                if req.needs_pin() {
                    card.verify_pin(req.pin()).map_err(card_error)?;
                }
            }
            let result = crate::admin::execute(&mut card, &req).map_err(card_error)?;
            if req.action == Action::FactoryReset
                || (req.action == Action::Unpair && req.slot == current_slot)
            {
                if let Some(uid) = &info.instance_uid {
                    lock(&self.s.default_pairing_attempted).insert(uid.clone());
                    lock(&self.s.store).remove_pairing(uid).map_err(|_| {
                        err(
                            ErrorCode::Internal,
                            "Card changed, but the old local pairing could not be removed",
                        )
                    })?;
                }
            }
            Ok(result)
        })();
        self.s.reread(&req.reader);
        drop(hold);
        self.s.refresh_cards();
        // Keep old offers and names: other cards may still hold their seed.
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        result
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
        let mut card = Card::select(channel, self.s.readers.trusted_cas(), self.s.trusted())
            .map_err(card_error)?;
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

    /// Trust a 4.0 card Keycard didn't sign, as the person decides in the Keycard app: from now
    /// on it is used like a genuine one. Only a card in a reader now, refused with this identity,
    /// can be trusted; any other card Keycard didn't sign is still refused.
    pub fn trust_card(&self, req: TrustRequest) -> Result<(), SignerError> {
        self.s.refresh_if_idle();
        let identity = req.identity.trim().to_ascii_lowercase();
        let reader = lock(&self.s.cards)
            .iter()
            .find(|p| {
                p.untrusted.as_deref() == Some(identity.as_str())
                    && req.reader.as_deref().is_none_or(|r| r == p.reader)
            })
            .map(|p| p.reader.clone())
            .ok_or_else(|| {
                err(
                    ErrorCode::Invalid,
                    "no card refused with this identity is in a reader",
                )
            })?;
        lock(&self.s.store)
            .trust(&identity)
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        self.s.reread(&reader);
        self.s.refresh_cards();
        Ok(())
    }

    /// Stop trusting a card Keycard didn't sign: it is refused again. Whether it was trusted.
    pub fn forget_card(&self, identity: &str) -> Result<bool, SignerError> {
        let gone = lock(&self.s.store)
            .untrust(identity)
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        let readers: Vec<String> = lock(&self.s.cards)
            .iter()
            .map(|p| p.reader.clone())
            .collect();
        for r in &readers {
            self.s.reread(r);
        }
        self.s.refresh_cards();
        Ok(gone)
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
            unlock_key: true,
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
                seed: Some(o.key_uid.clone()),
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
        self.sign_offered(request, offered)
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

    /// A seed's unlock key, in a PIN session, once the card proves it holds that seed.
    fn unlock_key(&mut self, request: UnlockKeyRequest) -> logos_signer_interface::Result<String> {
        let path = unlock_key_path(request.index)?;
        let uid = request.seed.trim().to_string();
        if !lock(&self.s.store).list().iter().any(|o| o.key_uid == uid) {
            return Err(err(
                ErrorCode::WrongSeed,
                "no Keycard account comes from this seed",
            ));
        }
        let pin = request
            .secret
            .ok_or_else(|| err(ErrorCode::Locked, "enter the Keycard's PIN"))?;
        digits(&pin, 6, "PIN")?;
        self.s.refresh_if_idle();
        let reader = self.s.reader_holding(&uid, Family::Evm)?;
        let hold = self.s.hold()?;
        let (job_tx, job_rx) = mpsc::channel::<String>();
        self.s.with_pin(
            hold,
            reader,
            pin,
            Some(format!("seed:{uid}")),
            move |card| {
                let job = job_rx.recv().ok()?;
                let outcome = card
                    .export_public("m")
                    .map_err(card_error)
                    .and_then(|root| {
                        use bitcoin::hashes::{sha256, Hash};
                        if sha256::Hash::hash(&root.serialize_uncompressed()).to_string() != uid {
                            return Err(err(ErrorCode::WrongSeed, "this card holds another seed"));
                        }
                        let key = card.export_public(&path).map_err(card_error)?;
                        Ok(UnlockKey {
                            key: Secret::new(hex::encode(key.serialize())),
                        })
                    });
                Some((job, outcome))
            },
            |s, done| {
                if let Some((job, outcome)) = done {
                    let _ = lock(&s.keys).finish(&job, outcome);
                }
            },
        )?;
        let job = lock(&self.s.keys).start(JobState::Working);
        let _ = job_tx.send(job.clone());
        Ok(job)
    }

    fn unlock_key_status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        lock(&self.s.keys).status(job)
    }

    fn unlock_key_result(&mut self, job: &str) -> logos_signer_interface::Result<UnlockKey> {
        lock(&self.s.keys).take(job)
    }

    fn cancel_unlock_key(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        lock(&self.s.keys).cancel(job)
    }
}

#[cfg(test)]
mod grouping_tests {
    use super::*;
    use crate::link::{Channel, Slot};

    struct NoReaders;
    impl Readers for NoReaders {
        fn present(&self) -> Vec<Slot> {
            vec![]
        }
        fn connect(&self, _: &str, _: bool) -> Result<Channel, String> {
            Err("offline".into())
        }
        fn trusted_cas(&self) -> Vec<[u8; 33]> {
            vec![]
        }
    }

    fn card(id: &str, seed: &str, v2: bool) -> CardInfo {
        CardInfo {
            admin_id: id.into(),
            capabilities: 31,
            free_pairing_slots: 0,
            version: if v2 { "4.0" } else { "3.1" }.into(),
            initialized: true,
            key_uid: Some(seed.into()),
            instance_uid: (!v2).then(|| id.into()),
            secure_channel: if v2 { 2 } else { 1 },
            pin_retries: None,
            taproot: v2,
            identity: v2.then(|| id.into()),
            trusted_by_person: false,
        }
    }

    fn key(byte: u8) -> DataKey {
        DataKey {
            key: Secret::new(hex::encode([byte; 32])),
            generation: 0,
        }
    }

    /// The store kept in `dir`, with `seed-a` unlocked.
    fn reopened(dir: &std::path::Path) -> Store {
        let mut store = Store::open(dir).unwrap();
        store.unlock("seed-a", &key(1), &key(1)).unwrap();
        store
    }

    #[test]
    fn accounts_are_sealed_per_seed_and_offered_only_while_it_is_unlocked() {
        let dir = std::env::temp_dir().join(format!("keycard-sealed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir).unwrap();
        store.put(vec![offered()]).unwrap();
        assert_eq!(store.list().len(), 1, "offered while its key is on its way");
        assert_eq!(store.closed(), vec![("seed-a".to_string(), None)]);
        store.unlock("seed-a", &key(1), &key(1)).unwrap();
        let text = std::fs::read_to_string(dir.join("accounts.sealed.json")).unwrap();
        assert!(
            !text.contains("0x0000000000000000000000000000000000000001"),
            "{text}"
        );
        assert!(
            !text.contains("Savings") && !text.contains("public-key"),
            "{text}"
        );

        let mut store = Store::open(&dir).unwrap();
        assert!(store.list().is_empty(), "locked after a restart");
        assert_eq!(store.closed(), vec![("seed-a".to_string(), Some(0))]);
        let mut more = offered();
        more.account = accounts::evm_account("0x0000000000000000000000000000000000000002", None);
        store.put(vec![more]).unwrap();
        assert!(
            store.list().is_empty(),
            "an account added while locked waits"
        );
        assert!(
            store.unlock("seed-a", &key(2), &key(2)).is_err(),
            "another key"
        );
        store.unlock("seed-a", &key(1), &key(1)).unwrap();
        assert_eq!(
            store.list().len(),
            2,
            "and joins its wallet's list when it unlocks"
        );
        store.lock();
        assert!(store.list().is_empty());
        assert_eq!(reopened(&dir).list().len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn offered() -> Offered {
        Offered {
            account: accounts::evm_account(
                "0x0000000000000000000000000000000000000001",
                Some("Savings".into()),
            ),
            key_uid: "seed-a".into(),
            key: "public-key".into(),
        }
    }

    #[test]
    fn legacy_offers_survive_and_join_a_card_when_seen() {
        let mut store = Store::new();
        // The old file contains no physical card identity.
        store
            .put(vec![serde_json::from_value(
                serde_json::to_value(offered()).unwrap(),
            )
            .unwrap()])
            .unwrap();
        let signer = KeycardSigner::new(Box::new(NoReaders), store, Box::new(Quiet));
        let groups = signer.card_groups();
        assert_eq!(groups[0].id, "seed:seed-a");
        assert_eq!(groups[0].accounts[0].label.as_deref(), Some("Savings"));
        lock(&signer.s.store)
            .remember_cards(&[card("card-a", "seed-a", false)])
            .unwrap();
        let groups = signer.card_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, "seed:seed-a");
        assert!(!groups[0].legacy);
        assert!(!groups[0].connected);
        assert_eq!(groups[0].accounts.len(), 1);
    }

    #[test]
    fn a_card_whose_wallet_is_locked_says_so_and_offers_nothing() {
        let dir = std::env::temp_dir().join(format!("keycard-locked-group-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir).unwrap();
        store.remember_cards(&[card("a", "seed-a", false)]).unwrap();
        store.put(vec![offered()]).unwrap();
        store.unlock("seed-a", &key(1), &key(1)).unwrap();
        let signer = KeycardSigner::new(
            Box::new(NoReaders),
            Store::open(&dir).unwrap(),
            Box::new(Quiet),
        );
        let groups = signer.card_groups();
        assert_eq!((groups.len(), groups[0].locked), (1, true));
        assert!(groups[0].accounts.is_empty());
        signer.open_seed("seed-a", &key(1), &key(1)).unwrap();
        let groups = signer.card_groups();
        assert_eq!((groups[0].locked, groups[0].accounts.len()), (false, 1));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn same_seed_on_two_cards_has_one_wallet_preserving_both_names() {
        let mut store = Store::new();
        store.put(vec![offered()]).unwrap();
        store
            .remember_cards(&[card("a", "seed-a", false), card("b", "seed-a", true)])
            .unwrap();
        store.rename_card("instance:a", "Daily").unwrap();
        store.rename_card("identity:b", "Backup").unwrap();
        let mut signer = KeycardSigner::new(Box::new(NoReaders), store, Box::new(Quiet));
        let origins = signer.account_origins();
        let origin = &origins[&offered().account.id];
        assert_eq!(origin["devices"].as_array().unwrap().len(), 2);
        assert_eq!(origin["devices"][0]["name"], "Daily");
        assert_eq!(origin["devices"][1]["name"], "Backup");
        assert_eq!(origin["phrase"]["id"], "seed:seed-a");
        // Hold the snapshot steady, as while a real card operation is under way.
        signer.s.busy.store(true, Ordering::SeqCst);
        lock(&signer.s.cards).push(Present {
            reader: "reader".into(),
            epoch: None,
            card: Some(card("b", "seed-a", true)),
            paired: false,
            error: None,
            untrusted: None,
        });
        let groups = signer.card_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "Daily");
        assert_eq!(groups[0].aliases, vec!["Daily", "Backup"]);
        assert_eq!(groups[0].connections.len(), 2);
        assert!(groups[0].accounts[0].available);
        let accounts = signer.accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].available);
    }

    #[test]
    fn names_survive_restart_and_seed_change_and_can_be_cleared() {
        let dir = std::env::temp_dir().join(format!(
            "keycard-names-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = Store::open(&dir).unwrap();
        store.remember_cards(&[card("a", "seed-a", false)]).unwrap();
        store.rename_card("instance:a", "  Travel  ").unwrap();
        drop(store);
        let mut store = Store::open(&dir).unwrap();
        store.remember_cards(&[card("a", "seed-b", false)]).unwrap();
        assert_eq!(store.cards().len(), 1);
        assert_eq!(store.cards()[0].name, "Travel");
        assert_eq!(store.cards()[0].key_uids, vec!["seed-a", "seed-b"]);
        assert!(store.rename_card("instance:a", &"x".repeat(81)).is_err());
        assert!(store.rename_card("instance:a", "bad\nname").is_err());
        assert!(store.rename_card("unknown", "Oops").is_err());
        assert_eq!(store.cards()[0].name, "Travel");
        store.rename_card("instance:a", "").unwrap();
        assert_eq!(Store::open(&dir).unwrap().cards()[0].name, "");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forgetting_removes_local_state_and_exclusive_offers_across_restart() {
        let dir = std::env::temp_dir().join(format!("keycard-forget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pairings.json"), r#"{"pairings":[{"instanceUid":"a","pairing":"local-a"},{"instanceUid":"b","pairing":"local-b"}]}"#).unwrap();
        std::fs::write(dir.join("trusted_cards.json"), r#"{"cards":["c","d"]}"#).unwrap();
        let mut store = Store::open(&dir).unwrap();
        store
            .remember_cards(&[
                card("a", "seed-a", false),
                card("b", "seed-b", false),
                card("c", "seed-c", true),
                card("d", "seed-d", true),
            ])
            .unwrap();
        store.put(vec![offered()]).unwrap();
        store.unlock("seed-a", &key(1), &key(1)).unwrap();
        store.rename_card("instance:a", "Daily").unwrap();
        let signer = KeycardSigner::new(Box::new(NoReaders), store, Box::new(Quiet));
        signer.forget_saved_card("instance:a").unwrap();
        signer.forget_saved_card("identity:c").unwrap();
        let store = Store::open(&dir).unwrap();
        assert!(store.closed().is_empty(), "its sealed list went too");
        assert_eq!(
            store
                .cards()
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["instance:b", "identity:d"]
        );
        let pairs: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("pairings.json")).unwrap()).unwrap();
        assert_eq!(pairs["pairings"].as_array().unwrap().len(), 1);
        assert_eq!(pairs["pairings"][0]["instanceUid"], "b");
        let trusted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("trusted_cards.json")).unwrap())
                .unwrap();
        assert_eq!(trusted["cards"], serde_json::json!(["d"]));
        assert!(signer.forget_saved_card("unknown").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forgetting_one_of_two_cards_preserves_the_shared_accounts() {
        let mut store = Store::new();
        store
            .remember_cards(&[card("a", "seed-a", false), card("b", "seed-a", true)])
            .unwrap();
        store.put(vec![offered()]).unwrap();
        store.forget_saved_card("instance:a").unwrap();
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.cards().len(), 1);
        store.forget_saved_card("identity:b").unwrap();
        assert!(store.list().is_empty());
        assert!(store.cards().is_empty());
    }

    #[test]
    fn forgetting_refuses_an_inserted_card_or_an_active_operation() {
        struct Inserted;
        impl Readers for Inserted {
            fn present(&self) -> Vec<Slot> {
                vec![Slot {
                    reader: "reader".into(),
                    epoch: Some(1),
                }]
            }
            fn connect(&self, _: &str, _: bool) -> Result<Channel, String> {
                Err("offline".into())
            }
            fn trusted_cas(&self) -> Vec<[u8; 33]> {
                vec![]
            }
        }
        let mut store = Store::new();
        store.remember_cards(&[card("a", "seed-a", false)]).unwrap();
        store.put(vec![offered()]).unwrap();
        let signer = KeycardSigner::new(Box::new(Inserted), store, Box::new(Quiet));
        *lock(&signer.s.cards) = vec![Present {
            reader: "reader".into(),
            epoch: Some(1),
            card: Some(card("a", "seed-a", false)),
            paired: true,
            error: None,
            untrusted: None,
        }];
        assert!(signer
            .forget_saved_card("instance:a")
            .unwrap_err()
            .message
            .contains("Remove this Keycard"));
        assert_eq!(lock(&signer.s.store).cards().len(), 1);
        assert_eq!(lock(&signer.s.store).list().len(), 1);
        let _hold = signer.s.hold().unwrap();
        assert!(signer
            .forget_saved_card("instance:a")
            .unwrap_err()
            .message
            .contains("busy"));
    }

    #[test]
    fn failed_forget_keeps_the_card_visible_for_retry() {
        let dir = std::env::temp_dir().join(format!("keycard-forget-fail-{}", std::process::id()));
        let mut store = Store::open(&dir).unwrap();
        store.remember_cards(&[card("a", "seed-a", false)]).unwrap();
        store.put(vec![offered()]).unwrap();
        std::fs::remove_file(dir.join("cards.json")).unwrap();
        std::fs::create_dir(dir.join("cards.json")).unwrap();
        assert!(store.forget_saved_card("instance:a").is_err());
        assert_eq!(store.cards().len(), 1);
        assert!(store.list().is_empty());
        std::fs::remove_dir(dir.join("cards.json")).unwrap();
        store.forget_saved_card("instance:a").unwrap();
        assert!(Store::open(&dir).unwrap().cards().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_save_does_not_change_the_name_in_memory() {
        let dir = std::env::temp_dir().join(format!("keycard-save-fail-{}", std::process::id()));
        let mut store = Store::open(&dir).unwrap();
        store.remember_cards(&[card("a", "seed-a", false)]).unwrap();
        store.rename_card("instance:a", "Original").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "not a directory").unwrap();
        assert!(store.rename_card("instance:a", "Lost").is_err());
        assert_eq!(store.cards()[0].name, "Original");
        std::fs::remove_file(dir).unwrap();
    }
    #[test]
    fn account_names_persist_clear_and_roll_back_on_failed_write() {
        let dir = std::env::temp_dir().join(format!("keycard-account-name-{}", std::process::id()));
        let mut store = Store::open(&dir).unwrap();
        let mut expected = offered();
        let id = expected.account.id.clone();
        store.put(vec![expected.clone()]).unwrap();
        store.unlock("seed-a", &key(1), &key(1)).unwrap();
        store
            .rename_account(&id.to_uppercase(), "  Travel ETH  ")
            .unwrap();
        expected.account.label = Some("Travel ETH".into());
        assert_eq!(reopened(&dir).find(&id), Some(&expected));
        assert!(store.rename_account("unknown", "Other").is_err());
        assert!(store.rename_account(&id, &"x".repeat(81)).is_err());
        assert!(store.rename_account(&id, "bad\nname").is_err());
        store.rename_account(&id, " ").unwrap();
        expected.account.label = None;
        assert_eq!(reopened(&dir).find(&id), Some(&expected));
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "not a directory").unwrap();
        assert!(store.rename_account(&id, "Unsaved").is_err());
        assert_eq!(store.find(&id), Some(&expected));
        std::fs::remove_file(dir).unwrap();
    }
}
