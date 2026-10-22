//! What the module keeps in its own directory: `accounts.sealed.json`, the accounts offered, one
//! list per seed sealed under the module's key for it from the signer manager, read only while that
//! seed is unlocked; `pairings.json`, a 3.x card's pairing key by the card's instance UID, which
//! only this user may read; and `trusted_cards.json`, the identity keys of the 4.0 cards Keycard
//! didn't sign that the person chose to trust. Those two and `cards.json` stay plain: they are
//! needed before the PIN.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::card::CardInfo;
use keycard_rs::Pairing;
use logos_signer_interface::sealed::SealedDocs;
use logos_signer_interface::wallets::DataKey;
use logos_signer_interface::Account;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Offered {
    pub account: Account,
    /// The card's key UID, hex: an account is available while a card with this key is inserted.
    pub key_uid: String,
    /// The account key, compressed, hex: what an EVM answer recovers to.
    pub key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Paired {
    instance_uid: String,
    /// keycard-rs's encoding: the slot, then the key, base64.
    pairing: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Pairings {
    pairings: Vec<Paired>,
}

/// Compressed identity keys, hex.
#[derive(Default, Serialize, Deserialize)]
struct Trusted {
    cards: Vec<String>,
}

/// Local names and the wallet keys previously seen on each physical card/applet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedCard {
    pub id: String,
    pub name: String,
    pub version: String,
    pub key_uids: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct SavedCards {
    cards: Vec<SavedCard>,
}

/// What the sealed account lists are called in their boxes.
const ACCOUNTS: &str = "keycard_module accounts";

pub struct Store {
    dir: Option<PathBuf>,
    /// Each seed's accounts, by key UID; the readable ones are in `offered`.
    docs: SealedDocs,
    offered: Vec<Offered>,
    /// Added while their wallet was locked: offered, and saved, once it unlocks.
    waiting: Vec<Offered>,
    paired: Vec<Paired>,
    trusted: Vec<String>,
    cards: Vec<SavedCard>,
    wallet_names: BTreeMap<String, String>,
}

fn read<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> std::io::Result<T> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e),
    }
}

/// Write `body` to `path` through a temporary file, readable by this user only.
fn write(path: &Path, body: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    std::io::Write::write_all(&mut opts.open(&tmp)?, body)?;
    std::fs::rename(tmp, path)
}

impl Default for Store {
    fn default() -> Self {
        Store {
            dir: None,
            docs: SealedDocs::in_memory(ACCOUNTS),
            offered: Vec::new(),
            waiting: Vec::new(),
            paired: Vec::new(),
            trusted: Vec::new(),
            cards: Vec::new(),
            wallet_names: BTreeMap::new(),
        }
    }
}

impl Store {
    /// In memory only, until [`Store::open`].
    pub fn new() -> Self {
        Store::default()
    }

    /// Read what `dir` keeps, kept there from now on. Missing files are empty lists. The accounts
    /// stay sealed until each seed's key arrives ([`Store::unlock`]).
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        let docs = SealedDocs::load(dir.join("accounts.sealed.json"), ACCOUNTS)
            .map_err(|e| std::io::Error::other(e.message))?;
        let paired = read::<Pairings>(&dir.join("pairings.json"))?.pairings;
        let trusted = read::<Trusted>(&dir.join("trusted_cards.json"))?.cards;
        let cards = read::<SavedCards>(&dir.join("cards.json"))?.cards;
        Ok(Store {
            dir: Some(dir.clone()),
            docs,
            offered: Vec::new(),
            waiting: Vec::new(),
            paired,
            trusted,
            wallet_names: read(&dir.join("wallet_names.json"))?,
            cards,
        })
    }

    pub fn wallet_name(&self, uid: &str) -> String {
        self.wallet_names.get(uid).cloned().unwrap_or_else(|| {
            self.cards
                .iter()
                .find(|c| c.key_uids.iter().any(|k| k == uid) && !c.name.is_empty())
                .map(|c| c.name.clone())
                .unwrap_or_default()
        })
    }

    pub fn rename_wallet(&mut self, uid: &str, name: &str) -> std::io::Result<()> {
        let name = name.trim();
        if name.chars().count() > 80
            || name.chars().any(char::is_control)
            || !(self
                .cards
                .iter()
                .any(|c| c.key_uids.iter().any(|k| k == uid))
                || self.offered.iter().any(|o| o.key_uid == uid))
        {
            return Err(std::io::Error::other("Unknown wallet or invalid name"));
        }
        let mut next = self.wallet_names.clone();
        next.insert(uid.into(), name.into());
        if let Some(dir) = &self.dir {
            write(
                &dir.join("wallet_names.json"),
                &serde_json::to_vec_pretty(&next)?,
            )?;
        }
        self.wallet_names = next;
        Ok(())
    }

    pub fn forget_wallet(&mut self, uid: &str) -> std::io::Result<()> {
        self.docs
            .remove(uid)
            .map_err(|e| std::io::Error::other(e.message))?;
        self.offered.retain(|o| o.key_uid != uid);
        self.waiting.retain(|o| o.key_uid != uid);
        let mut cards = self.cards.clone();
        cards.retain_mut(|c| {
            let affected = c.key_uids.iter().any(|k| k == uid);
            c.key_uids.retain(|k| k != uid);
            !affected || !c.key_uids.is_empty()
        });
        self.save_cards(cards)?;
        let mut names = self.wallet_names.clone();
        names.remove(uid);
        if let Some(dir) = &self.dir {
            write(
                &dir.join("wallet_names.json"),
                &serde_json::to_vec_pretty(&names)?,
            )?;
        }
        self.wallet_names = names;
        Ok(())
    }

    pub fn cards(&self) -> &[SavedCard] {
        &self.cards
    }

    /// Remember only successfully identified cards. Do not derive physical identity from a seed.
    pub fn remember_cards(&mut self, present: &[CardInfo]) -> std::io::Result<()> {
        let mut next = self.cards.clone();
        for info in present {
            let Some(id) = info.id() else { continue };
            let index = match next.iter().position(|c| c.id == id) {
                Some(index) => index,
                None => {
                    next.push(SavedCard {
                        id,
                        name: String::new(),
                        version: info.version.clone(),
                        key_uids: Vec::new(),
                    });
                    next.len() - 1
                }
            };
            let saved = &mut next[index];
            saved.version = info.version.clone();
            if let Some(uid) = &info.key_uid {
                if !saved.key_uids.contains(uid) {
                    saved.key_uids.push(uid.clone());
                }
            }
        }
        self.save_cards(next)
    }

    /// Empty names restore the default. Names are local metadata, never written to the card.
    pub fn rename_card(&mut self, id: &str, name: &str) -> std::io::Result<()> {
        let name = name.trim();
        if name.chars().count() > 80 || name.chars().any(char::is_control) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "card names must be at most 80 characters, without control characters",
            ));
        }
        let mut next = self.cards.clone();
        let card = next
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown card"))?;
        card.name = name.into();
        self.save_cards(next)
    }

    /// Forget local records, retaining offers also associated with another remembered card.
    /// Commit each file before changing its in-memory counterpart. Keep the card record last,
    /// so a failed cleanup remains visible and can be retried without resurrecting removed data.
    pub fn forget_saved_card(&mut self, id: &str) -> std::io::Result<()> {
        let card = self
            .cards
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown card"))?;
        let cards: Vec<_> = self.cards.iter().filter(|c| c.id != id).cloned().collect();
        let offered: Vec<_> = self
            .offered
            .iter()
            .filter(|o| {
                !card.key_uids.contains(&o.key_uid)
                    || cards.iter().any(|c| c.key_uids.contains(&o.key_uid))
            })
            .cloned()
            .collect();
        let paired: Vec<_> = self
            .paired
            .iter()
            .filter(|p| id != format!("instance:{}", p.instance_uid))
            .cloned()
            .collect();
        let trusted: Vec<_> = self
            .trusted
            .iter()
            .filter(|t| id != format!("identity:{t}"))
            .cloned()
            .collect();
        let previous = std::mem::replace(&mut self.offered, offered);
        if let Err(e) = self.save_accounts() {
            self.offered = previous;
            return Err(e);
        }
        // A locked wallet of this card alone goes too, though its accounts can't be read.
        for uid in card
            .key_uids
            .iter()
            .filter(|uid| !cards.iter().any(|c| c.key_uids.contains(uid)))
        {
            self.docs
                .remove(uid)
                .map_err(|e| std::io::Error::other(e.message))?;
            self.waiting.retain(|o| &o.key_uid != uid);
        }
        if let Some(dir) = &self.dir {
            write(
                &dir.join("pairings.json"),
                &serde_json::to_vec_pretty(&Pairings {
                    pairings: paired.clone(),
                })?,
            )?;
        }
        self.paired = paired;
        if let Some(dir) = &self.dir {
            write(
                &dir.join("trusted_cards.json"),
                &serde_json::to_vec_pretty(&Trusted {
                    cards: trusted.clone(),
                })?,
            )?;
        }
        self.trusted = trusted;
        self.save_cards(cards)
    }

    fn save_cards(&mut self, next: Vec<SavedCard>) -> std::io::Result<()> {
        if next == self.cards {
            return Ok(());
        }
        if let Some(dir) = &self.dir {
            let body = serde_json::to_vec_pretty(&SavedCards {
                cards: next.clone(),
            })?;
            write(&dir.join("cards.json"), &body)?;
        }
        self.cards = next;
        Ok(())
    }

    pub fn list(&self) -> &[Offered] {
        &self.offered
    }

    pub fn find(&self, id: &str) -> Option<&Offered> {
        self.offered.iter().find(|o| same(&o.account, id))
    }

    /// Add or replace accounts by id, and save.
    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        for o in &add {
            if self
                .find(&o.account.id)
                .is_some_and(|old| old.key != o.key || old.key_uid != o.key_uid)
            {
                return Err(std::io::Error::other(
                    "Account identifier belongs to another key; existing account was kept",
                ));
            }
        }
        let previous = self.offered.clone();
        for mut o in add {
            let to = if self.is_locked(&o.key_uid) {
                &mut self.waiting
            } else {
                &mut self.offered
            };
            match to
                .iter_mut()
                .find(|have| same(&have.account, &o.account.id))
            {
                Some(have) => {
                    o.account.label = have.account.label.clone();
                    *have = o;
                }
                None => to.push(o),
            }
        }
        if let Err(e) = self.save_accounts() {
            self.offered = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Local display metadata only. A failed write must not change the offered account.
    pub fn rename_account(&mut self, id: &str, name: &str) -> std::io::Result<()> {
        let name = name.trim();
        if name.chars().count() > 80 || name.chars().any(char::is_control) {
            return Err(std::io::Error::other(
                "Account names must be at most 80 characters, without control characters",
            ));
        }
        let index = self
            .offered
            .iter()
            .position(|o| same(&o.account, id))
            .ok_or_else(|| std::io::Error::other("Unknown account"))?;
        let previous = self.offered[index].account.label.clone();
        self.offered[index].account.label = (!name.is_empty()).then(|| name.to_owned());
        if let Err(e) = self.save_accounts() {
            self.offered[index].account.label = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Whether an account went, saved.
    pub fn remove(&mut self, id: &str) -> std::io::Result<bool> {
        let before = self.offered.len();
        self.offered.retain(|o| !same(&o.account, id));
        self.waiting.retain(|o| !same(&o.account, id));
        self.save_accounts()?;
        Ok(self.offered.len() != before)
    }

    pub fn pairing(&self, instance_uid: &str) -> Option<Pairing> {
        self.paired
            .iter()
            .find(|p| p.instance_uid == instance_uid)
            .and_then(|p| Pairing::from_base64(&p.pairing).ok())
    }

    pub fn remove_pairing(&mut self, instance_uid: &str) -> std::io::Result<()> {
        self.paired.retain(|p| p.instance_uid != instance_uid);
        self.save_pairings()
    }

    pub fn put_pairing(&mut self, instance_uid: &str, pairing: &Pairing) -> std::io::Result<()> {
        self.paired.retain(|p| p.instance_uid != instance_uid);
        self.paired.push(Paired {
            instance_uid: instance_uid.into(),
            pairing: pairing.to_base64(),
        });
        self.save_pairings()
    }

    /// The identity keys of the cards the person trusted though Keycard didn't sign them.
    pub fn trusted(&self) -> Vec<[u8; 33]> {
        self.trusted
            .iter()
            .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
            .collect()
    }

    pub fn trust(&mut self, identity: &str) -> std::io::Result<()> {
        let identity = identity.trim().to_ascii_lowercase();
        if !self.trusted.contains(&identity) {
            self.trusted.push(identity);
        }
        self.save_trusted()
    }

    /// Whether the card was trusted, saved.
    pub fn untrust(&mut self, identity: &str) -> std::io::Result<bool> {
        let identity = identity.trim().to_ascii_lowercase();
        let before = self.trusted.len();
        self.trusted.retain(|t| *t != identity);
        self.save_trusted()?;
        Ok(self.trusted.len() != before)
    }

    fn save_trusted(&self) -> std::io::Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let body = serde_json::to_vec_pretty(&Trusted {
            cards: self.trusted.clone(),
        })?;
        write(&dir.join("trusted_cards.json"), &body)
    }

    /// Each readable seed's accounts, sealed under its key, or kept in memory until it comes.
    fn save_accounts(&mut self) -> std::io::Result<()> {
        let mut by_seed: BTreeMap<String, Vec<Offered>> = BTreeMap::new();
        for o in &self.offered {
            by_seed
                .entry(o.key_uid.clone())
                .or_default()
                .push(o.clone());
        }
        let gone: Vec<String> = self
            .docs
            .readable()
            .into_iter()
            .map(|(seed, _)| seed)
            .filter(|seed| !by_seed.contains_key(seed))
            .collect();
        let sealing = |e: logos_signer_interface::SignerError| std::io::Error::other(e.message);
        for seed in gone {
            self.docs.remove(&seed).map_err(sealing)?;
        }
        for (seed, list) in by_seed {
            self.docs
                .put(&seed, serde_json::to_vec(&list)?)
                .map_err(sealing)?;
        }
        Ok(())
    }

    /// Every seed whose accounts are kept here, locked or not: the keys to ask for.
    pub fn seeds(&self) -> Vec<String> {
        self.docs.seeds()
    }

    /// The seeds whose accounts wait for their key, each with the generation its list is sealed
    /// under, if it is sealed yet.
    pub fn closed(&self) -> Vec<(String, Option<u32>)> {
        let mut out: Vec<(String, Option<u32>)> = self
            .docs
            .seeds()
            .into_iter()
            .filter(|s| !self.docs.is_open(s))
            .map(|s| {
                let g = self.docs.wanted(&s);
                (s, g)
            })
            .collect();
        for o in &self.waiting {
            if !out.iter().any(|(s, _)| s == &o.key_uid) {
                out.push((o.key_uid.clone(), None));
            }
        }
        out
    }

    /// Sealed, and its key not given yet.
    fn is_locked(&self, seed: &str) -> bool {
        self.docs.wanted(seed).is_some()
    }

    /// A seed's key arrived: its accounts are offered again, with any added meanwhile.
    pub fn unlock(
        &mut self,
        seed: &str,
        box_key: &DataKey,
        current: &DataKey,
    ) -> std::io::Result<()> {
        self.docs
            .unlock(seed, box_key, current)
            .map_err(|e| std::io::Error::other(e.message))?;
        let mut list: Vec<Offered> = self
            .docs
            .get(seed)
            .filter(|b| !b.is_empty())
            .map(serde_json::from_slice)
            .transpose()?
            .unwrap_or_default();
        let added: Vec<Offered> = self
            .waiting
            .iter()
            .filter(|o| o.key_uid == seed)
            .cloned()
            .collect();
        for mut o in added {
            match list
                .iter_mut()
                .find(|have| same(&have.account, &o.account.id))
            {
                Some(have) => {
                    o.account.label = have.account.label.clone();
                    *have = o;
                }
                None => list.push(o),
            }
        }
        self.waiting.retain(|o| o.key_uid != seed);
        self.offered.retain(|o| o.key_uid != seed);
        self.offered.extend(list);
        self.save_accounts()
    }

    /// Wallets were locked: no account of a locked seed is offered or read. Accounts still
    /// waiting for their seed's key stay.
    pub fn lock(&mut self) {
        self.docs.lock();
        let readable: Vec<String> = self.docs.readable().into_iter().map(|(s, _)| s).collect();
        self.offered.retain(|o| readable.contains(&o.key_uid));
    }

    fn save_pairings(&self) -> std::io::Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let body = serde_json::to_vec_pretty(&Pairings {
            pairings: self.paired.clone(),
        })?;
        write(&dir.join("pairings.json"), &body)
    }
}

/// EVM addresses compare without case; other ids exactly.
fn same(a: &Account, id: &str) -> bool {
    if a.family == logos_signer_interface::Family::Evm {
        a.id.eq_ignore_ascii_case(id.trim())
    } else {
        a.id == id.trim()
    }
}
