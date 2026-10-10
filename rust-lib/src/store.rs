//! What the module keeps in its own directory: `accounts.json`, the accounts offered, public
//! material only; `pairings.json`, a 3.x card's pairing key by the card's instance UID, which
//! only this user may read; and `trusted_cards.json`, the identity keys of the 4.0 cards Keycard
//! didn't sign that the person chose to trust.

use std::path::{Path, PathBuf};

use keycard_rs::Pairing;
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

#[derive(Default, Serialize, Deserialize)]
struct Accounts {
    accounts: Vec<Offered>,
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

#[derive(Default)]
pub struct Store {
    dir: Option<PathBuf>,
    offered: Vec<Offered>,
    paired: Vec<Paired>,
    trusted: Vec<String>,
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

impl Store {
    /// In memory only, until [`Store::open`].
    pub fn new() -> Self {
        Store::default()
    }

    /// Read what `dir` keeps, kept there from now on. Missing files are empty lists.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        let offered = read::<Accounts>(&dir.join("accounts.json"))?.accounts;
        let paired = read::<Pairings>(&dir.join("pairings.json"))?.pairings;
        let trusted = read::<Trusted>(&dir.join("trusted_cards.json"))?.cards;
        Ok(Store {
            dir: Some(dir),
            offered,
            paired,
            trusted,
        })
    }

    pub fn list(&self) -> &[Offered] {
        &self.offered
    }

    pub fn find(&self, id: &str) -> Option<&Offered> {
        self.offered.iter().find(|o| same(&o.account, id))
    }

    /// Add or replace accounts by id, and save.
    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        for o in add {
            match self
                .offered
                .iter_mut()
                .find(|have| same(&have.account, &o.account.id))
            {
                Some(have) => *have = o,
                None => self.offered.push(o),
            }
        }
        self.save_accounts()
    }

    /// Whether an account went, saved.
    pub fn remove(&mut self, id: &str) -> std::io::Result<bool> {
        let before = self.offered.len();
        self.offered.retain(|o| !same(&o.account, id));
        self.save_accounts()?;
        Ok(self.offered.len() != before)
    }

    pub fn pairing(&self, instance_uid: &str) -> Option<Pairing> {
        self.paired
            .iter()
            .find(|p| p.instance_uid == instance_uid)
            .and_then(|p| Pairing::from_base64(&p.pairing).ok())
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

    fn save_accounts(&self) -> std::io::Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let body = serde_json::to_vec_pretty(&Accounts {
            accounts: self.offered.clone(),
        })?;
        write(&dir.join("accounts.json"), &body)
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
