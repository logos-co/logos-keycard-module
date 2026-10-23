//! Logos module glue for `keycard_module`. The builder derives the `.lidl` from the
//! `KeycardModule` trait and injects the generated scaffold at the `include!` point.
//!
//! Every reply is a JSON string: `{ "ok": true, ... }` or `{ "ok": false, "error": "...", "code"? }`.
//! A request that carries a PIN, PUK or pairing password is wiped once read.

use std::time::Duration;

use logos_signer_interface::json as signer_json;
use logos_signer_interface::JobState;
use serde_json::json;
use zeroize::Zeroize;

use crate::link;
use crate::signer::{
    AddRequest, ChangePinRequest, Events, KeycardSigner, PairRequest, TrustRequest, UnblockRequest,
};
use crate::store::Store;
use logos_signer_interface::wallets::{read_data_key, DataKey, DataKeyRequest};

pub trait KeycardModule: Send + Sync + 'static {
    // ── logos.signer/1 ──────────────────────────────────────────────────
    fn signer_info(&self) -> String;
    fn signer_accounts(&self) -> String;
    fn sign(&self, request_json: String) -> String;
    fn sign_status(&self, job: String) -> String;
    fn sign_result(&self, job: String) -> String;
    fn cancel_sign(&self, job: String) -> String;
    /// A seed's unlock key, for the signer manager alone: `{ seed, index, secret }`, the secret
    /// being the card's PIN → `{ ok, job }`, once the PIN is checked.
    fn unlock_key(&self, request_json: String) -> String;
    fn unlock_key_status(&self, job: String) -> String;
    /// `{ ok, job, key }`, once: the job forgets it.
    fn unlock_key_result(&self, job: String) -> String;
    fn cancel_unlock_key(&self, job: String) -> String;

    // ── the Keycard's app ────────────────────────────────────────────────
    /// The readers holding a card, and what each card tells before its PIN:
    /// `{ ok, cards: [{ reader, version?, initialized?, keyUid?, secureChannel?, pinRetries?, taproot?, identity?, trustedByPerson?, paired, error?, untrusted? }] }`.
    fn cards(&self) -> String;
    /// Physical card administration; see README for the strict action schema. Secrets are transient.
    fn administer(&self, params_json: String) -> String;
    /// Remembered cards with local names and their offered accounts: `{ ok, groups: [...] }`.
    fn card_groups(&self) -> String;
    /// Public account address previews, in input order; no card access or stored changes.
    fn account_previews(&self, accounts_json: String) -> String;
    /// Set a local card name (empty restores the default): `{ ok }`.
    fn rename_card(&self, id: String, name: String) -> String;
    /// Forget an absent card: its local name, exclusive offers, pairing and trust.
    fn forget_saved_card(&self, id: String) -> String;
    /// Export accounts once the card's PIN opens it:
    /// `{ families | entries, chain?, account?, label?, reader?, pin, preview?, fromPreview? }` → `{ ok, job }`.
    fn add_accounts(&self, params_json: String) -> String;
    /// An export's progress: `{ ok, job, state, accounts?, error? }`.
    fn add_status(&self, job: String) -> String;
    /// Stop offering an account: `{ ok, removed }`. Nothing on the card changes.
    fn remove_account(&self, id: String) -> String;
    /// Rename a locally offered account; an empty name restores the default.
    fn rename_account(&self, id: String, name: String) -> String;
    /// Pair a 3.x card for its secure channel: `{ reader?, pairingPassword }` → `{ ok }`.
    fn pair(&self, params_json: String) -> String;
    /// Change the PIN: `{ reader?, pin, newPin }` → `{ ok }`.
    fn change_pin(&self, params_json: String) -> String;
    /// Set a new PIN with the PUK: `{ reader?, puk, newPin }` → `{ ok }`.
    fn unblock_pin(&self, params_json: String) -> String;
    /// Trust a 4.0 card Keycard didn't sign, by the identity `cards` shows as `untrusted`:
    /// `{ reader?, identity }` → `{ ok }`.
    fn trust_card(&self, params_json: String) -> String;
    /// Stop trusting such a card: `{ ok, removed }`.
    fn forget_card(&self, identity: String) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

pub trait KeycardModuleEvents {
    fn signer_accounts_changed(&self, count: i64);
    fn signer_changed(&self, state: String);
    fn sign_progress(&self, job: String, state: String);
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/generated/provider_gen.rs"
));

/// The module behind `logos.wallets/1`: the signer manager, bound at runtime, since it depends on
/// this module and this module can't depend on it.
const WALLETS: &str = "signer_manager_module";

fn from_manager() -> bool {
    matches!(logos_rust_sdk::current_caller(), logos_rust_sdk::LogosCaller::Module { name, .. } if name == WALLETS)
}

struct Emit;

impl Events for Emit {
    /// The seed goes to the signer manager while its unlock key is at hand, so the person never
    /// unlocks it a second time. Asked without waiting: without a manager the add stands.
    fn seed_added(&self, seed: &str, unlock_key: Option<[u8; 33]>, name: &str) {
        let body = zeroize::Zeroizing::new(
            json!({ "seed": seed, "kind": "keycard", "unlockKey": unlock_key.map(hex::encode), "name": name })
                .to_string(),
        );
        wallets::WalletsClient::bind(WALLETS).enroll_seed_async(&body, |_| {});
    }
    fn sign_progress(&self, job: &str, state: JobState) {
        emit_sign_progress(job, state.as_str());
    }
    fn accounts_changed(&self, count: usize) {
        emit_signer_accounts_changed(count as i64);
    }
    fn device_changed(&self, connected: bool) {
        emit_signer_changed(if connected {
            "connected"
        } else {
            "disconnected"
        });
    }
}

/// A wallet's accounts open with this module's key for them, which the signer manager gives once
/// the person unlocks the wallet in the Signer app, and close when it locks. Asked from threads
/// of their own, never while answering the manager, which would wait on itself.
fn watch_wallets(keycard: KeycardSigner) {
    let mut client = wallets::WalletsClient::bind(WALLETS);
    let changed = client.on_wallets_changed();
    let locked = client.on_wallets_locked();
    let k = keycard.clone();
    std::thread::spawn(move || {
        open_wallets(&k);
        if let Ok(sub) = changed {
            for _ in sub {
                open_wallets(&k);
            }
        }
    });
    if let Ok(sub) = locked {
        std::thread::spawn(move || {
            for _ in sub {
                keycard.lock_seeds();
                // Only some may have locked.
                open_wallets(&keycard);
            }
        });
    }
}

/// Every closed wallet's key; a locked one answers `locked` and stays closed.
fn open_wallets(keycard: &KeycardSigner) {
    for (seed, sealed_under) in keycard.closed_seeds() {
        let Some(current) = data_key(&seed, None) else {
            continue;
        };
        let box_key = match sealed_under {
            Some(g) if g != current.generation => match data_key(&seed, Some(g)) {
                Some(k) => k,
                None => continue,
            },
            _ => current.clone(),
        };
        if let Err(e) = keycard.open_seed(&seed, &box_key, &current) {
            eprintln!("keycard_module: a wallet's accounts didn't open: {e}");
        }
    }
}

/// The key for a wallet's account list, named by the card's key UID, as the manager knows it.
fn data_key(seed: &str, generation: Option<u32>) -> Option<DataKey> {
    let body = serde_json::to_string(&DataKeyRequest {
        seed: seed.to_string(),
        scope: "accounts".into(),
        generation,
    })
    .ok()?;
    let (tx, rx) = std::sync::mpsc::channel();
    wallets::WalletsClient::bind(WALLETS).data_key_async_with_timeout(
        &body,
        Duration::from_secs(10),
        move |r| {
            let _ = tx.send(r);
        },
    );
    read_data_key(&rx.recv().ok()?.ok()?).ok()
}

struct KeycardModuleImpl {
    keycard: KeycardSigner,
}

impl Default for KeycardModuleImpl {
    fn default() -> Self {
        let keycard = KeycardSigner::new(link::from_env(), Store::new(), Box::new(Emit));
        keycard.watch(Duration::from_millis(1500));
        KeycardModuleImpl { keycard }
    }
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

fn signer_err(e: logos_signer_interface::SignerError) -> String {
    json!({ "ok": false, "code": e.code, "error": e.message }).to_string()
}

/// Read a request that may carry a secret, and wipe its text.
fn read<T: serde::de::DeserializeOwned>(mut params_json: String) -> Result<T, String> {
    let parsed = serde_json::from_str(&params_json).map_err(|e| err(format!("params: {e}")));
    params_json.zeroize();
    parsed
}

fn done(r: Result<(), logos_signer_interface::SignerError>) -> String {
    match r {
        Ok(()) => json!({ "ok": true }).to_string(),
        Err(e) => signer_err(e),
    }
}

impl KeycardModule for KeycardModuleImpl {
    fn signer_info(&self) -> String {
        signer_json::signer_info(&self.keycard)
    }

    fn signer_accounts(&self) -> String {
        let raw = signer_json::signer_accounts(&mut self.keycard.clone());
        let mut reply: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => return raw,
        };
        let origins = self.keycard.account_origins();
        if let Some(rows) = reply["accounts"].as_array_mut() {
            for row in rows {
                if let Some(origin) = row["id"].as_str().and_then(|id| origins.get(id)) {
                    row["origin"] = origin.clone();
                }
            }
        }
        let public = self.keycard.routing_accounts();
        if let Some(rows) = reply["accounts"].as_array_mut() {
            for row in rows {
                if let Some(offer) = row["id"].as_str().and_then(|id| public.get(id)) {
                    row["keycardAccount"] = offer.clone();
                }
            }
        }
        reply["keycardRouting"] = self.keycard.routing_connections();
        reply.to_string()
    }

    fn sign(&self, request_json: String) -> String {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Routed {
            account: String,
            #[serde(flatten)]
            payload: logos_signer_interface::Payload,
            secret: Option<logos_signer_interface::Secret>,
            #[serde(default)]
            xpub: Option<String>,
            keycard_account: Option<serde_json::Value>,
        }
        let request_json = zeroize::Zeroizing::new(request_json);
        let request: Routed = match serde_json::from_str(&request_json) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        drop(request_json);
        let req = logos_signer_interface::SignRequest {
            account: request.account,
            payload: request.payload,
            secret: request.secret,
            xpub: request.xpub,
        };
        use logos_signer_interface::Signer;
        let result = if let Some(v) = request.keycard_account {
            if !matches!(logos_rust_sdk::current_caller(), logos_rust_sdk::LogosCaller::Module { name, .. } if name == "signer_manager_module")
            {
                return err("Only the signer manager can route public Keycard accounts");
            }
            let account: logos_signer_interface::Account =
                match serde_json::from_value(v["account"].clone()) {
                    Ok(a) => a,
                    Err(e) => return err(e),
                };
            let root = v["masterKeyId"].as_str().unwrap_or_default();
            let key = v["key"].as_str().unwrap_or_default();
            if root.len() != 64
                || hex::decode(root).is_err()
                || hex::decode(key)
                    .ok()
                    .and_then(|k| bitcoin::secp256k1::PublicKey::from_slice(&k).ok())
                    .is_none()
            {
                return err("Invalid public Keycard routing metadata");
            }
            self.keycard.clone().sign_offered(
                req,
                crate::store::Offered {
                    account,
                    key_uid: root.into(),
                    key: key.into(),
                },
            )
        } else {
            self.keycard.clone().sign(req)
        };
        match result {
            Ok(job) => json!({"ok": true, "job": job}).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn sign_status(&self, job: String) -> String {
        signer_json::sign_status(&mut self.keycard.clone(), &job)
    }

    fn sign_result(&self, job: String) -> String {
        signer_json::sign_result(&mut self.keycard.clone(), &job)
    }

    fn cancel_sign(&self, job: String) -> String {
        signer_json::cancel_sign(&mut self.keycard.clone(), &job)
    }

    fn unlock_key(&self, request_json: String) -> String {
        let request_json = zeroize::Zeroizing::new(request_json);
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key(&mut self.keycard.clone(), &request_json)
    }

    fn unlock_key_status(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key_status(&mut self.keycard.clone(), &job)
    }

    fn unlock_key_result(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key_result(&mut self.keycard.clone(), &job)
    }

    fn cancel_unlock_key(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::cancel_unlock_key(&mut self.keycard.clone(), &job)
    }

    fn cards(&self) -> String {
        json!({ "ok": true, "cards": self.keycard.cards() }).to_string()
    }

    fn administer(&self, mut params_json: String) -> String {
        // Factory reset is intentionally PIN-free on the applet. Keep administration behind
        // the authenticated Keycard UI / trusted host, never arbitrary signer consumers.
        let allowed = match logos_rust_sdk::current_caller() {
            logos_rust_sdk::LogosCaller::Module { name, .. } => name == "keycard_ui",
            logos_rust_sdk::LogosCaller::HostAnchor => true,
            _ => false,
        };
        if !allowed {
            params_json.zeroize();
            return err("Only the Keycard app or trusted host can administer cards");
        }
        let request = match read::<crate::admin::Request>(params_json) {
            Ok(r) => r,
            Err(_) => return err("Invalid administration request"),
        };
        match self.keycard.administer(request) {
            Ok(mut result) => {
                result["ok"] = json!(true);
                result.to_string()
            }
            Err(e) => signer_err(e),
        }
    }

    fn account_previews(&self, accounts_json: String) -> String {
        let accounts: Vec<logos_signer_interface::Account> =
            match serde_json::from_str(&accounts_json) {
                Ok(v) => v,
                Err(_) => return err("Invalid public account list"),
            };
        let previews: Vec<_> = accounts
            .iter()
            .map(|a| crate::accounts::address_preview(a).unwrap_or_else(|e| json!({"error":e})))
            .collect();
        json!({"ok":true,"previews":previews}).to_string()
    }

    fn card_groups(&self) -> String {
        json!({ "ok": true, "groups": self.keycard.card_groups() }).to_string()
    }

    fn rename_account(&self, id: String, name: String) -> String {
        done(self.keycard.rename_account(&id, &name))
    }

    fn rename_card(&self, id: String, name: String) -> String {
        done(self.keycard.rename_card(&id, &name))
    }

    fn forget_saved_card(&self, id: String) -> String {
        done(self.keycard.forget_saved_card(&id))
    }

    fn add_accounts(&self, params_json: String) -> String {
        let req: AddRequest = match read(params_json) {
            Ok(r) => r,
            Err(e) => return e,
        };
        match self.keycard.add_accounts(req) {
            Ok(job) => json!({ "ok": true, "job": job }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn add_status(&self, job: String) -> String {
        match self.keycard.add_status(&job) {
            Some(added) => {
                let mut v = json!({ "ok": true, "job": job });
                if let (Some(out), Ok(serde_json::Value::Object(fields))) =
                    (v.as_object_mut(), serde_json::to_value(added))
                {
                    out.extend(fields);
                }
                v.to_string()
            }
            None => err(format!("no export {job}")),
        }
    }

    fn remove_account(&self, id: String) -> String {
        match self.keycard.remove_account(&id) {
            Ok(removed) => json!({ "ok": true, "removed": removed }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn pair(&self, params_json: String) -> String {
        match read::<PairRequest>(params_json) {
            Ok(req) => done(self.keycard.pair(req)),
            Err(e) => e,
        }
    }

    fn change_pin(&self, params_json: String) -> String {
        match read::<ChangePinRequest>(params_json) {
            Ok(req) => done(self.keycard.change_pin(req)),
            Err(e) => e,
        }
    }

    fn unblock_pin(&self, params_json: String) -> String {
        match read::<UnblockRequest>(params_json) {
            Ok(req) => done(self.keycard.unblock_pin(req)),
            Err(e) => e,
        }
    }

    fn trust_card(&self, params_json: String) -> String {
        match read::<TrustRequest>(params_json) {
            Ok(req) => done(self.keycard.trust_card(req)),
            Err(e) => e,
        }
    }

    fn forget_card(&self, identity: String) -> String {
        match self.keycard.forget_card(&identity) {
            Ok(removed) => json!({ "ok": true, "removed": removed }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn on_context_ready(&self, ctx: &RustModuleContext) {
        // The accounts offered and the pairings live in the module's own directory.
        match Store::open(&ctx.instance_persistence_path) {
            Ok(store) => {
                self.keycard.set_store(store);
                watch_wallets(self.keycard.clone());
            }
            Err(e) => eprintln!("keycard_module: {}: {e}", ctx.instance_persistence_path),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeycardModuleImpl>();
}
