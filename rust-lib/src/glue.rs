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

pub trait KeycardModule: Send + Sync + 'static {
    // ── logos.signer/1 ──────────────────────────────────────────────────
    fn signer_info(&self) -> String;
    fn signer_accounts(&self) -> String;
    fn sign(&self, request_json: String) -> String;
    fn sign_status(&self, job: String) -> String;
    fn sign_result(&self, job: String) -> String;
    fn cancel_sign(&self, job: String) -> String;

    // ── the Keycard's app ────────────────────────────────────────────────
    /// The readers holding a card, and what each card tells before its PIN:
    /// `{ ok, cards: [{ reader, version?, initialized?, keyUid?, secureChannel?, pinRetries?, taproot?, identity?, trustedByPerson?, paired, error?, untrusted? }] }`.
    fn cards(&self) -> String;
    /// Export accounts once the card's PIN opens it:
    /// `{ families, chain?, account?, label?, reader?, pin }` → `{ ok, job }`.
    fn add_accounts(&self, params_json: String) -> String;
    /// An export's progress: `{ ok, job, state, accounts?, error? }`.
    fn add_status(&self, job: String) -> String;
    /// Stop offering an account: `{ ok, removed }`. Nothing on the card changes.
    fn remove_account(&self, id: String) -> String;
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

struct Emit;

impl Events for Emit {
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
        signer_json::signer_accounts(&mut self.keycard.clone())
    }

    fn sign(&self, mut request_json: String) -> String {
        let reply = signer_json::sign(&mut self.keycard.clone(), &request_json);
        request_json.zeroize();
        reply
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

    fn cards(&self) -> String {
        json!({ "ok": true, "cards": self.keycard.cards() }).to_string()
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
            Ok(store) => self.keycard.set_store(store),
            Err(e) => eprintln!("keycard_module: {}: {e}", ctx.instance_persistence_path),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeycardModuleImpl>();
}
