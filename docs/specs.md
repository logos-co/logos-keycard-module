# keycard_module

A bare Keycard behind [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface), in a
smart-card reader. A Keycard has no screen: it signs the 32-byte hash it is given, once its PIN has
opened it. So the signer manager computes every hash itself, and the person relies on the manager's
lines in the signer app. This module lists the accounts the person offered from the card, and has
the card sign each hash the manager hands it.

**During signing, the keys stay on the card.** The PIN reaches the card from the signer
app through the manager and this module, over the card's encrypted channel, and none of them keeps
it. What the module keeps is each offered account's public material and the card's key UID, and,
for a 3.x card only, the pairing key its secure channel needs, readable by this user alone.

## The link

PC/SC: pcsc-lite's `pcscd` on Linux, the system's smart-card service on macOS and Windows. A card in
a USB reader or on an NFC one is the same to it. Each operation is one session: SELECT the Keycard
applet, open the secure channel, verify the PIN, send the commands, then reset the card, so no
verified PIN outlives the session.

[keycard-rs](https://github.com/keycard-tech/keycard-rs) speaks the applet's commands and both
secure channels:

- **Applet 4.0** (from 2026-09) proves its identity with a key its CA signed at the factory, which
  the module checks against Keycard's CA. It needs no pairing.
- **Applet 3.x** pairs first, with the card's pairing password, in one of its five pairing slots.
  After persistence loads, the module tries `KeycardDefaultPairing` once per unpaired card per
  app session. Failed attempts fall back to manual `pair`; saved pairings are reused.
  Explicit unpair suppresses automatic pairing until restart. The module keeps the pairing
  by the card's instance UID.

**A card Keycard didn't sign.** A 4.0 card whose identity no trusted CA signed is refused: one a
person loaded the applet onto, or a counterfeit. `cards` lists it with that error and its identity
key as `untrusted`, and nothing else is done with it. The person may still trust that one card in
the Keycard app (`trust_card`), after a warning that a counterfeit could keep their PIN or their
keys. Its identity key is then kept in `trusted_cards.json`, and keycard-rs accepts it in place of a
CA's signature. The secure channel still proves the card holds that identity, so any other card
Keycard didn't sign is still refused. `cards` marks a trusted one `trustedByPerson`, and
`forget_card` refuses it again.

| Status word | Means | The module answers |
|---|---|---|
| `63Cx` | wrong PIN or PUK, `x` tries left | `wrong_secret`, with the tries left |
| `63C0`, `6983` | the PIN or PUK is blocked | `unavailable`: unblock the PIN with the PUK in the Keycard app |
| `6985` | no PIN verified, or no key yet | `unavailable` |
| others | the applet refused the command | `internal` |

## Accounts

The Keycard's app asks for the accounts the person chooses (`add_accounts`), with the PIN, since a
card exports even public keys only once its PIN is verified:

- **EVM**: `m/44'/60'/0'/0/i`, where `i` is the requested account index. The id is the address, in lowercase.
  It carries the card's master fingerprint, naming the same wallet as the card's Bitcoin accounts; an
  account added before this, or from a card that won't export its master key, has none.
- **Native segwit** and **taproot**: `m/84'` or `m/86'`, then `0'` for Bitcoin or `1'` for the test
  networks, then the account. The module builds the xpub from the account's public key and chain
  code, its parent's key for the parent fingerprint, and the master key for the master fingerprint.
  The id is `keycard-<fingerprint>-<purpose>-<coin>-<account>`. Taproot needs applet 4.0.

They are kept in `accounts.sealed.json` in the module's own directory, each with the card's key UID,
the SHA-256 of its master public key, which SELECT tells before any PIN. Each key UID's list is sealed
under the module's key for that seed, `data_key({ seed: <key UID>, scope: "accounts" })` from the signer
manager ([logos.wallets/1](https://github.com/logos-co/logos-signer-interface/blob/main/docs/wallets.md)),
asked for when `wallets_changed` says a wallet unlocked. While a seed is locked none of its accounts
is offered; one added meanwhile waits in memory and joins the list when it unlocks. The pairings,
trusted identities and remembered cards stay plain: they are needed before the PIN. An account is `available` while
a card with that key UID is in a reader. The module looks at the readers every second and a half,
reads a card when it is inserted and again after each of its own sessions, which can change the
card's pairing or its PIN tries, and announces a change with `signer_changed` and
`signer_accounts_changed`. `remove_account` stops offering an account.

**The alternate PIN.** Applet 4.0 has a second PIN that opens a decoy wallet: the same master key with
another chain code, so every derived key differs while the key UID stays the same. Without one given
at INIT, the card takes the PUK's first six digits. An account offered under one PIN and signed under
the other fails with `unavailable`, naming this, since the card's key is not the account's.

## The seed's unlock key

Every account names its `seed`: the card's key UID. The signer manager unlocks that seed's data, in
every app, with the public key at `m/1280263247'/n'`, which every holder of the seed gives.

- **At add**, in the same PIN session, the card exports the key at `m/1280263247'/0'`, and the module
  registers the seed with the manager: `enroll_seed({ seed, kind: "keycard", unlockKey, name })`
  through `logos.wallets/1` (`wallets.lidl`), bound to `signer_manager_module` at runtime and asked
  without waiting. A card that won't export it still adds; its wallet then unlocks by a password.
- **`unlock_key`** (`{ seed, index, secret }`, the secret being the PIN, the manager alone) opens the
  card in the reader holding that key UID, verifies the PIN, checks that the master public key is
  that seed's, and exports the key at `m/1280263247'/<index>'`. It returns a job once the PIN is
  checked; `unlock_key_result` gives the key once.
  - A seed no account comes from is `wrong_seed`, and so is a card that holds another one.
  - No PIN is `locked`, and a wrong one `wrong_secret`.
  - Nothing signs under that purpose: an item under it is refused.

## Signing

`signer_info` says a Keycard takes `hash` requests only, shows nothing, and collects a `pin`.

`sign` checks every item before the card is touched: an EVM item has no path; a Bitcoin item's path
lies below the account's with only unhardened steps; each item's scheme matches the account's family.
It then opens the card in the reader holding the account's key UID, verifies the PIN, and answers
with the job only once the PIN is checked, so a wrong PIN is refused at once (`wrong_secret`) and the
person can try again. A PIN is six digits and a PUK twelve; anything else is refused before the card
counts it as a wrong try.

- **`evm`**: ECDSA by the account's key. The card gives no recovery id, so the module finds it by
  recovering the account's key over the digest, after lowering a high S.
- **`ecdsa`**: ECDSA by the item's key, in low S, for native segwit.
- **`bip86`**: BIP340 by the item's key tweaked as BIP86 says. The module computes the tweak from
  the key it derives from the account's xpub and hands it to the card with the hash; the card adds
  it to its key. The answer names the tweaked output key, which the module works out itself: the
  card names the untweaked one.

A Bitcoin request may bring the account's xpub, from the wallet that has it open; one that isn't
the account's is refused.

Each key the card says it signed with must be the one the module derived, and each signature is
checked as the manager checks it, with `verify::check`, before the job settles. A card with another
key, or opened by its alternate PIN, signs nothing for the account.

One request at a time: while the card works, another is refused as `busy`. `cancel_sign` drops a
job's answer.

## Methods

Every reply is `{ "ok": true, … }` or `{ "ok": false, "error": …, "code"? }`. A request that carries
a PIN, PUK or pairing password is wiped once read.

The signer interface's methods, as `docs/interface.md` there specifies them:

- `signer_info`: the interface, `keycard`, the three families, `hash`, `showsRequest: false`,
  `collects: pin` and `unlockKey: true`.
- `signer_accounts`: the offered accounts, each `available` while its card is in a reader, and each
  naming its `seed`.
- `unlock_key`, `unlock_key_status`, `unlock_key_result`, `cancel_unlock_key`: the signer manager
  alone; see [The seed's unlock key](#the-seeds-unlock-key).
- `sign`: `{ account, kind: "hash", items, secret }`, the secret being the PIN. Returns a job once the
  PIN is verified.
- `sign_status`, `sign_result`, `cancel_sign`.

For the Keycard's app:

- `cards`: the readers holding a card, and what each card's SELECT told:
  `{ ok, cards: [{ reader, version?, initialized?, keyUid?, instanceUid?, secureChannel?, pinRetries?, taproot?, identity?, trustedByPerson?, paired, error?, untrusted? }] }`.
  `secureChannel` is 1 for a 3.x card and 2 for a 4.0 one; only a 4.0 card tells `pinRetries`
  before its PIN. `identity` is a 4.0 card's identity key; `untrusted` is the identity key of a
  card refused because Keycard didn't sign it.
- `add_accounts`: `{ families, chain?, account?, label?, reader?, cardId?, pin }` → `{ ok, job }`, once the PIN
  is verified. `chain` is `main` or `test`, `test` by default; `reader` is needed only when more
  than one holds a Keycard. `cardId` optionally pins the physical identity and is checked before PIN verification.
- `add_status`: an export's progress, `{ ok, job, state, accounts?, error? }`, the state `working`,
  `done` or `failed`.
- `remove_account`: stop offering an account, `{ ok, removed }`.
- `rename_account`: `(id, name)` → `{ ok }`, a local label; an empty name restores the default.
- `card_groups`, `rename_card`, `forget_saved_card`: the seed wallets, their names and forgetting
  one; see [Named seed wallets and physical cards](#named-seed-wallets-and-physical-cards).
- `account_previews`: public address previews, in input order; see the end of this reference.
- `pair`: `{ reader?, pairingPassword }` → `{ ok }`. A 3.x card only.
- `change_pin`: `{ reader?, pin, newPin }` → `{ ok }`.
- `unblock_pin`: `{ reader?, puk, newPin }` → `{ ok }`.
- `trust_card`: `{ reader?, identity }` → `{ ok }`. Only a card refused with that identity, in a
  reader now, can be trusted.
- `forget_card`: the identity key → `{ ok, removed }`.

Who may call which comes from module identity in the new core.

## Events

`signer_accounts_changed` (count) when the offered accounts or their availability change.
`signer_changed` (state) with `connected` when a Keycard is first in a reader, `disconnected` when
none is left. `sign_progress` (job, state) when a job settles.

## The simulator

The tests run against the Keycard applet itself, built from
[its source](https://github.com/status-im/status-keycard) at the 4.0 and 3.2 releases, in jCardSim,
Java's smart-card simulator. `sim/KeycardSim.java` installs the applets and serves their APDUs over
TCP; the pseudo-APDU `FF 7F 00 00` swaps in a factory-fresh card. `nix run .#simulator -- <port>
[4.0|3.2]` runs one and sets it up with PIN 123456, PUK 987654321098 and the BIP39 test phrase's key,
through `keycard-simulator-setup`. A 4.0 card first gets the identity a factory gives it, signed by
the applet tests' CA, which only the simulator's link trusts; `--untrusted` has another CA sign it.
`KEYCARD_SIMULATOR=127.0.0.1:<port>` points the module at it instead of PC/SC.

Two changes make the applet run in jCardSim 3.0.5, both for the simulator only: 4.0's scratch EC
keys live in ordinary memory, since jCardSim has no transient ones, and jCardSim's RSA without
padding takes a block as long as its modulus, as a card does, which 4.0's BIP340 arithmetic needs.

The tests check, with `KEYCARD_SIMULATOR` naming a 4.0 card and `KEYCARD_SIMULATOR_V3` a 3.2 one:

- the EVM address and the BIP84 and BIP86 xpubs are the published ones for the test phrase, from
  bitcoin/bips;
- every account passes the conformance suite, on both cards;
- a wrong PIN counts down, a blocked one is unblocked with the PUK, and the PIN changes;
- the alternate PIN, and a card with another key, sign nothing for the account;
- a Bitcoin item outside its account is refused;
- a 3.x card signs only once paired, and refuses taproot;
- a card Keycard didn't sign is used only once the person trusts it, and is refused again once
  forgotten, while another such card stays refused.

## By hand, with a Keycard

1. Put a Keycard with a key in a reader, and start the module without `KEYCARD_SIMULATOR`.
2. `cards` shows it. For a 3.x card, `pair` with its pairing password.
3. `add_accounts` with `evm` and `bitcoin`, and the PIN; with `bitcoin_taproot` too on a 4.0 card.
4. Have the manager list `keycard_module` as a signer. Send a regtest PSBT and an Anvil EVM
   transaction through it, approving each with the PIN.
5. Approve one with a wrong PIN: the request stays, with the tries left.

## Platforms

- **macOS:** `PCSC.framework`.
- **Linux:** pcsc-lite's client library, talking to `pcscd`, which must be running, with the
  reader's driver (`ccid` for most).
- **Windows:** `winscard.dll`, on `nix-bundle-lgx`'s system-DLL list.

## Build and test

```sh
nix run .#simulator -- 47331 &                       # a 4.0 card
nix run .#simulator -- 47332 3.2 &                   # a 3.2 card
cd rust-lib && KEYCARD_SIMULATOR=127.0.0.1:47331 KEYCARD_SIMULATOR_V3=127.0.0.1:47332 \
  cargo test --no-default-features --features simulator
nix build                                            # the module
```

## Named seed wallets and physical cards

`card_groups()` returns `{ ok, groups: [{ id, name, version, connected, legacy, accounts,
connections, aliases }] }`. Wallet IDs are `seed:<keyUid>`. Keycard's key UID is SHA-256
of the full uncompressed master public key, also used by the Shell module after confirmed
root export. Multiple cards with the same seed form one wallet with multiple connections.
Old account files already carry key UIDs and migrate without another PIN/export.

Physical IDs remain `instance:<instanceUid>` on 3.x and `identity:<compressed identity key>`
on 4.0. They are used for pairing, trust and PIN checks. `cards.json` retains these IDs,
old names and observed key UIDs. Uninitialized cards with no seed still use a physical-ID
group until a seed exists. A card with changed keys does not mark its old wallet available.

`rename_card(id, name)` accepts either a seed wallet ID or physical card ID. Wallet names
are stored in `wallet_names.json`; the first existing nonempty card name is the migration
fallback, and all original card names are retained in `aliases`. Names are trimmed,
limited to 80 characters, and cannot contain control characters. Re-exporting an account
keeps its saved label; conflicting full public keys cannot overwrite an existing account ID.

`forget_saved_card(seedId)` removes a disconnected seed wallet's offers, name and seed
associations while retaining physical pairing/trust metadata. For compatibility, passing
a physical card ID retains the previous card-specific forget behavior (name, pairing,
trust and exclusive offers). `forget_card(identity)` only revokes trust. None of these
operations erase card keys or pairing slots. Partial disk cleanup failures are surfaced.

The simulator tests verify the applet key UID against a known master public key and cover
shared seeds, availability, naming, forgetting and signing without touching real devices.


## Physical-card administration

The `administer` endpoint adds setup, recovery-key management, credential changes,
pairing revocation, authenticity checks, public card data and reset. Its complete
[action schema and scope](../README.md#physical-card-administration) are separate
from signing. It checks the exact physical card and current key UID before any
credential attempt or mutation. The trusted host or authenticated Keycard UI is
required; arbitrary signing clients cannot invoke PIN-free factory reset.

BIP39 generation/import briefly handles recovery material in host memory, without
persisting it. Recovery verification compares the full master public key and a known derived
public key (which also checks the chain code): an alternate-PIN wallet can share the public key while deriving different
accounts. Erase/reset retain saved account and wallet metadata for other cards holding
the same seed. They only remove a local pairing when that pairing is revoked/reset.

`account_previews(accounts_json)` accepts an array of public signer accounts and returns `{ok, previews}` in the same order. Each preview contains `address`, full `path`, and `firstReceiving`, or an `error`. EVM uses its saved address; Bitcoin derives branch/index `0/0` with BIP84/BIP86 from the account xpub. Test accounts use testnet/signet encoding. No transport, PIN, state mutation, or private material is involved.
