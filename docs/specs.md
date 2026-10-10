# keycard_module

A bare Keycard behind [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface), in a
smart-card reader. A Keycard has no screen: it signs the 32-byte hash it is given, once its PIN has
opened it. So the signer manager computes every hash itself, and the person relies on the manager's
lines in the signer app. This module lists the accounts the person offered from the card, and has
the card sign each hash the manager hands it.

**It holds no secret but one.** The keys stay on the card. The PIN reaches the card from the signer
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
  The Keycard's app does this once (`pair`); the module keeps the pairing by the card's instance UID.

| Status word | Means | The module answers |
|---|---|---|
| `63Cx` | wrong PIN or PUK, `x` tries left | `wrong_secret`, with the tries left |
| `63C0`, `6983` | the PIN or PUK is blocked | `unavailable`: unblock the PIN with the PUK in the Keycard app |
| `6985` | no PIN verified, or no key yet | `unavailable` |
| others | the applet refused the command | `internal` |

## Accounts

The Keycard's app asks for the accounts the person chooses (`add_accounts`), with the PIN, since a
card exports even public keys only once its PIN is verified:

- **EVM**: `m/44'/60'/0'/0/0`. The id is the address, in lowercase.
- **Native segwit** and **taproot**: `m/84'` or `m/86'`, then `0'` for Bitcoin or `1'` for the test
  networks, then the account. The module builds the xpub from the account's public key and chain
  code, its parent's key for the parent fingerprint, and the master key for the master fingerprint.
  The id is `keycard-<fingerprint>-<purpose>-<coin>-<account>`. Taproot needs applet 4.0.

They are kept in `accounts.json` in the module's own directory, each with the card's key UID, the
SHA-256 of its master public key, which SELECT tells before any PIN. An account is `available` while
a card with that key UID is in a reader. The module looks at the readers every second and a half,
reads a card when it is inserted and again after each of its own sessions, which can change the
card's pairing or its PIN tries, and announces a change with `signer_changed` and
`signer_accounts_changed`. `remove_account` stops offering an account.

**The alternate PIN.** Applet 4.0 has a second PIN that opens a decoy wallet: the same master key with
another chain code, so every derived key differs while the key UID stays the same. Without one given
at INIT, the card takes the PUK's first six digits. An account offered under one PIN and signed under
the other fails with `unavailable`, naming this, since the card's key is not the account's.

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

Each key the card says it signed with must be the one the module derived, and each signature is
checked as the manager checks it, with `verify::check`, before the job settles. A card with another
key, or opened by its alternate PIN, signs nothing for the account.

One request at a time: while the card works, another is refused as `busy`. `cancel_sign` drops a
job's answer.

## Methods

Every reply is `{ "ok": true, … }` or `{ "ok": false, "error": …, "code"? }`. A request that carries
a PIN, PUK or pairing password is wiped once read.

The signer interface's methods, as `docs/interface.md` there specifies them:

- `signer_info`: the interface, `keycard`, the three families, `hash`, `showsRequest: false`, and
  `collects: pin`.
- `signer_accounts`: the offered accounts, each `available` while its card is in a reader.
- `sign`: `{ account, kind: "hash", items, secret }`, the secret being the PIN. Returns a job once the
  PIN is verified.
- `sign_status`, `sign_result`, `cancel_sign`.

For the Keycard's app:

- `cards`: the readers holding a card, and what each card's SELECT told:
  `{ ok, cards: [{ reader, version?, initialized?, keyUid?, instanceUid?, secureChannel?, pinRetries?, taproot?, paired, error? }] }`.
  `secureChannel` is 1 for a 3.x card and 2 for a 4.0 one; only a 4.0 card tells `pinRetries`
  before its PIN.
- `add_accounts`: `{ families, chain?, account?, label?, reader?, pin }` → `{ ok, job }`, once the PIN
  is verified. `chain` is `main` or `test`, `test` by default; `reader` is needed only when more
  than one holds a Keycard.
- `add_status`: an export's progress, `{ ok, job, state, accounts?, error? }`, the state `working`,
  `done` or `failed`.
- `remove_account`: stop offering an account, `{ ok, removed }`.
- `pair`: `{ reader?, pairingPassword }` → `{ ok }`. A 3.x card only.
- `change_pin`: `{ reader?, pin, newPin }` → `{ ok }`.
- `unblock_pin`: `{ reader?, puk, newPin }` → `{ ok }`.

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
the applet tests' CA, which only the simulator's link trusts. `KEYCARD_SIMULATOR=127.0.0.1:<port>`
points the module at it instead of PC/SC.

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
- a 3.x card signs only once paired, and refuses taproot.

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
