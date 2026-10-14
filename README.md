# logos-keycard-module

`keycard_module` is a bare Keycard behind [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface),
in a smart-card reader over PC/SC. The person offers accounts from the card with its PIN: an EVM
account, and native segwit and taproot ones. The signer manager then lists them beside the
keystore's. A Keycard has no screen, so the manager computes each hash itself, shows its own lines in
the signer app, and hands the card the hash with the PIN the person typed there. The keys stay on the
card, and the PIN only passes through; a 3.x card's pairing is the one secret the module keeps.

- The signer interface: `signer_info`, `signer_accounts`, `sign`, `sign_status`, `sign_result`,
  `cancel_sign`.
- For the Keycard's app: `cards`, `card_groups`, `rename_card`, `add_accounts`, `add_status`, `remove_account`, `pair`,
  `change_pin`, `unblock_pin`, `trust_card`, `forget_card`.

A 4.0 card whose identity Keycard didn't sign is refused, unless the person trusts that one card in
the Keycard app, after a warning that a counterfeit could keep their PIN or their keys.

Cards have persistent local names and their accounts are grouped by card. Applet 3.x uses its
instance UID; 4.0 uses its identity public key. The wallet key UID is separate: cards containing
the same seed remain individually nameable, while the signer inventory still deduplicates accounts.

See [`docs/specs.md`](docs/specs.md) for the reference.

```sh
nix run .#simulator -- 47331 &            # the Keycard applet 4.0 in jCardSim
cd rust-lib && KEYCARD_SIMULATOR=127.0.0.1:47331 cargo test --no-default-features --features simulator
nix build
```

The tests run against the Keycard applet itself, built from its source at the 4.0 and 3.2 releases,
in jCardSim. A real card is tested by hand, as the reference describes.

Licensed under MIT or Apache-2.0.

### Forget a remembered card

Each identified card group has **Forget Keycard…**. Remove the card from its reader, then
confirm to remove its saved name, local pairing/trust and accounts offered only by that card.
Accounts associated with another remembered card are retained. Nothing is erased on the card;
reinserting it discovers it again, with pairing/trust and account offering available as before.
The backend checks reader presence itself and refuses while another card operation is active.
A failed local cleanup leaves the card record visible for retry and reports the error.

### Account derivation in the unified Keycard app

`add_accounts.account` selects Ethereum address index `i` at `m/44'/60'/0'/0/i`, as well
as the Bitcoin hardened account index. The persisted path is used for signing. An optional
`cardId` rejects a different physical card before the supplied PIN is verified. The unified
Keycard UI also uses the USB Shell backend; this module continues to own reader transport.

Account labels can be changed locally with `rename_account(id, name)`. Names are trimmed, limited to 80 characters, and an empty name clears the label. Keys and derivation paths are unchanged; updated labels are announced to account consumers. In Keycard UI, use **Manage → Rename** beside an account.

### Seed wallet organization

`card_groups` now returns one group per Keycard key UID, using `seed:<keyUid>` as its ID.
The applet computes this UID as SHA-256 of the full SEC1 uncompressed master public key.
`connections` keeps the physical card IDs and reader availability separate; `aliases`
retains previous card names when wallets merge. `rename_card` and `forget_saved_card`
also accept seed IDs. Seed wallet names are saved in `wallet_names.json`, with old card
names used as the migration fallback. Pairing, trust and PIN handling remain per card.
Re-exporting an existing account keeps its label. A seed change creates a different group.

### Signing across connections

The signer manager shares saved public Keycard account offers between the reader and USB
Shell providers for each request. It does not copy account files: labels, wallet names and
removal continue to belong to the original saved offer. A matching, paired reader takes
priority over a USB Shell. The reader checks the seed before requesting the PIN and checks
the full master public key again after unlocking.

USB presence does not identify the card inside a Shell. On first use of each USB connection,
the user confirms the master public key. The public root is cached only in memory for that
attachment; later signatures and account exports reuse it. Removal, a changed attachment,
a link failure or module restart clears verification. On macOS, the HID path contains the
IORegistry service entry ID, detecting even a reconnect between polls; other backends also
invalidate on an observed removal or path change. Opening uses the enumerated attachment path.
The UI distinguishes an unverified connection, the verified wallet and a different wallet.
A confirmed mismatching root can advance to another connected Shell; refusal or cancellation
ends the request. Every returned signature is still checked by the signer manager against
the selected account and request before release, including if the seed changes while connected.
Active jobs remain pinned to the provider that started them, even after hotplug.

Only `signer_manager_module` may supply the optional `keycardAccount` public routing metadata
to `sign`. Legacy Shell accounts must first use “Identify wallet…” to establish their full
master key identity. No PIN or pairing data is shared between the providers.

## Physical-card administration

`administer(params_json)` is separate from the signer API. It manages the **physical card**,
not a seed wallet shared across cards. Every request requires `action`, `reader`, `cardId`
(the `adminId` returned by `cards`) and `keyUid` (the current value, or `""` for an empty
card). SELECT checks both identifiers before sending credentials or changing anything.
Calls are restricted to the authenticated `keycard_ui` module or trusted host anchor, including PIN-free reset.
An uninitialized 3.x card is guarded by the hash of its secure-channel public key until
initialization gives it an instance UID. Administration shares the module's busy lock.

| Action | Additional fields | Authorization/effect |
| --- | --- | --- |
| `status` | — | Secure channel; PIN/PUK attempts, key presence, pairing slot, on-card name |
| `check_identity` | — | Fresh identity proof checked against trusted CAs on 3.x; authenticated secure channel on 4.0; distinguishes manual trust from certification |
| `initialize` | `newPin`, `puk`, optional `pairingPassword` for 3.x (defaults to `KeycardDefaultPairing`); optional `alternatePin` for 4.0 | Empty, uninitialized card only; six-digit PIN and twelve-digit PUK |
| `pair` | `pairingPassword` | 3.x only; stores the resulting pairing locally |
| `change_pin` | `pin`, `newPin` | Current PIN required |
| `change_puk` | `pin`, `puk` | Current PIN; replaces the PUK |
| `unblock_pin` | `puk`, `newPin` | Current PUK; resets blocked PIN |
| `change_pairing_password` | `pin`, `pairingPassword` | 3.x; existing pairings remain valid |
| `unpair` | `pin`, `slot` | Revokes one slot (0–9; card rejects indexes it doesn't support); removing this app's slot also removes its local pairing |
| `generate_phrase` | `pin`, `words` | Card-generated BIP39 entropy, 12/15/18/21/24 words; returns `phrase` **without loading it** |
| `load_phrase` | `pin`, `phrase`, optional `passphrase`, `confirmation:"BACKED UP"` | Validated English BIP39, including checksum and Unicode-normalized passphrase; refuses to overwrite existing keys |
| `verify_phrase` | `pin`, `phrase`, optional `passphrase` | Compares the authenticated master public key and a known derived public key (checking the chain code without exporting it); does not load anything |
| `generate_key` | `pin`, `confirmation:"NO BACKUP"` | Empty card only; generates non-recoverable keys on card, with no mnemonic |
| `remove_key` | `pin`, `confirmation:"ERASE"` | Erases card keys; retains credentials and local account records |
| `factory_reset` | `confirmation:"RESET"` | No PIN required by applet; clears card keys/credentials/metadata and local pairing |
| `read_data` | `dataType` = 0 (public) or 2 (Cash) | Returns hexadecimal `data` |
| `write_data` | `pin`, `dataType`, hex `text`, `confirmation:"WRITE"` | Replaces selected public data, max 127 bytes |
| `set_name` | `pin`, `text` | Up to 20 printable ASCII characters, preserving existing Keycard metadata wallet set; refuses unknown metadata formats |
| `set_ndef` | `pin`, `text` | Public UTF-8 NFC text, max 120 bytes; empty clears NDEF |

Returns `{ok:true,message,...}` or `{ok:false,error,code?}`. A generated phrase is a direct
reply, never a stored job/status property. Request strings and Rust secret fields are
scrubbed on drop. Recovery material necessarily passes through host memory and IPC;
this is not a guarantee that every Qt/QML or library allocation can be securely erased.
Nothing writes PINs, PUKs, passphrases or recovery phrases to module storage.
Reset and key erasure retain saved wallet/account names and public offers, because
another physical card may still hold the same seed. Live availability is refreshed.

The surface was checked against [Keycard Pal](https://github.com/mmlado/keycard-pal)
and the pinned [keycard-rs command set](https://github.com/keycard-tech/keycard-rs/blob/142ab915eda6bc4c1dc10078028f0d7b0748b218/src/keycard.rs).
Shell's USB protocol does not expose card administration; use a PC/SC reader.
Applet installation/firmware updates, SLIP-39 share reconstruction, LEE key mode,
BIP85/private-key exports, ECDH and PIN-less signing configuration are not exposed by
this administration interface. It does not add or change signing APIs.

Simulator lifecycle tests cover both 3.x and 4.0, including destructive operations,
credential recovery, card/seed substitution guards and preservation of local names.
They must never be run against real cards.

### Default pairing for 3.x cards

After loading its saved pairings, the module tries `KeycardDefaultPairing` once for
each initialized, unpaired 3.x card. Successful pairings are saved and reused on
restart. A failed attempt leaves manual pairing available; polling and reconnects
do not retry it during the same app session. Explicitly removing this app's
pairing slot suppresses automatic re-pairing for that session. Uninitialized and
4.0 cards are never automatically paired.

`account_previews(accounts_json)` returns address previews in input order from public account records. Ethereum uses its saved address; Bitcoin derives receive branch/index `0/0` from the account xpub (BIP84 or BIP86). Test accounts show testnet/signet addresses; regtest uses a different address prefix. Previews do not change account identities or stored records and require no card.
