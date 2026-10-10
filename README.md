# logos-keycard-module

`keycard_module` is a bare Keycard behind [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface),
in a smart-card reader over PC/SC. The person offers accounts from the card with its PIN: an EVM
account, and native segwit and taproot ones. The signer manager then lists them beside the
keystore's. A Keycard has no screen, so the manager computes each hash itself, shows its own lines in
the signer app, and hands the card the hash with the PIN the person typed there. The keys stay on the
card, and the PIN only passes through; a 3.x card's pairing is the one secret the module keeps.

- The signer interface: `signer_info`, `signer_accounts`, `sign`, `sign_status`, `sign_result`,
  `cancel_sign`.
- For the Keycard's app: `cards`, `add_accounts`, `add_status`, `remove_account`, `pair`,
  `change_pin`, `unblock_pin`.

See [`docs/specs.md`](docs/specs.md) for the reference.

```sh
nix run .#simulator -- 47331 &            # the Keycard applet 4.0 in jCardSim
cd rust-lib && KEYCARD_SIMULATOR=127.0.0.1:47331 cargo test --no-default-features --features simulator
nix build
```

The tests run against the Keycard applet itself, built from its source at the 4.0 and 3.2 releases,
in jCardSim. A real card is tested by hand, as the reference describes.

Licensed under MIT or Apache-2.0.
