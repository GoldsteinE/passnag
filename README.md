# passnag

a simple thingy that nags you to train your passwords.

install with attached `flake.nix` or just with `cargo install --locked passnag`.
I will accept patches that add new packaging schemes as long as they're not too bothersome to maintain.

add `passnag nag` to your shell config so it nags you every time you start a new shell session.
run `passnag` to train your passwords. run `passnag all` to train _all_ of them, even if it's not time yet.
run `passnag add <name>` to add a new password.

passwords are stored in `$XDG_DATA_DIR/passnag/<name>`, salted + hashed with argon2id.
a token attempt is made to zeroize passwords from memory, but I don't really believe in reliable zeroizing.

you can store a config at `$XDG_CONFIG_DIR/passnag/config.toml`, which has a single key right now:

```toml
interval = "1w 1d 1h 1m 1s"
```

it accepts a sequence of space-separated suffixed numbers. suffixes mean weeks, days, hours, minutes and seconds respectively.
default is one day.

the time of the last successful attempt is stored in the file mtime, so if your FS messes with mtimes passnag will behave weird.

license is GPL 3.0 only.
