// passnag: nags you to train your passwords
//
// Copyright (C) 2025 Maximilian Siling
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#[cfg(not(unix))]
compile_error!("sorry, please use unixish systems");

use argon2::{
    password_hash::{PasswordHasher as _, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use std::{
    borrow::Cow,
    fmt::Display,
    fs,
    io::{self, Read as _, Write as _},
    mem,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr as _,
    time::{Duration, SystemTime},
};
use stdont::ResultExt as _;

use etcetera::AppStrategy as _;
use serde::{de::Error as _, Deserialize, Deserializer};
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(deserialize_with = "parse_duration", default = "default_interval")]
    interval: Duration,
}

fn main() -> ExitCode {
    let dirs = etcetera::choose_app_strategy(etcetera::AppStrategyArgs {
        top_level_domain: String::new(),
        author: String::new(),
        app_name: "passnag".to_owned(),
    })
    .expect_display("failed to find app directories");
    let passwords_dir = dirs.data_dir();
    fs::create_dir_all(&passwords_dir).expect_display("failed to create data dir");

    let config = parse_config(&dirs.config_dir());

    let args: Vec<_> = std::env::args().collect();
    let args: Vec<_> = args.iter().skip(1).map(String::as_str).collect();
    match args.as_slice() {
        ["add", name] => {
            let password = get_pass(format_args!("enter password for `{name}`: "));
            let repeat = get_pass("repeat: ");
            if password != repeat {
                eprintln!("not equal, try again");
                return ExitCode::FAILURE;
            }

            let salt = SaltString::generate(&mut rand_core::OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .unwrap_display()
                .to_string();
            fs::write(passwords_dir.join(name), password_hash)
                .expect_display("failed to write password hash");
        }
        [] => {
            train(&passwords_dir, config.interval);
        }
        ["all"] => {
            train(&passwords_dir, Duration::default());
        }
        ["nag"] => {
            if expired(&passwords_dir, config.interval).next().is_some() {
                // cutesy voice to make nagging less/more annoying
                println!("time to train your passwords~ run `passnag` now~");
            }
        }
        _ => {
            eprintln!("usage:");
            eprintln!("- `passnag` (to check your memory)");
            eprintln!("- `passnag all` (to check all passwords, regardless of intervals)");
            eprintln!("- `passnag nag` (to nag if needed)");
            eprintln!("- `passnag add <name>` (to add a new password)");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

fn train(passwords_dir: &Path, interval: Duration) {
    let now = SystemTime::now();
    let mut asked = 0;
    let mut skipped = 0;
    for password_path in expired(passwords_dir, interval) {
        asked += 1;
        let mut file = fs::File::open(&password_path)
            .unwrap_or_else(|err| panic!("failed to open {}: {err}", password_path.display()));
        let name = password_path.file_name().unwrap().to_string_lossy();
        let raw_hash = {
            let mut raw_hash = String::new();
            file.read_to_string(&mut raw_hash)
                .expect_display("failed to read password path");
            raw_hash
        };
        let hash = PasswordHash::new(&raw_hash).expect_display("failed to parse password hash");
        let argon2 = Argon2::default();
        loop {
            let password = get_pass(format_args!(
                "enter password for `{name}` (or `/skip` to skip): ",
            ));
            if password.as_str() == "/skip" {
                skipped += 1;
                break;
            }
            if argon2.verify_password(password.as_bytes(), &hash).is_ok() {
                file.set_modified(now).expect_display("failed to set mtime");
                break;
            }
            println!("try again, silly~");
        }
    }
    match (asked, skipped) {
        (0, _) => println!("nothing to train right now"),
        (_, 0) => println!("wow, you're so smart~"),
        (1, 1) => println!("really? you have a single password and you skipped it?"),
        (a, s) if a == s => println!("really? you skipped all of them? dumb."),
        _ => println!("make sure to remember the ones you skipped!"),
    }
}

fn expired(data_dir: &Path, interval: Duration) -> impl Iterator<Item = PathBuf> {
    let now = SystemTime::now();
    fs::read_dir(data_dir)
        .expect_display("failed to read passwords directory")
        .filter_map(move |entry| {
            let entry = entry.expect_display("failed to read directory entry");
            let meta = entry
                .metadata()
                .expect_display("failed to read password file metadata");
            let mtime = meta.modified().expect("failed to read password file mtime");
            // `>=` so `interval = 0` always triggers
            (now.duration_since(mtime).unwrap_or_default() >= interval).then(|| entry.path())
        })
}

fn get_pass(prompt: impl Display) -> Zeroizing<String> {
    with_no_echo(|| {
        let mut buf = Zeroizing::new(String::new());
        print!("{prompt}");
        std::io::stdout().flush().unwrap_display();
        std::io::stdin().read_line(&mut buf).unwrap_display();
        while buf.as_bytes().last() == Some(&b'\n') {
            buf.pop();
        }
        println!();
        buf
    })
    .unwrap_display()
}

fn with_no_echo<R>(f: impl FnOnce() -> R) -> io::Result<R> {
    // SAFETY: should be fine, it's just a bunch of ints.
    let mut termios: libc::termios = unsafe { mem::zeroed() };
    // SAFETY: we're passing a valid pointer (it's derived from a reference).
    if unsafe { libc::tcgetattr(0, &mut termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    termios.c_lflag &= !libc::ECHO;
    // SAFETY: still a valid pointer, we just flipped a flag
    if unsafe { libc::tcsetattr(0, 0, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let res = f();
    termios.c_lflag |= libc::ECHO;
    if unsafe { libc::tcsetattr(0, 0, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(res)
}

fn parse_config(config_dir: &Path) -> Config {
    let config_text = fs::read_to_string(config_dir.join("config.toml")).unwrap_or_default();
    toml::from_str(&config_text).expect_display("failed to parse config")
}

fn default_interval() -> Duration {
    // 1 day. Why is `::from_days()` unstable?
    Duration::from_secs(60 * 60 * 24)
}

fn parse_duration<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
    let raw = <Cow<'_, str>>::deserialize(de)?;
    if raw.trim().is_empty() {
        return Err(D::Error::invalid_value(
            serde::de::Unexpected::Other("an empty string"),
            &"a valid duration",
        ));
    }

    let mut result = Duration::default();
    for part in raw.split_whitespace() {
        let multiplier = match part.as_bytes().last() {
            None => continue,
            Some(b's') => 1,
            Some(b'm') => 60,
            Some(b'h') => 60 * 60,
            Some(b'd') => 60 * 60 * 24,
            Some(b'w') => 60 * 60 * 24 * 7,
            Some(&c) => {
                return Err(D::Error::invalid_value(
                    serde::de::Unexpected::Str(&String::from(c as char)),
                    &"number plus one of `s`, `m`, `h`, `d`, `w`",
                ))
            }
        };
        let digits = part[..part.len() - 1].trim();
        let Ok(number) = u64::from_str(digits) else {
            return Err(D::Error::invalid_value(
                serde::de::Unexpected::Str(digits),
                &"a valid number",
            ));
        };
        result += Duration::from_secs(multiplier * number);
    }

    Ok(result)
}
