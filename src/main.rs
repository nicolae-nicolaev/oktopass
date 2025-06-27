#![allow(dead_code)] // TODO: remove this

mod encryption;
mod errors;
mod generators;
mod password;

use std::process;

use clap::Parser;
use rpassword::prompt_password;

use crate::password::Vault;

#[derive(Parser, Debug)]
#[command(name = "oktopass")]
#[command(about = "A simple CLI password manager", long_about = None)]
struct Args {
    #[arg(short, long)]
    vault: String,

    #[arg(short, long)]
    password: String,
}

fn main() {
    let args = Args::parse();

    let master_password =
        match prompt_password(format!("Enter master password for '{}': ", args.vault)) {
            Ok(pwd) => pwd,
            Err(err) => {
                eprint!("❗ Failed to read password: {}", err);
                process::exit(1);
            }
        };

    let mut vault = match Vault::load_from_file(args.vault) {
        Ok(vlt) => vlt,
        Err(err) => {
            eprintln!("❗ Failed to load vault: {}", err);
            process::exit(1);
        }
    };

    let password = match vault.unlock(master_password) {
        Ok(()) => match vault.get_password(&args.password) {
            Some(pwd) => pwd,
            None => {
                eprintln!("❗ Failed to retrieve password for {}", args.password);
                process::exit(1);
            }
        },
        Err(err) => {
            eprintln!(
                "❗ Failed to retrieve password for '{}': {}",
                args.password, err
            );
            process::exit(1);
        }
    };

    println!("Password for {}: {}", &args.password, password.password);
}
