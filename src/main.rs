mod encryption;
mod errors;
mod generators;
mod password;

use std::error::Error;
use std::process;

use clap::Parser;
use copypasta::{ClipboardContext, ClipboardProvider};
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

    match vault.unlock(master_password) {
        Ok(()) => match vault.get_password(&args.password) {
            Some(pwd) => {
                copy_to_clipboard(&pwd.password).expect("Failed to copy to clipboard!");
                println!("✅ Password copied to clipboard!")
            }
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
}

fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut ctx = ClipboardContext::new()?;
    ctx.set_contents(text.to_owned())?;
    Ok(())
}
