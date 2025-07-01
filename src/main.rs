mod encryption;
mod errors;
mod generators;
mod password;

use std::error::Error;
use std::io::{self, Write};
use std::process;

use clap::{Parser, Subcommand};
use rpassword::prompt_password;

use crate::password::{PasswordRequest, Vault};

#[derive(Parser, Debug)]
#[command(name = "oktopass")]
#[command(about = "A simple CLI password manager", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    NewVault {
        #[arg(short, long)]
        name: String,
    },
    AddPass {
        #[arg(short, long)]
        vault_name: String,

        #[arg(short, long)]
        service: String,
    },
    GetPass {
        #[arg(short, long)]
        vault_name: String,

        #[arg(short, long)]
        service: String,
    },
    GenPass {
        #[arg(short, long)]
        vault_name: String,

        #[arg(short, long)]
        service: Option<String>,

        #[arg(short, long)]
        length: Option<usize>,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::NewVault { name } => {
            let master_password = prompt_password_with_confirmation(
                "Set master password: ",
                "Confirm master password: ",
            );
            let vault = match Vault::new(&name, &master_password) {
                Ok(vault) => vault,
                Err(err) => {
                    eprintln!("❗ Error creating vault: {err}");
                    std::process::exit(1);
                }
            };
            match vault.save() {
                Ok(_) => {
                    println!("✅ Vault {} created.", &vault.name)
                }
                Err(err) => {
                    eprintln!("❗ Error creating vault: {err}");
                    std::process::exit(1);
                }
            }
        }
        Commands::AddPass {
            vault_name,
            service,
        } => {
            let mut vault = load_vault(&vault_name);

            match vault.unlock(&request_password("Enter vault master password: ")) {
                Ok(_) => {
                    let password = prompt_password_with_confirmation(
                        "Enter new password: ",
                        "Confirm new password: ",
                    );
                    match vault.add_password(&service, &password) {
                        Ok(_) => {
                            println!("✅ Password successfully added to vault {}.", vault.name);
                        }
                        Err(err) => {
                            eprintln!("❗ Error saving password to vault {}: {err}", vault.name);
                            std::process::exit(1);
                        }
                    };

                    match vault.save() {
                        Ok(_) => {
                            println!("Vault {} successfully updated.", vault.name);
                        }
                        Err(err) => {
                            eprintln!(
                                "❗ Error updating vault {}. Password not saved: {err}",
                                vault.name
                            );
                            std::process::exit(1);
                        }
                    };
                }
                Err(err) => {
                    eprintln!("❗ Error unlocking vault: {err}");
                    std::process::exit(1);
                }
            }
        }
        Commands::GetPass {
            vault_name,
            service,
        } => {
            let mut vault = load_vault(&vault_name);

            match vault.unlock(&request_password("Enter vault master password: ")) {
                Ok(_) => match vault.get_password(&service) {
                    Some(pwd) => {
                        copy_to_clipboard(&pwd.password).expect("Failed to copy to clipboard!");
                        println!("✅ Password copied to clipboard!")
                    }
                    None => {
                        eprintln!("❗ Failed to retrieve password for {service}");
                        process::exit(1);
                    }
                },
                Err(err) => {
                    eprintln!("❗ Failed to retrieve password for '{service}': {err}",);
                    std::process::exit(1);
                }
            }
        }
        Commands::GenPass {
            vault_name,
            service,
            length,
        } => {
            let mut vault = load_vault(&vault_name);
            match vault.unlock(&request_password("Enter vault master password: ")) {
                Ok(_) => {
                    let options = prompt_password_options(service, length);
                    match vault.generate_password(options) {
                        Ok(_) => match vault.save() {
                            Ok(_) => {
                                println!("✅ Password successfully generated and vault saved!");
                            }
                            Err(err) => {
                                eprintln!("❗ Failed to save vault: {err}");
                                std::process::exit(1);
                            }
                        },
                        Err(err) => {
                            eprintln!("❗ Failed to generate password: {err}");
                            std::process::exit(1);
                        }
                    }
                }
                Err(err) => {
                    eprintln!("❗ Error unlocking vault: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn load_vault(vault_name: &str) -> Vault {
    match Vault::load(vault_name) {
        Ok(vault) => {
            println!("✅ Vault {} successfully loaded.", &vault_name);
            vault
        }
        Err(err) => {
            eprintln!("❗ Error loading vault {}: {err}", &vault_name);
            std::process::exit(1);
        }
    }
}

fn prompt_password_with_confirmation(prompt: &str, confirmation_prompt: &str) -> String {
    loop {
        let attempt_1 = request_password(prompt);
        let attempt_2 = request_password(confirmation_prompt);

        if attempt_1 == attempt_2 {
            return attempt_2;
        } else {
            eprintln!("❗ Passwords do not match. Try again.");
        }
    }
}

fn prompt_password_options(service: Option<String>, length: Option<usize>) -> PasswordRequest {
    fn prompt_password_name() -> String {
        print!("Enter password name (service): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        input.trim().to_string()
    }

    let name = match service {
        Some(name) => name,
        None => prompt_password_name(),
    };

    fn prompt_password_length() -> usize {
        print!("Enter the desired password length (default 16): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        input.trim().parse().unwrap_or(16)
    }

    let length = match length {
        Some(name) => name,
        None => prompt_password_length(),
    };

    fn ask(prompt: &str) -> bool {
        print!("{prompt} (y/n): ");
        io::stdout().flush().unwrap();

        let mut ans = String::new();
        io::stdin().read_line(&mut ans).unwrap();
        matches!(ans.trim().to_lowercase().as_str(), "y" | "yes")
    }

    PasswordRequest {
        name,
        length,
        lowercase: ask("Include lowercase letters?"),
        uppercase: ask("Include uppercase letters?"),
        numbers: ask("Include numbers?"),
        specials: ask("Include special characters?"),
    }
}

fn request_password(prompt: &str) -> String {
    match prompt_password(prompt) {
        Ok(pwd) => pwd,
        Err(err) => {
            eprint!("❗ Failed to read password: {err}");
            process::exit(1);
        }
    }
}

fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut ctx = copypasta_ext::try_context().expect("❗ Failed to get clipboard context.");
    ctx.set_contents(text.to_owned())?;
    Ok(())
}
