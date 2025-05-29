mod generators;
mod password;

use std::env;

use crate::password::{ Manager, PasswordRequest };

fn main() -> std::io::Result<()> {
    // TODO: load passwords file

    let args: Vec<String> = env::args().collect();
    let request = process_args(args);

    if let Ok(mut manager)  = Manager::new("passwords.json") {
        manager.read_passwords_file()?;
        manager.generate(request)?;
        manager.write_passwords_file()?;
    } else {
        eprintln!("Could not open password file.");
        std::process::exit(1);
    }

    Ok(())
}

fn process_args(args: Vec<String>) -> PasswordRequest {
    if !args.iter().any(|arg| arg == "--name" || arg == "-N") {
        eprintln!("Missing password name. Use --name or -N flag followed by password name.");
        std::process::exit(1);
    }

    if !args.iter().any(|arg| arg == "--length" || arg == "-L") {
        eprintln!("Missing password length. Use --length or -L flag followd by password length.");
        std::process::exit(1);
    }

    // TODO: load defaults from config
    let mut request = PasswordRequest {
        lowercase: true,
        uppercase: true,
        numbers: true,
        specials: true,
        length: 12,
        name: String::from(""),
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-specials" | "-s" => request.specials = false,
            "--no-numbers" | "-n" => request.numbers = false,
            "--no-lowercase" | "-l" => request.lowercase = false,
            "--no-uppercase" | "-u" => request.uppercase = false,
            "--name" | "-N" => {
                if i + 1 < args.len() {
                    let name = String::from(&args[i + 1]);
                    if name.contains("-") {
                        eprintln!("Invalid password name: {}", name);
                        std::process::exit(1);
                    }
                    request.name = name;
                    i += 1;
                } else {
                    eprintln!("Missing name after {}", args[i]);
                    std::process::exit(1);
                }
            }
            "--length" | "-L" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse::<usize>() {
                        request.length = n;
                        i += 1;
                    } else {
                        eprintln!("Invalid password length: {}", args[i + 1]);
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("Missing length after {}", args[i]);
                    std::process::exit(1);
                }
            }
            &_ => (),
        }
        i += 1;
    }
    request
}
