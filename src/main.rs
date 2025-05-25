mod generators;
mod password;

use std::env;

use crate::password::{Options, Password};

fn main() {
    let args: Vec<String> = env::args().collect();
    let options = process_args(args);
    let password = Password::generate(options.length, options);
    println!("{}", password);
}

fn process_args(args: Vec<String>) -> Options {
    let mut options = Options {
        lowercase: true,
        uppercase: true,
        numbers: true,
        specials: true,
        length: 12,
    };

    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--no-specials"  | "-s" => options.specials = false,
            "--no-numbers"   | "-n" => options.numbers = false,
            "--no-lowercase" | "-l" => options.lowercase = false,
            "--no-uppercase" | "-u" => options.uppercase = false,
            "--length"       | "-L" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i+1].parse::<usize>() {
                        options.length = n;
                        i += 1;
                    } else {
                        eprintln!("Invalid password length: {}", args[i+1]);
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

    options
}
