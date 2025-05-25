mod password;
mod generators;

use crate::password::{Password, Options};

fn main() {
    let options = Options {
        lowercase: true,
        uppercase: true,
        numbers: true,
        specials: true,
    };
    let password = Password::generate(13, options);
    println!("{}", password);
}
