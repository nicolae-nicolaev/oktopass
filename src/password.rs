use crate::generators::{generate_letter, generate_number, generate_special};

use rand::seq::IndexedRandom;
use rand::seq::SliceRandom;

pub struct Password;

pub struct Options {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub specials: bool,
}

impl Password {
    pub fn generate(n: usize, options: Options) -> String {
        let mut rng = rand::rng();

        let mut password: Vec<char> = Vec::new();
        let mut pools: Vec<Box<dyn Fn() -> char>> = Vec::new();

        if options.lowercase {
            pools.push(Box::new(|| generate_letter(false)));
        }

        if options.uppercase {
            pools.push(Box::new(|| generate_letter(true)));
        }

        if options.numbers {
            pools.push(Box::new(|| generate_number()));
        }

        if options.specials {
            pools.push(Box::new(|| generate_special()));
        }

        if pools.is_empty() {
            panic!("No options selected  for password generation.");
        }

        while password.len() < n {
            let generator = pools.choose(&mut rng).unwrap();
            password.push(generator());
        }

        password.shuffle(&mut rng);

        password.iter().collect()
    }
}
