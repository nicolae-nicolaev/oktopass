#![allow(dead_code)] // TODO: remove this

use rand::Rng;

pub fn generate_letter(uppercase: bool) -> char {
    let mut rng = rand::rng();
    let ascii_range = if uppercase { b'A'..=b'Z' } else { b'a'..=b'z' };

    rng.random_range(ascii_range) as char
}

pub fn generate_number() -> char {
    let mut rng = rand::rng();

    rng.random_range(b'0'..=b'9') as char
}

pub fn generate_special() -> char {
    let specials = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    let mut rng = rand::rng();

    let special_chars: Vec<char> = specials.chars().collect();
    let chosen_index = rng.random_range(0..special_chars.len());

    special_chars[chosen_index]
}
