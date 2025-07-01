# 🐙 Oktopass

**Oktopass** is a simple, secure, and lightweight command-line password manager written in Rust.  
It supports creating encrypted vaults, generating and storing passwords, and retrieving them securely—all from the terminal.

---

## ✨ Features

- 🔐 Create encrypted vaults protected by a master password
- 🔏 Add new passwords to a specific vault
- 🧠 Retrieve passwords by decrypting the vault
- 🎲 Generate strong, customizable passwords
- 📋 Copy passwords directly to the clipboard (Linux, Wayland, macOS support)
- 🦀 Fully written in Rust for speed and safety

---

## 🚀 Getting Started

### Prerequisites

- Rust (>=1.70)
- Cargo

### Build

```bash
git clone https://github.com/nicolae-nicolaev/oktopass.git
cd oktopass
cargo build --release
