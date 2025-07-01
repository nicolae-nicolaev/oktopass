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

## 🛠️ Usage

```bash
oktopass [COMMAND] [OPTIONS]
```

### Commands

#### 🔐 `new-vault`

Create a new encrypted vault.

```bash
oktopass new-vault --name <vault_name>
```

You will be prompted to enter and confirm the master password.

---

#### ➕ `add-pass`

Add a password to an existing vault.

```bash
oktopass add-pass --vault-name <vault_name> --service <service_name>
```

You will be prompted to unlock the vault and enter a new password for the service.

---

#### 🔑 `get-pass`

Retrieve a password from a vault and copy it to your clipboard.

```bash
oktopass get-pass --vault-name <vault_name> --service <service_name>
```

You will be prompted to unlock the vault. If successful, the password will be copied to the clipboard.

---

#### 🔧 `gen-pass`

Generate a new secure password and add it to a vault.

```bash
oktopass gen-pass --vault-name <vault_name> --service <service_name>
```

You will be prompted to unlock the vault and provide password generation options (length, character sets, etc.).

---

## 🚀 Getting Started

### Prerequisites

- Rust (>=1.70)
- Cargo

### Build

```bash
git clone https://github.com/nicolae-nicolaev/oktopass.git
cd oktopass
./install.sh
