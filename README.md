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
oktopass add-pass --vault <vault_name> --service <service_name>
```

You will be prompted to unlock the vault with the master password and enter a new password for the service.

---

#### 🔑 `get-pass`

Retrieve a password from a vault and copy it to your clipboard.

```bash
oktopass get-pass --vault <vault_name> --service <service_name>
```

You will be prompted to unlock the vault with the master password. If successful, the password will be copied to the clipboard.

---

#### 🔧 `gen-pass`

Generate a new secure password and add it to a vault.

```bash
oktopass gen-pass --vault <vault_name>
```

You will be prompted to unlock the vault with the master password and provide password generation options (service, length, character sets, etc.).

Service and length arguments can also be provided in the command.

```bash
oktopass gen-pass --vault-name <vault-name> --service <service> --length <length>
```

---

#### 👀 `show-serv`

Show the services password available in a vault.

```bash
oktopass show-serv --vault <vault>
```

You will be prompted to unlock the vault with the master password. If successful, the list of services available in the vault will be shown.

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
```
