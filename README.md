# PasswordCracker

> ⚠️ **For educational and authorised testing purposes only. Only use this tool on systems you own or have explicit written permission to test. Unauthorised use is illegal.**

A Python utility that automatically identifies and cracks password hashes, encoded strings, SSH key passphrases, and password-protected archives. Paste anything — hash, encoding, file path, or raw key text — and it attempts to recover the plaintext automatically.

## Setup

```bash
git clone https://github.com/ledksv/pscracker.git
cd pscracker
python3 PasswordCracker.py
```

**Requirements:** `hashcat`, `john`, `zip2john`, `rar2john`, `7z2john`, `pdf2john`, `keepass2john`, `ssh2john`

Optional online lookup: active internet connection for CrackStation API.

---

## What it does

Paste anything into the prompt — the tool detects what it is and runs the appropriate cracking pipeline.

| Input | Detection | Method |
|-------|-----------|--------|
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 hash | hashcat → john → brute-force |
| `$2y$10$...` | bcrypt | john + rockyou |
| `$krb5tgs$...` | Kerberoast TGS | hashcat mode 13100 |
| `-----BEGIN RSA PRIVATE KEY-----` | SSH private key | ssh2john + john |
| `file:archive.zip` | ZIP archive | zip2john + john |
| `file:document.pdf` | PDF | pdf2john + john |
| `file:database.kdbx` | KeePass vault | keepass2john + john |
| `aGVsbG8=` | Base64 | instant decode |
| `68656c6c6f` | Hex | instant decode |
| `%68%65%6C%6C%6F` | URL encoding | instant decode |

**Supported hash types:** MD5, NTLM, SHA-1/256/512, bcrypt, SHA-512 Crypt, Kerberos 5 TGS/AS-REP, Net-NTLMv1/v2, MSSQL, Oracle H, MySQL 3.23/4.1, Cisco Type 7, Django, Drupal, WPA-PBKDF2

**Encoding detection:** Base64, Hex, URL, ROT13, Binary, Octal, Cisco Type 7 (instant — no wordlist needed)

**Pipeline order:**
1. Encoding check (instant)
2. CrackStation online lookup
3. hashcat with rockyou + rules
4. john with rockyou
5. Brute-force masks (length 1–8)

---

## Demo

### SSH Key Passphrase (THM — Overpass)
Paste the raw private key text. The tool extracts the hash with `ssh2john` and cracks the passphrase with john.

![Startup screen](screenshots/01-startup.png)
![SSH key cracked → james13](screenshots/02-ssh-cracked.png)

---

### MD5 Hash
Paste a raw MD5 hash. Cracked via hashcat with rockyou + dive.rule.

![MD5 hash input](screenshots/03-md5-input.png)
![MD5 cracked → batman](screenshots/04-md5-cracked.png)

---

### ZIP Archive
Use `file:` prefix for file paths. Extracts the hash with `zip2john` and cracks with john.

![ZIP file input](screenshots/05-zip-input.png)
![ZIP cracked → dragon](screenshots/06-zip-cracked.png)

---

## Usage

```
$ python3 PasswordCracker.py

Paste ANYTHING below and press Enter:

  Hash      →  MD5 / NTLM / bcrypt / SHA / Kerberos / ...
  Encoding  →  Base64 / hex / URL / ROT13 / binary / Cisco7
  SSH key   →  paste key text directly (reads until -----END)
  File path →  prefix with 'file:'
                e.g.  file:/etc/shadow
                      file:/root/.ssh/id_rsa
                      file:archive.zip
                      file:document.pdf
                      file:database.kdbx
```

Output is saved to `cracked.txt`.

---

## Disclaimer

This tool is provided for educational purposes, CTF competitions, and authorised penetration testing engagements only. The authors accept no responsibility for misuse. Always obtain explicit written permission before testing any system you do not own.
