#!/usr/bin/env python3
"""
PasswordCracker - Universal automated password cracker / decoder.
Paste anything. It identifies it, picks the right tool, and gives you the password.
"""

import base64
import codecs
import html
import json
import os
import re
import readline
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

BANNER = r"""
  ____                                     _  ____                _
 |  _ \ __ _ ___ _____      _____  _ __ __| |/ ___|_ __ __ _  ___| | _____ _ __
 | |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` | |   | '__/ _` |/ __| |/ / _ \ '__|
 |  __/ (_| \__ \__ \\ V  V / (_) | | | (_| | |__| | | | (_| | (__|   <  __/ |
 |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|\____|_|  \__,_|\___|_|\_\___|_|

  Universal Password Cracker — paste anything, get the password.
"""

OUTPUT_FILE = "cracked.txt"

WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/opt/wordlists/rockyou.txt",
    os.path.expanduser("~/wordlists/rockyou.txt"),
]

RULE_FILES = [
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/dive.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
]

SSH2JOHN_CANDIDATES = [
    "/usr/share/john/ssh2john.py",
    "/usr/lib/john/ssh2john.py",
    "/opt/john/ssh2john.py",
]

PDF2JOHN_CANDIDATES = [
    "/usr/share/john/pdf2john.pl",
    "/usr/share/john/pdf2john.py",
    "/usr/lib/john/pdf2john.pl",
]

# Brute-force masks tried in order (most common short passwords first)
BRUTE_MASKS = [
    ("4-digit PIN",        "?d?d?d?d"),
    ("6-digit PIN",        "?d?d?d?d?d?d"),
    ("4-char lowercase",   "?l?l?l?l"),
    ("5-char lowercase",   "?l?l?l?l?l"),
    ("6-char lowercase",   "?l?l?l?l?l?l"),
    ("4-char mixed",       "?a?a?a?a"),
    ("Cap+4lower+digit",   "?u?l?l?l?l?d"),
    ("6lower+2digit",      "?l?l?l?l?l?l?d?d"),
]

# XOR key for Cisco Type 7 passwords
_CISCO7_KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c,
    0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a,
    0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63,
    0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66,
    0x67, 0x38, 0x37,
]

# ─────────────────────────────────────────────────────────────────────────────
# Hash signature table
# (regex, display_name, hashcat_mode, jtr_format, use_rules)
# use_rules: True = fast hash (apply mangling rules); False = slow (wordlist only)
# ─────────────────────────────────────────────────────────────────────────────
HASH_SIGS = [
    # ── Unix crypt ───────────────────────────────────────────────────────────
    (r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{50,60}$',
        "bcrypt",                       3200,  "bcrypt",          False),
    (r'^\$6\$[^$]*\$[./A-Za-z0-9]{86}$',
        "sha512crypt ($6$)",             1800,  "sha512crypt",     False),
    (r'^\$5\$[^$]*\$[./A-Za-z0-9]{43}$',
        "sha256crypt ($5$)",             7400,  "sha256crypt",     False),
    (r'^\$1\$[^$]*\$[./A-Za-z0-9]{22}$',
        "md5crypt ($1$)",                500,   "md5crypt",        False),
    (r'^\$apr1\$[^$]*\$[./A-Za-z0-9]{22}$',
        "APR1-md5crypt",                1600,  "md5crypt-apr1",   False),
    # ── CMS / framework ──────────────────────────────────────────────────────
    (r'^\$P\$[./A-Za-z0-9]{31}$',
        "phpass (WordPress/Drupal)",     400,   "phpass",          False),
    (r'^\$H\$[./A-Za-z0-9]{31}$',
        "phpass (phpBB3)",               400,   "phpass",          False),
    (r'^\$S\$[./A-Za-z0-9]{52}$',
        "Drupal7 (SHA-512)",            7900,  "drupal7",         False),
    (r'^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$',
        "Django PBKDF2-SHA256",         10000, None,              False),
    (r'^sha1\$[A-Za-z0-9]+\$[a-fA-F0-9]{40}$',
        "Django SHA-1",                 124,   None,              True),
    (r'^md5\$[A-Za-z0-9]+\$[a-fA-F0-9]{32}$',
        "Django MD5",                   3910,  None,              True),
    # ── Kerberos ─────────────────────────────────────────────────────────────
    (r'^\$krb5asrep\$23\$',
        "Kerberos 5 AS-REP",            18200, None,              True),
    (r'^\$krb5tgs\$23\$',
        "Kerberos 5 TGS (RC4)",         13100, None,              True),
    (r'^\$krb5tgs\$17\$',
        "Kerberos 5 TGS (AES-128)",     19600, None,              True),
    (r'^\$krb5tgs\$18\$',
        "Kerberos 5 TGS (AES-256)",     19700, None,              True),
    # ── Windows ──────────────────────────────────────────────────────────────
    (r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$',
        "NetNTLMv2",                    5600,  "netntlmv2",       True),
    (r'^[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::',
        "NTLM (SAM dump)",              1000,  "NT",              True),
    (r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$',
        "NetNTLMv1",                    5500,  "netntlm",         True),
    # ── MSSQL ────────────────────────────────────────────────────────────────
    (r'^0x[a-fA-F0-9]{80}$',
        "MSSQL 2000",                   131,   "mssql",           True),
    (r'^0x[a-fA-F0-9]{88}$',
        "MSSQL 2005",                   132,   "mssql05",         True),
    (r'^0x[a-fA-F0-9]{136}$',
        "MSSQL 2012+",                  1731,  "mssql12",         True),
    # ── Oracle ───────────────────────────────────────────────────────────────
    (r'^S:[a-fA-F0-9]{60}$',
        "Oracle 11g/12c (SHA-1)",       112,   "oracle11",        True),
    (r'^[a-fA-F0-9]{16}$',
        "Oracle 10g / MySQL 3.x",       3100,  "oracle",          True),
    # ── Cisco ────────────────────────────────────────────────────────────────
    (r'^\$8\$[./a-zA-Z0-9]{14}\$[./a-zA-Z0-9]{43}$',
        "Cisco Type 8 (PBKDF2-SHA256)", 9200,  None,              False),
    (r'^\$9\$[./a-zA-Z0-9]{14}\$[./a-zA-Z0-9]{43}$',
        "Cisco Type 9 (scrypt)",        9300,  None,              False),
    # Note: Cisco Type 5 = md5crypt, matched above by the $1$ pattern
    # Cisco Type 7 is XOR — handled in try_decodings(), not here
    # ── MySQL ─────────────────────────────────────────────────────────────────
    (r'^\*[A-F0-9]{40}$',
        "MySQL 4.1+",                   300,   "mysql-sha1",      True),
    # ── Generic length-based (checked last) ──────────────────────────────────
    (r'^[a-fA-F0-9]{32}$',
        "MD5",                          0,     "raw-md5",         True),
    (r'^[a-fA-F0-9]{32}$',
        "NTLM",                         1000,  "NT",              True),
    (r'^[a-fA-F0-9]{40}$',
        "SHA-1",                        100,   "raw-sha1",        True),
    (r'^[a-fA-F0-9]{56}$',
        "SHA-224",                      1300,  "raw-sha224",      True),
    (r'^[a-fA-F0-9]{64}$',
        "SHA-256",                      1400,  "raw-sha256",      True),
    (r'^[a-fA-F0-9]{96}$',
        "SHA-384",                      10800, "raw-sha384",      True),
    (r'^[a-fA-F0-9]{128}$',
        "SHA-512",                      1700,  "raw-sha512",      True),
]

# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────
def _c(t, code): return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t
def green(t):  return _c(t, 92)
def red(t):    return _c(t, 91)
def yellow(t): return _c(t, 93)
def cyan(t):   return _c(t, 96)
def bold(t):   return _c(t, 1)
def dim(t):    return _c(t, 2)


# ─────────────────────────────────────────────────────────────────────────────
# Environment helpers
# ─────────────────────────────────────────────────────────────────────────────
def which(name): return shutil.which(name)

def find_wordlist():
    for wl in WORDLISTS:
        p = Path(wl).expanduser()
        if p.exists():
            return str(p)
    return None

def find_rule():
    for r in RULE_FILES:
        if Path(r).exists():
            return r
    return None

def find_script(candidates, path_name):
    """Find a helper script (ssh2john, pdf2john, etc.) from a list of candidates."""
    if which(path_name):
        return path_name
    for c in candidates:
        if Path(c).exists():
            return c
    return None

def has_gpu():
    try:
        r = subprocess.run(["hashcat", "-I"], capture_output=True, text=True, timeout=10)
        return "GPU" in r.stdout
    except Exception:
        return False

def _tmp(suffix=""):
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.close()
    return f.name

def _cleanup(*paths):
    for p in paths:
        try: os.unlink(p)
        except FileNotFoundError: pass


# ─────────────────────────────────────────────────────────────────────────────
# Detection helpers
# ─────────────────────────────────────────────────────────────────────────────
def _looks_like_text(s, min_len=4):
    """True if s is likely a real human-readable string (not binary garbage)."""
    if not s or len(s) < min_len:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in "\n\r\t")
    return printable / len(s) >= 0.85

def _looks_like_known_hash(s):
    for pattern, *_ in HASH_SIGS:
        if re.match(pattern, s.strip(), re.IGNORECASE):
            return True
    return False

def is_ssh_key_text(s):
    return "BEGIN" in s and "PRIVATE KEY" in s and "END" in s

def is_ssh_key_file(path):
    try:
        with open(path, errors="ignore") as f:
            h = f.read(80)
        return "BEGIN" in h and "PRIVATE KEY" in h
    except Exception:
        return False

def file_type(path):
    """Detect file type for special handling. Returns one of: ssh, zip, rar, 7z, pdf, keepass, hashes."""
    p = Path(path)
    ext = p.suffix.lower()
    if is_ssh_key_file(path):
        return "ssh"
    if ext in (".zip",):
        return "zip"
    if ext in (".rar",):
        return "rar"
    if ext in (".7z",):
        return "7z"
    if ext in (".pdf",):
        return "pdf"
    if ext in (".kdbx", ".kdb"):
        return "keepass"
    # Magic bytes
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
        if magic[:4] == b"PK\x03\x04":
            return "zip"
        if magic[:7] == b"Rar!\x1a\x07":
            return "rar"
        if magic[:6] == b"7z\xbc\xaf'\x1c":
            return "7z"
        if magic[:4] == b"%PDF":
            return "pdf"
        if magic[:4] == b"\x03\xd9\xa2\x9a":  # KeePass 1.x
            return "keepass"
        if magic[:4] == b"\x03\xd9\xa2\x9a" or b"KDBX" in magic:
            return "keepass"
    except Exception:
        pass
    return "hashes"


# ─────────────────────────────────────────────────────────────────────────────
# Stage 0 — Online hash lookup (no wordlist needed)
# ─────────────────────────────────────────────────────────────────────────────
def online_lookup(hash_str):
    """
    Query CrackStation for an instant result.
    Returns (service_name, plaintext) or (None, None).
    """
    print(dim("      → CrackStation online lookup..."))
    try:
        data = urllib.parse.urlencode({"hash": hash_str, "key": ""}).encode()
        req  = urllib.request.Request(
            "https://crackstation.net/api/",
            data=data,
            headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read().decode())
        if results and isinstance(results, list):
            for entry in results:
                if entry.get("cracked") is not False and entry.get("result"):
                    return "CrackStation (online)", entry["result"]
    except Exception:
        pass
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Encoding / cipher detection (fully reversible, no wordlist)
# ─────────────────────────────────────────────────────────────────────────────
def decode_cisco_type7(s):
    """Decode a Cisco IOS Type 7 obfuscated password."""
    if not re.match(r'^\d{2}[a-fA-F0-9]+$', s):
        return None
    try:
        seed = int(s[:2])
        raw  = bytes.fromhex(s[2:])
        return "".join(chr(b ^ _CISCO7_KEY[(seed + i) % len(_CISCO7_KEY)]) for i, b in enumerate(raw))
    except Exception:
        return None


def try_decodings(s):
    """
    Try all reversible encodings/ciphers.
    Returns list of (encoding_name, decoded_value) for everything that produces readable text.
    """
    found = []

    def _add(name, decoded):
        if decoded and decoded != s and _looks_like_text(decoded, min_len=4) and not _looks_like_known_hash(decoded):
            entry = (name, decoded)
            if entry not in found:
                found.append(entry)

    # Base64 standard
    try:
        padded = s + "=" * (-len(s) % 4)
        _add("Base64", base64.b64decode(padded, validate=True).decode("utf-8"))
    except Exception: pass

    # Base64 URL-safe
    try:
        padded = s + "=" * (-len(s) % 4)
        _add("Base64 URL-safe", base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception: pass

    # Hex → text (only even-length strings ≥6 chars that decode to printable)
    try:
        if re.match(r'^[a-fA-F0-9]+$', s) and len(s) % 2 == 0 and len(s) >= 6:
            _add("Hex-encoded text", bytes.fromhex(s).decode("utf-8"))
    except Exception: pass

    # URL encoding
    try:
        _add("URL-encoded", urllib.parse.unquote(s))
    except Exception: pass

    # HTML entities
    try:
        _add("HTML entities", html.unescape(s))
    except Exception: pass

    # ROT13 — only flag if:
    #   - result is mostly alphabetic (not a hash or hex string rotated)
    #   - result doesn't start with $ (would indicate a hash-like format)
    #   - original doesn't look like a known hash (no point ROT13-ing a hash)
    try:
        if not s.startswith("$") and not _looks_like_known_hash(s):
            dec = codecs.decode(s, "rot_13")
            alpha_ratio = sum(c.isalpha() for c in dec) / max(len(dec), 1)
            if (dec != s and _looks_like_text(dec, min_len=6)
                    and alpha_ratio >= 0.6 and not dec.startswith("$")):
                found.append(("ROT13", dec))
    except Exception: pass

    # Binary string
    try:
        bits = s.replace(" ", "").replace("\t", "")
        if re.match(r'^[01]+$', bits) and len(bits) % 8 == 0 and len(bits) >= 16:
            _add("Binary", "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)))
    except Exception: pass

    # Octal (space-separated numbers)
    try:
        parts = s.split()
        if len(parts) >= 3 and all(re.match(r'^[0-7]{2,3}$', p) for p in parts):
            _add("Octal", "".join(chr(int(p, 8)) for p in parts))
    except Exception: pass

    # Cisco IOS Type 7
    try:
        dec = decode_cisco_type7(s)
        if dec and _looks_like_text(dec, min_len=1):
            found.append(("Cisco IOS Type 7", dec))
    except Exception: pass

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Hash identification
# ─────────────────────────────────────────────────────────────────────────────
def identify_hashes(s):
    """
    Return list of (name, hashcat_mode, jtr_format, use_rules) candidates.
    For ambiguous types (MD5 vs NTLM) both are returned — both will be tried.
    """
    candidates = []

    # hashid gives confident results on Kali
    if which("hashid"):
        try:
            r = subprocess.run(["hashid", "-m", s], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                m = re.search(r'\[\+\] (.+?) \[Hashcat Mode: (\d+)\]', line)
                if m:
                    name = m.group(1).strip()
                    hc   = int(m.group(2))
                    if any(c[1] == hc for c in candidates):
                        continue
                    use_rules = next((sig[4] for sig in HASH_SIGS if sig[2] == hc), True)
                    jtr       = next((sig[3] for sig in HASH_SIGS if sig[2] == hc), None)
                    candidates.append((name, hc, jtr, use_rules))
        except Exception: pass

    if candidates:
        return candidates

    # Regex fallback
    seen = set()
    for pattern, name, hc, jtr, use_rules in HASH_SIGS:
        if re.match(pattern, s.strip(), re.IGNORECASE):
            key = (hc, jtr)
            if key not in seen:
                seen.add(key)
                candidates.append((name, hc, jtr, use_rules))

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Cracking engines
# ─────────────────────────────────────────────────────────────────────────────
def _write_hash(s):
    hf = _tmp(".hash")
    with open(hf, "w") as f:
        f.write(s.strip() + "\n")
    return hf


def crack_hashcat(hash_str, hc_mode, use_rules, wordlist):
    """Wordlist attack with optional rule mangling. Returns {hash: pw} or {}."""
    hf  = _write_hash(hash_str)
    out = hf + ".out"
    pot = hf + ".pot"

    cmd = [
        "hashcat", "-m", str(hc_mode), hf, wordlist,
        "--potfile-path", pot, "--outfile", out, "--outfile-format", "2",
        "--force", "--status", "--status-timer=15",
    ]
    rule = find_rule() if use_rules else None
    if rule:
        cmd += ["-r", rule]

    print(dim(f"      → hashcat -m {hc_mode}" + (" + rules" if rule else "")))
    try:
        subprocess.run(cmd, timeout=600)
    except subprocess.TimeoutExpired:
        print(yellow("      [!] hashcat timed out"))
    except Exception as e:
        print(yellow(f"      [!] hashcat: {e}"))

    result = _read_outfile(out) or _read_potfile(pot)
    _cleanup(hf, out, pot)
    return result


def brute_force(hash_str, hc_mode):
    """Mask attack fallback. Returns {hash: pw} or {}."""
    if not which("hashcat"):
        return {}
    print(cyan("      Trying brute-force masks..."))
    hf  = _write_hash(hash_str)
    out = hf + ".out"
    pot = hf + ".pot"

    for label, mask in BRUTE_MASKS:
        print(dim(f"        → {label}  ({mask})"))
        cmd = [
            "hashcat", "-m", str(hc_mode), "-a", "3", hf, mask,
            "--potfile-path", pot, "--outfile", out, "--outfile-format", "2",
            "--force", "--status", "--status-timer=15",
        ]
        try:
            subprocess.run(cmd, timeout=120)
        except (subprocess.TimeoutExpired, Exception):
            pass
        result = _read_outfile(out) or _read_potfile(pot)
        if result:
            _cleanup(hf, out, pot)
            return result

    _cleanup(hf, out, pot)
    return {}


def crack_john(hash_str, jtr_fmt, wordlist):
    """John wordlist attack. Returns {id: pw} or {}."""
    hf = _write_hash(hash_str)
    print(dim(f"      → john --format={jtr_fmt}"))
    try:
        subprocess.run(
            ["john", f"--format={jtr_fmt}", f"--wordlist={wordlist}", hf],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        print(yellow("      [!] john timed out"))
    except Exception as e:
        print(yellow(f"      [!] john: {e}"))
        _cleanup(hf)
        return {}

    show = subprocess.run(
        ["john", f"--format={jtr_fmt}", "--show", hf],
        capture_output=True, text=True,
    )
    result = {}
    for line in show.stdout.splitlines():
        if ":" in line and not re.match(r'^\d+ password', line):
            k, _, v = line.partition(":")
            result[k.strip()] = v.split(":")[0].strip()

    _cleanup(hf)
    return result


def _john_convert_and_crack(converter_cmd, label, jtr_format, wordlist):
    """
    Generic helper: run a *2john converter, write its output, crack with john.
    Returns (method, password) or (None, None).
    """
    hash_file = _tmp(".jtrash")
    print(dim(f"      → {' '.join(converter_cmd[:3])} (extracting hash)"))
    try:
        r = subprocess.run(converter_cmd, capture_output=True, text=True, timeout=15)
        if not r.stdout.strip():
            err = r.stderr.strip()[:120]
            if any(kw in err.lower() for kw in ("no password", "no encrypted", "not encrypted")):
                print(yellow(f"      [!] {label}: no passphrase set"))
            else:
                print(yellow(f"      [!] {label} converter failed: {err}"))
            _cleanup(hash_file)
            return None, None
        with open(hash_file, "w") as f:
            f.write(r.stdout)
    except Exception as e:
        print(red(f"      [!] {label} converter error: {e}"))
        _cleanup(hash_file)
        return None, None

    print(dim(f"      → john --format={jtr_format} --wordlist=..."))
    try:
        subprocess.run(
            ["john", f"--format={jtr_format}", f"--wordlist={wordlist}", hash_file],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        print(yellow(f"      [!] john timed out on {label}"))

    show = subprocess.run(
        ["john", f"--format={jtr_format}", "--show", hash_file],
        capture_output=True, text=True,
    )
    _cleanup(hash_file)

    for line in show.stdout.splitlines():
        if ":" in line and not re.match(r'^\d+ password', line):
            _, _, pw = line.partition(":")
            pw = pw.split(":")[0].strip()
            if pw:
                return f"{label} passphrase (john)", pw

    print(dim(f"      john: passphrase not in wordlist"))
    return None, None


def crack_ssh_key(key_path, wordlist):
    ssh2john = find_script(SSH2JOHN_CANDIDATES, "ssh2john")
    if not ssh2john:
        print(red("      [!] ssh2john not found"))
        return None, None
    if not which("john"):
        print(red("      [!] john not found"))
        return None, None
    cmd = ["python3", ssh2john, key_path] if ssh2john.endswith(".py") else [ssh2john, key_path]
    return _john_convert_and_crack(cmd, "SSH key", "ssh", wordlist)


def crack_zip(zip_path, wordlist):
    if not which("zip2john"):
        print(yellow("      [!] zip2john not found"))
        return None, None
    return _john_convert_and_crack(["zip2john", zip_path], "ZIP", "pkzip", wordlist)


def crack_rar(rar_path, wordlist):
    if not which("rar2john"):
        print(yellow("      [!] rar2john not found"))
        return None, None
    return _john_convert_and_crack(["rar2john", rar_path], "RAR", "rar", wordlist)


def crack_7z(path, wordlist):
    j2j = find_script([], "7z2john") or find_script([], "7z2john.pl")
    if not j2j:
        # try common Kali location
        for c in ["/usr/share/john/7z2john.pl", "/usr/lib/john/7z2john.pl"]:
            if Path(c).exists():
                j2j = c
                break
    if not j2j:
        print(yellow("      [!] 7z2john not found"))
        return None, None
    cmd = ["perl", j2j, path] if j2j.endswith(".pl") else [j2j, path]
    return _john_convert_and_crack(cmd, "7z archive", "7z", wordlist)


def crack_pdf(pdf_path, wordlist):
    pdf2john = find_script(PDF2JOHN_CANDIDATES, "pdf2john")
    if not pdf2john:
        print(yellow("      [!] pdf2john not found"))
        return None, None
    if pdf2john.endswith(".pl"):
        cmd = ["perl", pdf2john, pdf_path]
    elif pdf2john.endswith(".py"):
        cmd = ["python3", pdf2john, pdf_path]
    else:
        cmd = [pdf2john, pdf_path]
    return _john_convert_and_crack(cmd, "PDF", "pdf", wordlist)


def crack_keepass(kdbx_path, wordlist):
    if not which("keepass2john"):
        print(yellow("      [!] keepass2john not found"))
        return None, None
    return _john_convert_and_crack(["keepass2john", kdbx_path], "KeePass", "keepass", wordlist)


def _read_outfile(path):
    result = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if ":" in line:
                    h, pw = line.rsplit(":", 1)
                    result[h] = pw
    except FileNotFoundError: pass
    return result


def _read_potfile(path):
    result = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if ":" in line:
                    h, pw = line.split(":", 1)
                    result[h] = pw
    except FileNotFoundError: pass
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Core orchestration
# ─────────────────────────────────────────────────────────────────────────────
def process(raw, wordlist):
    """
    Fully automatic detection and cracking/decoding of a single string.
    Returns (method, plaintext) or (None, None).

    Order of operations:
      0. SSH private key pasted directly
      1. Encoding / cipher detection  (instant, no wordlist)
      2. Online hash lookup           (instant, no wordlist)
      3. Wordlist + rules attack      (hashcat preferred, john fallback)
      4. Brute-force mask attack      (last resort)
    """
    raw = raw.strip()
    if not raw:
        return None, None

    # ── 0. SSH key pasted as raw text ─────────────────────────────────────
    if is_ssh_key_text(raw):
        print(cyan("  Detected: SSH private key (pasted text)"))
        if not wordlist:
            print(red("      No wordlist — cannot crack passphrase"))
            return None, None
        kf = _tmp(".pem")
        with open(kf, "w") as f:
            f.write(raw + "\n")
        os.chmod(kf, 0o600)
        method, pw = crack_ssh_key(kf, wordlist)
        _cleanup(kf)
        return method, pw

    # ── 1. Encoding / cipher detection ────────────────────────────────────
    print(cyan("  [1] Checking encodings / ciphers..."))
    decoded = try_decodings(raw)
    if decoded:
        best = next((d for d in decoded if "ROT13" not in d[0]), decoded[0])
        enc_name, plaintext = best
        if len(decoded) > 1:
            others = ", ".join(f"{e}" for e, _ in decoded if (e, _) != best)
            print(dim(f"      (also matched by: {others})"))
        return enc_name, plaintext
    print(dim("      Nothing decodable."))

    # ── 2. Online hash lookup ─────────────────────────────────────────────
    print(cyan("  [2] Online lookup..."))
    method, pw = online_lookup(raw)
    if pw:
        return method, pw
    print(dim("      Not found online."))

    # ── 3. Local cracking ─────────────────────────────────────────────────
    if not wordlist:
        print(red("  [!] No wordlist found — skipping local crack"))
        return None, None

    print(cyan("  [3] Identifying hash and cracking locally..."))
    candidates = identify_hashes(raw)
    if not candidates:
        print(red("  [!] Unknown type — not a recognised hash, encoding, or cipher."))
        return None, None

    for name, hc_mode, jtr_fmt, use_rules in candidates:
        strat = "wordlist + rules" if use_rules else "wordlist only (slow hash)"
        print(cyan(f"      Type : {name}  |  {strat}"))

        if which("hashcat") and hc_mode is not None:
            result = crack_hashcat(raw, hc_mode, use_rules, wordlist)
            if result:
                return f"{name} (hashcat)", next(iter(result.values()))
            print(dim("      hashcat: not in wordlist"))

        if which("john") and jtr_fmt is not None:
            result = crack_john(raw, jtr_fmt, wordlist)
            if result:
                return f"{name} (john)", next(iter(result.values()))
            print(dim("      john: not in wordlist"))

    # ── 4. Brute-force fallback ───────────────────────────────────────────
    print(cyan("  [4] Wordlist exhausted — trying brute-force..."))
    for name, hc_mode, jtr_fmt, _ in candidates:
        if which("hashcat") and hc_mode is not None:
            result = brute_force(raw, hc_mode)
            if result:
                return f"{name} (brute-force)", next(iter(result.values()))
            break  # only brute-force with the first candidate to avoid repeating

    return None, None


def process_file(path, wordlist):
    """Route a file to the correct cracking function based on its type."""
    ftype = file_type(path)
    label = {
        "ssh":     "SSH private key",
        "zip":     "ZIP archive",
        "rar":     "RAR archive",
        "7z":      "7z archive",
        "pdf":     "PDF document",
        "keepass": "KeePass database",
    }.get(ftype, None)

    if label:
        print(cyan(f"\n  Detected: {label}  ({Path(path).name})"))
        if not wordlist:
            print(red("      No wordlist — cannot crack passphrase"))
            return None, None
        fn = {
            "ssh":     crack_ssh_key,
            "zip":     crack_zip,
            "rar":     crack_rar,
            "7z":      crack_7z,
            "pdf":     crack_pdf,
            "keepass": crack_keepass,
        }[ftype]
        return fn(path, wordlist)

    # Plain hash list / shadow / SAM file
    return None, None   # caller will extract hashes and call process() on each


# ─────────────────────────────────────────────────────────────────────────────
# Hash file parsing
# ─────────────────────────────────────────────────────────────────────────────
def extract_hashes(path):
    """Extract hash strings from a shadow, SAM dump, or plain one-per-line file."""
    hashes = []
    with open(path) as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            # SAM dump: user:RID:LM:NT:::
            m = re.match(r'^[^:]+:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::', raw)
            if m:
                hashes.append(m.group(1))
                continue
            # Shadow / colon-separated
            if ":" in raw and not re.match(r'^[a-fA-F0-9$*!]', raw):
                parts = raw.split(":")
                cand  = parts[1] if len(parts) > 1 else ""
                if cand and cand not in ("*", "!", "x", ""):
                    hashes.append(cand)
                continue
            hashes.append(raw)
    return hashes


# ─────────────────────────────────────────────────────────────────────────────
# Save result
# ─────────────────────────────────────────────────────────────────────────────
def save(original, plaintext):
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"{original}:{plaintext}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(cyan(BANNER))

    # Inventory
    tools = []
    if which("hashcat"):
        tools.append(f"hashcat [{'GPU' if has_gpu() else 'CPU'}]")
    if which("john"):
        tools.append("john")
    if which("hashid"):
        tools.append("hashid")
    if which("zip2john"):
        tools.append("zip2john")
    if which("rar2john"):
        tools.append("rar2john")
    if which("keepass2john"):
        tools.append("keepass2john")
    if find_script(SSH2JOHN_CANDIDATES, "ssh2john"):
        tools.append("ssh2john")
    if find_script(PDF2JOHN_CANDIDATES, "pdf2john"):
        tools.append("pdf2john")

    print(cyan(f"  Tools    : {', '.join(tools) if tools else 'none found'}"))
    wordlist = find_wordlist()
    print(cyan(f"  Wordlist : {wordlist or 'not found (encoding/online lookup still work)'}"))
    print(cyan(f"  Output   : {OUTPUT_FILE}"))

    print(bold("\n" + "─" * 60))
    print(bold("  Paste ANYTHING below and press Enter:"))
    print(bold(""))
    print(bold("    Hash         →  MD5 / NTLM / bcrypt / SHA / Kerberos / ..."))
    print(bold("    Encoding     →  Base64 / hex / URL / ROT13 / binary / Cisco7"))
    print(bold("    SSH key      →  paste key text directly (reads until -----END)"))
    print(bold("    File path    →  prefix with 'file:'"))
    print(bold("                    e.g.  file:/etc/shadow"))
    print(bold("                          file:/root/.ssh/id_rsa"))
    print(bold("                          file:archive.zip"))
    print(bold("                          file:document.pdf"))
    print(bold("                          file:database.kdbx"))
    print(bold("─" * 60 + "\n"))

    first_line = input("  > ").strip()
    if not first_line:
        sys.exit(0)

    # ── Multi-line input for SSH keys ──────────────────────────────────────
    # If the first line looks like the start of a PEM key, keep reading until
    # the END marker so the user can paste the whole key directly.
    if "BEGIN" in first_line and "KEY" in first_line:
        print(dim("  (SSH key detected — paste remaining lines, then press Enter on a blank line)"))
        lines = [first_line]
        while True:
            try:
                line = input()
            except EOFError:
                break
            lines.append(line)
            if "END" in line and "KEY" in line:
                break
        raw = "\n".join(lines)
    else:
        raw = first_line

    # ── File mode ─────────────────────────────────────────────────────────
    if raw.lower().startswith("file:"):
        path = Path(raw[5:].strip()).expanduser()
        if not path.exists():
            print(red(f"\n  [!] File not found: {path}"))
            sys.exit(1)

        method, pw = process_file(str(path), wordlist)

        if method and pw:
            # Single-target file (SSH, zip, PDF, etc.)
            print(green(f"\n  ✔  RESULT  →  {pw}"))
            print(green(f"     Method : {method}"))
            save(str(path), pw)
            print()
            sys.exit(0)

        if file_type(str(path)) != "hashes":
            # Cracking already attempted above; nothing more to do
            print(red("  ✘  Could not crack passphrase."))
            print()
            sys.exit(1)

        # Hash list / shadow / SAM
        targets = extract_hashes(str(path))
        print(cyan(f"\n  Loaded {len(targets)} hash(es) from {path.name}\n"))

    else:
        targets = [raw]

    # ── Process each target ───────────────────────────────────────────────
    cracked = 0
    for entry in targets:
        display = entry if len(entry) <= 60 else entry[:57] + "..."
        print(bold(f"\n  Input : {display}"))

        method, plaintext = process(entry, wordlist)

        if plaintext is not None:
            cracked += 1
            print(green(f"\n  ✔  RESULT  →  {plaintext}"))
            print(green(f"     Method : {method}"))
            save(entry, plaintext)
        else:
            print(red("  ✘  Could not crack or decode."))
        print()

    if len(targets) > 1:
        print(bold("─" * 60))
        print(bold(f"  Done : {cracked}/{len(targets)} cracked / decoded"))
        if cracked:
            print(green(f"  Saved to {OUTPUT_FILE}"))
    print()


if __name__ == "__main__":
    main()
