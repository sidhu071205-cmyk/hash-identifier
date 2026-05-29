"""
core.py — pure-function hash identification engine.

No network, no filesystem, no global state. All detection is stateless and
returns a sorted list of HashCandidate objects ranked by confidence.
"""

from __future__ import annotations

import re
import base64
import json
from dataclasses import dataclass, field
from typing import Literal

Confidence = Literal["high", "medium", "low"]
_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class HashCandidate:
    """A single identification result."""

    name: str
    confidence: Confidence
    reason: str
    format_class: str = ""
    bit_length: int = 0
    extra: dict = field(default_factory=dict)

    def __lt__(self, other: "HashCandidate") -> bool:
        return _CONF_ORDER[self.confidence] < _CONF_ORDER[other.confidence]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _is_base64(s: str) -> bool:
    # Allow missing padding commonly seen in web payloads
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s))


def _is_base64url(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]+=*", s))


def _decode_b64(s: str) -> bytes | None:
    try:
        padded = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# (prefix, name, confidence, reason, format_class)
_PREFIX_RULES: list[tuple[str, str, Confidence, str, str]] = [
    ("$2b$",          "bcrypt (cost factor variant)",         "high",   "$2b$ prefix = modern bcrypt (Blowfish-based KDF)",        "bcrypt"),
    ("$2a$",          "bcrypt (legacy, pre-2011)",            "high",   "$2a$ prefix = older bcrypt; some implementations buggy",  "bcrypt"),
    ("$2y$",          "bcrypt (PHP variant)",                 "high",   "$2y$ prefix = PHP password_hash() bcrypt",                "bcrypt"),
    ("$argon2id$",    "Argon2id",                             "high",   "$argon2id$ = RFC 9106 winner; memory-hard KDF",           "argon2"),
    ("$argon2i$",     "Argon2i",                              "high",   "$argon2i$ = side-channel-resistant Argon2 variant",       "argon2"),
    ("$argon2d$",     "Argon2d",                              "high",   "$argon2d$ = fastest Argon2 variant; GPU-vulnerable",      "argon2"),
    ("$6$",           "SHA-512crypt (sha512crypt)",           "high",   "$6$ = Linux /etc/shadow SHA-512 (glibc crypt)",           "crypt"),
    ("$5$",           "SHA-256crypt (sha256crypt)",           "high",   "$5$ = Linux /etc/shadow SHA-256 (glibc crypt)",           "crypt"),
    ("$1$",           "MD5crypt",                             "high",   "$1$ = MD5-based crypt(3); weak, avoid",                  "crypt"),
    ("$apr1$",        "APR1 (Apache MD5 htpasswd)",           "high",   "$apr1$ = Apache httpd htpasswd MD5 variant",             "crypt"),
    ("$sha1$",        "SHA-1crypt",                           "high",   "$sha1$ = NetBSD SHA-1 crypt(3)",                         "crypt"),
    ("pbkdf2_sha256$","Django PBKDF2-SHA256",                 "high",   "pbkdf2_sha256$ = Django default password hasher",        "django"),
    ("pbkdf2_sha512$","Django PBKDF2-SHA512",                 "high",   "pbkdf2_sha512$ = Django PBKDF2 with SHA-512",            "django"),
    ("pbkdf2_sha1$",  "Django PBKDF2-SHA1",                   "high",   "pbkdf2_sha1$ = older Django PBKDF2 hasher",              "django"),
    ("sha1$",         "Django PBKDF2 legacy / salted SHA-1",  "medium", "sha1$ = pre-1.4 Django salted SHA-1",                   "django"),
    ("{SSHA}",        "LDAP Salted SHA-1 ({SSHA})",           "high",   "{SSHA} = OpenLDAP userPassword salted SHA-1",            "ldap"),
    ("{SHA}",         "LDAP SHA-1 ({SHA})",                   "high",   "{SHA} = OpenLDAP unsalted SHA-1; avoid",                 "ldap"),
    ("{MD5}",         "LDAP MD5 ({MD5})",                     "high",   "{MD5} = OpenLDAP unsalted MD5; deprecated",             "ldap"),
    ("{CRYPT}",       "LDAP crypt(3) wrapper",                "high",   "{CRYPT} = LDAP delegation to OS crypt(3)",               "ldap"),
    ("{SSHA512}",     "LDAP Salted SHA-512",                  "high",   "{SSHA512} = OpenLDAP 389-ds salted SHA-512",             "ldap"),
    ("scrypt:",       "scrypt (passlib format)",              "high",   "scrypt: = passlib scrypt identifier",                   "kdf"),
    ("$scrypt$",      "scrypt (modular crypt format)",        "high",   "$scrypt$ = modular-crypt scrypt",                       "kdf"),
    ("$P$",           "phpass (WordPress / phpBB3)",          "high",   "$P$ = phpass portable hash; used by WordPress",         "phpass"),
    ("$H$",           "phpass (phpBB3 variant)",              "high",   "$H$ = phpass variant used by phpBB3",                   "phpass"),
    ("$S$",           "Drupal 7 SHA-512",                     "high",   "$S$ = Drupal 7 password hasher (SHA-512 + stretching)", "drupal"),
    ("U$",            "WordPress unsalted MD5 (legacy)",      "medium", "U$ = WordPress pre-2.5 plain MD5 migration marker",    "wordpress"),
    ("$DCC2$",        "Domain Cached Credentials v2 (mscash2)","high",  "$DCC2$ = Windows domain cached credentials v2",        "windows"),
    ("$krb5pa$",      "Kerberos 5 AS-REQ preauth (etype23)", "high",   "$krb5pa$ = Kerberos pre-authentication hash",           "kerberos"),
    ("$krb5tgs$",     "Kerberos 5 TGS-REP (Kerberoasting)",  "high",   "$krb5tgs$ = Kerberos service ticket; used in Kerberoasting","kerberos"),
    ("$krb5asrep$",   "Kerberos 5 AS-REP (AS-REP roasting)", "high",   "$krb5asrep$ = AS-REP hash; no pre-auth required accounts","kerberos"),
    ("sha256:",       "PBKDF2-SHA256 (generic label)",        "medium", "sha256: prefix — likely a PBKDF2-SHA256 or raw label",  "kdf"),
    ("md5:",          "MD5 (labeled)",                        "medium", "md5: prefix — MD5 with explicit label",                "hex"),
]

# (hex_length, name, confidence, reason)
_HEX_RULES: list[tuple[int, str, Confidence, str]] = [
    (32,  "MD5",          "high",   "32 hex chars = 128-bit MD5"),
    (32,  "NTLM",         "medium", "32 hex — NTLM also 128-bit; used for Windows auth"),
    (32,  "MD4",          "medium", "32 hex — MD4 is 128-bit; used internally by NTLM"),
    (32,  "LM hash",      "low",    "32 hex — LM hash is 128-bit; case-insensitive, very weak"),
    (40,  "SHA-1",        "high",   "40 hex chars = 160-bit SHA-1"),
    (40,  "RIPEMD-160",   "medium", "40 hex — RIPEMD-160 also 160-bit; used in Bitcoin"),
    (48,  "Tiger-192",    "low",    "48 hex chars = 192-bit Tiger"),
    (56,  "SHA-224",      "high",   "56 hex chars = 224-bit SHA-224"),
    (56,  "SHA3-224",     "medium", "56 hex — SHA3-224 also 224-bit"),
    (64,  "SHA-256",      "high",   "64 hex chars = 256-bit SHA-256"),
    (64,  "SHA3-256",     "medium", "64 hex — SHA3-256 also 256-bit"),
    (64,  "BLAKE2s-256",  "medium", "64 hex — BLAKE2s-256 also 256-bit"),
    (64,  "RIPEMD-256",   "low",    "64 hex — RIPEMD-256 also 256-bit"),
    (80,  "RIPEMD-320",   "low",    "80 hex chars = 320-bit RIPEMD-320"),
    (96,  "SHA-384",      "high",   "96 hex chars = 384-bit SHA-384"),
    (96,  "SHA3-384",     "medium", "96 hex — SHA3-384 also 384-bit"),
    (128, "SHA-512",      "high",   "128 hex chars = 512-bit SHA-512"),
    (128, "SHA3-512",     "medium", "128 hex — SHA3-512 also 512-bit"),
    (128, "BLAKE2b-512",  "medium", "128 hex — BLAKE2b-512 also 512-bit"),
    (128, "Whirlpool",    "low",    "128 hex — Whirlpool-512 also 512-bit"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def identify(raw: str) -> list[HashCandidate]:
    """
    Identify the hash type(s) of *raw*.

    Returns a list of HashCandidate objects sorted by confidence (high → low).
    The list may contain multiple candidates when several formats share the
    same length or prefix structure. Returns at least one candidate (unknown).
    """
    s = raw.strip()
    if not s:
        return [HashCandidate("(empty input)", "low", "Nothing to analyze", "none")]

    results: list[HashCandidate] = []

    # --- JWT ---
    parts = s.split(".")
    if len(parts) == 3 and all(_is_base64url(p) or _is_base64(p) for p in parts):
        decoded = _decode_b64(parts[0])
        alg = "unknown"
        if decoded:
            try:
                hdr = json.loads(decoded)
                alg = hdr.get("alg", "unknown")
            except Exception:
                pass
        results.append(HashCandidate(
            "JWT (JSON Web Token)",
            "high",
            f"Three base64url segments; header declares alg={alg}",
            "token",
            extra={"alg": alg},
        ))
        return sorted(results)

    # --- Prefix rules ---
    prefix_hit = False
    for prefix, name, conf, reason, fmt in _PREFIX_RULES:
        if s.startswith(prefix):
            results.append(HashCandidate(name, conf, reason, fmt))
            prefix_hit = True

    # --- MySQL5: *<40 hex> ---
    if re.fullmatch(r"\*[0-9a-fA-F]{40}", s):
        results.append(HashCandidate(
            "MySQL5 (MySQL 4.1+ PASSWORD())",
            "high",
            "Asterisk + 40 hex chars = MySQL 4.1+ PASSWORD() function",
            "mysql",
        ))
        prefix_hit = True

    # --- NetNTLMv1: user::domain:challenge(16 hex):response(48 hex):... ---
    if re.fullmatch(r".+::.+:[0-9a-fA-F]{16}:[0-9a-fA-F]{48}:[0-9a-fA-F]*", s):
        results.append(HashCandidate(
            "NetNTLMv1",
            "high",
            "user::domain:challenge:response structure matches NetNTLMv1",
            "netntlm",
        ))
        prefix_hit = True

    # --- NetNTLMv2: user::domain:challenge(16):NTproofStr(32):blob(10+) ---
    if re.fullmatch(r".+::.+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{10,}", s):
        results.append(HashCandidate(
            "NetNTLMv2",
            "high",
            "user::domain:challenge:NTproofStr:blob structure = NetNTLMv2",
            "netntlm",
        ))
        prefix_hit = True

    # --- Traditional DES crypt(3): 13 chars, [./A-Za-z0-9], not hex ---
    if re.fullmatch(r"[./A-Za-z0-9]{13}", s) and not _is_hex(s):
        results.append(HashCandidate(
            "DES crypt(3) (traditional)",
            "medium",
            "13-char [./A-Za-z0-9] = two-char salt + 11-char DES crypt(3)",
            "descrypt",
        ))

    # --- Hex-length table ---
    if _is_hex(s):
        hl = len(s)
        matched = False
        for length, name, conf, reason in _HEX_RULES:
            if hl == length:
                results.append(HashCandidate(name, conf, reason, "hex", bit_length=length * 4))
                matched = True
        if not matched:
            results.append(HashCandidate(
                f"Unknown hex ({hl} chars / {hl * 4} bits)",
                "low",
                f"{hl} hex chars does not match any standard hash length",
                "hex",
                bit_length=hl * 4,
            ))

    # --- Base64 blob (non-hash) ---
    if not results and _is_base64(s) and not s.startswith("$") and not s.startswith("{"):
        results.append(HashCandidate(
            "Base64-encoded blob",
            "medium",
            "Matches base64 charset and padding but no known hash prefix was found",
            "encoding",
        ))

    # --- Fallback ---
    if not results:
        results.append(HashCandidate(
            "Unrecognized format",
            "low",
            "No known hash prefix, hex length, or structural pattern matched",
            "unknown",
        ))

    return sorted(results)
