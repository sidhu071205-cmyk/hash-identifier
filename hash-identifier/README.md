# 🔍 hash-identifier

[![CI](https://github.com/sidhu071205-cmyk/hash-identifier/actions/workflows/ci.yml/badge.svg)](https://github.com/sidhu071205-cmyk/hash-identifier/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![codecov](https://codecov.io/gh/sidhu071205-cmyk/hash-identifier/branch/main/graph/badge.svg)](https://codecov.io/gh/sidhu071205-cmyk/hash-identifier)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A **zero-dependency** Python library and CLI tool that identifies hash formats by prefix, length, and structural shape — returning ranked candidates with `high` / `medium` / `low` confidence and a one-line reason for every guess.

Built for CTF players, penetration testers, and security researchers.

---

## ⚡ Quick Start

```bash
pip install hash-identifier[color]
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# → Most likely: MD5
```

---

## Features

| Capability | Details |
|---|---|
| **~30 prefix formats** | bcrypt, Argon2, SHA-512crypt, phpass, Django, LDAP, Drupal, DCC2, Kerberos, scrypt, and more |
| **Hex-length table** | MD5, SHA-1, SHA-224/256/384/512, SHA3-*, BLAKE2, RIPEMD, NTLM, MD4, Whirlpool, Tiger |
| **Shape matching** | MySQL5 (`*HEX`), NetNTLMv1/v2 (colon-delimited), DES crypt(3) (13-char) |
| **Token detection** | JWTs (decodes header, extracts `alg`), Base64 blobs |
| **Confidence ranking** | `high` / `medium` / `low` with a reason per candidate |
| **Pure-function core** | No network, no filesystem, no global state — instant runtime |
| **Rich terminal output** | Color-coded table; falls back to plain ASCII when `rich` is not installed |
| **JSON output** | Machine-readable for shell scripting and CI pipelines |
| **Exit codes** | `0`=high, `1`=medium, `2`=low — composable with `&&` / `||` |

---

## Installation

### From PyPI

```bash
pip install hash-identifier[color]   # with rich terminal output
pip install hash-identifier          # zero-dep stdlib-only mode
```

### From source (development)

```bash
git clone https://github.com/sidhu071205-cmyk/hash-identifier.git
cd hash-identifier
pip install -e ".[dev]"
```

---

## CLI Usage

```bash
# Identify a hash
hashid 5f4dcc3b5aa765d61d8327deb882cf99

# Pipe from stdin
echo '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW' | hashid -

# JSON output (machine-readable)
hashid --json 5f4dcc3b5aa765d61d8327deb882cf99

# Top candidate only (scriptable)
hashid --top 5f4dcc3b5aa765d61d8327deb882cf99
# → MD5

# Exit code reflects confidence (use in shell scripts)
hashid --exit-code "$HASH" && echo "High confidence" || echo "Low confidence"

# Disable color
hashid --no-color 5f4dcc3b5aa765d61d8327deb882cf99
```

### Example output

```
  Hash Identifier
────────────────────────────────────────────────────────────────────────
  Input  : 5f4dcc3b5aa765d61d8327deb882cf99
  Length : 32 chars

  #   Confidence   Format class   Hash / Format
────────────────────────────────────────────────────────────────────────
  1   ● high       hex            MD5
                                  32 hex chars = 128-bit MD5

  2   ◐ medium     hex            NTLM
                                  32 hex — NTLM also 128-bit; used for Windows auth

  3   ◐ medium     hex            MD4
                                  32 hex — MD4 is 128-bit; used internally by NTLM

  4   ○ low        hex            LM hash
                                  32 hex — LM hash is 128-bit; case-insensitive, very weak
────────────────────────────────────────────────────────────────────────

  → Most likely: MD5
```

---

## Python API

```python
from hash_identifier import identify, format_table, format_json

candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99")

for c in candidates:
    print(c.name, c.confidence, c.reason)

# Rich terminal output
format_table(candidates, input_str="5f4dcc3b5aa765d61d8327deb882cf99")

# JSON string
print(format_json(candidates))
```

### `HashCandidate` fields

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Human-readable format name |
| `confidence` | `"high" \| "medium" \| "low"` | Detection confidence |
| `reason` | `str` | One-line explanation |
| `format_class` | `str` | Category: `hex`, `bcrypt`, `crypt`, `kdf`, `ldap`, `token`, … |
| `bit_length` | `int` | Bit length (hex hashes only, else 0) |
| `extra` | `dict` | Extra metadata (e.g. `{"alg": "HS256"}` for JWTs) |

---

## Supported Formats

### Prefix-detected (~30 formats)

| Prefix | Format |
|---|---|
| `$2b$`, `$2a$`, `$2y$` | bcrypt variants |
| `$argon2id$`, `$argon2i$`, `$argon2d$` | Argon2 variants |
| `$6$`, `$5$`, `$1$` | SHA-512/256/MD5 crypt(3) |
| `$apr1$` | Apache APR1 MD5 |
| `$sha1$` | SHA-1crypt (NetBSD) |
| `pbkdf2_sha256$`, `pbkdf2_sha512$`, `pbkdf2_sha1$` | Django PBKDF2 |
| `{SSHA}`, `{SHA}`, `{MD5}`, `{CRYPT}`, `{SSHA512}` | LDAP formats |
| `$scrypt$`, `scrypt:` | scrypt |
| `$P$`, `$H$` | phpass (WordPress, phpBB3) |
| `$S$` | Drupal 7 |
| `U$` | WordPress legacy MD5 |
| `$DCC2$` | Domain Cached Credentials v2 |
| `$krb5pa$`, `$krb5tgs$`, `$krb5asrep$` | Kerberos 5 |

### Shape-detected

| Pattern | Format |
|---|---|
| `*` + 40 hex chars | MySQL5 `PASSWORD()` |
| `user::domain:16hex:48hex:...` | NetNTLMv1 |
| `user::domain:16hex:32hex:10+hex` | NetNTLMv2 |
| 13-char `[./A-Za-z0-9]`, not pure hex | DES crypt(3) |
| Three dot-separated base64url segments | JWT |

### Hex-length table (19 algorithms)

32 · 40 · 48 · 56 · 64 · 80 · 96 · 128 hex chars → all algorithms of that bit-width ranked by likelihood.

---

## Development

```bash
# Install in editable mode with all dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=hash_identifier --cov-report=term-missing

# Lint and auto-format
ruff check .
ruff format .

# Type check
mypy hash_identifier/
```

---

## Shell Scripting Example

```bash
#!/usr/bin/env bash
# Feed a list of hashes and print only the format names
while IFS= read -r hash; do
    fmt=$(hashid --top "$hash" 2>/dev/null)
    echo "$hash  →  $fmt"
done < hashes.txt
```

---

## Project Structure

```
hash-identifier/
├── hash_identifier/
│   ├── __init__.py       # Public API
│   ├── __main__.py       # CLI entry point (hashid command)
│   ├── core.py           # Pure-function detection engine
│   └── formatter.py      # Rich table + JSON renderers
├── tests/
│   ├── conftest.py
│   └── test_core.py      # Full unit test suite
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions (Python 3.9–3.12)
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Contributing

Contributions, bug reports, and feature requests are welcome!

1. Fork the repository on [GitHub](https://github.com/sidhu071205-cmyk/hash-identifier)
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests for any new behaviour
4. Run `pytest` and `ruff check .` to verify everything passes
5. Open a pull request against `main`

Please ensure all tests pass and new detection rules include appropriate test coverage.

---

## Author

**sidhu071205-cmyk** — [github.com/sidhu071205-cmyk](https://github.com/sidhu071205-cmyk)

---

## License

MIT — see [LICENSE](LICENSE).
