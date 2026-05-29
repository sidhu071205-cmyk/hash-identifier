# 🔍 Hash Identifier

[![CI](https://github.com/sidhu071205-cmyk/hash-identifier/actions/workflows/ci.yml/badge.svg)](https://github.com/sidhu071205-cmyk/hash-identifier/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Ever found a mystery hash string and had no idea what algorithm made it?** This tool figures it out for you — instantly.

Paste in any hash (like `5d41402abc4b2a76b9719d911017c592`) and it tells you what type it is — MD5, bcrypt, SHA-256, and many more — along with a confidence level explaining *why* it thinks so.

Great for CTF challenges, penetration testing, or just exploring how hashes work.

---

## What is a hash?

A hash is a scrambled fingerprint of a piece of data. For example, the word `hello` produces the MD5 hash `5d41402abc4b2a76b9719d911017c592`. Different hashing algorithms produce hashes of different lengths and formats — this tool uses those clues to identify which algorithm was used.

---

## ⚡ 30-second quickstart

**Step 1 — Install:**
```bash
pip install hash-identifier
```

**Step 2 — Identify a hash:**
```bash
hashid 5d41402abc4b2a76b9719d911017c592
```

That's it! You'll see something like this:

```
  Hash Identifier
────────────────────────────────────────────────────────────────────────
  Input  : 5d41402abc4b2a76b9719d911017c592
  Length : 32 chars

  #   Confidence   Format       Algorithm
────────────────────────────────────────────────────────────────────────
  1   ● high       hex          MD5
                                32 hex chars = 128-bit MD5

  2   ◐ medium     hex          NTLM
                                32 hex — NTLM also 128-bit; used for Windows auth

  3   ◐ medium     hex          MD4
                                32 hex — MD4 is 128-bit; used internally by NTLM
────────────────────────────────────────────────────────────────────────

  → Most likely: MD5
```

The results are ranked by confidence. The top result is always the most likely match.

---

## What can it recognize?

- **~30 prefixed formats** — things like `$2b$` (bcrypt), `$argon2$` (Argon2), Kerberos hashes, LDAP hashes, phpass, and more
- **19 hex-length formats** — MD5, SHA-1, SHA-256, SHA-512, NTLM, MD4, and others identified by their length and character set

---

## Requirements

- Python 3.9 or newer (check with `python --version`)

---

## Installing from source (for developers)

If you want to modify or contribute to the code, clone the repo first:

```bash
# 1. Download the code
git clone https://github.com/sidhu071205-cmyk/hash-identifier.git

# 2. Enter the folder
cd hash-identifier

# 3. Install it in "editable" mode (changes to source take effect immediately)
pip install -e ".[dev]"
```

Want colorful output in your terminal? Add the `color` extra:
```bash
pip install -e ".[color]"
```

---

## All the ways to use it

### Basic — just identify a hash
```bash
hashid 5d41402abc4b2a76b9719d911017c592
```

### Get JSON output (useful for scripts and automation)
```bash
hashid --json 5d41402abc4b2a76b9719d911017c592
```

### Get just the top algorithm name
```bash
hashid --top 5d41402abc4b2a76b9719d911017c592
# Output: MD5
```

### Use exit codes to check confidence in shell scripts
```bash
# Exit code 0 = high confidence, 1 = medium, 2 = low
hashid --exit-code "$HASH" && echo "Identified with high confidence!"
```

### Turn off colors
```bash
hashid --no-color 5d41402abc4b2a76b9719d911017c592
```

### Pipe a hash directly from another command
```bash
echo '5d41402abc4b2a76b9719d911017c592' | hashid -
```

---

## Understanding confidence levels

| Symbol | Level  | Meaning |
|--------|--------|---------|
| ●      | High   | Strong match — length, characters, and prefix all fit |
| ◐      | Medium | Likely match — shares the same length as multiple algorithms |
| ○      | Low    | Possible match — only one or two clues matched |

---

## Contributing

Found a bug? Want to add support for a new hash format? Contributions are welcome!

1. Fork the repo on [GitHub](https://github.com/sidhu071205-cmyk/hash-identifier)
2. Create a branch for your change: `git checkout -b feature/my-feature`
3. Make your changes and write tests for them
4. Check everything works: `pytest` and `ruff check .`
5. Open a pull request against `main`

Report bugs or request features on the [issues page](https://github.com/sidhu071205-cmyk/hash-identifier/issues).

---

## Author

Made by **sidhu071205-cmyk** — [github.com/sidhu071205-cmyk](https://github.com/sidhu071205-cmyk)

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
