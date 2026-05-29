"""
tests/test_core.py — unit tests for hash_identifier.core.identify()
"""

import pytest
from hash_identifier.core import identify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def top(h: str) -> str:
    """Return the top candidate name for a hash string."""
    return identify(h)[0].name


def conf(h: str) -> str:
    """Return the confidence of the top candidate."""
    return identify(h)[0].confidence


def names(h: str) -> list[str]:
    """Return all candidate names."""
    return [c.name for c in identify(h)]


# ---------------------------------------------------------------------------
# Empty / whitespace
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self):
        result = identify("")
        assert result[0].format_class == "none"

    def test_whitespace_only(self):
        result = identify("   \n\t  ")
        assert result[0].format_class == "none"

    def test_whitespace_trimmed(self):
        # Leading/trailing whitespace should be stripped
        r1 = identify("5f4dcc3b5aa765d61d8327deb882cf99")
        r2 = identify("  5f4dcc3b5aa765d61d8327deb882cf99  ")
        assert r1[0].name == r2[0].name


# ---------------------------------------------------------------------------
# Hex-length hashes
# ---------------------------------------------------------------------------

class TestHexHashes:
    def test_md5(self):
        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        assert "MD5" in names(h)
        assert conf(h) == "high"

    def test_sha1(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert "SHA-1" in names(h)
        assert conf(h) == "high"

    def test_sha224(self):
        h = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        assert "SHA-224" in names(h)

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert "SHA-256" in names(h)
        assert conf(h) == "high"

    def test_sha384(self):
        h = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        assert "SHA-384" in names(h)

    def test_sha512(self):
        h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        assert "SHA-512" in names(h)
        assert conf(h) == "high"

    def test_ntlm_in_md5_candidates(self):
        h = "CC36CF7AA8514F81D9E0CE10E9548E6B"
        n = names(h)
        assert "NTLM" in n

    def test_sha3_256_listed(self):
        h = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        assert "SHA3-256" in names(h)

    def test_blake2b_listed(self):
        h = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"[:-2]
        # 126 hex — not a standard length; should return unknown
        r = identify(h)
        assert any("Unknown" in c.name or "Unrecognized" in c.name for c in r)

    def test_unknown_hex_length(self):
        h = "deadbeefcafe"  # 12 hex chars — no standard hash
        r = identify(h)
        assert any("Unknown" in c.name for c in r)


# ---------------------------------------------------------------------------
# Prefix-based hashes
# ---------------------------------------------------------------------------

class TestPrefixHashes:
    def test_bcrypt_2b(self):
        h = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        assert "bcrypt (cost factor variant)" in names(h)
        assert conf(h) == "high"

    def test_bcrypt_2a(self):
        h = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        assert "bcrypt (legacy, pre-2011)" in names(h)

    def test_bcrypt_2y(self):
        h = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        assert "bcrypt (PHP variant)" in names(h)

    def test_argon2id(self):
        h = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        assert "Argon2id" in names(h)
        assert conf(h) == "high"

    def test_argon2i(self):
        h = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6cr557sB8kXmJ6XA"
        assert "Argon2i" in names(h)

    def test_sha512crypt(self):
        h = "$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxLh7QbynLWcjCBVb1m67q78m1K8WmVFcxJWXmFDu8MXB4j5GiOmxl0B0DdKBEgB3x1"
        assert "SHA-512crypt (sha512crypt)" in names(h)

    def test_sha256crypt(self):
        h = "$5$rounds=5000$usesomesillystri$Gcm6FsVtF/Qa77ZKD.iwsJlCVPY0XSMgLyAa0KpVRV5"
        assert "SHA-256crypt (sha256crypt)" in names(h)

    def test_md5crypt(self):
        h = "$1$rasmuslerdorf$rISCgZzpwk3UhDidwXvin0"
        assert "MD5crypt" in names(h)

    def test_apr1(self):
        h = "$apr1$rt.ja2Ux$uYEFkbFhx0Nzmz7OTkRs0/"
        assert "APR1 (Apache MD5 htpasswd)" in names(h)

    def test_phpass_p(self):
        h = "$P$B/7Hp4J7kqK.4VkVwDFJxRKkBvFW0P0"
        assert "phpass (WordPress / phpBB3)" in names(h)

    def test_phpass_h(self):
        h = "$H$9IQRatMdHF/NpJjxp59XlRn9X1pXY/"
        assert "phpass (phpBB3 variant)" in names(h)

    def test_drupal(self):
        h = "$S$DWGrqeVJEnCiKCOSAFjcX9aS5VJSm0N1RVHsM5pRFkJy0hCkXpBQ"
        assert "Drupal 7 SHA-512" in names(h)

    def test_django_pbkdf2_sha256(self):
        h = "pbkdf2_sha256$260000$9P4MNwZLNKJaTg5x1Bx8kQ$HJ3DKfJSJi6FUmZBr3p6PPGWXK/q0LBCQ3C+J/TYJFA="
        assert "Django PBKDF2-SHA256" in names(h)

    def test_ldap_ssha(self):
        h = "{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        assert "LDAP Salted SHA-1 ({SSHA})" in names(h)

    def test_ldap_sha(self):
        h = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        assert "LDAP SHA-1 ({SHA})" in names(h)

    def test_dcc2(self):
        h = "$DCC2$10240#user#3f43220e1e3e9e7783e1d1d66a6bbebd"
        assert "Domain Cached Credentials v2 (mscash2)" in names(h)

    def test_krb5tgs(self):
        h = "$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe..."
        assert "Kerberos 5 TGS-REP (Kerberoasting)" in names(h)

    def test_krb5asrep(self):
        h = "$krb5asrep$23$user@DOMAIN:abc123..."
        assert "Kerberos 5 AS-REP (AS-REP roasting)" in names(h)


# ---------------------------------------------------------------------------
# Special shape matching
# ---------------------------------------------------------------------------

class TestShapeMatching:
    def test_mysql5(self):
        h = "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
        assert "MySQL5 (MySQL 4.1+ PASSWORD())" in names(h)
        assert conf(h) == "high"

    def test_des_crypt(self):
        h = "aB3dEfGhIjKlM"
        assert "DES crypt(3) (traditional)" in names(h)

    def test_netntlmv2(self):
        h = "admin::WORKGROUP:1122334455667788:AABBCCDDEEFF00112233445566778899:0101000000000000C0853A9E98DDCE01" + "A" * 20
        r = identify(h)
        assert any("NetNTLM" in c.name for c in r)


# ---------------------------------------------------------------------------
# Token / encoding detection
# ---------------------------------------------------------------------------

class TestTokens:
    def test_jwt_hs256(self):
        h = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        r = identify(h)
        assert r[0].name == "JWT (JSON Web Token)"
        assert r[0].confidence == "high"
        assert r[0].extra.get("alg") == "HS256"

    def test_base64_blob(self):
        h = "SGVsbG8gV29ybGQhISEhISEhISEhISEhISEhISEhISEhISE="
        r = identify(h)
        assert any("Base64" in c.name for c in r)


# ---------------------------------------------------------------------------
# Confidence ordering
# ---------------------------------------------------------------------------

class TestOrdering:
    def test_results_sorted_by_confidence(self):
        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        results = identify(h)
        order = {"high": 0, "medium": 1, "low": 2}
        levels = [order[c.confidence] for c in results]
        assert levels == sorted(levels)

    def test_single_high_conf_candidate(self):
        h = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        r = identify(h)
        assert r[0].confidence == "high"
