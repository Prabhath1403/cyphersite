"""Python cryptographic API detection rules.

Each rule describes a function / class constructor call that implies
a cryptographic operation.  The scanner matches these against AST
``ast.Call`` nodes to produce ``CryptoFindingData`` instances.

Rule structure:
    module:       fully-qualified module path
    qualname:     dotted name of the callable (from the module root)
    algorithm:    algorithm name (may include placeholders like ``{arg0}``)
    primitive:    symmetric | asymmetric | hash | mac | kdf | signature | rng | protocol
    usage:        encryption | signing | hashing | key_derivation | authentication | random | ...
    key_size:     static key size or None
    mode_arg:     index / kwarg name that carries the cipher mode, or None
    confidence:   detection confidence 0.0–1.0
    family:       algorithm family (RSA, ECC, AES, SHA, etc.)
    quantum:      vulnerable | reduced_security_margin | safe | unknown
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass(frozen=True)
class CryptoRule:
    """A single detection rule for a Python crypto API call."""
    module: str
    qualname: str
    algorithm: str
    primitive: str
    usage: str
    family: str = ""
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    confidence: float = 1.0
    quantum: str = "unknown"
    library: str = ""
    notes: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# cryptography (pyca/cryptography) — the most common Python crypto library
# ═══════════════════════════════════════════════════════════════════════════

CRYPTOGRAPHY_RULES: List[CryptoRule] = [
    # ── Symmetric encryption ─────────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="AES",
        algorithm="AES",
        primitive="symmetric",
        usage="encryption",
        family="AES",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
        notes="Key size from constructor arg (128/192/256 bits)",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="AES256",
        algorithm="AES-256",
        primitive="symmetric",
        usage="encryption",
        family="AES",
        key_size=256,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="AES128",
        algorithm="AES-128",
        primitive="symmetric",
        usage="encryption",
        family="AES",
        key_size=128,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="TripleDES",
        algorithm="3DES",
        primitive="symmetric",
        usage="encryption",
        family="DES",
        key_size=168,
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
        notes="Deprecated — vulnerable to SWEET32 and quantum attacks",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="ChaCha20",
        algorithm="ChaCha20",
        primitive="symmetric",
        usage="encryption",
        family="ChaCha",
        key_size=256,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="Blowfish",
        algorithm="Blowfish",
        primitive="symmetric",
        usage="encryption",
        family="Blowfish",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
        notes="Deprecated — 64-bit block size, vulnerable",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="CAST5",
        algorithm="CAST5",
        primitive="symmetric",
        usage="encryption",
        family="CAST",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.algorithms",
        qualname="SEED",
        algorithm="SEED",
        primitive="symmetric",
        usage="encryption",
        family="SEED",
        key_size=128,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),

    # ── Cipher modes ─────────────────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.modes",
        qualname="GCM",
        algorithm="GCM",
        primitive="symmetric",
        usage="encryption",
        family="AEAD",
        mode="GCM",
        confidence=0.9,
        quantum="reduced_security_margin",
        library="cryptography",
        notes="Authenticated encryption mode — detected as context for cipher",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.modes",
        qualname="CBC",
        algorithm="CBC",
        primitive="symmetric",
        usage="encryption",
        family="block_mode",
        mode="CBC",
        confidence=0.9,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.modes",
        qualname="CTR",
        algorithm="CTR",
        primitive="symmetric",
        usage="encryption",
        family="block_mode",
        mode="CTR",
        confidence=0.9,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.modes",
        qualname="ECB",
        algorithm="ECB",
        primitive="symmetric",
        usage="encryption",
        family="block_mode",
        mode="ECB",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
        notes="ECB mode is insecure — no semantic security",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.modes",
        qualname="CFB",
        algorithm="CFB",
        primitive="symmetric",
        usage="encryption",
        family="block_mode",
        mode="CFB",
        confidence=0.9,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.ciphers.modes",
        qualname="OFB",
        algorithm="OFB",
        primitive="symmetric",
        usage="encryption",
        family="block_mode",
        mode="OFB",
        confidence=0.9,
        quantum="reduced_security_margin",
        library="cryptography",
    ),

    # ── Asymmetric key generation ────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.rsa",
        qualname="generate_private_key",
        algorithm="RSA",
        primitive="asymmetric",
        usage="encryption",
        family="RSA",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
        notes="Key size from public_exponent/key_size args",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.ec",
        qualname="generate_private_key",
        algorithm="ECDSA",
        primitive="asymmetric",
        usage="signing",
        family="ECC",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.ed25519",
        qualname="Ed25519PrivateKey.generate",
        algorithm="Ed25519",
        primitive="signature",
        usage="signing",
        family="EdDSA",
        key_size=256,
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.ed448",
        qualname="Ed448PrivateKey.generate",
        algorithm="Ed448",
        primitive="signature",
        usage="signing",
        family="EdDSA",
        key_size=448,
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.x25519",
        qualname="X25519PrivateKey.generate",
        algorithm="X25519",
        primitive="asymmetric",
        usage="key_exchange",
        family="ECDH",
        key_size=256,
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.dh",
        qualname="generate_parameters",
        algorithm="DH",
        primitive="asymmetric",
        usage="key_exchange",
        family="DH",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.dsa",
        qualname="generate_private_key",
        algorithm="DSA",
        primitive="signature",
        usage="signing",
        family="DSA",
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
    ),

    # ── Padding schemes ──────────────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.padding",
        qualname="OAEP",
        algorithm="RSA-OAEP",
        primitive="asymmetric",
        usage="encryption",
        family="RSA",
        padding="OAEP",
        confidence=0.9,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.padding",
        qualname="PSS",
        algorithm="RSA-PSS",
        primitive="signature",
        usage="signing",
        family="RSA",
        padding="PSS",
        confidence=0.9,
        quantum="vulnerable",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.asymmetric.padding",
        qualname="PKCS1v15",
        algorithm="RSA-PKCS1v15",
        primitive="asymmetric",
        usage="encryption",
        family="RSA",
        padding="PKCS1v15",
        confidence=0.9,
        quantum="vulnerable",
        library="cryptography",
        notes="PKCS#1 v1.5 padding — susceptible to Bleichenbacher attacks",
    ),

    # ── Hashing ──────────────────────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="SHA256",
        algorithm="SHA-256",
        primitive="hash",
        usage="hashing",
        family="SHA-2",
        key_size=256,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="SHA384",
        algorithm="SHA-384",
        primitive="hash",
        usage="hashing",
        family="SHA-2",
        key_size=384,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="SHA512",
        algorithm="SHA-512",
        primitive="hash",
        usage="hashing",
        family="SHA-2",
        key_size=512,
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="SHA1",
        algorithm="SHA-1",
        primitive="hash",
        usage="hashing",
        family="SHA-1",
        key_size=160,
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
        notes="SHA-1 is deprecated — collision attacks practical",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="MD5",
        algorithm="MD5",
        primitive="hash",
        usage="hashing",
        family="MD5",
        key_size=128,
        confidence=1.0,
        quantum="vulnerable",
        library="cryptography",
        notes="MD5 is broken — collision attacks trivial",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="SHA3_256",
        algorithm="SHA3-256",
        primitive="hash",
        usage="hashing",
        family="SHA-3",
        key_size=256,
        confidence=1.0,
        quantum="safe",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="SHA3_512",
        algorithm="SHA3-512",
        primitive="hash",
        usage="hashing",
        family="SHA-3",
        key_size=512,
        confidence=1.0,
        quantum="safe",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="BLAKE2b",
        algorithm="BLAKE2b",
        primitive="hash",
        usage="hashing",
        family="BLAKE2",
        confidence=1.0,
        quantum="safe",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hashes",
        qualname="BLAKE2s",
        algorithm="BLAKE2s",
        primitive="hash",
        usage="hashing",
        family="BLAKE2",
        confidence=1.0,
        quantum="safe",
        library="cryptography",
    ),

    # ── KDF ───────────────────────────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.kdf.pbkdf2",
        qualname="PBKDF2HMAC",
        algorithm="PBKDF2",
        primitive="kdf",
        usage="key_derivation",
        family="PBKDF2",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.kdf.scrypt",
        qualname="Scrypt",
        algorithm="scrypt",
        primitive="kdf",
        usage="key_derivation",
        family="scrypt",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.kdf.hkdf",
        qualname="HKDF",
        algorithm="HKDF",
        primitive="kdf",
        usage="key_derivation",
        family="HKDF",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),

    # ── MAC ───────────────────────────────────────────────────────────────
    CryptoRule(
        module="cryptography.hazmat.primitives.cmac",
        qualname="CMAC",
        algorithm="CMAC",
        primitive="mac",
        usage="authentication",
        family="CMAC",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),
    CryptoRule(
        module="cryptography.hazmat.primitives.hmac",
        qualname="HMAC",
        algorithm="HMAC",
        primitive="mac",
        usage="authentication",
        family="HMAC",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
    ),

    # ── Fernet (high-level) ──────────────────────────────────────────────
    CryptoRule(
        module="cryptography.fernet",
        qualname="Fernet",
        algorithm="AES-128-CBC+HMAC-SHA256",
        primitive="symmetric",
        usage="encryption",
        family="AES",
        key_size=128,
        mode="CBC",
        confidence=1.0,
        quantum="reduced_security_margin",
        library="cryptography",
        notes="Fernet uses AES-128-CBC with HMAC-SHA256",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# hashlib — Python standard library
# ═══════════════════════════════════════════════════════════════════════════

HASHLIB_RULES: List[CryptoRule] = [
    CryptoRule(module="hashlib", qualname="md5",     algorithm="MD5",      primitive="hash", usage="hashing", family="MD5",   key_size=128, confidence=1.0, quantum="vulnerable", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha1",    algorithm="SHA-1",    primitive="hash", usage="hashing", family="SHA-1", key_size=160, confidence=1.0, quantum="vulnerable", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha224",  algorithm="SHA-224",  primitive="hash", usage="hashing", family="SHA-2", key_size=224, confidence=1.0, quantum="reduced_security_margin", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha256",  algorithm="SHA-256",  primitive="hash", usage="hashing", family="SHA-2", key_size=256, confidence=1.0, quantum="reduced_security_margin", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha384",  algorithm="SHA-384",  primitive="hash", usage="hashing", family="SHA-2", key_size=384, confidence=1.0, quantum="reduced_security_margin", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha512",  algorithm="SHA-512",  primitive="hash", usage="hashing", family="SHA-2", key_size=512, confidence=1.0, quantum="reduced_security_margin", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha3_256", algorithm="SHA3-256", primitive="hash", usage="hashing", family="SHA-3", key_size=256, confidence=1.0, quantum="safe", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha3_384", algorithm="SHA3-384", primitive="hash", usage="hashing", family="SHA-3", key_size=384, confidence=1.0, quantum="safe", library="hashlib"),
    CryptoRule(module="hashlib", qualname="sha3_512", algorithm="SHA3-512", primitive="hash", usage="hashing", family="SHA-3", key_size=512, confidence=1.0, quantum="safe", library="hashlib"),
    CryptoRule(module="hashlib", qualname="blake2b", algorithm="BLAKE2b",  primitive="hash", usage="hashing", family="BLAKE2", confidence=1.0, quantum="safe", library="hashlib"),
    CryptoRule(module="hashlib", qualname="blake2s", algorithm="BLAKE2s",  primitive="hash", usage="hashing", family="BLAKE2", confidence=1.0, quantum="safe", library="hashlib"),
    # hashlib.new("algo_name") is handled separately by the scanner
    CryptoRule(module="hashlib", qualname="new", algorithm="hashlib.new", primitive="hash", usage="hashing", family="hash", confidence=0.8, quantum="unknown", library="hashlib", notes="Algorithm determined at runtime"),
]


# ═══════════════════════════════════════════════════════════════════════════
# hmac — Python standard library
# ═══════════════════════════════════════════════════════════════════════════

HMAC_RULES: List[CryptoRule] = [
    CryptoRule(module="hmac", qualname="new",     algorithm="HMAC", primitive="mac", usage="authentication", family="HMAC", confidence=1.0, quantum="reduced_security_margin", library="hmac"),
    CryptoRule(module="hmac", qualname="HMAC",    algorithm="HMAC", primitive="mac", usage="authentication", family="HMAC", confidence=1.0, quantum="reduced_security_margin", library="hmac"),
    CryptoRule(module="hmac", qualname="digest",  algorithm="HMAC", primitive="mac", usage="authentication", family="HMAC", confidence=0.9, quantum="reduced_security_margin", library="hmac"),
]


# ═══════════════════════════════════════════════════════════════════════════
# ssl — Python standard library
# ═══════════════════════════════════════════════════════════════════════════

SSL_RULES: List[CryptoRule] = [
    CryptoRule(module="ssl", qualname="create_default_context", algorithm="TLS", primitive="protocol", usage="tls", family="TLS", confidence=0.9, quantum="vulnerable", library="ssl", notes="TLS context creation — exact version depends on config"),
    CryptoRule(module="ssl", qualname="SSLContext",             algorithm="TLS", primitive="protocol", usage="tls", family="TLS", confidence=0.9, quantum="vulnerable", library="ssl"),
    CryptoRule(module="ssl", qualname="wrap_socket",            algorithm="TLS", primitive="protocol", usage="tls", family="TLS", confidence=0.8, quantum="vulnerable", library="ssl"),
]


# ═══════════════════════════════════════════════════════════════════════════
# PyCryptodome / PyCryptodomex
# ═══════════════════════════════════════════════════════════════════════════

PYCRYPTODOME_RULES: List[CryptoRule] = [
    CryptoRule(module="Crypto.Cipher.AES",          qualname="new", algorithm="AES",       primitive="symmetric", usage="encryption", family="AES",       confidence=1.0, quantum="reduced_security_margin", library="PyCryptodome"),
    CryptoRule(module="Crypto.Cipher.DES",           qualname="new", algorithm="DES",       primitive="symmetric", usage="encryption", family="DES",  key_size=56, confidence=1.0, quantum="vulnerable",             library="PyCryptodome"),
    CryptoRule(module="Crypto.Cipher.DES3",          qualname="new", algorithm="3DES",      primitive="symmetric", usage="encryption", family="DES",  key_size=168, confidence=1.0, quantum="vulnerable",            library="PyCryptodome"),
    CryptoRule(module="Crypto.Cipher.Blowfish",      qualname="new", algorithm="Blowfish",  primitive="symmetric", usage="encryption", family="Blowfish", confidence=1.0, quantum="vulnerable",                    library="PyCryptodome"),
    CryptoRule(module="Crypto.Cipher.ChaCha20",      qualname="new", algorithm="ChaCha20",  primitive="symmetric", usage="encryption", family="ChaCha", key_size=256, confidence=1.0, quantum="reduced_security_margin", library="PyCryptodome"),
    CryptoRule(module="Crypto.Cipher.PKCS1_v1_5",    qualname="new", algorithm="RSA-PKCS1v15", primitive="asymmetric", usage="encryption", family="RSA", padding="PKCS1v15", confidence=1.0, quantum="vulnerable",  library="PyCryptodome"),
    CryptoRule(module="Crypto.Cipher.PKCS1_OAEP",    qualname="new", algorithm="RSA-OAEP",  primitive="asymmetric", usage="encryption", family="RSA",  padding="OAEP", confidence=1.0, quantum="vulnerable",       library="PyCryptodome"),
    CryptoRule(module="Crypto.PublicKey.RSA",         qualname="generate", algorithm="RSA",  primitive="asymmetric", usage="encryption", family="RSA",  confidence=1.0, quantum="vulnerable",                       library="PyCryptodome"),
    CryptoRule(module="Crypto.PublicKey.ECC",         qualname="generate", algorithm="ECC",  primitive="asymmetric", usage="signing",    family="ECC",  confidence=1.0, quantum="vulnerable",                       library="PyCryptodome"),
    CryptoRule(module="Crypto.PublicKey.DSA",         qualname="generate", algorithm="DSA",  primitive="signature",  usage="signing",    family="DSA",  confidence=1.0, quantum="vulnerable",                       library="PyCryptodome"),
    CryptoRule(module="Crypto.Hash.SHA256",           qualname="new", algorithm="SHA-256",   primitive="hash", usage="hashing", family="SHA-2", key_size=256, confidence=1.0, quantum="reduced_security_margin",     library="PyCryptodome"),
    CryptoRule(module="Crypto.Hash.SHA1",             qualname="new", algorithm="SHA-1",     primitive="hash", usage="hashing", family="SHA-1", key_size=160, confidence=1.0, quantum="vulnerable",                  library="PyCryptodome"),
    CryptoRule(module="Crypto.Hash.MD5",              qualname="new", algorithm="MD5",       primitive="hash", usage="hashing", family="MD5",   key_size=128, confidence=1.0, quantum="vulnerable",                  library="PyCryptodome"),
    CryptoRule(module="Crypto.Hash.SHA512",           qualname="new", algorithm="SHA-512",   primitive="hash", usage="hashing", family="SHA-2", key_size=512, confidence=1.0, quantum="reduced_security_margin",     library="PyCryptodome"),
    CryptoRule(module="Crypto.Hash.HMAC",             qualname="new", algorithm="HMAC",      primitive="mac",  usage="authentication", family="HMAC", confidence=1.0, quantum="reduced_security_margin",             library="PyCryptodome"),
]


# ═══════════════════════════════════════════════════════════════════════════
# Combined rule index — keyed by module for fast lookup
# ═══════════════════════════════════════════════════════════════════════════

ALL_RULES: List[CryptoRule] = (
    CRYPTOGRAPHY_RULES
    + HASHLIB_RULES
    + HMAC_RULES
    + SSL_RULES
    + PYCRYPTODOME_RULES
)


def build_rule_index() -> Dict[str, List[CryptoRule]]:
    """Build a module → rules lookup index.

    Returns:
        Dictionary mapping module names to the list of rules that
        apply to imports from that module.
    """
    index: Dict[str, List[CryptoRule]] = {}
    for rule in ALL_RULES:
        # Index by the top-level package (e.g. "cryptography", "hashlib")
        top_pkg = rule.module.split(".")[0]
        index.setdefault(top_pkg, []).append(rule)
        # Also index by full module path for exact matching
        index.setdefault(rule.module, []).append(rule)
    return index


RULE_INDEX = build_rule_index()
