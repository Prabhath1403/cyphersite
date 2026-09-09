"""Sample Python file with known cryptographic API usage.

Used as a test fixture for the Python source scanner.
Contains examples from: cryptography, hashlib, hmac, ssl.
"""

# ── hashlib usage ─────────────────────────────────────────────────────────
import hashlib

def hash_password(password: str) -> str:
    """Hash a password with SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def legacy_hash(data: bytes) -> str:
    """Deprecated MD5 hash."""
    return hashlib.md5(data).hexdigest()

def secure_hash(data: bytes) -> str:
    """SHA3-256 hash — quantum safe."""
    return hashlib.sha3_256(data).hexdigest()


# ── hmac usage ────────────────────────────────────────────────────────────
import hmac

def verify_signature(key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify HMAC-SHA256 signature."""
    computed = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(computed, signature)


# ── cryptography library usage ────────────────────────────────────────────
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def generate_rsa_key():
    """Generate a 2048-bit RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def generate_large_rsa_key():
    """Generate a 4096-bit RSA key."""
    return rsa.generate_private_key(65537, 4096)


def encrypt_aes_gcm(key: bytes, data: bytes, nonce: bytes) -> bytes:
    """Encrypt data with AES-GCM."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def insecure_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """BAD: ECB mode encryption — insecure!"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)


class CryptoService:
    """Service class with crypto operations."""

    def __init__(self):
        self.fernet = Fernet(Fernet.generate_key())

    def encrypt(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def sign_data(self, private_key, data: bytes) -> bytes:
        """Sign data using RSA-PSS."""
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def generate_ec_key(self):
        """Generate ECDSA key."""
        return ec.generate_private_key(ec.SECP384R1())


# ── ssl usage ─────────────────────────────────────────────────────────────
import ssl

def create_tls_context():
    """Create a TLS context."""
    ctx = ssl.create_default_context()
    return ctx


# ── Legacy / insecure patterns ───────────────────────────────────────────
def triple_des_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """Insecure 3DES encryption."""
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
