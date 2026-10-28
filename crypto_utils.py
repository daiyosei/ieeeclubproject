"""Cryptographic helpers for the Secure Messenger demo.

This module contains **no UI code**.  It implements the hybrid scheme used by
the app:

* AES-256-GCM encrypts the message (confidentiality + integrity).
* RSA-2048-OAEP (SHA-256) encrypts ("wraps") the AES key.

Every helper raises :class:`CryptoError` with a human-readable message when it
cannot complete, so the UI can display the reason without crashing.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: AES-256 uses a 32-byte key.
AES_KEY_SIZE = 32
#: Standard nonce length for AES-GCM.
GCM_NONCE_SIZE = 12
#: Key size of the RSA key pair.
RSA_KEY_SIZE = 2048

#: Fields every encrypted message bundle must contain.
BUNDLE_FIELDS = ("wrapped_key", "nonce", "ciphertext")


class CryptoError(Exception):
    """Raised when a cryptographic operation cannot be completed."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _oaep_padding() -> padding.OAEP:
    """Return the RSA-OAEP parameters used everywhere in this module."""

    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _check_aes_key(key: Any) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise CryptoError("Invalid AES key: expected bytes.")
    key = bytes(key)
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(
            f"Invalid AES key: expected {AES_KEY_SIZE} bytes, got {len(key)}."
        )
    return key


def _check_bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise CryptoError(f"Invalid {name}: expected bytes.")
    return bytes(value)


def _read_file(path: Any) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError as exc:
        raise CryptoError(f"File not found: {path}") from exc
    except IsADirectoryError as exc:
        raise CryptoError(f"Path is a directory, not a file: {path}") from exc
    except OSError as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        raise CryptoError(f"Could not read {path}: {reason}") from exc


def _b64decode_field(bundle: Dict[str, Any], field: str) -> bytes:
    if field not in bundle:
        raise CryptoError(
            f'The encrypted message is missing the "{field}" field.'
        )
    value = bundle[field]
    if not isinstance(value, str) or not value.strip():
        raise CryptoError(
            f'The "{field}" field is empty or is not a text value.'
        )
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise CryptoError(
            f'The "{field}" field is not valid base64 data.'
        ) from exc


# ---------------------------------------------------------------------------
# 1a. RSA key management
# ---------------------------------------------------------------------------


def generate_rsa_keys() -> Tuple[bytes, bytes]:
    """Generate a 2048-bit RSA key pair and return ``(public_pem, private_pem)``."""

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_KEY_SIZE
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"Could not generate RSA keys: {exc}") from exc

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return public_pem, private_pem


def public_key_from_pem(pem: Any) -> rsa.RSAPublicKey:
    """Load an RSA public key from PEM-encoded bytes."""

    pem = _check_bytes(pem, "public key data")
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CryptoError(
            "The public key file is malformed or is not a PEM key."
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"Could not load public key: {exc}") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("The public key is not an RSA public key.")
    return key


def private_key_from_pem(pem: Any) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM-encoded bytes."""

    pem = _check_bytes(pem, "private key data")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CryptoError(
            "The private key file is malformed, encrypted, or is not a PEM key."
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"Could not load private key: {exc}") from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("The private key is not an RSA private key.")
    return key


def public_pem_from_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key object back to PEM bytes."""

    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"Could not serialize public key: {exc}") from exc


def private_pem_from_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key object back to PEM bytes."""

    try:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"Could not serialize private key: {exc}") from exc


def save_keys(
    public_pem: Any, private_pem: Any, pub_path: Any, priv_path: Any
) -> None:
    """Write the PEM-encoded key pair to ``pub_path`` and ``priv_path``."""

    public_pem = _check_bytes(public_pem, "public key data")
    private_pem = _check_bytes(private_pem, "private key data")

    for path, data, label in (
        (pub_path, public_pem, "public key"),
        (priv_path, private_pem, "private key"),
    ):
        try:
            with open(path, "wb") as handle:
                handle.write(data)
        except OSError as exc:
            reason = getattr(exc, "strerror", None) or str(exc)
            raise CryptoError(f"Could not save {label} to {path}: {reason}") from exc


def load_public_key(path: Any) -> rsa.RSAPublicKey:
    """Read and parse an RSA public key from ``path``."""

    return public_key_from_pem(_read_file(path))


def load_private_key(path: Any) -> rsa.RSAPrivateKey:
    """Read and parse an RSA private key from ``path``."""

    return private_key_from_pem(_read_file(path))


# ---------------------------------------------------------------------------
# 1b. AES-GCM encrypt / decrypt
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(key: Any, plaintext: Any) -> Dict[str, bytes]:
    """Encrypt ``plaintext`` with AES-256-GCM.

    Returns ``{"nonce": <12 bytes>, "ciphertext": <ciphertext + 16-byte tag>}``.
    """

    key = _check_aes_key(key)
    plaintext = _check_bytes(plaintext, "plaintext")
    nonce = os.urandom(GCM_NONCE_SIZE)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"AES-GCM encryption failed: {exc}") from exc
    return {"nonce": nonce, "ciphertext": ciphertext}


def aes_gcm_decrypt(key: Any, nonce: Any, ciphertext: Any) -> bytes:
    """Decrypt AES-256-GCM ``ciphertext`` and verify its authentication tag."""

    key = _check_aes_key(key)
    nonce = _check_bytes(nonce, "nonce")
    ciphertext = _check_bytes(ciphertext, "ciphertext")
    if len(nonce) != GCM_NONCE_SIZE:
        raise CryptoError(
            f"Invalid nonce: expected {GCM_NONCE_SIZE} bytes, got {len(nonce)}."
        )
    if not ciphertext:
        raise CryptoError("Invalid ciphertext: it is empty.")

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise CryptoError(
            "Decryption failed: invalid authentication tag "
            "(wrong key or tampered data)."
        ) from exc
    except Exception as exc:
        raise CryptoError(f"Decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 1c. RSA-OAEP encrypt / decrypt
# ---------------------------------------------------------------------------


def rsa_encrypt(public_key: rsa.RSAPublicKey, data: Any) -> bytes:
    """Encrypt ``data`` with RSA-OAEP (SHA-256)."""

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptoError("Invalid public key object.")
    data = _check_bytes(data, "data")
    if not data:
        raise CryptoError("Nothing to encrypt: the data is empty.")
    try:
        return public_key.encrypt(data, _oaep_padding())
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"RSA encryption failed: {exc}") from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"RSA encryption failed: {exc}") from exc


def rsa_decrypt(private_key: rsa.RSAPrivateKey, data: Any) -> bytes:
    """Decrypt RSA-OAEP (SHA-256) ``data`` with the private key."""

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("Invalid private key object.")
    data = _check_bytes(data, "data")
    if not data:
        raise CryptoError("Nothing to decrypt: the data is empty.")
    try:
        return private_key.decrypt(data, _oaep_padding())
    except (ValueError, TypeError) as exc:
        raise CryptoError(
            "RSA decryption failed: wrong private key or corrupted data."
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"RSA decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 1d. Hybrid end-to-end helpers
# ---------------------------------------------------------------------------


def encrypt_message(public_key: rsa.RSAPublicKey, plaintext: Any) -> Dict[str, str]:
    """Encrypt a text message using the hybrid AES-GCM + RSA-OAEP scheme.

    The returned dictionary contains base64-encoded strings and is ready to be
    stored as JSON.
    """

    if not isinstance(plaintext, str):
        raise CryptoError("The message must be text.")
    if not plaintext:
        raise CryptoError("Nothing to encrypt: the message is empty.")
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptoError("Invalid public key object.")

    aes_key = os.urandom(AES_KEY_SIZE)
    wrapped_key = rsa_encrypt(public_key, aes_key)
    result = aes_gcm_encrypt(aes_key, plaintext.encode("utf-8"))

    return {
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "nonce": base64.b64encode(result["nonce"]).decode("ascii"),
        "ciphertext": base64.b64encode(result["ciphertext"]).decode("ascii"),
    }


def decrypt_message(private_key: rsa.RSAPrivateKey, bundle: Any) -> str:
    """Decrypt a bundle produced by :func:`encrypt_message` back to text."""

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("Invalid private key object.")
    if not isinstance(bundle, dict):
        raise CryptoError("The encrypted message is not a valid bundle.")

    wrapped_key = _b64decode_field(bundle, "wrapped_key")
    nonce = _b64decode_field(bundle, "nonce")
    ciphertext = _b64decode_field(bundle, "ciphertext")

    if not wrapped_key:
        raise CryptoError('The "wrapped_key" field is empty.')
    if not ciphertext:
        raise CryptoError('The "ciphertext" field is empty.')

    aes_key = rsa_decrypt(private_key, wrapped_key)
    if len(aes_key) != AES_KEY_SIZE:
        raise CryptoError("The unwrapped AES key has an invalid length.")

    plaintext = aes_gcm_decrypt(aes_key, nonce, ciphertext)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError("Decrypted data is not valid UTF-8 text.") from exc


# ---------------------------------------------------------------------------
# 1e. File persistence for encrypted messages
# ---------------------------------------------------------------------------


def save_encrypted(path: Any, bundle: Any) -> None:
    """Write an encrypted message bundle to ``path`` as UTF-8 JSON."""

    if not isinstance(bundle, dict):
        raise CryptoError("There is no encrypted message to save.")
    try:
        payload = json.dumps(bundle, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"Could not serialize the message: {exc}") from exc

    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except OSError as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        raise CryptoError(f"Could not save the message to {path}: {reason}") from exc


def load_encrypted(path: Any) -> Dict[str, str]:
    """Read an encrypted message bundle from ``path``."""

    raw = _read_file(path)
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise CryptoError(f"{path} is not a UTF-8 JSON file.") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise CryptoError(f"{path} does not contain valid JSON.") from exc

    if not isinstance(bundle, dict):
        raise CryptoError(f"{path} does not contain an encrypted message.")

    missing = [field for field in BUNDLE_FIELDS if field not in bundle]
    if missing:
        raise CryptoError(
            f"{path} is missing required field(s): {', '.join(missing)}."
        )
    return bundle
