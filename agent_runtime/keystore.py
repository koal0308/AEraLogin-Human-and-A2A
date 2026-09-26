"""Local Ed25519 key storage for the Agent Runtime.

THE TRUST BOUNDARY
------------------
The private key is the agent's identity. It is generated here, it lives here,
and it never leaves this process except as a *signature*. There is deliberately
no method on this class that returns private key bytes to a caller, no
serialisation of the key into a response, and no `__repr__` that could put it
into a log line or a traceback.

AEra never receives it, never asks for it, and has nowhere to put it.

ENCRYPTION
----------
An unencrypted file protected only by `chmod 0600` relies entirely on the
filesystem: any backup, any snapshot, any misconfigured sync, any root-level
compromise and any accidental `tar` yields a usable agent identity. That is a
weak resting state for the one secret that defines the agent.

So when a passphrase is configured (`AERA_RUNTIME_KEY_PASSPHRASE`), the key is
sealed with **scrypt + AES-256-GCM**:

  * scrypt (n=2^15, r=8, p=1) makes brute-forcing a weak passphrase expensive
    rather than instant;
  * AES-GCM is authenticated, so a tampered file is *rejected* rather than
    silently decrypted into a different key;
  * the salt and nonce are random per write, so rewriting the same key twice
    never produces identical ciphertext.

Without a passphrase the key is stored raw at mode 0600. That is supported
because an operator evaluating the runtime should not be blocked by key
management, but it is an **explicitly documented MVP limitation**, it is
reported by `describe()`, and the runtime says so at startup rather than
staying quiet about it.

In both cases the file is created with mode 0600 *before* any bytes are written
(via `O_CREAT | O_EXCL` and an explicit mode), never written world-readable and
then narrowed — which would leave a window where the key was readable.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Reuse the PRODUCTION primitives. Re-implementing Ed25519 handling here would
# risk silent divergence from what AEra verifies against.
from agent.crypto import Ed25519Signer, encode_public_key  # noqa: F401

ENV_PASSPHRASE = "AERA_RUNTIME_KEY_PASSPHRASE"

_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32
_SALT_LEN = 16
_NONCE_LEN = 12

_FORMAT_RAW = "raw-ed25519-v1"
_FORMAT_SEALED = "scrypt-aesgcm-v1"


class KeyStoreError(Exception):
    """Key material could not be created, read or decrypted."""


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _write_private(path: Path, data: bytes) -> None:
    """Write with 0600 applied at creation time, never after."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:  # pragma: no cover - best effort on odd filesystems
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)  # atomic: no half-written key file is ever visible


@dataclass(frozen=True)
class KeyStoreInfo:
    """Safe-to-log description of the key store. Contains no key material."""

    path: str
    encrypted: bool
    public_key: str
    mode: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "encrypted": self.encrypted,
            "public_key": self.public_key,  # public by definition
            "mode": self.mode,
        }


class LocalKeyStore:
    """Holds exactly one Ed25519 private key, on disk and in memory.

    The signer is kept private. Callers can ask for a *signature* or the
    *public* key; there is no accessor that yields the private key.
    """

    def __init__(self, path: str | Path, *, passphrase: Optional[str] = None) -> None:
        self.path = Path(path).expanduser()
        self._passphrase = passphrase if passphrase else os.getenv(ENV_PASSPHRASE) or None
        self._signer: Optional[Ed25519Signer] = None

    # -- state ---------------------------------------------------------------
    @property
    def exists(self) -> bool:
        return self.path.is_file()

    @property
    def encrypted(self) -> bool:
        return bool(self._passphrase)

    @property
    def loaded(self) -> bool:
        return self._signer is not None

    def __repr__(self) -> str:
        # Never render key material, not even indirectly.
        return f"<LocalKeyStore path={self.path} loaded={self.loaded}>"

    # -- creation and loading ------------------------------------------------
    def create(self, *, overwrite: bool = False) -> str:
        """Generate a new keypair locally. Returns the PUBLIC key."""
        if self.exists and not overwrite:
            raise KeyStoreError(
                f"refusing to overwrite an existing key at {self.path}; "
                "an agent identity would become unusable")
        signer = Ed25519Signer.generate()
        self._persist(signer)
        self._signer = signer
        return signer.public_key_encoded()

    def _persist(self, signer: Ed25519Signer) -> None:
        raw = signer.raw_private()
        if self._passphrase:
            salt = secrets.token_bytes(_SALT_LEN)
            nonce = secrets.token_bytes(_NONCE_LEN)
            sealed = AESGCM(_derive(self._passphrase, salt)).encrypt(nonce, raw, None)
            blob = json.dumps({
                "format": _FORMAT_SEALED,
                "salt": salt.hex(),
                "nonce": nonce.hex(),
                "ciphertext": sealed.hex(),
                "kdf": {"n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P},
            }).encode("utf-8")
        else:
            blob = json.dumps({"format": _FORMAT_RAW, "key": raw.hex()}).encode("utf-8")
        _write_private(self.path, blob)

    def load(self) -> "LocalKeyStore":
        if self._signer is not None:
            return self
        if not self.exists:
            raise KeyStoreError(f"no key at {self.path}; generate one first")
        try:
            blob = json.loads(self.path.read_bytes().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise KeyStoreError(f"key file at {self.path} is unreadable") from exc

        fmt = blob.get("format")
        if fmt == _FORMAT_SEALED:
            if not self._passphrase:
                raise KeyStoreError(
                    f"key at {self.path} is encrypted; set {ENV_PASSPHRASE}")
            try:
                key = _derive(self._passphrase, bytes.fromhex(blob["salt"]))
                raw = AESGCM(key).decrypt(bytes.fromhex(blob["nonce"]),
                                          bytes.fromhex(blob["ciphertext"]), None)
            except Exception as exc:
                # Wrong passphrase and tampered file are indistinguishable here,
                # and deliberately so.
                raise KeyStoreError(
                    "cannot decrypt the agent key: wrong passphrase or the file "
                    "has been modified") from exc
        elif fmt == _FORMAT_RAW:
            try:
                raw = bytes.fromhex(blob["key"])
            except (KeyError, ValueError) as exc:
                raise KeyStoreError("key file is malformed") from exc
        else:
            raise KeyStoreError(f"unsupported key format {fmt!r}")

        try:
            self._signer = Ed25519Signer.from_raw(raw)
        except ValueError as exc:
            raise KeyStoreError("stored key is not a valid Ed25519 private key") from exc
        return self

    def load_or_create(self) -> str:
        """Returns the public key either way."""
        if self.exists:
            self.load()
        else:
            self.create()
        return self.public_key

    # -- use -----------------------------------------------------------------
    @property
    def public_key(self) -> str:
        """`ed25519:<b64u>` — safe to publish, register and log."""
        if self._signer is None:
            self.load()
        return self._signer.public_key_encoded()  # type: ignore[union-attr]

    def sign(self, data: bytes) -> bytes:
        """The ONLY use of the private key. Raw bytes are never returned."""
        if self._signer is None:
            self.load()
        return self._signer.sign(data)  # type: ignore[union-attr]

    # -- reporting -----------------------------------------------------------
    def describe(self) -> KeyStoreInfo:
        mode = "unknown"
        if self.exists:
            mode = stat.filemode(self.path.stat().st_mode)
        return KeyStoreInfo(path=str(self.path), encrypted=self.encrypted,
                            public_key=self.public_key, mode=mode)

    def permissions_are_safe(self) -> bool:
        """True when the key file is not readable by group or others."""
        if not self.exists:
            return False
        return not (self.path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))
