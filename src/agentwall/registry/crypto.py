"""Ed25519 signing of manifests."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from agentwall.registry.manifest import Manifest


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex)."""
    key = SigningKey.generate()
    return key.encode().hex(), key.verify_key.encode().hex()


def write_keypair(directory: str | Path, name: str = "operator") -> tuple[Path, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    private_hex, public_hex = generate_keypair()
    private_path, public_path = directory / f"{name}.key", directory / f"{name}.pub"
    private_path.write_text(private_hex + "\n", encoding="utf-8")
    public_path.write_text(public_hex + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):  # not all filesystems support chmod
        private_path.chmod(0o600)
    return private_path, public_path


def read_key(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def sign_manifest(manifest: Manifest, private_key_hex: str) -> Manifest:
    signed = SigningKey(bytes.fromhex(private_key_hex)).sign(manifest.canonical_bytes())
    manifest.signature = signed.signature.hex()
    return manifest


def verify_manifest(manifest: Manifest, public_keys_hex: Iterable[str]) -> bool:
    if not manifest.signature:
        return False
    try:
        signature = bytes.fromhex(manifest.signature)
    except ValueError:
        return False
    for key_hex in public_keys_hex:
        try:
            VerifyKey(bytes.fromhex(key_hex)).verify(manifest.canonical_bytes(), signature)
            return True
        except (BadSignatureError, ValueError):
            continue
    return False
