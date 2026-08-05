import base64
import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_logger = logging.getLogger(__name__)

_V3_PREFIX = "v3:"
_V2_PREFIX = "v2:"

_LEGACY_WARNED: set[str] = set()


def _derive_subkey(master: bytes, domain: bytes) -> bytes:
    """HKDF-SHA256 으로 마스터키 → 도메인별 32 byte sub-key 파생.

    동일 마스터키여도 도메인이 다르면 서로 다른 sub-key — 한 도메인의 ciphertext
    가 다른 도메인 키로 복호화되지 않는다 (key separation).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"afterglow-k3s/" + domain,
    ).derive(master)


def derive_encryption_subkey(master_key: bytes, domain: bytes) -> bytes:
    """Return an AES-256 sub-key for a non-empty application encryption domain."""
    if not domain:
        raise ValueError("encryption domain must not be empty")
    return _derive_subkey(master_key, domain)


def _warn_legacy_once(domain: bytes, version: str) -> None:
    """legacy/v2 ciphertext 복호화 1회만 로그 (도메인 단위) — 운영 spam 방지."""
    key = f"{version}:{domain.decode('latin-1')}"
    if key in _LEGACY_WARNED:
        return
    _LEGACY_WARNED.add(key)
    _logger.warning(
        "k3s_crypto: %s ciphertext detected for domain=%s — please migrate to v3 (HKDF sub-key) before next release",
        version,
        domain.decode("latin-1"),
    )


def encrypt(master_key: bytes, domain: bytes, plaintext: str) -> str:
    """v3 — HKDF sub-key 사용. AAD = domain."""
    key = _derive_subkey(master_key, domain)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), domain)
    return _V3_PREFIX + base64.b64encode(nonce + ct).decode()


def decrypt(master_key: bytes, domain: bytes, ciphertext_b64: str) -> str:
    """복호화 — v3 우선, v2/legacy 는 fallback + deprecation warning."""
    if ciphertext_b64.startswith(_V3_PREFIX):
        key = _derive_subkey(master_key, domain)
        raw = base64.b64decode(ciphertext_b64[len(_V3_PREFIX) :])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(key).decrypt(nonce, ct, domain).decode()

    if ciphertext_b64.startswith(_V2_PREFIX):
        _warn_legacy_once(domain, "v2")
        raw = base64.b64decode(ciphertext_b64[len(_V2_PREFIX) :])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(master_key).decrypt(nonce, ct, domain).decode()

    # 접두사 없음 — legacy (AAD 없음)
    _warn_legacy_once(domain, "legacy")
    raw = base64.b64decode(ciphertext_b64)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(master_key).decrypt(nonce, ct, None).decode()
