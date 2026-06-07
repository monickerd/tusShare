"""Storage test helpers.

Provides MinIO reachability checks and direct DB volume seeding — bypassing
the admin API (and its SSRF blocklist) so the test suite can exercise S3
storage I/O against a real MinIO container without requiring backend changes.

The encryption reproduces app/storage/crypto.py _get_storage_key() exactly:
  IKM  = settings.JWT_SECRET.encode()  ← 64-byte ASCII hex string, NOT decoded
  HKDF-SHA256(salt=b"storage-config-enc-v1",
              info=b"tusShare-storage-config-encryption")
  then AES-256-GCM(iv=random 12 bytes)
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
import socket

# ---------------------------------------------------------------------------
# MinIO connection constants — must match docker-compose.test.yml
# ---------------------------------------------------------------------------

MINIO_ENDPOINT_URL  = "http://minio:9000"   # docker-internal name (used by app container)
MINIO_ACCESS_KEY    = "minioadmin"
MINIO_SECRET_KEY    = "minioadmin123"
MINIO_BUCKET        = "tusshare-test"
MINIO_REGION        = "us-east-1"
MINIO_VOLUME_ID      = "a1b2c3d4-e5f6-7890-abcd-ef1234567801"

# Warm-tier volume — second bucket on the same MinIO instance
MINIO_WARM_BUCKET    = "tusshare-warm"
MINIO_WARM_VOLUME_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678902"
MINIO_HOST_PORT     = 9000                  # mapped to localhost in docker-compose.test.yml

# JWT_SECRET from docker-compose.test.yml (app environment)
_TEST_JWT_SECRET_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"


# ---------------------------------------------------------------------------
# Reachability check
# ---------------------------------------------------------------------------

def minio_reachable() -> bool:
    """Return True if MinIO is accessible on localhost:9000."""
    try:
        with socket.create_connection(("localhost", MINIO_HOST_PORT), timeout=3):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# HKDF-SHA256 — matches hkdf_sha256() in app/auth/stepup.py
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t, okm, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _derive_storage_key() -> bytes:
    """Derive the AES-256 key used to encrypt storage volume configs.

    Reproduces app/storage/crypto.py _get_storage_key() when
    TUSSHARE_STORAGE_ENCRYPTION_KEY is unset (HKDF path).

    IKM is the 64-byte ASCII encoding of the hex secret string — this matches
    settings.JWT_SECRET.encode() in the running app.
    """
    ikm = _TEST_JWT_SECRET_HEX.encode()   # 64-byte ASCII, not decoded bytes
    prk = _hkdf_extract(b"storage-config-enc-v1", ikm)
    return _hkdf_expand(prk, b"tusShare-storage-config-encryption", 32)


# ---------------------------------------------------------------------------
# Encrypt a volume config dict — matches encrypt_volume_config() in storage/crypto.py
# ---------------------------------------------------------------------------

def encrypt_test_volume_config(config: dict) -> str:
    """AES-256-GCM encrypt a volume config dict using the test environment key.

    Returns the base64url-encoded blob (iv[12] || ct || tag[16]).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _derive_storage_key()
    iv = os.urandom(12)
    plaintext = json.dumps(config, separators=(",", ":")).encode()
    ct_and_tag = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.urlsafe_b64encode(iv + ct_and_tag).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# DB seed — insert MinIO volume directly, bypassing the admin API + SSRF check
# ---------------------------------------------------------------------------

def seed_warm_volume(
    hot_volume_id: str = MINIO_VOLUME_ID,
    warm_volume_id: str = MINIO_WARM_VOLUME_ID,
) -> None:
    """Insert a warm-tier MinIO volume and configure the tiering policy via psql.

    Expects the hot MinIO volume to already be present (seed_s3_volume called
    first).  Sets hot_to_warm_days=0 so the very next tiering pass will move
    any eligible file regardless of age — suitable for test environments only.

    After calling this, restart_app_and_wait() must be called so the
    StorageManager reloads its volume list and picks up the new warm volume.
    """
    from tests.e2e.helpers.db import PG_DB_NAME, _psql

    warm_config = {
        "endpoint_url":      MINIO_ENDPOINT_URL,
        "bucket":            MINIO_WARM_BUCKET,
        "access_key_id":     MINIO_ACCESS_KEY,
        "secret_access_key": MINIO_SECRET_KEY,
        "region":            MINIO_REGION,
    }
    warm_config_enc = encrypt_test_volume_config(warm_config)

    # Insert the warm volume (not default, higher priority number = lower preference)
    _psql(
        f"INSERT INTO storage_volumes "
        f"  (id, name, provider, config_enc, tier, is_default, priority) "
        f"VALUES "
        f"  ('{warm_volume_id}', 'MinIO Warm', 's3', '{warm_config_enc}', 'warm', 0, 20) "
        f"ON CONFLICT (id) DO UPDATE SET "
        f"  config_enc = EXCLUDED.config_enc;",
        db=PG_DB_NAME,
    )

    # Configure tiering policy — 0 days so the pass migrates files immediately
    for key, value in [
        ("storage_tiering_enabled",   "1"),
        ("storage_hot_to_warm_days",  "0"),
        ("storage_warm_volume_id",    warm_volume_id),
    ]:
        _psql(
            f"INSERT INTO admin_settings (key, value) VALUES ('{key}', '{value}') "
            f"ON CONFLICT (key) DO UPDATE SET value = '{value}';",
            db=PG_DB_NAME,
        )


# ---------------------------------------------------------------------------
# Azurite connection constants — must match docker-compose.test.yml
# ---------------------------------------------------------------------------

# Well-known Azurite development credentials (safe to commit — emulator only)
AZURITE_ACCOUNT    = "devstoreaccount1"
AZURITE_ACCOUNT_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq"
    "/K1SZFPTOtr/KBHBeksoGMGw=="
)
# docker-internal URL used by the app container
AZURITE_BLOB_ENDPOINT_INTERNAL = "http://azurite:10000/devstoreaccount1"
# host-mapped URL used by the test runner
AZURITE_BLOB_ENDPOINT_HOST     = "http://localhost:10000/devstoreaccount1"
AZURITE_CONTAINER  = "tusshare-test"
AZURITE_HOST_PORT  = 10000
AZURITE_VOLUME_ID  = "c3d4e5f6-a7b8-9012-cdef-012345678903"

# Connection string used by the running app (docker-internal endpoint)
AZURITE_CONNECTION_STRING_INTERNAL = (
    f"DefaultEndpointsProtocol=http;"
    f"AccountName={AZURITE_ACCOUNT};"
    f"AccountKey={AZURITE_ACCOUNT_KEY};"
    f"BlobEndpoint={AZURITE_BLOB_ENDPOINT_INTERNAL};"
)


def azurite_reachable() -> bool:
    """Return True if Azurite is accessible on localhost:10000."""
    try:
        with socket.create_connection(("localhost", AZURITE_HOST_PORT), timeout=3):
            return True
    except OSError:
        return False


def seed_azure_volume(volume_id: str = AZURITE_VOLUME_ID) -> None:
    """Insert an Azurite storage_volumes row directly into the test DB.

    Also demotes the local-default volume so the Azurite volume becomes the
    upload target.  After calling this, use restart_app_and_wait() so the
    StorageManager reloads its volume list.

    Uses the internal docker network endpoint (http://azurite:10000/...) so
    the running app container can reach the Azurite container by name.
    """
    from tests.e2e.helpers.db import PG_DB_NAME, _psql

    config = {
        "connection_string": AZURITE_CONNECTION_STRING_INTERNAL,
        "container_name":    AZURITE_CONTAINER,
    }
    config_enc = encrypt_test_volume_config(config)

    _psql(
        "UPDATE storage_volumes SET is_default = 0 WHERE id = 'local-default';",
        db=PG_DB_NAME,
    )
    _psql(
        f"INSERT INTO storage_volumes "
        f"  (id, name, provider, config_enc, tier, is_default, priority) "
        f"VALUES "
        f"  ('{volume_id}', 'Azurite Test', 'azure', '{config_enc}', 'hot', 1, 10) "
        f"ON CONFLICT (id) DO UPDATE SET "
        f"  config_enc = EXCLUDED.config_enc, is_default = 1;",
        db=PG_DB_NAME,
    )


def seed_s3_volume(volume_id: str = MINIO_VOLUME_ID) -> None:
    """Insert a MinIO storage_volumes row directly into the test DB.

    Also demotes the local-default volume so the MinIO volume becomes the
    upload target.  After calling this, use restart_app_and_wait() so the
    StorageManager reloads its volume list.

    This approach intentionally bypasses POST /admin/storage/volumes so that
    the SSRF blocklist (which rejects RFC-1918 endpoints) is never involved.
    The SSRF logic is covered separately in tests/unit/test_storage_ssrf.py.
    """
    from tests.e2e.helpers.db import PG_DB_NAME, _psql

    config = {
        "endpoint_url":    MINIO_ENDPOINT_URL,
        "bucket":          MINIO_BUCKET,
        "access_key_id":   MINIO_ACCESS_KEY,
        "secret_access_key": MINIO_SECRET_KEY,
        "region":          MINIO_REGION,
    }
    config_enc = encrypt_test_volume_config(config)

    # Demote the local-default so only MinIO is marked as default
    _psql(
        "UPDATE storage_volumes SET is_default = 0 WHERE id = 'local-default';",
        db=PG_DB_NAME,
    )

    # Insert (or update) the MinIO volume row.
    # config_enc is base64url — charset [A-Za-z0-9_-] — safe in SQL string literal.
    _psql(
        f"INSERT INTO storage_volumes "
        f"  (id, name, provider, config_enc, tier, is_default, priority) "
        f"VALUES "
        f"  ('{volume_id}', 'MinIO Test', 's3', '{config_enc}', 'hot', 1, 10) "
        f"ON CONFLICT (id) DO UPDATE SET "
        f"  config_enc = EXCLUDED.config_enc, is_default = 1;",
        db=PG_DB_NAME,
    )
