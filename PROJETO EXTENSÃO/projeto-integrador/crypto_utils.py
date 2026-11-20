import os
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_key = None


def load_key(path):
    global _key
    with open(path, "rb") as f:
        _key = f.read()
    if len(_key) != 32:
        raise RuntimeError("Chave de cifragem inválida (esperado 32 bytes).")


def encrypt(plaintext, context):
    iv = os.urandom(12)
    aesgcm = AESGCM(_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, context.encode())
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return iv + tag + ciphertext


def decrypt(data, context):
    if len(data) < 29:
        raise ValueError("Conteúdo cifrado inválido.")
    iv = bytes(data[:12])
    tag = bytes(data[12:28])
    ciphertext = bytes(data[28:])
    aesgcm = AESGCM(_key)
    return aesgcm.decrypt(iv, ciphertext + tag, context.encode())


def pack(obj, context):
    return encrypt(json.dumps(obj, ensure_ascii=False).encode(), context)


def unpack(data, context):
    return json.loads(decrypt(data, context))


def hmac_index(value):
    return hmac.new(_key, ("lookup:" + value).encode(), hashlib.sha256).hexdigest()


def hash_password(password):
    salt = os.urandom(16).hex()
    h = hashlib.scrypt(
        password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3, dklen=64,
        maxmem=128 * 32768 * 8 * 3 + 1024 * 1024,
    )
    return f"scrypt:32768:8:3:{salt}:{h.hex()}"


def verify_password(password, stored):
    parts = stored.split(":")
    if len(parts) != 6:
        return False
    algo, n, r, p, salt, expected = parts
    if algo != "scrypt" or n != "32768" or r != "8" or p != "3":
        return False
    try:
        actual = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3, dklen=64,
            maxmem=128 * 32768 * 8 * 3 + 1024 * 1024,
        )
        return hmac.compare_digest(actual.hex(), expected)
    except Exception:
        return False
