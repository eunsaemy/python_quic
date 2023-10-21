# built-in modules
import os
import rsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from logging import getLogger
from rsa import PrivateKey, PublicKey
from typing import Optional

# logging module
logger = getLogger(__name__)


class CryptoContextError(ValueError):
    pass


class AsymmetricContext:
    def __init__(self, public_key: Optional[PublicKey] = None, private_key: Optional[PrivateKey] = None) -> None:
        self._public_key = public_key
        self._public_key_bytes = None
        if public_key is not None:
            self._public_key_bytes = public_key.save_pkcs1()

        self._private_key = private_key
        self._private_key_bytes = None
        if private_key is not None:
            self._private_key_bytes = private_key.save_pkcs1()

    def set_public_key(self, key: bytes) -> None:
        self._public_key = rsa.PublicKey.load_pkcs1(key)
        self._public_key_bytes = key

    @property
    def public_key(self) -> bytes:
        return self._public_key_bytes

    @property
    def private_key(self) -> bytes:
        return self._private_key_bytes

    def encrypt(self, data: bytes) -> bytes:

        if self._public_key is None:
            raise CryptoContextError("Missing public key for encryption")

        logger.debug(f"before encryption data: {data}")
        data = rsa.encrypt(data, self._public_key)
        logger.debug(f"rsa encrypted data: {data}")
        return data

    def decrypt(self, data: bytes) -> bytes:

        if self._private_key is None:
            raise CryptoContextError("Missing private key for decryption")

        logger.debug(f"before encryption data: {data}")
        data = rsa.decrypt(data, self._private_key)
        logger.debug(f"rsa encrypted data: {data}")
        return data


class SymmetricContext:
    def __init__(self) -> None:
        self._key: bytes = ChaCha20Poly1305.generate_key()
        self._nonce: bytes = os.urandom(12)
        self._chacha = ChaCha20Poly1305(self._key)

    @property
    def key(self) -> bytes:
        return self._key

    @key.setter
    def key(self, value: bytes) -> None:
        self._key = value
        self._chacha = ChaCha20Poly1305(self._key)

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @nonce.setter
    def nonce(self, value: bytes) -> None:
        self._nonce = value

    def encrypt(self, payload: bytes, associated_data: bytes) -> bytes:
        logger.debug(f"payload value: {payload}")
        logger.debug(f"associated value: {associated_data}")
        logger.debug(f"nonce value: {self._nonce}")
        return self._chacha.encrypt(self._nonce, payload, associated_data)

    def decrypt(self, payload: bytes, associated_data: bytes) -> bytes:
        logger.debug(f"payload value: {payload}")
        logger.debug(f"associated value: {associated_data}")
        logger.debug(f"nonce value: {self._nonce}")
        return self._chacha.decrypt(self._nonce, payload, associated_data)
