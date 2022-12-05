#!/usr/bin/env python3

from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key: str):
        password = key.encode('utf-8')
        self.key = md5(password).digest()

    @staticmethod
    def encrypt(shared_key: str, data: bytes) -> bytes:
        shared_key = shared_key.encode("utf-8")
        vector = get_random_bytes(AES.block_size)
        encryption_cipher = AES.new(shared_key, AES.MODE_CBC, vector)
        return vector + encryption_cipher.encrypt(pad(data,  AES.block_size))

    @staticmethod
    def decrypt(iv: bytes, shared_key: str, data: bytes) -> bytes:
        """
        """
        decryption_cipher = AES.new(
                shared_key.encode('utf-8'), 
                AES.MODE_CBC, 
                iv)
        return unpad(decryption_cipher.decrypt(data), AES.block_size)

