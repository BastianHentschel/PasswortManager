import string
import pathlib
import random

import msgpack
import pyperclip
from Crypto.Cipher import AES
from Crypto.Hash import SHA512


class PasswordData:
    RANDOM = object()

    def __init__(self, password, path: pathlib.Path = None, save_callback=None, load_callback=None):
        self.save_callback = save_callback
        self.load_callback = load_callback
        self.path = path
        hash_data = SHA512.new(bytes(password, encoding="UTF-8")).digest()
        self.key = bytes(a ^ b for a, b in zip(hash_data[:32], hash_data[32:]))

        if self.path and self.path.exists():
            with self.path.open("rb") as f:
                content = f.read()
                if content:
                    self.__password_dict = self.decrypt(content)
                else:
                    self.__password_dict = {}
        elif self.path:
            self.__password_dict = {}
        elif self.load_callback:
            try:
                self.__password_dict = self.decrypt(self.load_callback(self.key))
            except ConnectionError:
                self.__password_dict = {}

    def save(self):
        if self.save_callback:
            self.save_callback(self.key, self.encrypt())
        else:
            with self.path.open("wb") as f:
                f.write(self.encrypt())

    def decrypt(self, data: bytes) -> dict:
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=data[:16])
        data = cipher.decrypt_and_verify(data[32:], data[16:32])
        return msgpack.loads(data)

    def encrypt(self) -> bytes:
        cipher = AES.new(self.key, AES.MODE_EAX)
        enc_data = b"".join([cipher.nonce, *cipher.encrypt_and_digest(msgpack.dumps(self.__password_dict))[::-1]])
        return enc_data

    def copy_password(self, key):
        pyperclip.copy(self.__password_dict.get(key, None))

    def add_password(self, key, password: str = RANDOM, length=64):
        if password is self.RANDOM:
            password = "".join(
                random.choices(string.ascii_letters + string.digits + string.punctuation, k=length)
            )
        if key in self.__password_dict:
            raise KeyError(f"Key {key} already exists")
        self.__password_dict[key] = password

        self.copy_password(key)

    def remove_password(self, key):
        self.__password_dict.pop(key, None)

    def keys(self):
        return [key for key in self.__password_dict]

    def set_all(self, passwords: dict):
        self.__password_dict = passwords
