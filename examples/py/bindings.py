import ctypes
import os
from functools import lru_cache
from pathlib import Path
from ctypes import (
    c_uint8, c_uint32, c_size_t, c_char_p, c_void_p,
    Structure, Union, POINTER, create_string_buffer
)


@lru_cache
def get_bip32_module():
    if os.environ.get('BIP32_DEV') and Path('../../bip32.c').exists():
        os.system('cd ../../ && make libbip32.so')
        bip32_lib = ctypes.CDLL('../../libbip32.so')
    else:
        bip32_lib = ctypes.CDLL('libbip32.so')

    # Set function prototypes
    bip32_lib.bip32_init.argtypes = [POINTER(BIP32Key)]
    bip32_lib.bip32_init.restype = None

    bip32_lib.bip32_derive.argtypes = [POINTER(BIP32Key), c_char_p, c_char_p]
    bip32_lib.bip32_derive.restype = ctypes.c_int

    bip32_lib.bip32_derive.argtypes = [POINTER(BIP32Key), c_char_p, c_char_p]
    bip32_lib.bip32_derive.restype = ctypes.c_int

    bip32_lib.bip32_serialize.argtypes = [POINTER(BIP32Key), c_char_p, c_size_t]
    bip32_lib.bip32_serialize.restype = ctypes.c_bool

    bip32_lib.bip32_deserialize.argtypes = [POINTER(BIP32Key), c_char_p, c_size_t]
    bip32_lib.bip32_deserialize.restype = ctypes.c_bool

    bip32_lib.bip32_get_public.argtypes = [POINTER(BIP32Key), POINTER(BIP32Key)]
    bip32_lib.bip32_get_public.restype = ctypes.c_int

    return bip32_lib


class KeyUnion(Union):
    _fields_ = [
        ('privkey', c_uint8 * 32),
        ('pubkey', c_uint8 * 33)
    ]

class BIP32Key(Structure):
    _fields_ = [
        ('ctx', c_void_p),
        ('chain_code', c_uint8 * 32),
        ('key', KeyUnion),
        ('child_number', c_uint32),
        ('parent_fingerprint', c_uint32),
        ('depth', c_uint8),
        ('is_testnet', c_uint8),
        ('is_private', c_uint8),
    ]

    def print(self):
        for field_name, field_type in self._fields_:
            print(f"{field_name}: {getattr(self, field_name)}")


class BIP32:
    def __init__(self):
        self.key = BIP32Key()
        self.bip32_lib = get_bip32_module()
        self.bip32_lib.bip32_init(self.key)

    def from_seed(self, seed):
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        return self.bip32_lib.bip32_from_seed(self.key, seed, len(seed))

    def derive(self, path: str) -> 'BIP32':
        return derive(self.serialize(), path)

    def serialize(self):
        buf = create_string_buffer(200)  # Standard BIP32 serialization length
        if not self.bip32_lib.bip32_serialize(self.key, buf, len(buf)):
            raise ValueError("Serialization failed")
        return buf.value.decode()

    def deserialize(self, xkey):
        if not self.bip32_lib.bip32_deserialize(self.key, xkey.encode(), len(xkey)):
            raise ValueError("Deserialization failed")

    def get_public(self):
        pub = BIP32()
        if self.bip32_lib.bip32_get_public(pub.key, self.key) != 1:
            raise ValueError("Public key derivation failed")
        return pub


def derive(source: str, path: str = 'm') -> BIP32:
    b = BIP32()
    if not get_bip32_module().bip32_derive(b.key, source.encode(), path.encode()):
        raise ValueError("failed")
    return b
