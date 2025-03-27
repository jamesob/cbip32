import ctypes
import os
from functools import lru_cache
from pathlib import Path
from ctypes import (
    c_uint8,
    c_uint32,
    c_size_t,
    c_char_p,
    c_ubyte,
    c_void_p,
    Structure,
    Union,
    POINTER,
    create_string_buffer,
    byref)


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

    bip32_lib.bip32_derive_from_seed.argtypes = [
        POINTER(BIP32Key), POINTER(c_ubyte), c_size_t, c_char_p
    ]
    bip32_lib.bip32_derive_from_seed.restype = ctypes.c_int

    bip32_lib.bip32_derive_from_str.argtypes = [POINTER(BIP32Key), c_char_p, c_char_p]
    bip32_lib.bip32_derive_from_str.restype = ctypes.c_int

    bip32_lib.bip32_derive.argtypes = [POINTER(BIP32Key), c_char_p]
    bip32_lib.bip32_derive.restype = ctypes.c_int

    bip32_lib.bip32_serialize.argtypes = [
        POINTER(BIP32Key), c_char_p, POINTER(c_size_t)
    ]
    bip32_lib.bip32_serialize.restype = ctypes.c_bool

    bip32_lib.bip32_deserialize.argtypes = [POINTER(BIP32Key), c_char_p, c_size_t]
    bip32_lib.bip32_deserialize.restype = ctypes.c_bool

    bip32_lib.bip32_get_public.argtypes = [POINTER(BIP32Key), POINTER(BIP32Key)]
    bip32_lib.bip32_get_public.restype = ctypes.c_int

    bip32_lib.bip32_b58_encode.argtypes = [
        c_char_p, POINTER(c_size_t), POINTER(c_ubyte), c_size_t
    ]
    bip32_lib.bip32_b58_encode.restype = ctypes.c_bool

    bip32_lib.bip32_b58_decode.argtypes = [
        POINTER(c_ubyte), POINTER(c_size_t), c_char_p, c_size_t
    ]
    bip32_lib.bip32_b58_decode.restype = ctypes.c_bool

    return bip32_lib


class KeyUnion(Union):
    _fields_ = [('privkey', c_uint8 * 32), ('pubkey', c_uint8 * 33)]


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
        out_len = c_size_t(len(buf))

        if not self.bip32_lib.bip32_serialize(self.key, buf, byref(out_len)):
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
    """
    Get a BIP32 derivation.

    Args:
        source: Can either be the secret key hex or a serialized base58 BIP32 string
          (xpub/xprv)
        path: The path to derive, e.g. m/12/2'

    """
    b = BIP32()
    if not get_bip32_module().bip32_derive_from_str(
            b.key, source.encode(), path.encode()):
        raise ValueError("failed")
    return b


def derive_from_seed(seed: bytes, path: str = 'm') -> BIP32:
    b = BIP32()
    c_seed = ctypes.c_char_p(seed)
    seed_ptr = ctypes.cast(c_seed, POINTER(c_ubyte))
    if not get_bip32_module().bip32_derive_from_seed(
            b.key, seed_ptr, len(seed), path.encode()):
        raise ValueError("failed")
    return b


def b58_encode(inp: bytes) -> str:
    data_len = len(inp)
    data_arr = (c_ubyte * data_len)(*inp)

    out_size = c_size_t(data_len * 2)
    str_out = ctypes.create_string_buffer(out_size.value)

    if not get_bip32_module().bip32_b58_encode(
            str_out, byref(out_size), data_arr, data_len):
        raise ValueError("base58 encoding failed")

    return str_out.value[:out_size.value].decode('utf-8')


def b58_decode(in_str: str) -> bytes:
    str_bytes = c_char_p(in_str.encode('utf-8'))
    str_len = len(in_str)

    out_size = c_size_t(str_len * 2)
    bin_out = (c_ubyte * out_size.value)()

    if not get_bip32_module().bip32_b58_decode(
            bin_out, byref(out_size), str_bytes, str_len):
        raise ValueError("base58 decoding failed")

    return bytes(bin_out[-out_size.value:])
