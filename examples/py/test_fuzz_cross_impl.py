# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "bip32",
#     "hypothesis",
#     "pytest",
# ]
# ///
import random
import logging
import time
from contextlib import contextmanager

import pytest
from hypothesis import given, strategies as st, target, settings
from bip32 import BIP32

from bindings import derive

log = logging.getLogger(__name__)
logging.basicConfig()

# Strategy for valid hex seeds (must be 128-512 bits)
valid_seeds = st.binary(min_size=16, max_size=64).map(lambda b: b.hex())

INVALID_KEY = '_'

@contextmanager
def timer(label):
   start = time.perf_counter()
   yield
   target(time.perf_counter() - start, label=label)


def their_derive(seed_hex_str: str, bip32_path: str) -> str:
    bip32 = BIP32.from_seed(bytes.fromhex(seed_hex_str))
    try:
        return bip32.get_xpriv_from_path(bip32_path)
    except Exception:
        return INVALID_KEY


def their_xpub_derive(base58: str, bip32_path: str) -> str:
    bip32 = BIP32.from_xpub(base58)
    try:
        return bip32.get_xpub_from_path(bip32_path)
    except Exception:
        return INVALID_KEY


def our_derive(hex_str, path) -> str:
    try:
        b32 = derive(hex_str, path)
        return b32.serialize()
    except Exception:
        return INVALID_KEY


@st.composite
def bip32_paths(draw):
    depth = draw(st.integers(min_value=0, max_value=255))
    path_parts = ["m"]
    for _ in range(depth):
        index = draw(st.integers(min_value=0, max_value=(2**31 - 1)))
        hardened = draw(st.booleans())
        path_parts.append(f"{index}{"h" if hardened else ''}")
    return "/".join(path_parts)


@given(seed_hex_str=valid_seeds, bip32_path=bip32_paths())
@settings(max_examples=2_000)
def test_impls(seed_hex_str, bip32_path):
    with timer('ours'):
        ours = our_derive(seed_hex_str, bip32_path)
    with timer('python-bip32'):
        theirs = their_derive(seed_hex_str, bip32_path)
    assert ours == theirs


@given(bip32_path=bip32_paths())
@settings(max_examples=200)
def test_xpub_impls(bip32_path):
    xpub = 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'

    with timer('ours'):
        ours = our_derive(xpub, bip32_path)
    with timer('python-bip32'):
        theirs = their_xpub_derive(xpub, bip32_path)
    assert ours == theirs


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--capture=no", "--hypothesis-show-statistics"])
