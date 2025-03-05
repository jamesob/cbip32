# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "bip32",
#     "hypothesis",
#     "pytest",
#     "verystable",
# ]
# ///
import sys
import logging
import time
from contextlib import contextmanager

import bip32 as py_bip32
from verystable import bip32 as vs_bip32

import pytest
from hypothesis import given, strategies as st, target, settings

from bindings import derive, derive_from_seed

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


def py_derive(seed_hex_str: str, bip32_path: str) -> str:
    bip32 = py_bip32.BIP32.from_seed(bytes.fromhex(seed_hex_str))
    try:
        return bip32.get_xpriv_from_path(bip32_path)
    except Exception:
        return INVALID_KEY


def _path_str_to_ints(bip32_path) -> list[int] | None:
    if not bip32_path.startswith('m'):
        return None

    path_ints = []
    components = filter(None, bip32_path.lstrip('m').split('/'))

    for comp in components:
        if comp.endswith('h'):
            path_ints.append(int(comp[:-1]) | vs_bip32.HARDENED_INDEX)
        else:
            path_ints.append(int(comp))

    return path_ints


def verystable_derive(seed_hex_str: str, bip32_path: str) -> str:
    bip32 = vs_bip32.BIP32.from_bytes(bytes.fromhex(seed_hex_str), True)
    path_ints = _path_str_to_ints(bip32_path)

    if path_ints is None:
        return INVALID_KEY
    elif not path_ints:
        return bip32.serialize()

    try:
        derived, _ = bip32.derive(*path_ints)
        return derived.serialize()
    except Exception:
        return INVALID_KEY


def py_xpub_derive(base58: str, bip32_path: str) -> str:
    bip32 = py_bip32.BIP32.from_xpub(base58)
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
def py_compatible_bip32_paths(draw):
    """
    Given python-bip32's too-large path issue, clamp the max_values that we can fuzz:
      https://github.com/darosior/python-bip32/issues/46
    """
    MAX_ALLOWED_DEPTH = 255
    MAX_UNHARDENED_IDX = 2**31 - 1

    depth = draw(st.integers(min_value=0, max_value=(MAX_ALLOWED_DEPTH + 3)))
    path_parts = ["m"]
    for _ in range(depth):
        index = draw(st.integers(min_value=-2, max_value=MAX_UNHARDENED_IDX))
        hardened = draw(st.booleans())
        path_parts.append(f"{index}{"h" if hardened else ''}")
    return "/".join(path_parts)


@st.composite
def bip32_paths(draw):
    """
    Generate BIP32 paths with some out of bound values.
    """
    MAX_ALLOWED_DEPTH = 255
    MAX_UNHARDENED_IDX = 2**31 - 1

    depth = draw(st.integers(min_value=0, max_value=(MAX_ALLOWED_DEPTH + 3)))
    path_parts = ["m"]
    for _ in range(depth):
        index = draw(st.integers(min_value=-2, max_value=(MAX_UNHARDENED_IDX + 2)))
        hardened = draw(st.booleans())
        path_parts.append(f"{index}{"h" if hardened else ''}")
    return "/".join(path_parts)


@given(seed_hex_str=valid_seeds, bip32_path=py_compatible_bip32_paths())
@settings(max_examples=2_000)
def test_versus_py(seed_hex_str, bip32_path):
    """
    Compare implementations of BIP32 on a random seed and path.
    """
    with timer('ours'):
        ours = our_derive(seed_hex_str, bip32_path)
    with timer('python-bip32'):
        pys = py_derive(seed_hex_str, bip32_path)

    assert ours == pys


@given(seedhex=valid_seeds, path=py_compatible_bip32_paths())
@settings(max_examples=2_000)
def test_versus_ourselves(seedhex, path):
    """
    Ensure that our different derive functions work properly.
    """
    seed = bytes.fromhex(seedhex)
    from_seed = INVALID_KEY
    try:
        from_seed = derive_from_seed(seed, path).serialize()
    except Exception:
        pass
    assert our_derive(seedhex, path) == from_seed


@given(seed_hex_str=valid_seeds, bip32_path=py_compatible_bip32_paths())
@settings(max_examples=100, deadline=5000)  # verstable is slooooww, so allow 5s tests
def test_versus_vs(seed_hex_str, bip32_path):
    """
    Since the verystable implemention is VERY slow (100x+), limit the number of cases.
    """
    with timer('ours'):
        ours = our_derive(seed_hex_str, bip32_path)
    with timer('verystable'):
        vs = verystable_derive(seed_hex_str, bip32_path)

    assert ours == vs


@given(bip32_path=py_compatible_bip32_paths())
@settings(max_examples=200)
def test_xpub_impls(bip32_path):
    xpub = 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'

    with timer('ours'):
        ours = our_derive(xpub, bip32_path)
    with timer('python-bip32'):
        pys = py_xpub_derive(xpub, bip32_path)
    assert ours == pys


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--capture=no", "--hypothesis-show-statistics", "-x"] + sys.argv[1:])
