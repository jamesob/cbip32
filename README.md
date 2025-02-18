# cbip32

![test workflow](https://github.com/jamesob/cbip32/actions/workflows/tests.yml/badge.svg)

A fast, secure, low-dependency implementation of BIP32

- Depends only on [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) and
  [`libsodium`](https://github.com/jedisct1/libsodium) (for SHA256, HMAC-SHA512, and
  context randomization)
- No heap allocations (aside from secp context), which allows end users to manage memory securely
- Implemented in pure C for ease of FFI
- Extensively tested
  - Uses [cross-implementation fuzz testing](./examples/py/test_fuzz_cross_impl.py) 
    against [`python-bip32`](https://github.com/darosior/python-bip32) and 
    [`verystable`](https://github.com/jamesob/verystable/blob/master/verystable/bip32.py).


## Installation from source

Install libsecp256k1
```bash
git clone https://github.com/bitcoin-core/secp256k1.git && \
  cd secp256k1 && ./autogen.sh && ./configure && make && sudo make install
```

Install libsodium
```bash
git clone https://github.com/jedisct1/libsodium.git && \
  cd libsodium && ./autogen.sh -sb && ./configure && make && sudo make install
```

Install this library
```
git clone https://github.com/jamesob/cbip32.git && \
  make && sudo make install
```

## Performance

The Python bindings for this implementation have been shown to be
- *~2x* faster than `python-bip32`, an implementation based on `coincurve` which itself
  wraps libsecp256k1
- *>100x* faster than `verystable`, which is a "dumb" pure Python implementation.

From fuzzing:
```
  - Highest target scores [time per derivation]:
     0.0162932  (label='ours')
     0.0379755  (label='python-bip32')

  - Highest target scores [time per derivation]:
     0.00222896  (label='ours')
     0.315636    (label='verystable')
```


## Example bindings included

### Python [(`./examples/py`)](./examples/py)

```python
>>> from bindings import derive
>>> derive('0' * 32, 'm/1/2h').get_public().serialize()
'xpub69s9RVsS4kfK2VFed2giqFm9gQ4VmCWuWcPHFJ51Rj6dHvBjCicCZm2HR88Z6J5zRYyHkt7W9LPygBc57RCCPp2t1AxCNa1VtvSq4qWYLqK'
```

### Go [(`./examples/go`)](./examples/go)

```go
package cbip32

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -lbip32
// #include "bip32.h"
import "C"
import (
    "unsafe"
)

type BIP32Key struct {
    cKey C.bip32_key
}

func NewKey() *BIP32Key {
    key := &BIP32Key{}
    C.bip32_init(&key.cKey)
    return key
}

func Derive(source, path string) (*BIP32Key, bool) {
    key := NewKey()
    cSource := C.CString(source)
    cPath := C.CString(path)
    defer C.free(unsafe.Pointer(cSource))
    defer C.free(unsafe.Pointer(cPath))

    result := C.bip32_derive(&key.cKey, cSource, cPath)
    return key, result == 1
}
```
