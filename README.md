# cbip32

A fast, secure, low-dependency implementation of BIP32

- Depends only on [`libsecp256k1`](https://github.com/bitcoin-core/libsecp256k1) and
  [`libsodium`](https://github.com/jedisct1/libsodium)
- No heap allocations (aside from secp context), which allows end users to manage memory securely
- Implemented in pure C for ease of FFI
- Extensively tested
  - Uses [cross-implementation fuzz testing](./examples/py/test_fuzz_cross_impl.py) 
    against `python-bip32` and `verystable`.


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

## Example bindings included

### [Python](./examples/py)

```python
>>> from bindings import derive
>>> derive('0' * 32, 'm/1/2h').get_public().serialize()
'xpub69s9RVsS4kfK2VFed2giqFm9gQ4VmCWuWcPHFJ51Rj6dHvBjCicCZm2HR88Z6J5zRYyHkt7W9LPygBc57RCCPp2t1AxCNa1VtvSq4qWYLqK'
```

### [Go](./examples/go)

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
