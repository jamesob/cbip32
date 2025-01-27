# cbip32

A fast, secure, low-dependency implementation of BIP32

- Depends only on [`libsecp256k1`](https://github.com/bitcoin-core/libsecp256k1) and
  [`libsodium`](https://github.com/jedisct1/libsodium)
- Zero heap allocations to allow end users to manage memory securely
- Implemented in pure C for ease of FFI
- Extensively tested
  - Uses cross-implementation fuzz testing against `python-bip32`


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
