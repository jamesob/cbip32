## 0.0.2

- Changed `bip32_serialze` str_len to a pointer which returns the final length of the
  base58-encoded out string.
- Added some precautionary `sodium_memzero()` calls.
- Made `bip32_b58_encode()` and `bip32_b58_decode()` a public part of the API.
