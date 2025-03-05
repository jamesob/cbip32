#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define HARDENED_INDEX 0x80000000
#define BIP32_CHAINCODE_SIZE 32
#define BIP32_PRIVKEY_SIZE 32
#define BIP32_PUBKEY_SIZE 33

#ifdef __cplusplus
extern "C" {
#endif

#define VERSION_XPUB 0x0488B21E
#define VERSION_XPRIV 0x0488ADE4
#define VERSION_TPUB 0x043587CF
#define VERSION_TPRIV 0x04358394

typedef struct {
    unsigned char chain_code[BIP32_CHAINCODE_SIZE];
    union {
        unsigned char privkey[BIP32_PRIVKEY_SIZE];
        unsigned char pubkey[BIP32_PUBKEY_SIZE];
    } key;
    uint32_t child_number;
    uint32_t parent_fingerprint;
    uint8_t depth;
    uint8_t is_testnet;
    uint8_t is_private;
} bip32_key;


/** Initialize a BIP32 key struct.
 */
void bip32_init(bip32_key *key);

/** Set a BIP32 key to `m/` given a seed hex string.
 *
 * Returns 1 if successful.
 */
int bip32_from_seed(bip32_key *key, const unsigned char *seed, size_t seed_len);

/** Derive a BIP32 path from a raw seed.
 *
 * Returns 1 if successful.
 */
int bip32_derive_from_seed(bip32_key* target, const unsigned char* seed, size_t seed_len, const char* path);

/** Derive a BIP32 path. `source` as a null-terminated string that can either be a
 * 32 byte seed (secret), or a serialized BIP32 key (xprv*, xpub*, tprv*, tpub*).
 *
 * Returns 1 if successful.
 */
int bip32_derive_from_str(bip32_key *target, const char* source, const char* path);

/** Derive a BIP32 key along a path in-place. This is destructive on `target`.
 *
 * Returns 1 if successful.
 */
int bip32_derive(bip32_key *target, const char* path);

/** Serialize a BIP32 key to its base58 string representation.
 *
 * Returns 1 if successful.
 */
int bip32_serialize(const bip32_key *key, char *str, size_t str_len);

/** Deserialize a BIP32 key from its base58 string representation.
 *
 * Returns 1 if successful.
 */
int bip32_deserialize(bip32_key *key, const char *str, size_t str_len);

/** Get a private BIP32 key's public key.
 *
 * Returns 1 if successful.
 */
int bip32_get_public(bip32_key *target, const bip32_key *source);

/** Get the `index` child of a given BIP32 key.
 *
 * Returns 1 if successful.
 */
int bip32_index_derive(bip32_key *target, const bip32_key *source, uint32_t index);

/** Given a private key, set `out`'s bytes to the corresponding compressed pubkey.
 *
 * Returns 1 if successful.
 */
int bip32_pubkey_from_privkey(unsigned char* out, const unsigned char* privkey_in);

/** Get a key's fingerpint.
 *
 * Returns 1 if successful.
 */
int bip32_fingerprint(const bip32_key* key, uint32_t* out);

void bip32_sha256_double(uint8_t *hash, const uint8_t *data, size_t len);

void bip32_hmac_sha512(
    unsigned char* hmac_out,
    const unsigned char* key,
    size_t key_len,
    const unsigned char* msg,
    size_t msg_len
);

#ifdef __cplusplus
}
#endif
