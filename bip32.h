#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define HARDENED_INDEX 0x80000000
#define BIP32_CHAINCODE_SIZE 32
#define BIP32_PRIVKEY_SIZE 32
#define BIP32_PUBKEY_SIZE 33
#define RIPEMD160_SIZE 20
#define SHA256_SIZE 32
#define SHA512_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

// Version bytes
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

/** Derive a BIP32 path. `source` as a null-terminated string that can either be a
 * 32 byte seed (secret), or a serialized BIP32 key (xprv*, xpub*, tprv*, tpub*).
 *
 * Returns 1 if successful.
 */
int bip32_derive(bip32_key *target, const char* source, const char* path);

int bip32_serialize(const bip32_key *key, char *str, size_t str_len);

int bip32_deserialize(bip32_key *key, const char *str, size_t str_len);

int bip32_get_public(bip32_key *target, const bip32_key *source);

int bip32_index_derive(bip32_key *target, const bip32_key *source, uint32_t index);

/**
 * Given a private key, set `out`'s bytes to the corresponding compressed pubkey.
 *
 * Returns 1 if successful.
 */
int pubkey_from_privkey(unsigned char* out, const unsigned char* privkey_in);

void sha256_double(uint8_t *hash, const uint8_t *data, size_t len);

void hmac_sha512(
    unsigned char* hmac_out,
    const unsigned char* key,
    size_t key_len,
    const unsigned char* msg,
    size_t msg_len
);

#ifdef __cplusplus
}
#endif
