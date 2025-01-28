#include "bip32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include <secp256k1.h>
#include <sodium.h>

#include "ripemd160.c"
#include "base58.c"


static void get_secp_ctx(secp256k1_context** ctx) {
    assert(sodium_init() >= 0);

    *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char rand[33];
    randombytes_buf(rand, 32);
    assert(secp256k1_context_randomize(*ctx, rand));
}

static uint32_t to_big_endian(uint32_t value) {
    return htonl(value);
}

static void sha256(unsigned char* out, const unsigned char* msg, size_t msg_len) {
    assert(sodium_init() >= 0);
    crypto_hash_sha256(out, msg, msg_len);
}

void bip32_init(bip32_key *key) {
    assert(sodium_init() >= 0);

    memset(key->chain_code, 0, sizeof(key->chain_code));
    memset(&key->key, 0, sizeof(key->key));
    key->child_number = 0;
    key->parent_fingerprint = 0;
    key->depth = 0;
    key->is_testnet = 0;
    key->is_private = 1;
}

int bip32_from_seed(bip32_key *key, const unsigned char *seed, size_t seed_len) {
    int retcode = 1;
    unsigned char output[crypto_auth_hmacsha512_BYTES];
    const unsigned char bitcoin_seed[] = "Bitcoin seed";

    bip32_hmac_sha512(output, bitcoin_seed, strlen((char*)bitcoin_seed), seed, seed_len);

    secp256k1_context* ctx = NULL;
    get_secp_ctx(&ctx);

    if (!secp256k1_ec_seckey_verify(ctx, output)) {
        retcode = 0; goto exit;
    }

    bip32_init(key);

    memcpy(key->key.privkey, output, BIP32_PRIVKEY_SIZE);
    memcpy(key->chain_code, output + BIP32_PRIVKEY_SIZE, BIP32_CHAINCODE_SIZE);

exit:
    secp256k1_context_destroy(ctx);
    return retcode;
}

int bip32_pubkey_from_privkey(unsigned char* out, const unsigned char* privkey_in) {
    int retcode = 1;
    secp256k1_context* ctx = NULL;
    get_secp_ctx(&ctx);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey_in)) {
        retcode = 0; goto exit;
    }

    size_t pubkey_len = BIP32_PUBKEY_SIZE;
    if (!secp256k1_ec_pubkey_serialize(
            ctx, out, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        retcode = 0; goto exit;
    }

exit:
    secp256k1_context_destroy(ctx);
    return retcode;
}

int bip32_fingerprint(const bip32_key* key, uint32_t* out) {
    unsigned char pubkey_bytes[BIP32_PUBKEY_SIZE];

    if (key->is_private) {
        if (!bip32_pubkey_from_privkey(pubkey_bytes, key->key.privkey)) {
            return 0;
        }
    } else {
        memcpy(pubkey_bytes, key->key.pubkey, BIP32_PUBKEY_SIZE);
    }

    assert(sodium_init() >= 0);
    unsigned char shaout[crypto_hash_sha256_BYTES];
    sha256(shaout, pubkey_bytes, BIP32_PUBKEY_SIZE);

    unsigned char ripeout[RIPEMD160_DIGEST_LENGTH];
    ripemd160(shaout, crypto_hash_sha256_BYTES, ripeout);

    memcpy(out, ripeout, 4);

    return 1;
}

int bip32_index_derive(bip32_key *target, const bip32_key *source, uint32_t index) {
    int retcode = 1;
    const size_t hmac_msg_len = BIP32_PUBKEY_SIZE + sizeof(uint32_t);
    unsigned char hmac_msg[hmac_msg_len];
    unsigned char output[crypto_hash_sha512_BYTES];
    bool is_hardened = index >= HARDENED_INDEX;

    if (is_hardened && !source->is_private) {
        return 0;
    }

    if (source->depth >= 255) {
        // Depth will overflow.
        return 0;
    }

    target->child_number = index;
    target->depth = source->depth + 1;
    target->is_testnet = source->is_testnet;
    target->is_private = source->is_private;

    secp256k1_context* ctx = NULL;
    get_secp_ctx(&ctx);

    if (is_hardened) {
        hmac_msg[0] = 0;
        memcpy(hmac_msg + 1, source->key.privkey, BIP32_PRIVKEY_SIZE);
    } else {
        if (source->is_private) {
            secp256k1_pubkey pubkey;
            size_t pubkey_len = BIP32_PUBKEY_SIZE;

            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, source->key.privkey)) {
                retcode = 0; goto exit;
            }

            if (!secp256k1_ec_pubkey_serialize(ctx, hmac_msg, &pubkey_len, &pubkey,
                SECP256K1_EC_COMPRESSED)) {
                retcode = 0; goto exit;
            }
        } else {
            memcpy(hmac_msg, source->key.pubkey, BIP32_PUBKEY_SIZE);
        }
    }

    uint32_t bigindex = to_big_endian(index);
    memcpy(hmac_msg + BIP32_PUBKEY_SIZE, &bigindex, sizeof(uint32_t));

    bip32_hmac_sha512(output, source->chain_code, BIP32_CHAINCODE_SIZE, hmac_msg, hmac_msg_len);

    memcpy(target->chain_code, output + BIP32_PRIVKEY_SIZE, BIP32_CHAINCODE_SIZE);

    if (source->is_private) {
        unsigned char tweak[BIP32_PRIVKEY_SIZE];
        memcpy(tweak, output, BIP32_PRIVKEY_SIZE);
        memcpy(target->key.privkey, source->key.privkey, BIP32_PRIVKEY_SIZE);

        if (!secp256k1_ec_seckey_tweak_add(ctx, target->key.privkey, tweak)) {
            retcode = 0; goto exit;
        }
    } else {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, source->key.pubkey,
            BIP32_PUBKEY_SIZE)) {
            retcode = 0; goto exit;
        }

        if (!secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, output)) {
            retcode = 0; goto exit;
        }

        size_t pubkey_len = BIP32_PUBKEY_SIZE;
        if (!secp256k1_ec_pubkey_serialize(ctx, target->key.pubkey, &pubkey_len,
            &pubkey, SECP256K1_EC_COMPRESSED)) {
            retcode = 0; goto exit;
        }
    }

    target->is_private = source->is_private;

    // Compute parent fingerprint
    unsigned char pubkey_bytes[BIP32_PUBKEY_SIZE];
    secp256k1_pubkey pubkey;
    size_t pubkey_len = BIP32_PUBKEY_SIZE;

    if (source->is_private) {
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, source->key.privkey)) {
            retcode = 0; goto exit;
        }
    } else {
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, source->key.pubkey,
            BIP32_PUBKEY_SIZE)) {
            retcode = 0; goto exit;
        }
    }

    if (!secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &pubkey_len, &pubkey,
            SECP256K1_EC_COMPRESSED)) {
        retcode = 0; goto exit;
    }

    bip32_fingerprint(source, &target->parent_fingerprint);

exit:
    secp256k1_context_destroy(ctx);
    return retcode;
}

int bip32_derive(bip32_key *target, const char* source, const char* path) {
    if (!target || !source || !path || strncmp(path, "m", 1) != 0) {
        return 0;
    }
    if (strlen(source) < 1) {
        return 0;
    }
    bip32_key basekey;
    size_t source_len = strlen(source);
     
    if (strncmp(source, "xprv", 4) == 0 || 
        strncmp(source, "tprv", 4) == 0 ||
        strncmp(source, "xpub", 4) == 0 || 
        strncmp(source, "tpub", 4) == 0) {
        if (!bip32_deserialize(&basekey, source, strlen(source))) {
            return 0;
        }
    }
    else if (strspn(source, "0123456789abcdefABCDEF") == source_len) {
        // TODO error if seed is more than 256
        unsigned char seedbytes[256];
        size_t bin_len;
        if (sodium_hex2bin(seedbytes, 256, source, strlen(source), ": ", &bin_len, NULL) != 0) {
            return 0;
        }
        if (!bip32_from_seed(&basekey, seedbytes, bin_len)) {
            return 0;
        }
    } else {
        return 0;
    }
    
    char *p = (char*)strchr(path, '/');
    if (!p) {
        memcpy(target, &basekey, sizeof(bip32_key));
        return 1;
    }
    
    while (p && *p) {
        char *end;
        uint32_t index = strtoul(p + 1, &end, 10);
        
        if (end == p + 1) {
            return 0;
        }
        
        if (*end == '\'' || *end == 'h' || *end == 'H' || *end == 'p' || *end == 'P') {
            index |= 0x80000000;
            end++;
        }

        bip32_key tmp;
        memcpy(&tmp, &basekey, sizeof(bip32_key));
        if (bip32_index_derive(&basekey, &tmp, index) != 1) {
            return 0;
        }
        p = strchr(end, '/');
    }
    
    memcpy(target, &basekey, sizeof(bip32_key));
    return 1;
}

#define SER_SIZE 78
#define SER_PLUS_CHECKSUM_SIZE (SER_SIZE + 4)

int bip32_serialize(const bip32_key *key, char *str, size_t str_len) {
    unsigned char data[SER_PLUS_CHECKSUM_SIZE];
    uint32_t version;
    
    // Set version bytes based on network and key type
    if (key->is_private) {
        version = key->is_testnet ? VERSION_TPRIV : VERSION_XPRIV;
    } else {
        version = key->is_testnet ? VERSION_TPUB : VERSION_XPUB;
    }
    version = to_big_endian(version);
    
    memcpy(data, &version, sizeof(version));
    
    data[4] = key->depth;
    
    // Write parent fingerprint
    uint32_t parfinger = key->parent_fingerprint;
    memcpy(data + 5, &parfinger, sizeof(parfinger));

    // Write child number in big-endian
    uint32_t childnum = to_big_endian(key->child_number);
    memcpy(data + 9, &childnum, sizeof(childnum));
    
    // Copy chain code
    memcpy(data + 13, key->chain_code, 32);
    
    if (key->is_private) {
        data[45] = 0;
        memcpy(data + 46, key->key.privkey, 32);
    } else {
        memcpy(data + 45, key->key.pubkey, 33);
    }
    
    // Add checksum and base58 encode
    uint8_t hash[32];
    bip32_sha256_double(hash, data, 78);
    memcpy(data + SER_SIZE, hash, 4);

    return b58enc(str, &str_len, data, SER_PLUS_CHECKSUM_SIZE);
}

#define BIP32_BASE58_BYTES_LEN 82

int bip32_deserialize(bip32_key *key, const char *str, const size_t str_len) {
    unsigned char data[BIP32_BASE58_BYTES_LEN];
    size_t data_len = BIP32_BASE58_BYTES_LEN;

    if (!b58tobin(data, &data_len, str, str_len) || data_len != BIP32_BASE58_BYTES_LEN) {
        return 0;
    }

    // Verify checksum
    unsigned char hash[crypto_hash_sha512_BYTES];
    bip32_sha256_double(hash, data, 78);
    if (memcmp(hash, data + 78, 4) != 0) {
        return 0;
    }

    bip32_init(key);

    uint32_t version = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];

    switch (version) {
        case VERSION_XPUB:
            key->is_testnet = 0;
            key->is_private = 0;
            break;
        case VERSION_XPRIV:
            key->is_testnet = 0; 
            key->is_private = 1;
            break;
        case VERSION_TPRIV:
            key->is_testnet = 1;
            key->is_private = 1;
            break;
        case VERSION_TPUB:
            key->is_testnet = 1;
            key->is_private = 0;
            break;
        default:
            return 0;
    }

    key->depth = data[4];
    memcpy(&key->parent_fingerprint, data + 5, 4);
    key->child_number = (data[9] << 24) | (data[10] << 16) | (data[11] << 8) | data[12];
    memcpy(key->chain_code, data + 13, BIP32_CHAINCODE_SIZE);

    if (key->depth == 0) {
        if (key->parent_fingerprint != 0) {
            return 0;
        }
        if (key->child_number != 0) {
            return 0;
        }
    }

    secp256k1_context* ctx = NULL;
    get_secp_ctx(&ctx);

    if (key->is_private) {
        if (data[45] != 0) {
            secp256k1_context_destroy(ctx);
            return 0;
        }
        memcpy(key->key.privkey, data + 46, BIP32_PRIVKEY_SIZE);
        if (!secp256k1_ec_seckey_verify(ctx, key->key.privkey)) {
            secp256k1_context_destroy(ctx);
            return 0;
        }
    } else {
        memcpy(key->key.pubkey, data + 45, BIP32_PUBKEY_SIZE);
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, key->key.pubkey, BIP32_PUBKEY_SIZE)) {
            secp256k1_context_destroy(ctx);
            return 0;
        }
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

int bip32_get_public(bip32_key *target, const bip32_key *source) {
    if (!source->is_private) {
        return 0;
    }

    memcpy(target->chain_code, source->chain_code, BIP32_CHAINCODE_SIZE);
    memset(target->key.pubkey, 0, BIP32_PUBKEY_SIZE);
    target->child_number = source->child_number;
    target->parent_fingerprint = source->parent_fingerprint;
    target->depth = source->depth;
    target->is_testnet = source->is_testnet;
    target->is_private = 0;

    bip32_pubkey_from_privkey(target->key.pubkey, source->key.privkey);
    return 1;
}

void bip32_sha256_double(uint8_t *hash, const uint8_t *data, size_t len) {
    assert(sodium_init() >= 0);
    unsigned char inthash[crypto_hash_sha256_BYTES];
    sha256(inthash, data, len);
    sha256(hash, inthash, crypto_hash_sha256_BYTES);
}

void bip32_hmac_sha512(
    unsigned char* hmac_out, 
    const unsigned char* key, 
    size_t key_len, 
    const unsigned char* msg, 
    size_t msg_len
) {
    assert(sodium_init() >= 0);
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, key, key_len);
    crypto_auth_hmacsha512_update(&state, msg, msg_len);
    crypto_auth_hmacsha512_final(&state, hmac_out);
}
