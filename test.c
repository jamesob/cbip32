#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "bip32.h"

typedef struct {
    const char* seed;
    struct {
        const char* pub;
        const char* priv;
        uint32_t index;
    } vectors[6];
    size_t num_vectors;
} test_vector;


void test_vector_1(void) {
    bip32_key master, child;
    char str[200];
    const unsigned char SEED_HEX[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    bip32_key k;
    bip32_derive(&k, "000102030405060708090a0b0c0d0e0f\000", "m/1'");

    printf("\nTesting BIP32 Test Vector 1:\n");
    printf("Seed: ");
    for(int i = 0; i < 16; i++) printf("%02x", SEED_HEX[i]);
    printf("\n");

    // Chain m
    printf("\nChain m:\n");
    bip32_init(&master);
    if (!bip32_from_seed(&master, SEED_HEX, sizeof(SEED_HEX))) {
        printf("FAILED to create master key\n");
        return;
    }

    // Test private key
    bip32_serialize(&master, str, sizeof(str));
    printf("  Private:  %s\n", str);
    printf("  Expected: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi\n");
    if (strcmp(str, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi") != 0) {
        printf("FAILED: Master private key mismatch\n");
        return;
    }

    // Test public key
    bip32_key pub;
    bip32_get_public(&pub, &master);
    bip32_serialize(&pub, str, sizeof(str));
    printf("  Public:   %s\n", str);
    printf("  Expected: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8\n");
    if (strcmp(str, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8") != 0) {
        printf("FAILED: Master public key mismatch\n");
        return;
    }

    // Chain m/0H
    printf("\nChain m/0h:\n");
    if (!bip32_index_derive(&child, &master, 0 | HARDENED_INDEX)) {
        printf("FAILED to derive m/0H\n");
        return;
    }
    
    bip32_serialize(&child, str, sizeof(str));
    printf("  Private:  %s\n", str);
    printf("  Expected: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\n");

    bip32_get_public(&pub, &child);
    bip32_serialize(&pub, str, sizeof(str));
    printf("  Public:   %s\n", str);
    printf("  Expected: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\n");

    // Chain m/0H/1
    printf("\nChain m/0H/1:\n");
    if (!bip32_index_derive(&master, &child, 1)) {
        printf("FAILED to derive m/0H/1\n");
        return;
    }

    bip32_serialize(&master, str, sizeof(str));
    printf("  Private:  %s\n", str);
    printf("  Expected: xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs\n");

    bip32_get_public(&pub, &master);
    bip32_serialize(&pub, str, sizeof(str));
    printf("  Public:   %s\n", str);
    printf("  Expected: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ\n");

    // Continue for m/0H/1/2H, m/0H/1/2H/2, and m/0H/1/2H/2/1000000000...
}

int main() {
    
#if defined(__ARM_FEATURE_SHA2)
    printf("HAS SHA\n");
#endif
    test_vector_1();
    return 0;
}
