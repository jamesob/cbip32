package cbip32

import (
    "testing"
    "encoding/hex"
)

func FuzzBIP32Derive(f *testing.F) {
    // Add seed corpus
    f.Add([]byte("11111111111111111111111111111111"))
    f.Add([]byte("000102030405060708090a0b0c0d0e0f"))
    
    f.Fuzz(func(t *testing.T, data []byte) {
        if len(data) < 16 {
            return
        }

        // Use first few bytes for path construction
        pathDepth := int(data[0] % 5)
        path := "m"
        
        for i := 0; i < pathDepth && i < len(data)-1; i++ {
            index := uint32(data[i+1])
            if data[i+1]%2 == 0 {
                path += "/" + string(rune(index)) + "'"
            } else {
                path += "/" + string(rune(index))
            }
        }

        // Use remaining bytes as seed
        seed := hex.EncodeToString(data[pathDepth+1:])
        
        // Attempt derivation
        _, ok := Derive(seed, path)
        if ok {
            // Successful derivation
            t.Logf("Success with seed %s and path %s", seed, path)
        }
    })
}

type testVector struct {
    seed     string
    path     string
    xprv     string
    xpub     string
}

// Test vectors from BIP32 specification
var testVectors = []testVector{
    {
        // Test vector 1
        seed: "000102030405060708090a0b0c0d0e0f",
        path: "m",
        xprv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        xpub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    },
    {
        // Test vector 1 - Chain m/0'
        seed: "000102030405060708090a0b0c0d0e0f",
        path: "m/0'",
        xprv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        xpub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    },
    {
        // Test vector 1 - Chain m/0'/1
        seed: "000102030405060708090a0b0c0d0e0f",
        path: "m/0'/1",
        xprv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        xpub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    },
    {
        // Test vector 1 - Chain m/0'/1/2'
        seed: "000102030405060708090a0b0c0d0e0f",
        path: "m/0'/1/2'",
        xprv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        xpub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    },
    {
        // Test vector 1 - Chain m/0'/1/2'/2
        seed: "000102030405060708090a0b0c0d0e0f",
        path: "m/0'/1/2'/2",
        xprv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        xpub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
    },
    {
        // Test vector 2
        seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        path: "m",
        xprv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        xpub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
    },
    {
        // Test vector 2 - Chain m/0
        seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        path: "m/0",
        xprv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        xpub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
    },
}

func TestBIP32Vectors(t *testing.T) {
    for i, vector := range testVectors {
        // Test derivation
        _, ok := Derive(vector.seed, vector.path)
        if !ok {
            t.Errorf("Vector %d: Failed to derive path %s from seed %s",
                i, vector.path, vector.seed)
            continue
        }
    }
}

func TestEdgeCases(t *testing.T) {
    testCases := []struct {
        name string
        seed string
        path string
        shouldSucceed bool
    }{
        {
            name: "Empty seed",
            seed: "",
            path: "m",
            shouldSucceed: false,
        },
        {
            name: "Invalid path",
            seed: "000102030405060708090a0b0c0d0e0f",
            path: "invalid",
            shouldSucceed: false,
        },
        {
            name: "Path without m",
            seed: "000102030405060708090a0b0c0d0e0f",
            path: "0/1/2",
            shouldSucceed: false,
        },
        {
            name: "Very deep path",
            seed: "000102030405060708090a0b0c0d0e0f",
            path: "m/0/1/2/3/4/5/6/7/8/9/10",
            shouldSucceed: true,
        },
        {
            name: "All hardened indices",
            seed: "000102030405060708090a0b0c0d0e0f",
            path: "m/0'/1'/2'/3'/4'",
            shouldSucceed: true,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            _, ok := Derive(tc.seed, tc.path)
            if ok != tc.shouldSucceed {
                t.Errorf("Expected success=%v, got=%v for seed=%s path=%s",
                    tc.shouldSucceed, ok, tc.seed, tc.path)
            }
        })
    }
}
