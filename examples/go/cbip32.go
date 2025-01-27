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
