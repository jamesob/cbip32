CC := $(shell command -v clang 2>/dev/null || command -v $(CC) 2>/dev/null || echo cc)

CFLAGS = -Wall -Werror
ifdef DEBUG
    CFLAGS += -g -DDEBUG
else
    CFLAGS += -O2
endif

LDCONFIG := ldconfig
INSTALL_PREFIX := /usr/local

UNAME_S := $(shell uname -s)

# Set default paths
STD_INCLUDE_PATHS := /usr/local/include
STD_LIB_PATHS := /usr/local/lib

# Add Homebrew paths for macOS
ifeq ($(UNAME_S),Darwin)
    UNAME_MACHINE := $(shell uname -m)
	LDCONFIG := test 1
    ifeq ($(UNAME_MACHINE),arm64)
        BREW_PREFIX := /opt/homebrew
    else
        BREW_PREFIX := /usr/local
    endif
    INCLUDE_PATHS := $(BREW_PREFIX)/include $(STD_INCLUDE_PATHS)
    LIB_PATHS := $(BREW_PREFIX)/lib $(STD_LIB_PATHS)
else
    INCLUDE_PATHS := $(STD_INCLUDE_PATHS)
    LIB_PATHS := $(STD_LIB_PATHS)
endif

# Convert paths to compiler flags
CFLAGS += $(foreach path,$(INCLUDE_PATHS),-I$(path))
LDFLAGS += $(foreach path,$(LIB_PATHS),-L$(path)) -lsecp256k1 -lsodium

all: libbip32.so
	$(CC) $(CFLAGS) -o bip32-cli examples/cli.c libbip32.so $(LDFLAGS)

libbip32.so:
	$(CC) $(CFLAGS) -I. -shared -fPIC bip32.c $(LDFLAGS) -o libbip32.so

fuzz_target: libbip32.so
	$(CC) -fsanitize=fuzzer,address fuzz.c libbip32.so $(LDFLAGS) -o fuzz_target

.PHONY: test
test: libbip32.so
	$(CC) $(CFLAGS) -o test-bip32 test/test.c libbip32.so $(LDFLAGS)
	./test-bip32

.PHONY: fuzz
fuzz: fuzz_target
	./fuzz_target -jobs=$$(nproc --ignore=1)

.PHONY: install
install: libbip32.so
	install -m755 libbip32.so $(INSTALL_PREFIX)/lib/
	install -m755 bip32.h $(INSTALL_PREFIX)/include/
	$(LDCONFIG)

.PHONY: clean
clean:
	rm -f *.o *.so test-bip32
