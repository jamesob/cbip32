CC := $(shell command -v clang 2>/dev/null || command -v $(CC) 2>/dev/null || echo cc)
CFLAGS = -DDEBUG -Wall -Werror
LDFLAGS = -lsecp256k1 -lsodium

all: libbip32.so
	$(CC) $(CFLAGS) -o bip32-cli cli.c libbip32.so $(LDFLAGS)

libbip32.so:
	$(CC) $(CFLAGS) -I. -shared -fPIC bip32.c $(LDFLAGS) -o libbip32.so

fuzz_target: libbip32.so
	$(CC) -fsanitize=fuzzer,address fuzz.c libbip32.so $(LDFLAGS) -o fuzz_target

.PHONY: test
test: libbip32.so
	$(CC) $(CFLAGS) -o test test.c libbip32.so $(LDFLAGS)
	./test

.PHONY: fuzz
fuzz: fuzz_target
	./fuzz_target -jobs=$$(nproc --ignore=1)

.PHONY: install
install: libbip32.so
	install -m755 libbip32.so /usr/local/lib/
	install -m755 bip32.h /usr/local/include/
	ldconfig

.PHONY: clean
clean:
	rm -f *.o *.so test
