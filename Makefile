#CC := aarch64-linux-android-gcc
#CPP := aarch64-linux-android-g++
CC := clang
CPP := clang
CFLAGS := -I./

all:
	$(CC) test.c rsa.c crypto.c crc32.c  sha256.c sha512.c $(CFLAGS) -o out
clean:
	rm out
