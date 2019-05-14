CC := aarch64-linux-android-gcc
CPP := aarch64-linux-android-g++
CFLAGS := -I./

all:
	$(CC) test.c rsa.c crypto.c crc32.c  $(CFLAGS) -o out
clean:
	rm out
