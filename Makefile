# Makefile
# Author: Gerry Wan

# Dependency rules for non-file targets
all: testkeychain

clean:
	rm -f *.o

# Dependency rules for file targets
testkeychain: testkeychain.o keychain.o
	gcc testkeychain.o keychain.o -o testkeychain
testkeychain.o: testkeychain.c keychain.h
	gcc -c testkeychain.c
keychain.o: keychain.c keychain.h
	gcc -c keychain.c

