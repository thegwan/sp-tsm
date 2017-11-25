# Makefile
# Author: Gerry Wan

# Dependency rules for non-file targets
all: testkeychain memkeychain testkeycrypto

clean:
	rm -f *.o

# Dependency rules for file targets
memkeychain: testkeychain.o keychain.o
	gcc -g testkeychain.o keychain.o -o memkeychain
testkeychain: testkeychain.o keychain.o
	gcc testkeychain.o keychain.o -o testkeychain
testkeycrypto: testkeycrypto.o keycrypto.o
	gcc testkeycrypto.o keycrypto.o -o testkeycrypto
testkeychain.o: testkeychain.c keychain.h
	gcc -c testkeychain.c
keychain.o: keychain.c keychain.h
	gcc -c keychain.c
testkeycrypto.o: testkeycrypto.c keychain.h
	gcc -c testkeycrypto.c
keycrypto.o: keycrypto.c keycrypto.h
	gcc -c keycrypto.c

