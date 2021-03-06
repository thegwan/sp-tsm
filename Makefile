# Makefile
# Author: Gerry Wan

# Dependency rules for non-file targets
all: testkeychain memkeychain testkeycrypto testtsm demo1_driver

clean:
	rm -f *.o
	rm testkeychain memkeychain testkeycrypto testtsm demo1_driver

# Dependency rules for file targets
memkeychain: testkeychain.o keychain.o keycrypto.o sha256.o
	gcc -g testkeychain.o keychain.o keycrypto.o  sha256.o -o memkeychain
testtsm: testtsm.o tsm.o keychain.o keycrypto.o sha256.o
	gcc testtsm.o tsm.o keychain.o keycrypto.o sha256.o -o testtsm
demo1_driver: demo1_driver.o tsm.o keychain.o keycrypto.o sha256.o
	gcc demo1_driver.o tsm.o keychain.o keycrypto.o sha256.o -o demo1_driver
testkeychain: testkeychain.o keychain.o keycrypto.o sha256.o
	gcc testkeychain.o keychain.o keycrypto.o sha256.o -o testkeychain
testkeycrypto: testkeycrypto.o keycrypto.o sha256.o
	gcc testkeycrypto.o keycrypto.o sha256.o -o testkeycrypto
testtsm.o: testtsm.c keychain.h keycrypto.h sha256.h
	gcc -c testtsm.c
demo1_driver.o: demo1_driver.c keychain.h keycrypto.h sha256.h
	gcc -c demo1_driver.c
tsm.o: tsm.c keychain.h keycrypto.h sha256.h
	gcc -c tsm.c
testkeychain.o: testkeychain.c keychain.h sha256.h
	gcc -c testkeychain.c
keychain.o: keychain.c keychain.h keycrypto.h sha256.h
	gcc -c keychain.c
testkeycrypto.o: testkeycrypto.c keychain.h sha256.h
	gcc -c testkeycrypto.c
keycrypto.o: keycrypto.c keycrypto.h
	gcc -c keycrypto.c
sha256.o: sha256.c sha256.h
	gcc -c sha256.c

