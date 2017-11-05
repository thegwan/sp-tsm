# Makefile
# Author: Gerry Wan

# Dependency rules for non-file targets
all: testkeyrecord

# Dependency rules for file targets
testkeyrecord: testkeyrecord.o keyrecord.o
	gcc testkeyrecord.o keyrecord.o -o testkeyrecord
testkeyrecord.o: testkeyrecord.c keyrecord.h
	gcc -c testkeyrecord.c
keyrecord.o: keyrecord.c keyrecord.h
	gcc -c keyrecord.c

