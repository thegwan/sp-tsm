/*--------------------------------------------------------------------*/
/* tsm.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "tsm.h"
#include "keychain.h"
#include "keycrypto.h"
#include "sha256.h"
#include <stdlib.h> 
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define KEYLEN  8
#define HASHLEN 32
#define BUFLEN  (sizeof(unsigned char) * KEYLEN*2 + 1)

/*--------------------------------------------------------------------*/
/* Private functions:                                                 */
/*--------------------------------------------------------------------*/

/* Determine if a file is padded using PKCS#7 */
static int isPadded(int pad, char *buf) {
    int i;

    if (!(1 <= pad && pad <= KEYLEN)) 
        return 0;
    for (i = 0; i < pad; i++) {
        if (buf[KEYLEN - 1 - i] != pad)
            return 0;
    }
    return 1;
}

/*--------------------------------------------------------------------*/
/* Public functions:                                                  */
/*--------------------------------------------------------------------*/

int AddKeyToChain(KeyChain_T oKeyChain, 
                  char *pcParentKeyID, 
                  char *pcKeyID,
                  int iType)
{
    // generate a 64 bit random key
    srand(time(NULL));
    unsigned char key[] = {rand() & 0xff, rand() & 0xff,
                           rand() & 0xff, rand() & 0xff,
                           rand() & 0xff, rand() & 0xff,
                           rand() & 0xff, rand() & 0xff};
    return KeyChain_addKey(oKeyChain, pcParentKeyID, pcKeyID, key, iType);
}

/*--------------------------------------------------------------------*/

int DeleteKeyFromChain(KeyChain_T oKeyChain, char *pcKeyID)
{
    // auto updates intermediate hashes
    return KeyChain_removeKey(oKeyChain, pcKeyID);
}

/*--------------------------------------------------------------------*/

int Encrypt(const char *inputFileName, 
            const char *outputFileName,
            KeyChain_T oKeyChain, 
            char *pcKeyID)
{
    int c;
    int numRead;
    int padded;                   // for PKCS#7 padding
    FILE *fpi, *fpo;
    unsigned char keybuf[KEYLEN];
    unsigned char inbuf[KEYLEN];
    unsigned char outbuf[KEYLEN];
    unsigned char hash[HASHLEN];
    char temp_buf[BUFLEN];
    SHA256_CTX ctx;

    // must be a leaf key
    if (KeyChain_getType(oKeyChain, pcKeyID) != 1) {
        printf("\n---wrong type!\n");  // for demo
        return 0;
    }

    // retrieve key
    KeyChain_getKey(oKeyChain, pcKeyID, keybuf);

    // verify integrity of key node
    if (!KeyChain_verifyKey(oKeyChain, pcKeyID)) {
        printf("\n---hash mismatch!\n");   // for demo
        return 0;
    }

    fpi = fopen(inputFileName, "r");
    if (fpi == NULL)
        return 0;
    fpo = fopen(outputFileName, "w");
    if (fpo == NULL)
        return 0;

    sha256_init(&ctx);

    padded = 0;
    while ((numRead = fread(inbuf, 1, KEYLEN, fpi)) > 0) {
        if (numRead < KEYLEN) {
            // requires padding to a multiple of 8 bytes
            memset(inbuf+numRead, KEYLEN - numRead, KEYLEN - numRead);
            padded = 1;
        }
        // encrypt-then-hash
        xor_encrypt(inbuf, outbuf, KEYLEN, keybuf);
        arrToString(outbuf, temp_buf, KEYLEN);
        sha256_update(&ctx, temp_buf, strlen(temp_buf));
        fwrite(outbuf, 1, KEYLEN, fpo);
    }

    if (!padded) {
        memset(inbuf, KEYLEN, KEYLEN);
        xor_encrypt(inbuf, outbuf, KEYLEN, keybuf);
        arrToString(outbuf, temp_buf, KEYLEN);
        sha256_update(&ctx, temp_buf, strlen(temp_buf));
        fwrite(outbuf, 1, KEYLEN, fpo);
    }

    sha256_final(&ctx, hash);

    // set internal hash of key with hash of data ciphertext
    KeyChain_updateKey(oKeyChain, pcKeyID, hash);

    fclose(fpi);
    fclose(fpo);
    return 1;
}

/*--------------------------------------------------------------------*/

int Decrypt(const char *inputFileName, 
            const char *outputFileName,
            KeyChain_T oKeyChain,
            char *pcKeyID)
{
    int c;
    int numRead;
    int pad;
    int padded;
    FILE *fpi, *fpo;
    unsigned char keybuf[KEYLEN];
    unsigned char inbuf[KEYLEN];
    unsigned char outbuf[KEYLEN];
    unsigned char hash[HASHLEN];
    char temp_buf[BUFLEN];
    SHA256_CTX ctx;

    fpi = fopen(inputFileName, "r");
    if (fpi == NULL)
        return 0;

    if (!KeyChain_contains(oKeyChain, pcKeyID)) {
        printf("\n---invalid key\n");   // for demo
        return 0;
    }

    // verify hash of the data
    sha256_init(&ctx);
    while ((numRead = fread(inbuf, 1, KEYLEN, fpi)) > 0) {
        arrToString(inbuf, temp_buf, KEYLEN);
        sha256_update(&ctx, temp_buf, strlen(temp_buf));
    }
    sha256_final(&ctx, hash);
    if (memcmp(KeyChain_getInterHash(oKeyChain, pcKeyID), hash, HASHLEN) != 0) {
        printf("\n---data hash mismatch!\n");   // for demo
        fclose(fpi);
        return 0;
    }
    fclose(fpi);

    // verify integrity of key node
    if (!KeyChain_verifyKey(oKeyChain, pcKeyID)) {
        printf("\n---key hash mismatch!\n");   // for demo
        return 0;
    }

    KeyChain_getKey(oKeyChain, pcKeyID, keybuf);

    fpi = fopen(inputFileName, "r");
    if (fpi == NULL)
        return 0;
    fpo = fopen(outputFileName, "w");
    if (fpo == NULL)
        return 0;

    padded = 0;
    while ((numRead = fread(inbuf, 1, KEYLEN, fpi)) > 0) {
        // if previous block had padding
        if (padded) {
            fwrite(outbuf + KEYLEN - pad, 1, pad, fpo);
            padded = 0;
        }
        if (numRead < KEYLEN) {
            return 0;
        }

        xor_decrypt(inbuf, outbuf, KEYLEN, keybuf);
        pad = outbuf[KEYLEN-1];
        padded = isPadded(pad, outbuf);
        if (padded) {
            fwrite(outbuf, 1, KEYLEN - pad, fpo);
        } else {
            fwrite(outbuf, 1, KEYLEN, fpo);
        }
    }

    fclose(fpi);
    fclose(fpo);
    return 1;
}
