/*--------------------------------------------------------------------*/
/* tsm.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "tsm.h"
#include "keychain.h"
#include "keycrypto.h"
#include <assert.h>
#include <stdlib.h> 
#include <string.h>
#include <stdio.h>

#define KEYLEN 8

/* For debugging */
static void phex(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < KEYLEN; i++)
        printf("%.2x", str[i]);
    printf("\n");
}

static void pch(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < KEYLEN; i++)
        printf("%c", str[i]);
    printf("\n");
}

/*--------------------------------------------------------------------*/

int AddKeyToChain(KeyChain_T oKeyChain, char *pcParentKeyID, char *pcKeyID)
{
    // generate random key
    srand(time(NULL));
    unsigned char key[] = {rand() & 0xff,
                           rand() & 0xff,
                           rand() & 0xff,
                           rand() & 0xff,
                           rand() & 0xff,
                           rand() & 0xff,
                           rand() & 0xff,
                           rand() & 0xff};
    // phex(key);
    return KeyChain_addKey(oKeyChain, pcParentKeyID, pcKeyID, key);
}

/*--------------------------------------------------------------------*/

int DeleteKeyFromChain(KeyChain_T oKeyChain, char *pcKeyID)
{
    return KeyChain_removeKey(oKeyChain, pcKeyID);
}

/*--------------------------------------------------------------------*/

int Encrypt(const char *inputFileName, const char *outputFileName,
             KeyChain_T oKeyChain, char *pcKeyID)
{
    int c;
    int numRead;
    int padded;
    FILE *fpi, *fpo;
    unsigned char keybuf[KEYLEN];
    unsigned char inbuf[KEYLEN];
    unsigned char outbuf[KEYLEN];


    // retrieve key
    KeyChain_getKey(oKeyChain, pcKeyID, keybuf);
    // phex(keybuf);

    // verify integrity
    if (!KeyChain_verifyKey(oKeyChain, pcKeyID))
        return 0;

    fpi = fopen(inputFileName, "r");
    if (fpi == NULL)
        return 0;
    fpo = fopen(outputFileName, "w");
    if (fpo == NULL)
        return 0;

    padded = 0;
    while ((numRead = fread(inbuf, 1, KEYLEN, fpi)) > 0) {
        // printf("enc numread: %d\n", numRead);
        // pch(inbuf);
        if (numRead < KEYLEN) {
            memset(inbuf+numRead, KEYLEN - numRead, KEYLEN - numRead);
            padded = 1;
        }
        xor_encrypt(inbuf, outbuf, KEYLEN, keybuf);
        // printf("outbuf: %s\n", outbuf);
        fwrite(outbuf, 1, KEYLEN, fpo);
    }

    if (!padded) {
        memset(inbuf, KEYLEN, KEYLEN);
        xor_encrypt(inbuf, outbuf, KEYLEN, keybuf);
        fwrite(outbuf, 1, KEYLEN, fpo);
    }

    fclose(fpi);
    fclose(fpo);
    return 1;

}

/*--------------------------------------------------------------------*/

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

int Decrypt(const char *inputFileName, const char *outputFileName,
             KeyChain_T oKeyChain, char *pcKeyID)
{
    int c;
    int numRead;
    int pad;
    int padded;
    FILE *fpi, *fpo;
    unsigned char keybuf[KEYLEN];
    unsigned char inbuf[KEYLEN];
    unsigned char outbuf[KEYLEN];


    // retrieve key
    KeyChain_getKey(oKeyChain, pcKeyID, keybuf);
    // phex(keybuf);

    // verify integrity
    if (!KeyChain_verifyKey(oKeyChain, pcKeyID))
        return 0;

    fpi = fopen(inputFileName, "r");
    if (fpi == NULL)
        return 0;
    fpo = fopen(outputFileName, "w");
    if (fpo == NULL)
        return 0;

    padded = 0;
    while ((numRead = fread(inbuf, 1, KEYLEN, fpi)) > 0) {
        // if prev block had padding
        if (padded) {
            // printf("filling in %d\n", pad);
            fwrite(outbuf + KEYLEN - pad, 1, pad, fpo);
            padded = 0;
        }
        // printf("dec numread: %d\n", numRead);
        // pch(inbuf);
        if (numRead < KEYLEN) {
            return 0;
        }

        xor_decrypt(inbuf, outbuf, KEYLEN, keybuf);
        pad = outbuf[KEYLEN-1];
        padded = isPadded(pad, outbuf);
        if (padded) {
            //printf("%d\n", pad);
            fwrite(outbuf, 1, KEYLEN - pad, fpo);
        } else {
            fwrite(outbuf, 1, KEYLEN, fpo);
        }
    }

    fclose(fpi);
    fclose(fpo);
    return 1;
}



