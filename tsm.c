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

/* For debugging */
static void phex(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < 4; i++)
        printf("%.2x", str[i]);
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
                           rand() & 0xff};
    // phex(key);
    return KeyChain_addKey(oKeyChain, pcParentKeyID, pcKeyID, key);
}

/*--------------------------------------------------------------------*/

int Encrypt(const char *inputFileName, const char *outputFileName,
             KeyChain_T oKeyChain, char *pcKeyID)
{
    int c;
    int numRead;
    FILE *fpi, *fpo;
    unsigned char keybuf[4];
    unsigned char inbuf[4];
    unsigned char outbuf[4];


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

    while ((numRead = fread(inbuf, 1, 4, fpi)) > 0) {
        // printf("%d\n", numRead);
        // printf("inbuf: %s\n", inbuf);
        if (numRead == 3) {
            inbuf[3] = 0;
        }
        else if (numRead == 2) {
            inbuf[3] = 0;
            inbuf[2] = 0;
        }
        else if (numRead == 1) {
            inbuf[3] = 0;
            inbuf[2] = 0;
            inbuf[1] = 0;
        }
        xor_encrypt(inbuf, outbuf, 4, keybuf);
        // printf("outbuf: %s\n", outbuf);
        fwrite(outbuf, 1, 4, fpo);
    }

    fclose(fpi);
    fclose(fpo);
    return 1;

}

/*--------------------------------------------------------------------*/

int Decrypt(const char *inputFileName, const char *outputFileName,
             KeyChain_T oKeyChain, char *pcKeyID)
{
    int c;
    int numRead;
    FILE *fpi, *fpo;
    unsigned char keybuf[4];
    unsigned char inbuf[4];
    unsigned char outbuf[4];


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

    while ((numRead = fread(inbuf, 1, 4, fpi)) > 0) {
        // printf("%d\n", numRead);
        // printf("inbuf: %s\n", inbuf);
        if (numRead == 3) {
            inbuf[3] = 0;
        }
        else if (numRead == 2) {
            inbuf[3] = 0;
            inbuf[2] = 0;
        }
        else if (numRead == 1) {
            inbuf[3] = 0;
            inbuf[2] = 0;
            inbuf[1] = 0;
        }
        xor_decrypt(inbuf, outbuf, 4, keybuf);
        // printf("outbuf: %s\n", outbuf);
        fwrite(outbuf, 1, 4, fpo);
    }

    fclose(fpi);
    fclose(fpo);
    return 1;
}



