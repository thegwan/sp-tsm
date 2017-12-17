/*--------------------------------------------------------------------*/
/* keycrypto.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keycrypto.h"
#include <assert.h>
#include <stdlib.h> 
#include <string.h>
#include <stdio.h>

#define KEYLEN 8                                   // 64 bit keys
#define INTBUFLEN (sizeof(int) * 8 + 1)            
#define ARRBUFLEN (sizeof(unsigned char) * 16 + 1)


/*--------------------------------------------------------------------*/

void xor_encrypt(unsigned char *pucInput,
                 unsigned char *pucOutput,
                 unsigned int uiLength, 
                 unsigned char *pucKey)

{
    unsigned int i;

    assert(pucInput != NULL);
    assert(pucOutput != NULL);
    assert(pucKey != NULL);
    assert(uiLength % KEYLEN == 0);

    memcpy(pucOutput, pucInput, uiLength);
    for (i = 0; i < uiLength; i++) {
        pucOutput[i] ^= pucKey[i % KEYLEN];
    }
}

/*--------------------------------------------------------------------*/

void xor_decrypt(unsigned char *pucInput,
                 unsigned char *pucOutput,
                 unsigned int uiLength, 
                 unsigned char *pucKey)

{
    xor_encrypt(pucInput, pucOutput, uiLength, pucKey);
}


/*--------------------------------------------------------------------*/

void intToString(int i, char *pcBuf)
{
    assert(pcBuf != NULL);
    snprintf(pcBuf, INTBUFLEN, "%d", i);
}

/*--------------------------------------------------------------------*/


void arrToString(unsigned char *pucArr, char *pcBuf)
{
    int i;

    assert(pucArr != NULL);
    assert(pcBuf != NULL);

    for (i = 0; i < KEYLEN; i++) {
        sprintf(pcBuf + i*2, "%.2x", pucArr[i]);
    }
    pcBuf[ARRBUFLEN-1] = '\0';
}