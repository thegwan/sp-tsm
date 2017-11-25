/*--------------------------------------------------------------------*/
/* keycrypto.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keycrypto.h"
#include <assert.h>
#include <stdlib.h> 
#include <string.h>

#define KEYLEN 4    // 32 bit keys


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


/*--------------------------------------------------------------------*/