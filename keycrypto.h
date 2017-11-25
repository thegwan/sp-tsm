/*--------------------------------------------------------------------*/
/* keycrypto.h                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#ifndef KEY_CRYPTO_INCLUDED
#define KEY_CRYPTO_INCLUDED


/*--------------------------------------------------------------------*/

/* XOR Encrypt the uiLength input pucInput with 32 bit key pucKey */

void xor_encrypt(unsigned char *pucInput,
                 unsigned char *pucOutput,
                 unsigned int uiLength, 
                 unsigned char *pucKey);

/*--------------------------------------------------------------------*/

/* XOR Decrypt the uiLength input pucInput with 32 bit key pucKey */


void xor_decrypt(unsigned char *pucInput,
                 unsigned char *pucOutput,
                 unsigned int uiLength, 
                 unsigned char *pucKey);


#endif
