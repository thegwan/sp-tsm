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

/*--------------------------------------------------------------------*/

/* Convert int i to string and place the result in pcBuf */

void intToString(int i, char *pcBuf);

/*--------------------------------------------------------------------*/

/* Convert 32 bit unsigned char array pucArr to string and place the 
   result in pcBuf */

void arrToString(unsigned char *pucArr, char *pcBuf);


#endif
