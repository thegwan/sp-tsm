/*--------------------------------------------------------------------*/
/* tsm.h                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#ifndef TSM_INCLUDED
#define TSM_INCLUDED

#include "keychain.h"


/*--------------------------------------------------------------------*/

/* Encrypt input into output, return 1 on success, 0 on failure */

int Encrypt(const char *inputFileName, const char *outputFileName,
             KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Decrypt input into output, return 1 on success, 0 on failure */

int Decrypt(const char *inputFileName, const char *outputFileName,
            KeyChain_T oKeyChain, char *pcKeyID);


#endif
