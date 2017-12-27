/*--------------------------------------------------------------------*/
/* tsm.h                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#ifndef TSM_INCLUDED
#define TSM_INCLUDED

#include "keychain.h"


/*--------------------------------------------------------------------*/

/* Generate a random 32 bit key and add it to the keychain under 
   the parent key id */

int AddKeyToChain(KeyChain_T oKeyChain, 
                char *pcParentKeyID, 
                char *pcKeyID,
                int iType);

/*--------------------------------------------------------------------*/

/* Delete pcKeyID from the keychain */

int DeleteKeyFromChain(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Encrypt input into output, return 1 on success, 0 on failure */

int Encrypt(const char *inputFileName, const char *outputFileName,
             KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Decrypt input into output, return 1 on success, 0 on failure */

int Decrypt(const char *inputFileName, const char *outputFileName,
            KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

#endif
