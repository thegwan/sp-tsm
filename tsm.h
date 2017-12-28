/*--------------------------------------------------------------------*/
/* tsm.h                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#ifndef TSM_INCLUDED
#define TSM_INCLUDED

#include "keychain.h"

/*--------------------------------------------------------------------*/

/* Generate a random 64 bit key and add it to the keychain under 
   the parent key. */

int AddKeyToChain(KeyChain_T oKeyChain, 
                  char *pcParentKeyID, 
                  char *pcKeyID,
                  int iType);

/*--------------------------------------------------------------------*/

/* Delete pcKeyID from the keychain. */

int DeleteKeyFromChain(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Encrypt inputFileName into outputFileName using pcKeyID.
   Return 1 on success, 0 on failure. */

int Encrypt(const char *inputFileName, 
            const char *outputFileName,
            KeyChain_T oKeyChain, 
            char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Decrypt inputFileName into outputFileName using pcKeyID.
   Return 1 on success, 0 on failure. */

int Decrypt(const char *inputFileName, 
            const char *outputFileName,
            KeyChain_T oKeyChain, 
            char *pcKeyID);

/*--------------------------------------------------------------------*/

#endif
