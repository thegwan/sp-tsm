/*--------------------------------------------------------------------*/
/* keychain.h                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#ifndef KEYCHAIN_INCLUDED
#define KEYCHAIN_INCLUDED

/* A KeyChain_T object is a tree-like structure containing the all
   the key records, encrypted by its parent key. */

typedef struct KeyChain *KeyChain_T;

/*--------------------------------------------------------------------*/

/* Return a new KeyChain object, or NULL
   if insufficient memory is available. */

KeyChain_T KeyChain_new(void);

/*--------------------------------------------------------------------*/

/* Free all memory occupied by oKeyChain. */

void KeyChain_free(KeyChain_T oKeyChain);

/*--------------------------------------------------------------------*/

/* Return the number of keys in oKeyChain. */

int KeyChain_getNumKeys(KeyChain_T oKeyChain);

/*--------------------------------------------------------------------*/

/* Return 1 if the oKeyChain contains a key with key ID pcKeyID, 0
   otherwise. */

int KeyChain_contains(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Decrypt the 32 bit plaintext key of pcKeyID in oKeyChain and 
   place the result in pucOutput. Return a pointer to pucOutput.
   Return NULL if key is not in keychain. */

unsigned char *KeyChain_getKey(KeyChain_T oKeyChain, char *pcKeyID, unsigned char *pucOutput);

/*--------------------------------------------------------------------*/

/* Return the 32 bit encrypted key of pcKeyID in oKeyChain.
   Return NULL if key is not in keychain. */

unsigned char *KeyChain_getEncryptedKey(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Return the 32 bit keyed hash of pcKeyID in oKeyChain.
   Return NULL if key is not in keychain. */

unsigned char *KeyChain_getHash(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Add the key pcKeyID with the key pucKey as a child of 
   the parent key pcParentKeyID in oKeyChain. Return 1 on success, 
   0 on failure. */

int KeyChain_addKey(KeyChain_T oKeyChain, 
                    char *pcParentKeyID,
                    char *pcKeyID, 
                    unsigned char *pucKey);

/*--------------------------------------------------------------------*/

/* Remove the key with key ID pcKeyID from oKeyChain. Return 1 if
   successful, 0 otherwise. */

int KeyChain_removeKey(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Verify the integrity of the key pcKeyID in oKeyChain. Return 1 if
   verified, 0 otherwise. */

int KeyChain_verifyKey(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/



#endif
