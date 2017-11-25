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

/* Return the 32 bit encrypted key of pcKeyID in oKeyChain.
   *** Modify to return the plaintext key ***
   Return 0 if not found. */

unsigned int KeyChain_getKey(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/

/* Add the key pcKeyID with the encrypted key uiEncKey as a child of 
   the parent key pcParentKeyID in oKeyChain. Return 1 on success, 
   0 on failure. 
   *** Modify to add the plaintext key ***
   */

int KeyChain_addKey(KeyChain_T oKeyChain, 
                    char *pcParentKeyID,
                    char *pcKeyID, 
                    unsigned int uiEncKey);

/*--------------------------------------------------------------------*/

/* Remove the key with key ID pcKeyID from oKeyChain. Return 1 if
   successful, 0 otherwise.
   */

int KeyChain_removeKey(KeyChain_T oKeyChain, char *pcKeyID);

/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/

/* this should probably be a TSM function */

/* verify whole keychain? may not be necessary. */

int KeyChain_verify(KeyChain_T oKeyChain);


#endif
