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

/* Return the encrypted key of piKeyID in oKeyChain.
   *** Modify to return the plaintext key ***
   Return NULL if not found. */

char *KeyChain_getKey(KeyChain_T oKeyChain, int *piKeyID);

/*--------------------------------------------------------------------*/

/* Add the encrypted key pcEncKey as a child of the parent key with ID 
   piParentKeyID in oKeyChain. Return 1 on success, 0 on failure. 
   *** Modify to add the plaintext key ***
   */

int KeyChain_addKey(KeyChain_T oKeyChain,
                    int *piParentKeyID,
                    char *pcEncKey);

/*--------------------------------------------------------------------*/

/* Remove the key with key ID piKeyID from oKeyChain. Return the
   encrypted key of the removed key node, or NULL if not found. 
   *** Modify to return the plaintext key ***
   */

char *KeyChain_removeKey(KeyChain_T oKeyChain, int *piKeyID);

/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/

/* this should probably be a TSM function */

/* verify whole keychain? may not be necessary. */

int KeyChain_verify(KeyChain_T oKeyChain);


#endif
