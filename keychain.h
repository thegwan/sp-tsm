/*--------------------------------------------------------------------*/
/* keychain.h                                                        */
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

/* Return the key record oKeyRecord in oKeyChain. Will probably
   need more parameters to search. Return NULL if not found. */

KeyRecord_T KeyChain_getKey(KeyChain_T oKeyChain, KeyRecord_T oKey);

/*--------------------------------------------------------------------*/

/* Add the key record oChildKey as a child of the parent key
   record oParentKey in oKeyChain. Return 1 on success, 0 on
   failure. */

int KeyChain_addKey(KeyChain_T oKeyChain,
                    KeyRecord_T oParentKey,
                    KeyRecord_T oChildKey);

/*--------------------------------------------------------------------*/

/* Rempve the key record oKey from oKeyChain. Will probably need
   more parameters to search. Return removed item, or NULL if not 
   found. */

KeyRecord_T KeyChain_removeKey(KeyChain_T oKeyChain, KeyRecord_T oKey);

/*--------------------------------------------------------------------*/

/* Set the parent KIN of oKeyChain.*/

void KeyChain_setParentKIN(KeyChain_T oKeyChain, int iParentKin);

/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/

/* this should probably be a TSM function */

/* verify whole keychain? may not be necessary. */

int KeyChain_verify(KeyChain_T oKeyChain);


#endif
