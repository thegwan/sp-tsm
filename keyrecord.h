/*--------------------------------------------------------------------*/
/* keyrecord.h                                                        */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#ifndef KEYRECORD_INCLUDED
#define KEYRECORD_INCLUDED

/* A KeyRecord_T object is a structure containing the key identifaction
   number (KIN), parent KIN, an encryption algorithm identifier,
   encrypted key, and cryptographic hash of the entire key record. */

typedef struct KeyRecord *KeyRecord_T;

/*--------------------------------------------------------------------*/

/* Return a new KeyRecord object, or NULL
   if insufficient memory is available. */

KeyRecord_T KeyRecord_new(void);

/*--------------------------------------------------------------------*/

/* Free all memory occupied by oKeyRecord. */

void KeyRecord_free(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Return the KIN of oKeyRecord. */

int KeyRecord_getKIN(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Set the KIN of oKeyRecord. */

void KeyRecord_setKIN(KeyRecord_T oKeyRecord, int iKin);

/*--------------------------------------------------------------------*/

/* Return the encryption algorithm identifier of oKeyRecord. */

int KeyRecord_getEncAlgo(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Set the encryption algorithm identifier.*/

void KeyRecord_setEncAlgo(KeyRecord_T oKeyRecord, int iEncAlgo);

/*--------------------------------------------------------------------*/

/* Return the encrypted key of oKeyRecord. */

char *KeyRecord_getEncKey(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Encrypt the key using the parent key. Set the encrypted key of 
   oKeyRecord. Return 1 if success, 0 if failure. */

/* decide if this function should do the encrypting, or pass the
   already encrypted key as argument after TSM function does it.
    For now pass in */
/* maybe should be const char* ? */
int KeyRecord_setEncKey(KeyRecord_T oKeyRecord, char *pcEncKey);

/*--------------------------------------------------------------------*/

/* Return the keyed hash of oKeyRecord. */

char *KeyRecord_getHash(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Compute a keyed cryptographic hash of the entire key record using
   the parent key. Set the keyed hash of oKeyRecord. 
   Return 1 if success, 0 if failure.

   For now just set the hash to pcHash. */

int KeyRecord_setHash(KeyRecord_T oKeyRecord, char *pcHash);

/*--------------------------------------------------------------------*/

/* Return the parent keyrecord of oKeyRecord. */

KeyRecord_T KeyRecord_getParent(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Return the (first) child of oKeyRecord. */

KeyRecord_T KeyRecord_getChild(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Return the next keyrecord at the same level as oKeyRecord. */

KeyRecord_T KeyRecord_getNext(KeyRecord_T oKeyRecord);

/*--------------------------------------------------------------------*/

/* Set the parent of oKeyRecord to oParentKey. Return 1 if success,
   0 if failure. */

int KeyRecord_setParent(KeyRecord_T oKeyRecord, KeyRecord_T oParentKey);

/*--------------------------------------------------------------------*/

/* Set the first child of oKeyRecord to oChildKey. Return 1 if success,
   0 if failure. */

int KeyRecord_setChild(KeyRecord_T oKeyRecord, KeyRecord_T oChildKey);

/*--------------------------------------------------------------------*/

/* Set the next of oKeyRecord to oNextKey. Return 1 if success,
   0 if failure. */

int KeyRecord_setNext(KeyRecord_T oKeyRecord, KeyRecord_T oNextKey);

/*--------------------------------------------------------------------*/

/* Set the next 

/* this should probably be a TSM function */

/* If the cryptographic hash over the key record matches the value
   of the hash stored in the record, return 1 (TRUE). Otherwise, leave
   oKeyRecord unchanged and return 0 (FALSE). */

int KeyRecord_verify(KeyRecord_T oKeyRecord);


#endif
