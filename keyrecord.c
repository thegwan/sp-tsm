/*--------------------------------------------------------------------*/
/* keyrecord.c                                                        */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keyrecord.h"
/* #include "aes.c"   https://github.com/kokke/tiny-AES-c */
#include <stdlib.h>  /* malloc, free, inlining code possible? */
#include <string.h>  /* really only need strcpy and strlen, could 
                        implement myself */
#include <assert.h>  /* asserts, inlining code? necessary?  */

/*--------------------------------------------------------------------*/

/* A KeyRecord object consists the key identifaction number (KIN), 
   parent KIN, an encryption algorithm identifier, encrypted key, and cryptographic hash of the entire key record. */

struct KeyRecord
{
    /* The key identification number. */
    int iKin;

    /* The encryption algorithm identification number. */
    int iEncAlgo;

    /* The 128 bit encrypted key.  */
    char *pcEncKey;

    /* The 128 bit keyed hash of the key record. 
       last block of CBC mode? What is the key used for this, does
       it require another hardware reg? */
    char *pcHash;

    int depth;
    int numChildren;

    /* pointer to parent */
    struct KeyRecord *psParent;

    /* pointer to children of this node */
    struct KeyRecord *psChild;

    /* pointer to next node at same level. */
    struct KeyRecord *psNext;
};

/*--------------------------------------------------------------------*/

KeyRecord_T KeyRecord_new(void)
{
    /* number of bytes in encrypted key and hash */
    enum {NUM_ENCRYPT_BITS = 128, NUM_HASH_BITS = 128};  

    KeyRecord_T oKeyRecord;

    oKeyRecord = (KeyRecord_T)malloc(sizeof(struct KeyRecord));
    if (oKeyRecord == NULL)
        return NULL;

    oKeyRecord->iKin = 0;
    oKeyRecord->iParentKin = 0;
    oKeyRecord->iEncAlgo = 0;

    oKeyRecord->pcEncKey = (char*)calloc(NUM_ENCRYPT_BITS, sizeof(char));
    if (oKeyRecord->pcEncKey == NULL)
    {
        free(oKeyRecord);
        return NULL;
    }

    oKeyRecord->pcHash = (char*)calloc(NUM_HASH_BITS, sizeof(char));
    if (oKeyRecord->pcHash == NULL)
    {
        free(oKeyRecord);
        return NULL;
    }

    return oKeyRecord;

}

/*--------------------------------------------------------------------*/

void KeyRecord_free(KeyRecord_T oKeyRecord)
{
    assert(oKeyRecord != NULL);
    free(oKeyRecord->pcEncKey);
    free(oKeyRecord->pcHash);
    free(oKeyRecord->psParent);
    free(oKeyRecord->psChild);
    free(oKeyRecord->psNext);
    free(oKeyRecord);
}

/*--------------------------------------------------------------------*/

int KeyRecord_getKIN(KeyRecord_T oKeyRecord)
{
    assert(oKeyRecord != NULL);
    return oKeyRecord->iKin;
}

/*--------------------------------------------------------------------*/

void KeyRecord_setKIN(KeyRecord_T oKeyRecord, int iKin)
{
    assert(oKeyRecord != NULL);
    oKeyRecord->iKin = iKin;
}

/*--------------------------------------------------------------------*/

int KeyRecord_getEncAlgo(KeyRecord_T oKeyRecord)
{
    assert(oKeyRecord != NULL);
    return oKeyRecord->iEncAlgo;
}

/*--------------------------------------------------------------------*/

/* Set the encryption algorithm identifier.*/

void KeyRecord_setEncAlgo(KeyRecord_T oKeyRecord, int iEncAlgo)
{
    assert(oKeyRecord != NULL);
    oKeyRecord->iEncAlgo = iEncAlgo;
}

/*--------------------------------------------------------------------*/

/* Return the encrypted key of oKeyRecord. */

char *KeyRecord_getEncKey(KeyRecord_T oKeyRecord)
{
    assert(oKeyRecord != NULL);
    /* assert(oKeyRecord->pcEncKey != NULL); */
    return oKeyRecord->pcEncKey;
}

/*--------------------------------------------------------------------*/

int KeyRecord_setEncKey(KeyRecord_T oKeyRecord, char *pcEncKey)
{
    char *pcEncKeyCopy; /* defensive copy */

    assert(oKeyRecord != NULL);
    assert(pcEncKey != NULL);

    pcEncKeyCopy = (char*)malloc(strlen(pcEncKey) + 1);
    if (pcEncKeyCopy == NULL)
        return 0;
    strcpy(pcEncKeyCopy, pcEncKey);

    oKeyRecord->pcEncKey = pcEncKeyCopy;
    return 1;
}

/*--------------------------------------------------------------------*/

char *KeyRecord_getHash(KeyRecord_T oKeyRecord)
{
    assert(oKeyRecord != NULL);
    return oKeyRecord->pcHash;
}

/*--------------------------------------------------------------------*/

int KeyRecord_setHash(KeyRecord_T oKeyRecord, char *pcHash)
{
    char *pcHashCopy; /* defensive copy */

    assert(oKeyRecord != NULL);
    assert(pcHash != NULL);

    pcHashCopy = (char*)malloc(strlen(pcHash) + 1);
    if (pcHashCopy == NULL)
        return 0;
    strcpy(pcHashCopy, pcHash);

    oKeyRecord->pcHash = pcHashCopy;
    return 1;
}

/*--------------------------------------------------------------------*/

