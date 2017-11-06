/*--------------------------------------------------------------------*/
/* keychain.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
/* #include "aes.c"   https://github.com/kokke/tiny-AES-c */
#include <stdlib.h>  /* malloc, free, inlining code possible? */
#include <string.h>  /* really only need strcpy and strlen, could 
                        implement myself */
#include <assert.h>  /* asserts, inlining code? necessary?  */


/*--------------------------------------------------------------------*/

/* Each key is stored in a KeyNode, which are linked to form a key
   chain. */

struct KeyNode
{
    /* Key ID */
    int *piKeyID;

    /* 128 bit encrypted key, encrypted by the parent key */
    char *pcEncKey;

    /* 128 bit keyed hash of the key record */
    char *pcHash;

    /*-------------------------------------*/
    /* Not necessary, since parent KeyID is part of own KeyID
    /* pointer to parent node */
    /* struct KeyNode *psParent; */
    /*-------------------------------------*/

    /* pointer to children (first child) */
    struct KeyNode *psChild;

    /* pointer to next node at same level */
    struct KeyNode *psNext;

    /* encryption algorithm id */
    int iEncAlgo;

    /* depth of node */
    int depth;

    /* number of children */
    int numChildren;
};


/*--------------------------------------------------------------------*/

/* A KeyChain structure is an n-ary tree that points to the root
   KeyNode. */

struct KeyChain
{
    /* The number of keys in the key chain */
    int iNumKeys;

    /* The address of the root node */
    struct KeyNode *psRoot;
}

/*--------------------------------------------------------------------*/

KeyChain_T KeyChain_new(void)
{
    KeyChain_T oKeyChain;

    oKeyChain = (KeyChain_T)malloc(sizeof(struct KeyChain));
    if (oKeyChain == NULL)
        return NULL;

    iNumKeys = 0;
    oKeyChain->psRoot = NULL;

    return oKeyChain;
}

/*--------------------------------------------------------------------*/

/* Recursive helper function to free the nodes */
static void freeNodes(struct KeyNode *psNode)
{
    if (psNode) {
        freeNodes(psNode->psNext);
        freeNodes(psNode->psChild);

        /* free key data */
        free(psNode->piKeyID);
        free(psNode->pcEncKey);
        free(psNode->pcHash);

        // psNode->psNext = NULL;
        // psNode->psChild = NULL;
        free(psNode);
    }
}


/*--------------------------------------------------------------------*/

void KeyChain_free(KeyChain_T oKeyChain)
{
    assert(oKeyChain != NULL);

    freeNodes(oKeyChain->psRoot);
    free(oKeyChain);
}

/*--------------------------------------------------------------------*/

int KeyChain_getNumKeys(KeyChain_T oKeyChain)
{
    return oKeyChain->iNumKeys;
}

/*--------------------------------------------------------------------*/

/* Helper function to get keynode of piKeyID */
static struct KeyNode *getKey(struct KeyNode *psNode, int *piKeyID)
{
    int nodeDepth = psNode->depth;
    int targetDepth;
    
}

/*--------------------------------------------------------------------*/

char *KeyChain_getKey(KeyChain_T oKeyChain, int *piKeyID)
{
    struct KeyNode *psCurrNode;

    assert(oKeyChain != NULL);
    assert(piKeyID != NULL);

    psCurrNode = oKeyChain->psRoot;

}

/*--------------------------------------------------------------------*/

int KeyChain_addKey(KeyChain_T oKeyChain, int *piParentKeyID, char *pcEncKey)
{

}

/*--------------------------------------------------------------------*/

char *KeyChain_removeKey(KeyChain_T oKeyChain, int *piKeyID)
{

}

/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/