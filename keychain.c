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
    char *pcKeyID;

    /* 128 bit encrypted key, encrypted by the parent key */
    char *pcEncKey;

    /* 128 bit keyed hash of the key record */
    char *pcHash;

    /*-------------------------------------*/
    /* Not necessary, since parent KeyID is part of own KeyID
    /* pointer to parent node */
    /* struct KeyNode *psParent; */
    /*-------------------------------------*/

    /* depth of node */
    int iDepth;

    /* number of children */
    int iNumChildren;

    /* pointer to children (first child) */
    struct KeyNode *psChild;

    /* pointer to next node at same level */
    struct KeyNode *psNext;

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
};

/*--------------------------------------------------------------------*/

KeyChain_T KeyChain_new(void)
{
    KeyChain_T oKeyChain;

    oKeyChain = (KeyChain_T)malloc(sizeof(struct KeyChain));
    if (oKeyChain == NULL)
        return NULL;

    oKeyChain->iNumKeys = 0;
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
        free(psNode->pcKeyID);
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

/* Helper function to get keynode of pcKeyID */
static struct KeyNode *getKey(struct KeyNode *psNode, char *pcKeyID)
{
    int currDepth;

    if (psNode == NULL)
        return NULL;   // may need to make function return value a void*

    currDepth = psNode->iDepth;
    while (psNode != NULL) {
        if ((psNode->pcKeyID)[currDepth] == pcKeyID[currDepth]) {
            if (strlen(pcKeyID) == currDepth+1)
                return psNode;
            else
                return getKey(psNode->psChild, pcKeyID);
        }
        psNode = psNode->psNext;
    }
    return NULL;
}

/*--------------------------------------------------------------------*/

int KeyChain_contains(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKey(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return 1;
    return 0;

}

/*--------------------------------------------------------------------*/

char *KeyChain_getKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKey(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return psResultNode->pcEncKey;
    return NULL;

}

/*--------------------------------------------------------------------*/

int KeyChain_addKey(KeyChain_T oKeyChain, 
                    char *pcParentKeyID,
                    char *pcKeyID, 
                    char *pcEncKey)
{
    struct KeyNode *psNewNode;
    struct KeyNode *psParentNode;
    char *pcKeyIDCpy;
    char *pcEncKeyCpy;
    char *pcHash;

    assert(oKeyChain != NULL);
    assert(pcParentKeyID != NULL);
    assert(pcKeyID != NULL);
    assert(pcEncKey != NULL);

    // find parent node
    psParentNode = getKey(oKeyChain->psRoot, pcParentKeyID);
    if (psParentNode == NULL || psParentNode->iNumChildren >= 10)
        return 0;

    // make sure key is not already in the chain
    if (KeyChain_contains(oKeyChain, pcKeyID))
        return 0;

    psNewNode = (struct KeyNode *)malloc(sizeof(struct KeyNode));
    if (psNewNode == NULL)
        return 0;

    // make defensive copy of key id
    pcKeyIDCpy = (char *)malloc(strlen(pcKeyID) + 1);
    if (pcKeyIDCpy == NULL)
        return 0;
    strcpy(pcKeyIDCpy, pcKeyID);

    // make defensive copy of encrypted key
    pcEncKeyCpy = (char *)malloc(strlen(pcEncKey) + 1);
    if (pcEncKeyCpy == NULL)
        return 0;
    strcpy(pcEncKeyCpy, pcEncKey);

    pcHash = "0123456789abcdef";  // dummy hash

    psNewNode->pcKeyID = pcKeyIDCpy;
    psNewNode->pcEncKey = pcEncKeyCpy;
    psNewNode->pcHash = pcHash;
    
    psNewNode->iDepth = strlen(pcParentKeyID);
    psNewNode->iNumChildren = 0;

    psNewNode->psNext = psParentNode->psChild;
    psNewNode->psChild = NULL;
    psParentNode->psChild = psNewNode;

    psParentNode->iNumChildren++;
    oKeyChain->iNumKeys++;

    return 1;
}

/*--------------------------------------------------------------------*/

char *KeyChain_removeKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    return NULL;
}

/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/