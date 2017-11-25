/*--------------------------------------------------------------------*/
/* keychain.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include "keycrypto.h"
/* #include "aes.c"   https://github.com/kokke/tiny-AES-c */
#include <stdlib.h>  /* malloc, free, inlining code possible? */
#include <string.h>  /* really only need strcpy and strlen, could 
                        implement myself */
#include <assert.h>  /* asserts, inlining code? necessary?  */
#include <stdio.h>

// #define ROOT_KEY_ID "0"

/*--------------------------------------------------------------------*/

/* Key metadata */

struct MetaData
{
    int iType;

    char *pcPolicy;
    char *pcCertificate;
    char *pcPublicKey;
    char *pcMisc;
};

/* Each key is stored in a KeyNode, which are linked to form a key
   chain. */

struct KeyNode
{
    /* Key ID */
    char *pcKeyID;

    /* 32 bit encrypted key, encrypted by the parent key */
    unsigned char *pucEncKey;

    /* 32 bit keyed hash of the key record */
    unsigned char *pucHash;

    /* depth of node */
    int iDepth;

    /* number of children */
    int iNumChildren;

    /* pointer to children (first child) */
    struct KeyNode *psChild;

    /* pointer to next node at same level */
    struct KeyNode *psNext;

    /* pointer to the node's parent */
    struct KeyNode *psParent;

    /* pointer to the key's metadata */
    // struct MetaData *psMetaData;

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
    struct KeyNode *psRoot;
    char *pcRootKeyID;
    unsigned char *pucRootEncKey;
    unsigned char *pucRootHash;
    unsigned char aucDefaultRootEncKey[] = {0x01, 0x23, 0x45, 0x67};
    unsigned char aucDummyHash[] = {0x00, 0x01, 0x02, 0x03};

    oKeyChain = (KeyChain_T)malloc(sizeof(struct KeyChain));
    if (oKeyChain == NULL)
        return NULL;

    // if this fails, free oKeyChain?
    psRoot = (struct KeyNode *)malloc(sizeof(struct KeyNode));
    if (psRoot == NULL)
        return NULL;

    pcRootKeyID = (char *)malloc(2 * sizeof(char));
    if (pcRootKeyID == NULL)
        return NULL;
    strcpy(pcRootKeyID, "0");

    pucRootEncKey = (unsigned char *)malloc(4 * sizeof(unsigned char));  // 32 bits
    if (pucRootEncKey == NULL)
        return NULL;
    memcpy(pucRootEncKey, aucDefaultRootEncKey, 4); // dummy UMK

    pucRootHash = (unsigned char *)malloc(4 * sizeof(unsigned char));  // 32 bits
    if (pucRootHash == NULL)
        return NULL;
    memcpy(pucRootHash, aucDummyHash, 4); // dummy root hash


    psRoot->pcKeyID = pcRootKeyID;
    psRoot->pucEncKey = pucRootEncKey;
    psRoot->pucHash = pucRootHash;
    psRoot->iDepth = 0;
    psRoot->iNumChildren = 0;
    psRoot->psChild = NULL;
    psRoot->psNext = NULL;
    psRoot->psParent = NULL;
    // psRoot->psMetaData = NULL;

    oKeyChain->iNumKeys = 0;
    oKeyChain->psRoot = psRoot;

    return oKeyChain;
}

/*--------------------------------------------------------------------*/

/* Recursive helper function to free the KeyNode psNode and all its
   children and siblings */
static void freeNodes(struct KeyNode *psNode)
{
    if (psNode) {
        freeNodes(psNode->psNext);
        freeNodes(psNode->psChild);

        /* free key data */
        free(psNode->pcKeyID);
        free(psNode->pucEncKey);
        free(psNode->pucHash);
        // free(psNode->psMetaData);

        free(psNode);
    }
}
///////////////////////////////////////////////////
static void phex(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < 4; i++)
        printf("%.2x", str[i]);
    printf("\n");
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
static struct KeyNode *getKeyNode(struct KeyNode *psNode, char *pcKeyID)
{
    int currDepth;

    while (psNode != NULL) {
        currDepth = psNode->iDepth;
        if ((psNode->pcKeyID)[currDepth] == pcKeyID[currDepth]) {
            if (strlen(pcKeyID) == currDepth+1)
                return psNode;
            else
                return getKeyNode(psNode->psChild, pcKeyID);
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

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return 1;
    return 0;

}

static unsigned char *getPlainKey(struct KeyNode *psNode)
{
    static unsigned char aucPlainKey[4];
    unsigned char *pucParentPlainKey;

    if (psNode->psParent == NULL)     // is root, return UMK
        return psNode->pucEncKey;
    pucParentPlainKey = getPlainKey(psNode->psParent);
    printf("$$$");
    phex(pucParentPlainKey);
    // printf("child");
    // phex(psNode->pucEncKey);
    xor_decrypt(psNode->pucEncKey, aucPlainKey, 4, pucParentPlainKey);
    // printf("ret");
    // phex(aucPlainKey);
    return aucPlainKey;
}

/*--------------------------------------------------------------------*/

unsigned char *KeyChain_getKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return getPlainKey(psResultNode);
    return NULL;

}

/*--------------------------------------------------------------------*/

int KeyChain_addKey(KeyChain_T oKeyChain, 
                    char *pcParentKeyID,
                    char *pcKeyID, 
                    unsigned char *pucKey)
{
    struct KeyNode *psNewNode;
    struct KeyNode *psParentNode;
    struct KeyNode *psParentIter;
    char *pcKeyIDCpy;
    unsigned char *pucEncKey;
    unsigned char *pucHash;

    unsigned char aucDummyHash[] = {0x00, 0x01, 0x02, 0x03};  

    assert(oKeyChain != NULL);
    assert(pcParentKeyID != NULL);
    assert(pcKeyID != NULL);
    assert(pucKey != NULL);

    // find parent node
    psParentNode = getKeyNode(oKeyChain->psRoot, pcParentKeyID);
    if (psParentNode == NULL)
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

    pucEncKey = (unsigned char *)malloc(4 * sizeof(unsigned char));  // 32 bit
    if (pucEncKey == NULL)
        return 0;
    memset(pucEncKey, 0, 4);
    xor_encrypt(pucKey, pucEncKey, 4, getPlainKey(psParentNode));
    // printf("adding keyid %s with encrypted key: ", pcKeyIDCpy);
    // phex(pucEncKey);
    // printf("the plaintext key was: ");
    // phex(pucKey);
    // printf("----------------\n");

    pucHash = (unsigned char *)malloc(4 * sizeof(unsigned char));
    if (pucHash == NULL)
        return 0;
    memcpy(pucHash, aucDummyHash, 4); // dummy hash
    
    psNewNode->pcKeyID = pcKeyIDCpy;
    psNewNode->pucEncKey = pucEncKey;
    psNewNode->pucHash = pucHash;  // dummy hash
    
    psNewNode->iDepth = strlen(pcParentKeyID);
    psNewNode->iNumChildren = 0;

    psNewNode->psNext = psParentNode->psChild;
    psNewNode->psChild = NULL;
    psNewNode->psParent = psParentNode;
    psParentNode->psChild = psNewNode;

    psParentIter = psParentNode;
    while (psParentIter != NULL) {
        psParentIter->iNumChildren++;
        psParentIter = psParentIter->psParent;
    }
    oKeyChain->iNumKeys++;

    return 1;
}

/*--------------------------------------------------------------------*/

/* Helper function to remove keynode with id pcKeyID */
static struct KeyNode *removeKey(struct KeyNode *psCurrNode, 
                                 struct KeyNode *psPrevNode,
                                 char *pcKeyID)
{
    int currDepth;
    while (psCurrNode != NULL) {
        currDepth = psCurrNode->iDepth;
        if ((psCurrNode->pcKeyID)[currDepth] == pcKeyID[currDepth]) {
                // printf("correct digit");
            if (strlen(pcKeyID) == currDepth+1) {
                if (psPrevNode->iDepth == psCurrNode->iDepth) {
                    psPrevNode->psNext = psCurrNode->psNext;
                }
                else {
                    psPrevNode->psChild = psCurrNode->psNext;
                }
                freeNodes(psCurrNode->psChild);
                return psCurrNode;
            }
            else {
                return removeKey(psCurrNode->psChild, psCurrNode, pcKeyID);
            }             
        }
        psPrevNode = psCurrNode;
        psCurrNode = psCurrNode->psNext;
    }
    return NULL;
}

/*--------------------------------------------------------------------*/

int KeyChain_removeKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;
    struct KeyNode *psParentIter;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    if (strcmp(pcKeyID, "0") == 0)
        return 0;

    psResultNode = removeKey(oKeyChain->psRoot->psChild,
                             oKeyChain->psRoot,
                             pcKeyID);
    if (psResultNode == NULL)
        return 0;
    //printf("removd: %s\n", psResultNode->pcKeyID);
    //printf("numremove: %d\n", psResultNode->iNumChildren + 1);

    psParentIter = psResultNode->psParent;
    while (psParentIter != NULL) {
        (psParentIter->iNumChildren) -= (psResultNode->iNumChildren + 1);
        psParentIter = psParentIter->psParent;
    }

    (oKeyChain->iNumKeys) -= (psResultNode->iNumChildren + 1);
    free(psResultNode->pcKeyID);
    free(psResultNode->pucEncKey);
    free(psResultNode->pucHash);

    free(psResultNode);

    return 1;
}

/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/