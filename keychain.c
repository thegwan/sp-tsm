/*--------------------------------------------------------------------*/
/* keychain.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include "keycrypto.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>  /* memcpy, strcpy, strlen, memcmp, strcmp */
#include <assert.h>  /* asserts  */
// #include <stdio.h>

#define KEYLEN    8  // bytes
#define HASHLEN   8  // bytes
#define INTBUFLEN (sizeof(int) * 8 + 1)            
#define ARRBUFLEN (sizeof(unsigned char) * 16 + 1)

/*--------------------------------------------------------------------*/

/* Each key is stored in a KeyNode, which are linked to form a key
   chain. */

struct KeyNode
{
    /* Key ID */
    char *pcKeyID;

    /* 64 bit encrypted key, encrypted by the parent key */
    unsigned char *pucEncKey;

    /* 64 bit keyed hash of the key record */
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
/* Private functions:                                                 */
/*--------------------------------------------------------------------*/

/* 256 bit hash of key ID, the encrypted key, depth, and 
   parent key ID. */

static void hashKeyNode(struct KeyNode *psNode, unsigned char *hash)
{
    SHA256_CTX ctx;
    char int_buf[INTBUFLEN];
    char key_buf[ARRBUFLEN];
    char *pcParentKeyID;

    assert(psNode != NULL);
    assert(hash != NULL);
    assert(psNode->pcKeyID != NULL);
    assert(psNode->pucEncKey != NULL);

    memset(int_buf, 0, INTBUFLEN);
    memset(key_buf, 0, ARRBUFLEN);

    if (psNode->psParent == NULL)
        pcParentKeyID = "0";
    else
        pcParentKeyID = psNode->psParent->pcKeyID;

    sha256_init(&ctx);

    sha256_update(&ctx, psNode->pcKeyID, strlen(psNode->pcKeyID));

    arrToString(psNode->pucEncKey, key_buf);
    sha256_update(&ctx, key_buf, strlen(key_buf));

    intToString(psNode->iDepth, int_buf);
    sha256_update(&ctx, int_buf, strlen(int_buf));

    sha256_update(&ctx, pcParentKeyID, strlen(pcParentKeyID));

    sha256_final(&ctx, hash);
    // print_hash(hash);

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

/*--------------------------------------------------------------------*/

/* Recursive helper function to get keynode of pcKeyID */
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

/* Recursive helper function to get plaintext key of psNode */
static unsigned char *getPlainKey(struct KeyNode *psNode,
                                  unsigned char *pucOutput)
{
    unsigned char aucBuf[KEYLEN];
    unsigned char *pucParentPlainKey;

    if (psNode->psParent == NULL)     // is root, return UMK
        return psNode->pucEncKey;
    pucParentPlainKey = getPlainKey(psNode->psParent, pucOutput);

    xor_decrypt(psNode->pucEncKey, aucBuf, KEYLEN, pucParentPlainKey);
    memcpy(pucOutput, aucBuf, KEYLEN);

    return pucOutput;
}

/*--------------------------------------------------------------------*/

/* Helper function to remove keynode with id pcKeyID */
static struct KeyNode *removeKeyNode(struct KeyNode *psCurrNode, 
                                    struct KeyNode *psPrevNode,
                                    char *pcKeyID)
{
    int currDepth;
    while (psCurrNode != NULL) {
        currDepth = psCurrNode->iDepth;
        if ((psCurrNode->pcKeyID)[currDepth] == pcKeyID[currDepth]) {
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
                return removeKeyNode(psCurrNode->psChild, psCurrNode, pcKeyID);
            }             
        }
        psPrevNode = psCurrNode;
        psCurrNode = psCurrNode->psNext;
    }
    return NULL;
}


/*--------------------------------------------------------------------*/
/* Public functions:                                                  */
/*--------------------------------------------------------------------*/

KeyChain_T KeyChain_new(unsigned long umk)
{
    KeyChain_T oKeyChain;
    struct KeyNode *psRoot;
    char *pcRootKeyID;
    unsigned char *pucRootEncKey;
    unsigned char *pucRootHash;
    unsigned char aucHashBuf[32];   // 256 bit hash
    // unsigned char aucRootEncKey[] = {0x01, 0x23, 0x45, 0x67,
    //                                         0x89, 0xab, 0xcd, 0xef};
    unsigned char *aucRootEncKey;
    aucRootEncKey = (unsigned char*)&umk;


    oKeyChain = (KeyChain_T)malloc(sizeof(struct KeyChain));
    if (oKeyChain == NULL)
        return NULL;

    // if this fails, free oKeyChain?
    psRoot = (struct KeyNode *)malloc(sizeof(struct KeyNode));
    if (psRoot == NULL)
        return NULL;

    pcRootKeyID = (char *)malloc(sizeof(char) + 1);
    if (pcRootKeyID == NULL)
        return NULL;
    strcpy(pcRootKeyID, "0");

    pucRootEncKey = (unsigned char *)malloc(KEYLEN * sizeof(unsigned char));  // 64 bits
    if (pucRootEncKey == NULL)
        return NULL;
    memcpy(pucRootEncKey, aucRootEncKey, KEYLEN);


    pucRootHash = (unsigned char *)malloc(HASHLEN * sizeof(unsigned char));  // 64 bits
    if (pucRootHash == NULL)
        return NULL;

    psRoot->pcKeyID = pcRootKeyID;
    psRoot->pucEncKey = pucRootEncKey;

    psRoot->iDepth = 0;
    psRoot->iNumChildren = 0;
    psRoot->psChild = NULL;
    psRoot->psNext = NULL;
    psRoot->psParent = NULL;
    // psRoot->psMetaData = NULL;

    hashKeyNode(psRoot, aucHashBuf);
    memcpy(pucRootHash, aucHashBuf, HASHLEN);  // first 64 bits;
    psRoot->pucHash = pucRootHash;

    oKeyChain->iNumKeys = 0;
    oKeyChain->psRoot = psRoot;

    return oKeyChain;
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

/*--------------------------------------------------------------------*/

unsigned char *KeyChain_getKey(KeyChain_T oKeyChain, char *pcKeyID,
                               unsigned char *pucOutput)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);
    assert(pucOutput != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return getPlainKey(psResultNode, pucOutput);
    return NULL;

}

/*--------------------------------------------------------------------*/

unsigned char *KeyChain_getEncryptedKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return psResultNode->pucEncKey;
    return NULL;
}

/*--------------------------------------------------------------------*/

unsigned char *KeyChain_getHash(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return psResultNode->pucHash;
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

    unsigned char aucParentKeyBuf[KEYLEN];   // 64 bit key length
    unsigned char aucHashBuf[32];       // 256 bit SHA-256 

    assert(oKeyChain != NULL);
    assert(pcParentKeyID != NULL);
    assert(pcKeyID != NULL);
    assert(pucKey != NULL);

    // make sure key ID is a valid child of the parent
    if (strlen(pcParentKeyID) + 1 != strlen(pcKeyID))
        return 0;

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

    pucEncKey = (unsigned char *)malloc(KEYLEN * sizeof(unsigned char));  // 64 bit
    if (pucEncKey == NULL)
        return 0;
    memset(pucEncKey, 0, KEYLEN);
    xor_encrypt(pucKey, pucEncKey, KEYLEN, getPlainKey(psParentNode, aucParentKeyBuf));


    pucHash = (unsigned char *)malloc(HASHLEN * sizeof(unsigned char));
    if (pucHash == NULL)
        return 0;
    
    psNewNode->pcKeyID = pcKeyIDCpy;
    psNewNode->pucEncKey = pucEncKey;

    psNewNode->iDepth = strlen(pcParentKeyID);
    psNewNode->iNumChildren = 0;

    psNewNode->psNext = psParentNode->psChild;
    psNewNode->psChild = NULL;
    psNewNode->psParent = psParentNode;

    hashKeyNode(psNewNode, aucHashBuf);
    memcpy(pucHash, aucHashBuf, HASHLEN);    // first 64 bits
    psNewNode->pucHash = pucHash; 

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

int KeyChain_removeKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;
    struct KeyNode *psParentIter;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    if (strcmp(pcKeyID, "0") == 0)
        return 0;

    psResultNode = removeKeyNode(oKeyChain->psRoot->psChild,
                                oKeyChain->psRoot,
                                pcKeyID);
    if (psResultNode == NULL)
        return 0;

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

int KeyChain_verifyKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;
    unsigned char hash[32];

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL) {
        hashKeyNode(psResultNode, hash);
        return (memcmp(psResultNode->pucHash, hash, HASHLEN) == 0);
    }
    return 0;
}

/*--------------------------------------------------------------------*/


