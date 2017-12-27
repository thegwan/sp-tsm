/*--------------------------------------------------------------------*/
/* keychain.c                                                         */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include "keycrypto.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define KEYLEN     8   // bytes
#define HASHLEN    32  // bytes
#define INTBUFLEN  (sizeof(int) * 8 + 1)            
#define KEYBUFLEN  (sizeof(unsigned char) * KEYLEN*2 + 1)
#define HASHBUFLEN (sizeof(unsigned char) * HASHLEN*2 + 1)

/*--------------------------------------------------------------------*/

/* Each key is stored in a KeyNode, which are linked to form a key
   chain. */

struct KeyNode
{
    /* key ID */
    char *pcKeyID;

    /* 64 bit encrypted key, encrypted by the parent key */
    unsigned char *pucEncKey;

    /* 256 bit intermediate hash or hash of the data */
    unsigned char *pucInterHash;

    /* 256 bit keyed hash of the key record */
    unsigned char *pucHash;

    /* type non-leaf: 0, leaf: 1 */
    int iType;

    /* depth of node */
    int iDepth;

    /* number of children */
    int iNumChildren;

    /* pointer to children (first child) */
    struct KeyNode *psChild;

    /* pointer to sibling node at same level */
    struct KeyNode *psNext;

    /* pointer to parent */
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

/* 256 bit hash of the key node */
static void hashKeyNode(struct KeyNode *psNode, unsigned char *hash)
{
    SHA256_CTX ctx;
    char int_buf[INTBUFLEN];
    char key_buf[KEYBUFLEN];
    char hash_buf[HASHBUFLEN];
    char *pcParentKeyID;

    assert(psNode != NULL);
    assert(hash != NULL);
    assert(psNode->pcKeyID != NULL);
    assert(psNode->pucEncKey != NULL);

    // clear buffers
    memset(int_buf, 0, INTBUFLEN);
    memset(key_buf, 0, KEYBUFLEN);
    memset(hash_buf, 0, HASHBUFLEN);

    if (psNode->psParent == NULL)
        pcParentKeyID = "0";
    else
        pcParentKeyID = psNode->psParent->pcKeyID;

    // compute hash over all the contents
    sha256_init(&ctx);

    sha256_update(&ctx, psNode->pcKeyID, strlen(psNode->pcKeyID));

    sha256_update(&ctx, pcParentKeyID, strlen(pcParentKeyID));

    arrToString(psNode->pucEncKey, key_buf, KEYLEN);
    sha256_update(&ctx, key_buf, strlen(key_buf));

    arrToString(psNode->pucInterHash, hash_buf, HASHLEN);
    sha256_update(&ctx, hash_buf, strlen(hash_buf));

    intToString(psNode->iType, int_buf);
    sha256_update(&ctx, int_buf, strlen(int_buf));

    intToString(psNode->iDepth, int_buf);
    sha256_update(&ctx, int_buf, strlen(int_buf));

    sha256_final(&ctx, hash);

}

/*--------------------------------------------------------------------*/

/* Recursive helper function to free psNode and all its children and 
   siblings */
static void freeNodes(struct KeyNode *psNode)
{
    if (psNode) {
        freeNodes(psNode->psNext);
        freeNodes(psNode->psChild);

        // free key node content
        free(psNode->pcKeyID);
        free(psNode->pucEncKey);
        free(psNode->pucInterHash);
        free(psNode->pucHash);

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

/* Recursive helper function to get plaintext key of psNode, placing
   the result in pucOutput */
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

/* Recursive helper function to remove keynode with id pcKeyID */
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
                // free all children
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

/* Compute hash over the key node hashes psNode's children, place
   the result in aucHashBuf */
static void hashChildren(struct KeyNode *psNode, unsigned char *aucHashBuf)
{
    struct KeyNode *psCurrNode;
    char hash_buf[HASHBUFLEN];
    SHA256_CTX ctx;

    assert(psNode != NULL);
    assert(aucHashBuf != NULL);

    memset(aucHashBuf, 0, HASHLEN);
    memset(hash_buf, 0, HASHBUFLEN);

    if (psNode->iNumChildren == 0)
        return;

    sha256_init(&ctx);

    psCurrNode = psNode->psChild;
    while (psCurrNode != NULL) {
        arrToString(psCurrNode->pucHash, hash_buf, HASHLEN);
        sha256_update(&ctx, hash_buf, strlen(hash_buf));
        psCurrNode = psCurrNode->psNext;
    }
    sha256_final(&ctx, aucHashBuf);
}

/*--------------------------------------------------------------------*/

/* Update hash of intermediate node psNode */
static void updateHashes(struct KeyNode *psNode)
{
    char aucHashBuf[HASHLEN];

    assert(psNode != NULL);

    // update internal hash with hashes of children
    hashChildren(psNode, aucHashBuf);
    memcpy(psNode->pucInterHash, aucHashBuf, HASHLEN);

    // rehash entire key node
    memset(aucHashBuf, 0, HASHLEN);
    hashKeyNode(psNode, aucHashBuf);
    memcpy(psNode->pucHash, aucHashBuf, HASHLEN);
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
    unsigned char *pucRootInterHash;
    unsigned char *pucRootHash;
    unsigned char *aucRootEncKey;
    unsigned char aucHashBuf[HASHLEN];   // 256 bit hash
    aucRootEncKey = (unsigned char*)&umk;

    oKeyChain = (KeyChain_T)malloc(sizeof(struct KeyChain));
    if (oKeyChain == NULL)
        return NULL;

    // Instantiate software root node
    psRoot = (struct KeyNode *)malloc(sizeof(struct KeyNode));
    if (psRoot == NULL)
        return NULL;

    pcRootKeyID = (char *)malloc(sizeof(char) + 1);
    if (pcRootKeyID == NULL)
        return NULL;
    strcpy(pcRootKeyID, "0");

    // 64 bit key
    pucRootEncKey = (unsigned char *)malloc(KEYLEN * sizeof(unsigned char));
    if (pucRootEncKey == NULL)
        return NULL;
    memcpy(pucRootEncKey, aucRootEncKey, KEYLEN);

    // 256 bit internal hash
    pucRootInterHash = (unsigned char *)malloc(HASHLEN * sizeof(unsigned char));
    if (pucRootInterHash == NULL)
        return NULL;
    memset(pucRootInterHash, 0, HASHLEN);

    // 256 bit key node hash
    pucRootHash = (unsigned char *)malloc(HASHLEN * sizeof(unsigned char));
    if (pucRootHash == NULL)
        return NULL;

    psRoot->pcKeyID      = pcRootKeyID;
    psRoot->pucEncKey    = pucRootEncKey;
    psRoot->pucInterHash = pucRootInterHash;
    psRoot->iType        = 0;
    psRoot->iDepth       = 0;
    psRoot->iNumChildren = 0;
    psRoot->psChild      = NULL;
    psRoot->psNext       = NULL;
    psRoot->psParent     = NULL;

    hashKeyNode(psRoot, aucHashBuf);
    memcpy(pucRootHash, aucHashBuf, HASHLEN);
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

unsigned char *KeyChain_getKey(KeyChain_T oKeyChain, 
                               char *pcKeyID,
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

unsigned char *KeyChain_getInterHash(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return psResultNode->pucInterHash;
    return NULL;
}

/*--------------------------------------------------------------------*/

int KeyChain_getType(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode != NULL)
        return psResultNode->iType;
    return -1;
}

/*--------------------------------------------------------------------*/

int KeyChain_addKey(KeyChain_T oKeyChain, 
                    char *pcParentKeyID,
                    char *pcKeyID, 
                    unsigned char *pucKey,
                    int iType)
{
    struct KeyNode *psNewNode;
    struct KeyNode *psParentNode;
    struct KeyNode *psParentIter;
    char *pcKeyIDCpy;
    unsigned char *pucEncKey;
    unsigned char *pucInterHash;
    unsigned char *pucHash;

    unsigned char aucParentKeyBuf[KEYLEN];   // 64 bit key
    unsigned char aucHashBuf[HASHLEN];       // 256 bit hash 

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

    // create new key node
    psNewNode = (struct KeyNode *)malloc(sizeof(struct KeyNode));
    if (psNewNode == NULL)
        return 0;

    // make defensive copy of key id
    pcKeyIDCpy = (char *)malloc(strlen(pcKeyID) + 1);
    if (pcKeyIDCpy == NULL)
        return 0;
    strcpy(pcKeyIDCpy, pcKeyID);

    pucEncKey = (unsigned char *)malloc(KEYLEN * sizeof(unsigned char));
    if (pucEncKey == NULL)
        return 0;
    memset(pucEncKey, 0, KEYLEN);
    xor_encrypt(pucKey, pucEncKey, KEYLEN, getPlainKey(psParentNode, aucParentKeyBuf));

    pucInterHash = (unsigned char *)malloc(HASHLEN * sizeof(unsigned char));
    if (pucInterHash == NULL)
        return 0;
    memset(pucInterHash, 0, HASHLEN);

    pucHash = (unsigned char *)malloc(HASHLEN * sizeof(unsigned char));
    if (pucHash == NULL)
        return 0;
    
    psNewNode->pcKeyID = pcKeyIDCpy;
    psNewNode->pucEncKey = pucEncKey;
    psNewNode->pucInterHash = pucInterHash;

    psNewNode->iType = iType;
    psNewNode->iDepth = strlen(pcParentKeyID);
    psNewNode->iNumChildren = 0;

    psNewNode->psNext = psParentNode->psChild;
    psNewNode->psChild = NULL;
    psNewNode->psParent = psParentNode;

    hashKeyNode(psNewNode, aucHashBuf);
    memcpy(pucHash, aucHashBuf, HASHLEN);
    psNewNode->pucHash = pucHash; 

    psParentNode->psChild = psNewNode;

    // update metadata and intermediate hashes on path to root node
    psParentIter = psParentNode;
    while (psParentIter != NULL) {
        psParentIter->iNumChildren++;
        updateHashes(psParentIter);
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

    // update metadata and intermediate hashes on path to root node
    psParentIter = psResultNode->psParent;
    while (psParentIter != NULL) {
        (psParentIter->iNumChildren) -= (psResultNode->iNumChildren + 1);
        updateHashes(psParentIter);
        psParentIter = psParentIter->psParent;
    }

    (oKeyChain->iNumKeys) -= (psResultNode->iNumChildren + 1);
    free(psResultNode->pcKeyID);
    free(psResultNode->pucEncKey);
    free(psResultNode->pucInterHash);
    free(psResultNode->pucHash);

    free(psResultNode);

    return 1;
}

/*--------------------------------------------------------------------*/

int KeyChain_updateKey(KeyChain_T oKeyChain, 
                       char *pcKeyID, 
                       unsigned char *pucInterHash)
{
    struct KeyNode *psResultNode;
    struct KeyNode *psCurrNode;
    unsigned char aucHashBuf[HASHLEN];

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode == NULL) {
        return 0;
    }

    // update internal hash
    memcpy(psResultNode->pucInterHash, pucInterHash, HASHLEN);

    // rehash entire key node
    hashKeyNode(psResultNode, aucHashBuf);
    memcpy(psResultNode->pucHash, aucHashBuf, HASHLEN);

    // update intermediate hashes on path to root node
    psCurrNode = psResultNode->psParent;
    while (psCurrNode != NULL) {
        updateHashes(psCurrNode);
        psCurrNode = psCurrNode->psParent;
    }
    
    return 1;
}

/*--------------------------------------------------------------------*/

int KeyChain_verifyKey(KeyChain_T oKeyChain, char *pcKeyID)
{
    struct KeyNode *psResultNode;
    struct KeyNode *psNodeIter;
    struct KeyNode *psNodeChild;
    unsigned char aucHashBuf[HASHLEN];

    assert(oKeyChain != NULL);
    assert(pcKeyID != NULL);

    psResultNode = getKeyNode(oKeyChain->psRoot, pcKeyID);
    if (psResultNode == NULL)
        return 0;

    psNodeIter = psResultNode;
    while (psNodeIter != NULL) {
        hashChildren(psNodeIter, aucHashBuf);

        // non-leaf node intermediate hashes must match
        if (psNodeIter->iType == 0 && 
            memcmp(psNodeIter->pucInterHash, aucHashBuf, HASHLEN) != 0) {
            return 0;
        }

        // key node hash must match
        hashKeyNode(psNodeIter, aucHashBuf);
        if (memcmp(psNodeIter->pucHash, aucHashBuf, HASHLEN) != 0) {
            return 0;
        }
        psNodeIter = psNodeIter->psParent;
    }
    return 1;
}

/*--------------------------------------------------------------------*/
