/*--------------------------------------------------------------------*/
/* testkeychain.c                                                     */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include <stdlib.h>
#include <string.h>  
#include <assert.h>
#include <stdio.h>

#define ASSURE(i) assure(i, __LINE__)

/* If !iSuccessful, print a message to stdout indicating that the
   test failed. */

static void assure(int iSuccessful, int iLineNum)
{
    if (! iSuccessful)
    {
        printf("Test at line %d failed.\n", iLineNum);
        fflush(stdout);
    }
}

static void testBasics()
{
    KeyChain_T oKeyChain;

    char acRootKeyID_0[] = "0";
    unsigned char aucRootEncKey_0[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00};

    // dummy encrypted keys
    char acKeyID_00[] = "00";
    unsigned char aucEncKey_00[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x01};

    char acKeyID_01[] = "01";
    unsigned char aucEncKey_01[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x02};

    char acKeyID_02[] = "02";
    unsigned char aucEncKey_02[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x03};

    char acKeyID_000[] = "000";
    unsigned char aucEncKey_000[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x04};

    char acKeyID_010[] = "010";
    unsigned char aucEncKey_010[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x05};

    char acKeyID_011[] = "011";
    unsigned char aucEncKey_011[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x06};

    char acKeyID_0000[] = "0000";
    unsigned char aucEncKey_0000[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x07};

    char acKeyID_0001[] = "0001";
    unsigned char aucEncKey_0001[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x08};    

    // dummy hashes
    unsigned char aucDummyHash[] = {(unsigned char) 0x00, (unsigned char) 0x01, (unsigned char) 0x02, (unsigned char) 0x03};  

    char *pcResult;
    unsigned char *pucResult;
    int iValue;

    printf("------------------------------------------------------\n");
    printf("Testing KeyChain functions.\n");
    printf("No output should appear here:\n");
    fflush(stdout);

    oKeyChain = KeyChain_new();
    ASSURE(oKeyChain != NULL);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 0);

    pucResult = KeyChain_getKey(oKeyChain, acRootKeyID_0);
    // printf("root key: %s\n", pcResult);
    ASSURE(memcmp(pucResult, aucRootEncKey_0, 4) == 0);

    /* add 00 as a child of the root key 0 */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_00, aucEncKey_00);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_00);
    // printf("key id 00: %s\n", pcResult);
    ASSURE(memcmp(pucResult, aucEncKey_00, 4) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_01);
    ASSURE(pucResult == NULL);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 1);

    /* try to add key whose parent does not exist */
    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, aucEncKey_010);
    ASSURE(iValue == 0);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, aucEncKey_01);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_00, acKeyID_000, aucEncKey_000);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    /* try to add key that is already in the chain */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, aucEncKey_01);
    ASSURE(iValue == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_01);
    // printf("key id 01: %s\n", pcResult);
    ASSURE(memcmp(pucResult, aucEncKey_01, 4) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_000);
    // printf("key id 000: %s\n", pcResult);
    ASSURE(memcmp(pucResult, aucEncKey_000, 4) == 0);

    /* try to remove root */
    iValue = KeyChain_removeKey(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_02, aucEncKey_02);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, aucEncKey_010);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_011, aucEncKey_011);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, aucEncKey_0000);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0001, aucEncKey_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 8);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_0000);
    ASSURE(memcmp(pucResult, aucEncKey_0000, 4) == 0);    

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_0000);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0000);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);    

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 7);

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_01);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_01);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_010);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_011);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_02);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 4);

    /* add key back in */
    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, aucEncKey_0000);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 5);

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_0000);
    ASSURE(iValue == 1); 

    iValue = KeyChain_contains(oKeyChain, acKeyID_0000);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 4);

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_000);
    ASSURE(iValue == 0);  

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 0);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 1);            

    KeyChain_free(oKeyChain);

}

int main(void)
{
    testBasics();
    printf("------------------------------------------------------\n");
    printf("End of tests\n");
} 
