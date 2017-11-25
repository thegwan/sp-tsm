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
    unsigned int uiRootEncKey_0 = 0x00000000;

    char acKeyID_00[] = "00";
    unsigned int uiEncKey_00 = 0x00000001;   // dummy encrypted keys

    char acKeyID_01[] = "01";
    unsigned int uiEncKey_01 = 0x00000002;

    char acKeyID_02[] = "02";
    unsigned int uiEncKey_02 = 0x00000003;

    char acKeyID_000[] = "000";
    unsigned int uiEncKey_000 = 0x00000004;

    char acKeyID_010[] = "010";
    unsigned int uiEncKey_010 = 0x00000005;

    char acKeyID_011[] = "011";
    unsigned int uiEncKey_011 = 0x00000006;

    char acKeyID_0000[] = "0000";
    unsigned int uiEncKey_0000 = 0x00000007;

    char acKeyID_0001[] = "0001";
    unsigned int uiEncKey_0001 = 0x00000008;    


    unsigned int uiKey1Hash = 0x11111111;  // dummy hashes
    unsigned int uiKey2Hash = 0x11111112;
    unsigned int uiKey3Hash = 0x11111113;

    char *pcResult;
    unsigned int uiResult;
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

    uiResult = KeyChain_getKey(oKeyChain, acRootKeyID_0);
    printf("root key: %x\n", uiResult);
    ASSURE(uiResult == uiRootEncKey_0);

    /* add 00 as a child of the root key 0 */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_00, uiEncKey_00);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    uiResult = KeyChain_getKey(oKeyChain, acKeyID_00);
    printf("key id 00: %x\n", uiResult);
    ASSURE(uiResult == uiEncKey_00);

    uiResult = KeyChain_getKey(oKeyChain, acKeyID_01);
    ASSURE(uiResult == 0);  // default NULL value

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 1);

    /* try to add key whose parent does not exist */
    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, uiEncKey_010);
    ASSURE(iValue == 0);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, uiEncKey_01);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_00, acKeyID_000, uiEncKey_000);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    /* try to add key that is already in the chain */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, uiEncKey_01);
    ASSURE(iValue == 0);

    uiResult = KeyChain_getKey(oKeyChain, acKeyID_01);
    printf("key id 01: %x\n", uiResult);
    ASSURE(uiResult == uiEncKey_01);

    uiResult = KeyChain_getKey(oKeyChain, acKeyID_000);
    printf("key id 000: %x\n", uiResult);
    ASSURE(uiResult == uiEncKey_000);

    /* try to remove root */
    iValue = KeyChain_removeKey(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_02, uiEncKey_02);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, uiEncKey_010);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_011, uiEncKey_011);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, uiEncKey_0000);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0001, uiEncKey_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 8);

    uiResult = KeyChain_getKey(oKeyChain, acKeyID_0000);
    ASSURE(uiResult == uiEncKey_0000);    

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
    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, uiEncKey_0000);
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
