/*--------------------------------------------------------------------*/
/* testkeychain.c                                                        */
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
    char acRootEncKey_0[] = "0000000000000000";

    char acKeyID_00[] = "00";
    char acEncKey_00[] = "0000000000000001";   // dummy encrypted keys

    char acKeyID_01[] = "01";
    char acEncKey_01[] = "0000000000000002";

    char acKeyID_02[] = "02";
    char acEncKey_02[] = "0000000000000003";

    char acKeyID_000[] = "000";
    char acEncKey_000[] = "0000000000000004";

    char acKeyID_010[] = "010";
    char acEncKey_010[] = "0000000000000005";

    char acKeyID_011[] = "011";
    char acEncKey_011[] = "0000000000000006";

    char acKeyID_0000[] = "0000";
    char acEncKey_0000[] = "0000000000000007";

    char acKeyID_0001[] = "0001";
    char acEncKey_0001[] = "0000000000000008";    


    char acKey1Hash[] = "1111111111111111";  // dummy hashes
    char acKey2Hash[] = "1111111111111112";
    char acKey3Hash[] = "1111111111111113";

    char *pcResult;
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

    pcResult = KeyChain_getKey(oKeyChain, acRootKeyID_0);
    // printf("root key: %s\n", pcResult);
    ASSURE(strcmp(pcResult, acRootEncKey_0) == 0);

    /* add 00 as a child of the root key 0 */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_00, acEncKey_00);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    pcResult = KeyChain_getKey(oKeyChain, acKeyID_00);
    // printf("key id 00: %s\n", pcResult);
    ASSURE(strcmp(pcResult, acEncKey_00) == 0);

    pcResult = KeyChain_getKey(oKeyChain, acKeyID_01);
    ASSURE(pcResult == NULL);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 1);

    /* try to add key whose parent does not exist */
    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, acEncKey_010);
    ASSURE(iValue == 0);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, acEncKey_01);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_00, acKeyID_000, acEncKey_000);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    /* try to add key that is already in the chain */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, acEncKey_01);
    ASSURE(iValue == 0);

    pcResult = KeyChain_getKey(oKeyChain, acKeyID_01);
    // printf("key id 01: %s\n", pcResult);
    ASSURE(strcmp(pcResult, acEncKey_01) == 0);

    pcResult = KeyChain_getKey(oKeyChain, acKeyID_000);
    // printf("key id 000: %s\n", pcResult);
    ASSURE(strcmp(pcResult, acEncKey_000) == 0);

    /* try to remove root */
    iValue = KeyChain_removeKey(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_02, acEncKey_02);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, acEncKey_010);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_011, acEncKey_011);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, acEncKey_0000);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0001, acEncKey_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 8);

    pcResult = KeyChain_getKey(oKeyChain, acKeyID_0000);
    ASSURE(strcmp(pcResult, acEncKey_0000) == 0);    

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
    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, acEncKey_0000);
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
