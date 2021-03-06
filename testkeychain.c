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
#define KEYLEN 8

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

/*--------------------------------------------------------------------*/

/* print hex */

static void phex(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < 4; i++)
        printf("%.2x", str[i]);
    printf("\n");
}

/*--------------------------------------------------------------------*/

static void testBasics()
{
    KeyChain_T oKeyChain;
    unsigned long umk = 0xefcdab8967452301;

    char acRootKeyID_0[] = "0";
    unsigned char aucRootEncKey_0[] = {0x01, 0x23, 0x45, 0x67,
                                       0x89, 0xab, 0xcd, 0xef};

    // dummy keys
    char acKeyID_00[] = "00";
    unsigned char aucKey_00[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x01};

    char acKeyID_01[] = "01";
    unsigned char aucKey_01[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x02};

    char acKeyID_02[] = "02";
    unsigned char aucKey_02[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x03};

    char acKeyID_000[] = "000";
    unsigned char aucKey_000[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x04};

    char acKeyID_010[] = "010";
    unsigned char aucKey_010[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x05};

    char acKeyID_011[] = "011";
    unsigned char aucKey_011[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x06};

    char acKeyID_0000[] = "0000";
    unsigned char aucKey_0000[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x07};

    char acKeyID_0001[] = "0001";
    unsigned char aucKey_0001[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x08};     

    unsigned char *pucResult;
    unsigned char aucBuf[KEYLEN];
    int iValue;

    printf("------------------------------------------------------\n");
    printf("Testing Basic KeyChain functions.\n");
    printf("No output should appear here:\n");
    fflush(stdout);

    oKeyChain = KeyChain_new(umk);
    ASSURE(oKeyChain != NULL);

    //----- contains root key

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 0);

    pucResult = KeyChain_getKey(oKeyChain, acRootKeyID_0, aucBuf);
    ASSURE(memcmp(pucResult, aucRootEncKey_0, KEYLEN) == 0);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_00, aucKey_00, 0);
    ASSURE(iValue == 1);

    //----- contains root, 00

    iValue = KeyChain_contains(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_00, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_00, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_01, aucBuf);
    ASSURE(pucResult == NULL);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 1);

    /* try to add key whose parent does not exist */
    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, aucKey_010, 0);
    ASSURE(iValue == 0);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, aucKey_01, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_00, acKeyID_000, aucKey_000, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    /* try to add key that is already in the chain */
    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_01, aucKey_01, 0);
    ASSURE(iValue == 0);

    //----- contains root, 00, 01, 000

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_01, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_01, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_000, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_000, KEYLEN) == 0);

    /* try to remove root */
    iValue = KeyChain_removeKey(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID_0, acKeyID_02, aucKey_02, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_010, aucKey_010, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_01, acKeyID_011, aucKey_011, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, aucKey_0000, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0001, aucKey_0001, 0);
    ASSURE(iValue == 1);

    //----- contains root, 00, 01, 02, 000, 010, 011, 0000, 0001

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 8);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_0000, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_0000, KEYLEN) == 0);    


    iValue = KeyChain_removeKey(oKeyChain, acKeyID_0000);
    ASSURE(iValue == 1);

    //----- contains root, 00, 01, 02, 000, 010, 011, 0001

    iValue = KeyChain_contains(oKeyChain, acKeyID_0000);
    ASSURE(iValue == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);    

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 7);

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_01);
    ASSURE(iValue == 1);


    //----- contains root, 00, 02, 000, 0001

    iValue = KeyChain_verifyKey(oKeyChain, acRootKeyID_0);
    ASSURE(iValue == 1);

    iValue = KeyChain_verifyKey(oKeyChain, acKeyID_00);
    ASSURE(iValue == 1);

    iValue = KeyChain_verifyKey(oKeyChain, acKeyID_02);
    ASSURE(iValue == 1);

    iValue = KeyChain_verifyKey(oKeyChain, acKeyID_000);
    ASSURE(iValue == 1);

    iValue = KeyChain_verifyKey(oKeyChain, acKeyID_0001);
    ASSURE(iValue == 1);

    iValue = KeyChain_verifyKey(oKeyChain, acKeyID_01);
    ASSURE(iValue == 0);

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
    iValue = KeyChain_addKey(oKeyChain, acKeyID_000, acKeyID_0000, aucKey_0000, 0);
    ASSURE(iValue == 1);

    //----- contains root, 00, 02, 000, 0000, 0001

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

    //----- contains root, 02

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

/*--------------------------------------------------------------------*/

static void testVerticalTree()
{
    KeyChain_T oKeyChain;

    unsigned long umk = 0x192ba72c;   // some umk

    char acRootKeyID[] = "0";
    // unsigned char aucRootEncKey_0[] = {0x01, 0x23, 0x45, 0x67,
    //                                    0x89, 0xab, 0xcd, 0xef};

    // dummy keys
    char acKeyID_1[] = "00";
    unsigned char aucKey_1[] = {0x62, 0xac, 0xaa, 0x99,
                                0x29, 0x02, 0xab, 0xfd};

    char acKeyID_2[] = "000";
    unsigned char aucKey_2[] = {0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff};

    char acKeyID_3[] = "0000";
    unsigned char aucKey_3[] = {0x12, 0x50, 0x064, 0x00,
                                0x99, 0xca, 0x0b4, 0x12};

    char acKeyID_4[] = "00000";
    unsigned char aucKey_4[] = {0x10, 0x98, 0xcd, 0xbb,
                                0x61, 0xaf, 0x0d, 0x01};

    char acKeyID_5[] = "000000";
    unsigned char aucKey_5[] = {0x61, 0xaf, 0x0d, 0x01,
                                0xbb, 0xdc, 0x00, 0x40};

    char acKeyID_6[] = "0000000";
    unsigned char aucKey_6[] = {0x00, 0xaf, 0x0d, 0x00,
                                0x16, 0x23, 0x77, 0x86};

    char acKeyID_7[] = "00000000";
    unsigned char aucKey_7[] = {0xdd, 0xdd, 0x0d, 0x63,
                                0xb0, 0x1a, 0x8c, 0x87};
 

    unsigned char *pucResult;
    unsigned char aucBuf[KEYLEN];
    int iValue;

    printf("------------------------------------------------------\n");
    printf("Testing Vertical KeyChain functions.\n");
    printf("No output should appear here:\n");
    fflush(stdout);

    oKeyChain = KeyChain_new(umk);
    ASSURE(oKeyChain != NULL);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_1, aucKey_1, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_1, acKeyID_2, aucKey_2, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_2, acKeyID_3, aucKey_3, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_3, acKeyID_4, aucKey_4, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_4, acKeyID_5, aucKey_5, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_5, acKeyID_6, aucKey_6, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_6, acKeyID_7, aucKey_7, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 7);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_1, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_1, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_2, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_2, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_3, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_3, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_4, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_4, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_5, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_5, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_6, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_6, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_7, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_7, KEYLEN) == 0);

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_4);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_4, acKeyID_2, aucKey_2, 0);
    ASSURE(iValue == 0);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 3);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_6, aucBuf);
    ASSURE(pucResult == NULL);

    pucResult = KeyChain_getEncryptedKey(oKeyChain, acKeyID_7);
    ASSURE(pucResult == NULL);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_3, acKeyID_4, aucKey_4, 0);
    ASSURE(iValue == 1);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_4, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_4, KEYLEN) == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_4);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_3, acKeyID_7, aucKey_7, 0);
    ASSURE(iValue == 0);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 4);


    KeyChain_free(oKeyChain);

}

/*--------------------------------------------------------------------*/

static void testHorizontalTree()
{
    KeyChain_T oKeyChain;

    unsigned long umk = 0xb12ababa817;  // some umk

    char acRootKeyID[] = "0";
    // unsigned char aucRootEncKey_0[] = {0x01, 0x23, 0x45, 0x67,
    //                                    0x89, 0xab, 0xcd, 0xef};

    // dummy keys
    char acKeyID_0[] = "00";
    unsigned char aucKey_0[] = {0x62, 0xac, 0xaa, 0x99,
                                0x29, 0x02, 0xab, 0xfd};

    char acKeyID_1[] = "01";
    unsigned char aucKey_1[] = {0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff};

    char acKeyID_2[] = "02";
    unsigned char aucKey_2[] = {0x12, 0x50, 0x064, 0x00,
                                0x99, 0xca, 0x0b4, 0x12};

    char acKeyID_3[] = "03";
    unsigned char aucKey_3[] = {0x10, 0x98, 0xcd, 0xbb,
                                0x61, 0xaf, 0x0d, 0x01};

    char acKeyID_4[] = "04";
    unsigned char aucKey_4[] = {0x61, 0xaf, 0x0d, 0x01,
                                0xbb, 0xdc, 0x00, 0x40};

    char acKeyID_5[] = "05";
    unsigned char aucKey_5[] = {0x00, 0xaf, 0x0d, 0x00,
                                0x16, 0x23, 0x77, 0x86};

    char acKeyID_6[] = "06";
    unsigned char aucKey_6[] = {0xdd, 0xdd, 0x0d, 0x63,
                                0xb0, 0x1a, 0x8c, 0x87};

    char acKeyID_7[] = "07";
    unsigned char aucKey_7[] = {0x64, 0x23, 0x53, 0xbc,
                                0x60, 0x00, 0x00, 0xc4};

    char acKeyID_8[] = "08";
    unsigned char aucKey_8[] = {0xca, 0xac, 0x32, 0x34,
                                0xee, 0x75, 0xbc, 0x55};

    char acKeyID_9[] = "09";
    unsigned char aucKey_9[] = {0xf0, 0xf0, 0xec, 0xc4,
                                0xce, 0x9c, 0x81, 0x8f};

 
    unsigned char *pucResult;
    unsigned char aucBuf[KEYLEN];
    int iValue;

    printf("------------------------------------------------------\n");
    printf("Testing Horizontal KeyChain functions.\n");
    printf("No output should appear here:\n");
    fflush(stdout);

    oKeyChain = KeyChain_new(umk);
    ASSURE(oKeyChain != NULL);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_0, aucKey_0, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_1, aucKey_1, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_2, aucKey_2, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_3, aucKey_3, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_4, aucKey_4, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_5, aucKey_5, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_6, aucKey_6, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_7, aucKey_7, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_8, aucKey_8, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_9, aucKey_9, 0);
    ASSURE(iValue == 1);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 10);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_0, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_0, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_2, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_2, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_4, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_4, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_6, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_6, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_8, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_8, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_9, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_9, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_7, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_7, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_5, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_5, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_3, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_3, KEYLEN) == 0);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_1, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_1, KEYLEN) == 0);

    iValue = KeyChain_removeKey(oKeyChain, acKeyID_4);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_2, aucKey_2, 0);
    ASSURE(iValue == 0);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 9);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_6, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_6, KEYLEN) == 0);

    pucResult = KeyChain_getEncryptedKey(oKeyChain, acKeyID_7);
    ASSURE(pucResult != NULL);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_5, aucKey_5, 0);
    ASSURE(iValue == 0);

    iValue = KeyChain_addKey(oKeyChain, acRootKeyID, acKeyID_4, aucKey_4, 0);
    ASSURE(iValue == 1);

    pucResult = KeyChain_getKey(oKeyChain, acKeyID_4, aucBuf);
    ASSURE(memcmp(pucResult, aucKey_4, KEYLEN) == 0);

    iValue = KeyChain_contains(oKeyChain, acKeyID_4);
    ASSURE(iValue == 1);

    iValue = KeyChain_addKey(oKeyChain, acKeyID_3, acKeyID_7, aucKey_7, 0);
    ASSURE(iValue == 0);

    iValue = KeyChain_getNumKeys(oKeyChain);
    ASSURE(iValue == 10);


    KeyChain_free(oKeyChain);

}

/*--------------------------------------------------------------------*/

int main(void)
{
    testBasics();
    testVerticalTree();
    testHorizontalTree();
    printf("------------------------------------------------------\n");
    printf("End of tests\n");
} 
