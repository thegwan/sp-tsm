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

    char acUserMasterKey[] = "0000000000000000";

    char acEncKey1[] = "0000000000000001";   // dummy encrypted keys
    char acEncKey2[] = "0000000000000002";
    char acEncKey3[] = "0000000000000003";
    char acKey1Hash[] = "1111111111111111";  // dummy hashes
    char acKey2Hash[] = "1111111111111112";
    char acKey3Hash[] = "1111111111111113";

    oKeyChain = KeyChain_new();
    ASSURE(oKeyChain != NULL);


    KeyChain_free(oKeyChain);

}

int main(void)
{
    testBasics();
    printf("-----------------------");
    printf("End of tests\n");
} 
