/*--------------------------------------------------------------------*/
/* testkeyrecord.c                                                        */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/



#include "keyrecord.h"
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
    KeyRecord_T oKeyRecord1;
    KeyRecord_T oKeyRecord2;
    KeyRecord_T oKeyRecord3;

    oKeyRecord1 = KeyRecord_new();
    ASSURE(oKeyRecord1 != NULL);

    oKeyRecord2 = KeyRecord_new();
    ASSURE(oKeyRecord2 != NULL);

    oKeyRecord3 = KeyRecord_new();
    ASSURE(oKeyRecord3 != NULL);

    KeyRecord_free(oKeyRecord1);
    ASSURE(oKeyRecord1 == NULL);

    KeyRecord_free(oKeyRecord2);
    ASSURE(oKeyRecord2 == NULL);

    KeyRecord_free(oKeyRecord3);
    ASSURE(oKeyRecord3 == NULL);


}

int main(void)
{
    testBasics();
    printf("-----------------------");
    printf("End of tests\n");
} 
