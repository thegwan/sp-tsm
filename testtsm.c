/*--------------------------------------------------------------------*/
/* testtsm.c                                                       */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include "sha256.h"
#include "tsm.h"
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

/*--------------------------------------------------------------------*/

static void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

/*--------------------------------------------------------------------*/

static void phex(unsigned char *str)
{
    unsigned char i;

    for (i = 0; i < 4; i++)
        printf("%.2x", str[i]);
    printf("\n");
}


/*--------------------------------------------------------------------*/

int main(void)
{
    printf("------------------------------------------------------\n");
    printf("Begin tests\n");

    KeyChain_T oKeyChain;

    oKeyChain = KeyChain_new();
    AddKeyToChain(oKeyChain, "0", "00");
    sleep(1);
    AddKeyToChain(oKeyChain, "0", "01");

    Encrypt("file.txt", "file.enc", oKeyChain, "00");
    printf("encrypted file.txt into file.enc\n");
    Decrypt("file.enc", "file.dec", oKeyChain, "00");
    printf("decrypted file.enc into file.dec\n");


    Encrypt("elephant.jpg", "elephantenc.jpg", oKeyChain, "01");
    printf("encrypted elephant.jpg into elephantenc.jpg\n");
    Decrypt("elephantenc.jpg", "elephantdec.jpg", oKeyChain, "01");
    printf("decrypted elephantenc.jpg into elephantdec.jpg\n");

    KeyChain_free(oKeyChain);
    
    printf("------------------------------------------------------\n");
    printf("End of tests\n");
} 
