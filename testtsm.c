/*--------------------------------------------------------------------*/
/* testtsm.c                                                       */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include "sha256.h"
#include "tsm.h"
#include <stdlib.h>
//#include <string.h>  
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
    printf("Begin tests\n");
    printf("------------------------------------------------------\n");

    int status;
    unsigned long umk = 0xefcdab8967452301;
    KeyChain_T oKeyChain;

    oKeyChain = KeyChain_new(umk);
    status = AddKeyToChain(oKeyChain, "0", "00", 0);
    if (status) printf("added key!\n");
    sleep(1);
    status = AddKeyToChain(oKeyChain, "0", "01", 1);
    if (status) printf("added key!\n");
    sleep(1);
    status = AddKeyToChain(oKeyChain, "00", "000", 1);
    if (status) printf("added key!\n");
    sleep(1);
    status = AddKeyToChain(oKeyChain, "00", "001", 1);
    if (status) printf("added key!\n");

    // small text file
    status = Encrypt("file.txt", "file.enc", oKeyChain, "001");
    if (status) printf("encrypted file.txt into file.enc\n");
    else printf("encryption failed\n");

    status = Decrypt("file.enc", "file.dec", oKeyChain, "001");
    if (status) printf("decrypted file.enc into file.dec\n");
    else printf("decryption failed\n");

    // image
    status = Encrypt("elephant.jpg", "elephantenc.jpg", oKeyChain, "01");
    if (status) printf("encrypted elephant.jpg into elephantenc.jpg\n");
    else printf("encryption failed\n");

    status = Decrypt("elephantenc.jpg", "elephantdec.jpg", oKeyChain, "01");
    if (status) printf("decrypted elephantenc.jpg into elephantdec.jpg\n");
    else printf("decryption failed\n");

    // 8 byte multiple
    status = Encrypt("file2.txt", "file2.enc", oKeyChain, "000");
    if (status) printf("encrypted file2.txt into file2.enc\n");
    else printf("encryption failed\n");

    status = Decrypt("file2.enc", "file2.dec", oKeyChain, "000");
    if (status) printf("decrypted file2.enc into file2.dec\n");
    else printf("decryption failed\n");

    status = DeleteKeyFromChain(oKeyChain, "001");
    if (status) printf("deleted key!\n");

    // should fail, key revoked
    status = Decrypt("file.enc", "file.dec", oKeyChain, "001");
    if (status) printf("decrypted file.enc into file.dec\n");
    else printf("decryption failed\n");

    sleep(1);
    status = AddKeyToChain(oKeyChain, "0", "02", 1);
    if (status) printf("added key!\n");

    // should fail, wrong key
    status = Decrypt("file.enc", "file.dec", oKeyChain, "02");
    if (status) printf("decrypted file.enc into file.dec\n");
    else printf("decryption failed\n");   

    // encrypt with new key
    status = Encrypt("file.txt", "file.enc", oKeyChain, "02");
    if (status) printf("encrypted file.txt into file.enc\n");
    else printf("encryption failed\n");

    status = Decrypt("file.enc", "file.dec", oKeyChain, "02");
    if (status) printf("decrypted file.enc into file.dec\n");
    else printf("decryption failed\n"); 

    KeyChain_free(oKeyChain);
    
    printf("------------------------------------------------------\n");
    printf("End of tests\n");
} 
