/*--------------------------------------------------------------------*/
/* demo1_driver.c                                                     */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keychain.h"
#include "sha256.h"
#include "tsm.h"
#include <stdlib.h>
#include <stdio.h>

int main()
{
    unsigned long umk;
    int status;
    int c;
    unsigned int curr;
    unsigned int stop;
    FILE *fptr;

    // load umk with the value stored in UMK CSR 0x050
    __asm__ __volatile__(
        "csrr %0, 0x050;\n"
        : "=r" (umk));
    
    // umk = 0xefcdab8967452301;  // uncomment for x86 test

    // initialize a keychain 
    // (this would normally be done during user initialization)
    KeyChain_T oKeyChain;
    oKeyChain = KeyChain_new(umk);

    /*----------------------------------------------------------------*/
    /* Add some keys to the key chain                                 */
    /*----------------------------------------------------------------*/
    status = AddKeyToChain(oKeyChain, "0", "00", 0);
    if (status) printf("---added key!\n");

    // sleep(1)
    curr = time(0);
    stop = curr + 1;
    while (1) {
      curr = time(0);
      if (curr >= stop)
	break;
    }
    
    status = AddKeyToChain(oKeyChain, "0", "01", 1);
    if (status) printf("---added key!\n");

    // sleep(1)
    curr = time(0);
    stop = curr + 1;
    while (1) {
      curr = time(0);
      if (curr >= stop)
	break;
    }
    
    status = AddKeyToChain(oKeyChain, "00", "000", 1);
    if (status) printf("---added key!\n");

    /*----------------------------------------------------------------*/
    /* Encrypt a file                                                 */
    /*----------------------------------------------------------------*/

    // print original
    printf("---Original text:\n");
    fptr = fopen("file.txt", "r");
    while ((c = fgetc(fptr)) != EOF) {
        printf("%c", c);
    }
    fclose(fptr);

    // encrypt
    status = Encrypt("file.txt", "file.enc", oKeyChain, "01");
    if (status) printf("---encrypted file.txt into file.enc\n");
    else printf("---encryption failed\n");

    // print encrypted (should display gibberish)
    printf("---Encrypted text:\n");
    fptr = fopen("file.enc", "r");
    while ((c = fgetc(fptr)) != EOF) {
        printf("%c", c);
    }
    fclose(fptr);

    /*----------------------------------------------------------------*/
    /* Attempt to decrypt with an incorrect key                       */
    /*----------------------------------------------------------------*/

    status = Decrypt("file.enc", "file.dec", oKeyChain, "000");
    if (status) printf("---decrypted file.enc into file.dec\n");
    else printf("---decryption failed\n");

    /*----------------------------------------------------------------*/
    /* Decrypt with a correct key                                     */
    /*----------------------------------------------------------------*/

    status = Decrypt("file.enc", "file.dec", oKeyChain, "01");
    if (status) printf("---decrypted file.enc into file.dec\n");
    else printf("---decryption failed\n");

    // print decrypted (should match with original)
    printf("---Decrypted text with correct key:\n");
    fptr = fopen("file.dec", "r");
    while ((c = fgetc(fptr)) != EOF) {
        printf("%c", c);
    }
    fclose(fptr);

    /*----------------------------------------------------------------*/
    /* Revoke a key and attempt to use it                             */
    /*----------------------------------------------------------------*/

    // delete the key
    status = DeleteKeyFromChain(oKeyChain, "01");
    if (status) printf("---deleted key!\n"); 

    // try to decrypt with revoked key
    status = Decrypt("file.enc", "file.dec", oKeyChain, "01");
    if (status) printf("---decrypted file.enc into file.dec\n");
    else printf("---decryption failed\n");   

    printf("-----done----\n");
}
