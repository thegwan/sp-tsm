/*--------------------------------------------------------------------*/
/* testkeycrypto.c                                                       */
/* Author: Gerry Wan                                                  */
/*--------------------------------------------------------------------*/

#include "keycrypto.h"
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

    unsigned char aucKey0[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00};

    unsigned char aucKey1[] = {(unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x00, (unsigned char) 0x01};  

    unsigned char aucKey2[] = {(unsigned char) 0x6d, (unsigned char) 0x22, (unsigned char) 0xa5, (unsigned char) 0x1d};

    unsigned char aucKey3[] = {(unsigned char) 0x09, (unsigned char) 0xf1, (unsigned char) 0x73, (unsigned char) 0xba};

    unsigned char aucInput0[] = {(unsigned char) 0x72, (unsigned char) 0x3d, (unsigned char) 0x38, (unsigned char) 0xae};

    unsigned char aucInput1[] = {(unsigned char) 0xa5, (unsigned char) 0x51, (unsigned char) 0x0f, (unsigned char) 0x58,
                                 (unsigned char) 0xda, (unsigned char) 0x91, (unsigned char) 0xcd, (unsigned char) 0xc2,
                                 (unsigned char) 0x4b, (unsigned char) 0x40, (unsigned char) 0xd7, (unsigned char) 0xff,
                                 (unsigned char) 0x00, (unsigned char) 0xe0, (unsigned char) 0x8b, (unsigned char) 0x68};

    unsigned char aucOutput00[] = {(unsigned char) 0x72, (unsigned char) 0x3d, (unsigned char) 0x38, (unsigned char) 0xae};
    unsigned char aucOutput01[] = {(unsigned char) 0xa5, (unsigned char) 0x51, (unsigned char) 0x0f, (unsigned char) 0x58,
                                 (unsigned char) 0xda, (unsigned char) 0x91, (unsigned char) 0xcd, (unsigned char) 0xc2,
                                 (unsigned char) 0x4b, (unsigned char) 0x40, (unsigned char) 0xd7, (unsigned char) 0xff,
                                 (unsigned char) 0x00, (unsigned char) 0xe0, (unsigned char) 0x8b, (unsigned char) 0x68};
    unsigned char aucOutput10[] = {(unsigned char) 0x72, (unsigned char) 0x3d, (unsigned char) 0x38, (unsigned char) 0xaf};
    unsigned char aucOutput11[] = {(unsigned char) 0xa5, (unsigned char) 0x51, (unsigned char) 0x0f, (unsigned char) 0x59,
                                 (unsigned char) 0xda, (unsigned char) 0x91, (unsigned char) 0xcd, (unsigned char) 0xc3,
                                 (unsigned char) 0x4b, (unsigned char) 0x40, (unsigned char) 0xd7, (unsigned char) 0xfe,
                                 (unsigned char) 0x00, (unsigned char) 0xe0, (unsigned char) 0x8b, (unsigned char) 0x69};
    unsigned char aucOutput20[] = {(unsigned char) 0x1f, (unsigned char) 0x1f, (unsigned char) 0x9d, (unsigned char) 0xb3};
    unsigned char aucOutput21[] = {(unsigned char) 0xc8, (unsigned char) 0x73, (unsigned char) 0xaa, (unsigned char) 0x45,
                                 (unsigned char) 0xb7, (unsigned char) 0xb3, (unsigned char) 0x68, (unsigned char) 0xdf,
                                 (unsigned char) 0x26, (unsigned char) 0x62, (unsigned char) 0x72, (unsigned char) 0xe2,
                                 (unsigned char) 0x6d, (unsigned char) 0xc2, (unsigned char) 0x2e, (unsigned char) 0x75};
    unsigned char aucOutput30[] = {(unsigned char) 0x7b, (unsigned char) 0xcc, (unsigned char) 0x4b, (unsigned char) 0x14};
    unsigned char aucOutput31[] =  {(unsigned char) 0xac, (unsigned char) 0xa0, (unsigned char) 0x7c, (unsigned char) 0xe2,
                                 (unsigned char) 0xd3, (unsigned char) 0x60, (unsigned char) 0xbe, (unsigned char) 0x78,
                                 (unsigned char) 0x42, (unsigned char) 0xb1, (unsigned char) 0xa4, (unsigned char) 0x45,
                                 (unsigned char) 0x09, (unsigned char) 0x11, (unsigned char) 0xf8, (unsigned char) 0xd2};

    unsigned char aucBufferShort[4];
    unsigned char aucBufferLong[16];

    memset(aucBufferShort, 0, 4);
    memset(aucBufferLong, 0, 16);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey0);
    ASSURE(memcmp(aucBufferShort, aucOutput00, 4) == 0);

    xor_decrypt(aucOutput00, aucBufferShort, 4, aucKey0);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey0);
    ASSURE(memcmp(aucBufferLong, aucOutput01, 16) == 0);

    xor_decrypt(aucOutput01, aucBufferLong, 16, aucKey0);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey1);
    ASSURE(memcmp(aucBufferShort, aucOutput10, 4) == 0);

    xor_decrypt(aucOutput10, aucBufferShort, 4, aucKey1);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey1);
    ASSURE(memcmp(aucBufferLong, aucOutput11, 16) == 0);

    xor_decrypt(aucOutput11, aucBufferLong, 16, aucKey1);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey2);
    ASSURE(memcmp(aucBufferShort, aucOutput20, 4) == 0);

    xor_encrypt(aucOutput20, aucBufferShort, 4, aucKey2);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey2);
    ASSURE(memcmp(aucBufferLong, aucOutput21, 16) == 0);

    xor_decrypt(aucOutput21, aucBufferLong, 16, aucKey2);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);

    xor_encrypt(aucInput0, aucBufferShort, 4, aucKey3);
    ASSURE(memcmp(aucBufferShort, aucOutput30, 4) == 0);

    xor_decrypt(aucOutput30, aucBufferShort, 4, aucKey3);
    ASSURE(memcmp(aucBufferShort, aucInput0, 4) == 0);

    xor_encrypt(aucInput1, aucBufferLong, 16, aucKey3);
    ASSURE(memcmp(aucBufferLong, aucOutput31, 16) == 0);

    xor_decrypt(aucOutput31, aucBufferLong, 16, aucKey3);
    ASSURE(memcmp(aucBufferLong, aucInput1, 16) == 0);


}

int main(void)
{
    printf("------------------------------------------------------\n");
    printf("Testing XOR Encrypt and Decrypt.\n");
    printf("No output should appear here:\n");
    fflush(stdout);

    testBasics();

    printf("------------------------------------------------------\n");
    printf("End of tests\n");
} 
